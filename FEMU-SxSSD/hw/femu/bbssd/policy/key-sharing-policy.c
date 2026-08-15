#include "policy-wasm-abi.h"

#define KEY_SHARING_SUBMIT_OPCODE 0xe3U
#define KEY_SHARING_FETCH_OPCODE 0xe2U
#define KEY_SHARING_SUBMIT_PAIR 1U
#define KEY_SHARING_FETCH_PAIR 2U
#define KEY_SHARING_FIELD_SIZE 32U
#define KEY_SHARING_SIGNATURE_SIZE 64U

struct key_sharing_request {
    sxs_u8 owner_nonce[32];
    sxs_u8 owner_ephemeral_public_key[32];
    sxs_u8 tapp_signature[64];
};

struct key_sharing_response {
    sxs_u8 policy_ephemeral_public_key[32];
    sxs_u8 device_signature[64];
    sxs_u8 key_confirmation[32];
};

struct key_sharing_state {
    sxs_u8 shared_key[32];
    struct key_sharing_response pending_response;
    sxs_u32 shared_key_valid;
    sxs_u32 pending_response_valid;
};

static struct key_sharing_state key_sharing_state;

static const sxs_u8 tapp_public_key[32] = {
    0xb8, 0xde, 0xd4, 0x25, 0xfe, 0xf9, 0x63, 0x1f,
    0x3f, 0xa1, 0x1c, 0x1c, 0xf2, 0xe1, 0x57, 0x94,
    0xab, 0xae, 0xf9, 0xd5, 0xe0, 0x83, 0x75, 0xcb,
    0x65, 0x71, 0xd9, 0x4e, 0xc4, 0xc3, 0x7e, 0xbc,
};

static const sxs_u8 tapp_auth_domain[] =
    "SxSSD-TApp-Key-Bootstrap-Request-v1";
static const sxs_u8 kdf_info[] = "SxSSD-Policy-Shared-Key-v1";
static const sxs_u8 confirmation_domain[] =
    "SxSSD-Policy-Key-Confirmation-v1";

static void bytes_copy(sxs_u8 *destination, const sxs_u8 *source,
                       sxs_u32 length)
{
    for (sxs_u32 i = 0; i < length; i++) {
        destination[i] = source[i];
    }
}

static void bytes_zero(sxs_u8 *destination, sxs_u32 length)
{
    for (sxs_u32 i = 0; i < length; i++) {
        destination[i] = 0;
    }
}

static sxs_s64 hmac_sha256(const sxs_u8 *key, sxs_u32 key_length,
                           const sxs_u8 *message, sxs_u32 message_length,
                           sxs_u8 output[32])
{
    return sxs_crypto_hmac_sha256(key, key_length, message, message_length,
                                  output, 32);
}

static sxs_u64 key_sharing_init(void)
{
    if (sxs_subscribe(SXS_EVENT_NVME_ADMIN,
                      KEY_SHARING_SUBMIT_OPCODE,
                      KEY_SHARING_SUBMIT_PAIR, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_ADMIN,
                      KEY_SHARING_FETCH_OPCODE,
                      KEY_SHARING_FETCH_PAIR, 0) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    return 0;
}

static sxs_u64 key_sharing_condition(const struct sxs_policy_context *context)
{
    return context->pair_id == KEY_SHARING_SUBMIT_PAIR ||
           context->pair_id == KEY_SHARING_FETCH_PAIR;
}

static sxs_s64 read_state(struct key_sharing_state *state)
{
    if (!state) {
        return -SXS_WASM_EINVAL;
    }
    bytes_copy((sxs_u8 *)state, (const sxs_u8 *)&key_sharing_state,
               sizeof(*state));
    return 0;
}

static sxs_s64 write_state(const struct key_sharing_state *state)
{
    if (!state) {
        return -SXS_WASM_EINVAL;
    }
    bytes_copy((sxs_u8 *)&key_sharing_state, (const sxs_u8 *)state,
               sizeof(*state));
    return 0;
}

static sxs_u64 fetch_response(struct sxs_policy_context *context)
{
    struct key_sharing_state state;

    if (context->event.nvme.cdw12 != sizeof(state.pending_response) ||
        read_state(&state) != 0 || !state.pending_response_valid) {
        sxs_completion_status_set(0x4002);
        return 0;
    }
    if (sxs_command_write(0, &state.pending_response,
                          sizeof(state.pending_response)) != 0) {
        sxs_completion_status_set(0x4004);
        return 0;
    }
    bytes_zero((sxs_u8 *)&state.pending_response,
               sizeof(state.pending_response));
    state.pending_response_valid = 0;
    if (write_state(&state) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    sxs_completion_status_set(0);
    return 0;
}

static sxs_s64 verify_tapp(const struct key_sharing_request *request)
{
    sxs_u8 message[sizeof(tapp_auth_domain) - 1 + 64];
    sxs_u32 domain_length = sizeof(tapp_auth_domain) - 1;

    bytes_copy(message, tapp_auth_domain, domain_length);
    bytes_copy(message + domain_length, request->owner_nonce, 32);
    bytes_copy(message + domain_length + 32,
               request->owner_ephemeral_public_key, 32);

    return sxs_crypto_ed25519_verify(tapp_public_key, sizeof(tapp_public_key),
                                     message, sizeof(message),
                                     request->tapp_signature,
                                     sizeof(request->tapp_signature));
}

static sxs_s64 derive_shared_key(const struct key_sharing_request *request,
                                 const sxs_u8 private_key[32],
                                 sxs_u8 output[32])
{
    sxs_u8 shared_secret[32];
    sxs_u8 prk[32];
    sxs_u8 expand[sizeof(kdf_info)];
    sxs_u32 info_length = sizeof(kdf_info) - 1;
    sxs_s64 result;

    if (sxs_crypto_x25519_shared(
            private_key, 32, request->owner_ephemeral_public_key, 32,
            shared_secret, 32) != 0 ||
        hmac_sha256(request->owner_nonce, 32, shared_secret, 32, prk) != 0) {
        bytes_zero(shared_secret, sizeof(shared_secret));
        return -SXS_WASM_EIO;
    }
    bytes_copy(expand, kdf_info, info_length);
    expand[info_length] = 1;
    result = hmac_sha256(prk, 32, expand, sizeof(expand), output);
    bytes_zero(shared_secret, sizeof(shared_secret));
    bytes_zero(prk, sizeof(prk));
    return result;
}

static sxs_s64 create_confirmation(
    const struct key_sharing_request *request,
    const struct key_sharing_response *response, const sxs_u8 shared_key[32],
    sxs_u8 output[32])
{
    sxs_u8 message[sizeof(confirmation_domain) - 1 + 96];
    sxs_u32 domain_length = sizeof(confirmation_domain) - 1;

    bytes_copy(message, confirmation_domain, domain_length);
    bytes_copy(message + domain_length, request->owner_nonce, 32);
    bytes_copy(message + domain_length + 32,
               request->owner_ephemeral_public_key, 32);
    bytes_copy(message + domain_length + 64,
               response->policy_ephemeral_public_key, 32);
    return hmac_sha256(shared_key, 32, message, sizeof(message), output);
}

static sxs_u64 submit_request(struct sxs_policy_context *context)
{
    struct key_sharing_request request;
    struct key_sharing_response response;
    struct key_sharing_state state;
    sxs_u8 private_key[32];
    sxs_u8 shared_key[32];

    if (context->event.nvme.cdw12 != sizeof(request) ||
        sxs_command_read(0, &request, sizeof(request)) != 0 ||
        verify_tapp(&request) != 1) {
        sxs_completion_status_set(0x4002);
        return 0;
    }
    bytes_zero((sxs_u8 *)&response, sizeof(response));
    if (sxs_crypto_random(private_key, sizeof(private_key)) != 0 ||
        sxs_crypto_x25519_public(private_key, 32,
                                 response.policy_ephemeral_public_key, 32) != 0 ||
        derive_shared_key(&request, private_key, shared_key) != 0) {
        bytes_zero(private_key, sizeof(private_key));
        return SXS_WASM_ACTION_ERROR;
    }

    if (sxs_sign_key_bootstrap(request.owner_nonce,
                               request.owner_ephemeral_public_key,
                               response.policy_ephemeral_public_key,
                               response.device_signature) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    if (create_confirmation(
            &request, &response, shared_key, response.key_confirmation) != 0 ||
        read_state(&state) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }

    bytes_copy(state.shared_key, shared_key, 32);
    bytes_copy((sxs_u8 *)&state.pending_response,
               (const sxs_u8 *)&response, sizeof(response));
    state.shared_key_valid = 1;
    state.pending_response_valid = 1;
    bytes_zero(private_key, sizeof(private_key));
    bytes_zero(shared_key, sizeof(shared_key));
    if (write_state(&state) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    sxs_completion_status_set(0);
    return 0;
}

static sxs_u64 key_sharing_action(struct sxs_policy_context *context)
{
    switch (context->pair_id) {
    case KEY_SHARING_SUBMIT_PAIR:
        return submit_request(context);
    case KEY_SHARING_FETCH_PAIR:
        return fetch_response(context);
    default:
        return SXS_WASM_ACTION_ERROR;
    }
}

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    return (sxs_s32)key_sharing_init();
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 || context.pair_id != pair_id) {
        return -SXS_WASM_EINVAL;
    }
    return (sxs_s32)key_sharing_condition(&context);
}

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 || context.pair_id != pair_id) {
        return SXS_WASM_ACTION_ERROR;
    }
    return key_sharing_action(&context);
}
