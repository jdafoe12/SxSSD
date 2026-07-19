#include "policy-bpf-abi.h"

#define KEY_SHARING_SUBMIT_OPCODE 0xe3U
#define KEY_SHARING_FETCH_OPCODE 0xe2U
#define KEY_SHARING_SUBMIT_PAIR 1U
#define KEY_SHARING_FETCH_PAIR 2U
#define KEY_SHARING_STATE_OBJECT 1U
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

enum scratch_layout {
    REQUEST_OFFSET = 0,
    RESPONSE_OFFSET = 128,
    PRIVATE_KEY_OFFSET = 256,
    SHARED_SECRET_OFFSET = 288,
    PRK_OFFSET = 320,
    MESSAGE_OFFSET = 384,
    PUBLIC_KEY_OFFSET = 640,
    STATE_OFFSET = 704,
    HELPER_REQUEST_OFFSET = 896,
    BOOTSTRAP_REQUEST_OFFSET = 960,
};

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

static sxs_s64 hmac_sha256(struct sxs_bpf_context *context,
                           sxs_u32 key_offset, sxs_u32 key_length,
                           sxs_u32 message_offset, sxs_u32 message_length,
                           sxs_u32 output_offset)
{
    struct sxs_bpf_hmac_sha256_request *request =
        (struct sxs_bpf_hmac_sha256_request *)(context->scratch +
                                                HELPER_REQUEST_OFFSET);

    request->key_offset = key_offset;
    request->key_length = key_length;
    request->message_offset = message_offset;
    request->message_length = message_length;
    request->output_offset = output_offset;
    return sxs_crypto_hmac_sha256(HELPER_REQUEST_OFFSET, 0, 0, 0, 0);
}

static sxs_u64 key_sharing_init(void)
{
    if (sxs_state_create(KEY_SHARING_STATE_OBJECT,
                         sizeof(struct key_sharing_state), 1,
                         SXS_BPF_STATE_SECRET, 0) != 0 ||
        sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN,
                      KEY_SHARING_SUBMIT_OPCODE,
                      KEY_SHARING_SUBMIT_PAIR, 0, 0) != 0 ||
        sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN,
                      KEY_SHARING_FETCH_OPCODE,
                      KEY_SHARING_FETCH_PAIR, 0, 0) != 0) {
        return SXS_BPF_ACTION_ERROR;
    }
    return 0;
}

static sxs_u64 key_sharing_condition(const struct sxs_bpf_context *context)
{
    return context->pair_id == KEY_SHARING_SUBMIT_PAIR ||
           context->pair_id == KEY_SHARING_FETCH_PAIR;
}

static sxs_s64 read_state(void)
{
    return sxs_state_read(KEY_SHARING_STATE_OBJECT, 0, 0, STATE_OFFSET,
                          sizeof(struct key_sharing_state));
}

static sxs_s64 write_state(void)
{
    return sxs_state_write(KEY_SHARING_STATE_OBJECT, 0, 0, STATE_OFFSET,
                           sizeof(struct key_sharing_state));
}

static sxs_u64 fetch_response(struct sxs_bpf_context *context)
{
    struct key_sharing_state *state =
        (struct key_sharing_state *)(context->scratch + STATE_OFFSET);

    if (context->event.nvme.cdw12 != sizeof(state->pending_response) ||
        read_state() != 0 || !state->pending_response_valid) {
        sxs_completion_status_set(0x4002, 0, 0, 0, 0);
        return 0;
    }
    bytes_copy(context->scratch + RESPONSE_OFFSET,
               (const sxs_u8 *)&state->pending_response,
               sizeof(state->pending_response));
    if (sxs_command_write(0, RESPONSE_OFFSET,
                          sizeof(state->pending_response), 0, 0) != 0) {
        sxs_completion_status_set(0x4004, 0, 0, 0, 0);
        return 0;
    }
    bytes_zero((sxs_u8 *)&state->pending_response,
               sizeof(state->pending_response));
    state->pending_response_valid = 0;
    if (write_state() != 0) {
        return SXS_BPF_ACTION_ERROR;
    }
    sxs_completion_status_set(0, 0, 0, 0, 0);
    return 0;
}

static sxs_s64 verify_tapp(struct sxs_bpf_context *context,
                           const struct key_sharing_request *request)
{
    struct sxs_bpf_ed25519_verify_request *verify =
        (struct sxs_bpf_ed25519_verify_request *)(context->scratch +
                                                   HELPER_REQUEST_OFFSET);
    sxs_u8 *message = context->scratch + MESSAGE_OFFSET;
    sxs_u32 domain_length = sizeof(tapp_auth_domain) - 1;

    bytes_copy(context->scratch + PUBLIC_KEY_OFFSET, tapp_public_key,
               sizeof(tapp_public_key));
    bytes_copy(message, tapp_auth_domain, domain_length);
    bytes_copy(message + domain_length, request->owner_nonce, 32);
    bytes_copy(message + domain_length + 32,
               request->owner_ephemeral_public_key, 32);

    verify->public_key_offset = PUBLIC_KEY_OFFSET;
    verify->message_offset = MESSAGE_OFFSET;
    verify->message_length = domain_length + 64;
    verify->signature_offset = REQUEST_OFFSET +
        __builtin_offsetof(struct key_sharing_request, tapp_signature);
    return sxs_crypto_ed25519_verify(HELPER_REQUEST_OFFSET, 0, 0, 0, 0);
}

static sxs_s64 derive_shared_key(struct sxs_bpf_context *context,
                                 sxs_u32 output_offset)
{
    sxs_u8 *expand = context->scratch + MESSAGE_OFFSET;
    sxs_u32 info_length = sizeof(kdf_info) - 1;

    if (sxs_crypto_x25519_shared(
            PRIVATE_KEY_OFFSET,
            REQUEST_OFFSET + __builtin_offsetof(
                struct key_sharing_request,
                owner_ephemeral_public_key),
            SHARED_SECRET_OFFSET, 0, 0) != 0 ||
        hmac_sha256(context,
                    REQUEST_OFFSET + __builtin_offsetof(
                        struct key_sharing_request, owner_nonce),
                    32, SHARED_SECRET_OFFSET, 32, PRK_OFFSET) != 0) {
        return -SXS_BPF_EIO;
    }
    bytes_copy(expand, kdf_info, info_length);
    expand[info_length] = 1;
    return hmac_sha256(context, PRK_OFFSET, 32, MESSAGE_OFFSET,
                       info_length + 1, output_offset);
}

static sxs_s64 create_confirmation(
    struct sxs_bpf_context *context,
    const struct key_sharing_request *request,
    const struct key_sharing_response *response, sxs_u32 shared_key_offset,
    sxs_u32 output_offset)
{
    sxs_u8 *message = context->scratch + MESSAGE_OFFSET;
    sxs_u32 domain_length = sizeof(confirmation_domain) - 1;

    bytes_copy(message, confirmation_domain, domain_length);
    bytes_copy(message + domain_length, request->owner_nonce, 32);
    bytes_copy(message + domain_length + 32,
               request->owner_ephemeral_public_key, 32);
    bytes_copy(message + domain_length + 64,
               response->policy_ephemeral_public_key, 32);
    return hmac_sha256(context, shared_key_offset, 32, MESSAGE_OFFSET,
                       domain_length + 96, output_offset);
}

static sxs_u64 submit_request(struct sxs_bpf_context *context)
{
    struct key_sharing_request *request =
        (struct key_sharing_request *)(context->scratch + REQUEST_OFFSET);
    struct key_sharing_response *response =
        (struct key_sharing_response *)(context->scratch + RESPONSE_OFFSET);
    struct key_sharing_state *state =
        (struct key_sharing_state *)(context->scratch + STATE_OFFSET);
    struct sxs_bpf_bootstrap_sign_request *signing =
        (struct sxs_bpf_bootstrap_sign_request *)(context->scratch +
                                                   BOOTSTRAP_REQUEST_OFFSET);

    if (context->event.nvme.cdw12 != sizeof(*request) ||
        sxs_command_read(0, REQUEST_OFFSET, sizeof(*request), 0, 0) != 0 ||
        verify_tapp(context, request) != 1) {
        sxs_completion_status_set(0x4002, 0, 0, 0, 0);
        return 0;
    }
    bytes_zero((sxs_u8 *)response, sizeof(*response));
    if (sxs_crypto_random(PRIVATE_KEY_OFFSET, 32, 0, 0, 0) != 0 ||
        sxs_crypto_x25519_public(
            PRIVATE_KEY_OFFSET,
            RESPONSE_OFFSET + __builtin_offsetof(
                struct key_sharing_response,
                policy_ephemeral_public_key), 0, 0, 0) != 0 ||
        derive_shared_key(context, SHARED_SECRET_OFFSET) != 0) {
        return SXS_BPF_ACTION_ERROR;
    }

    bytes_copy(signing->owner_nonce, request->owner_nonce, 32);
    bytes_copy(signing->owner_ephemeral_public_key,
               request->owner_ephemeral_public_key, 32);
    bytes_copy(signing->policy_ephemeral_public_key,
               response->policy_ephemeral_public_key, 32);
    if (sxs_sign_key_bootstrap(BOOTSTRAP_REQUEST_OFFSET, 0, 0, 0, 0) != 0) {
        return SXS_BPF_ACTION_ERROR;
    }
    bytes_copy(response->device_signature, signing->signature, 64);
    if (create_confirmation(
            context, request, response, SHARED_SECRET_OFFSET,
            RESPONSE_OFFSET + __builtin_offsetof(
                struct key_sharing_response, key_confirmation)) != 0 ||
        read_state() != 0) {
        return SXS_BPF_ACTION_ERROR;
    }

    bytes_copy(state->shared_key, context->scratch + SHARED_SECRET_OFFSET, 32);
    bytes_copy((sxs_u8 *)&state->pending_response,
               (const sxs_u8 *)response, sizeof(*response));
    state->shared_key_valid = 1;
    state->pending_response_valid = 1;
    if (write_state() != 0) {
        return SXS_BPF_ACTION_ERROR;
    }
    sxs_completion_status_set(0, 0, 0, 0, 0);
    return 0;
}

static sxs_u64 key_sharing_action(struct sxs_bpf_context *context)
{
    switch (context->pair_id) {
    case KEY_SHARING_SUBMIT_PAIR:
        return submit_request(context);
    case KEY_SHARING_FETCH_PAIR:
        return fetch_response(context);
    default:
        return SXS_BPF_ACTION_ERROR;
    }
}

sxs_u64 policy_main(void *memory, sxs_u64 memory_size)
{
    struct sxs_bpf_context *context = memory;

    if (!context || memory_size != sizeof(*context) ||
        context->abi_version != SXS_BPF_ABI_VERSION ||
        context->context_size != sizeof(*context)) {
        return SXS_BPF_ACTION_ERROR;
    }
    switch (context->phase) {
    case SXS_BPF_PHASE_INIT:
        return key_sharing_init();
    case SXS_BPF_PHASE_CONDITION:
        return key_sharing_condition(context);
    case SXS_BPF_PHASE_ACTION:
        return key_sharing_action(context);
    default:
        return SXS_BPF_ACTION_ERROR;
    }
}
