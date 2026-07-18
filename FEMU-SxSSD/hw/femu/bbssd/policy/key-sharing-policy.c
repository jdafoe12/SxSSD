#include "femu_policy.h"
#include "key-sharing.h"

#include <endian.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct __attribute__((packed)) KeySharingNvmeCmd {
    uint16_t opcode_flags;
    uint16_t cid;
    uint32_t nsid;
    uint64_t rsvd2;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} KeySharingNvmeCmd;

struct key_sharing_context {
    uint8_t shared_key[KEY_SHARING_FIELD_SIZE];
    struct key_sharing_response pending_response;
    bool shared_key_valid;
    bool pending_response_valid;
};

static struct key_sharing_context key_sharing_ctx;

/*
 * Public half of the TApp identity provisioned for this policy. It matches
 * admin-simulation/admin_public.pem. The corresponding private key remains
 * exclusively with the TApp.
 */
static const uint8_t tapp_public_key[KEY_SHARING_FIELD_SIZE] = {
    0xb8, 0xde, 0xd4, 0x25, 0xfe, 0xf9, 0x63, 0x1f,
    0x3f, 0xa1, 0x1c, 0x1c, 0xf2, 0xe1, 0x57, 0x94,
    0xab, 0xae, 0xf9, 0xd5, 0xe0, 0x83, 0x75, 0xcb,
    0x65, 0x71, 0xd9, 0x4e, 0xc4, 0xc3, 0x7e, 0xbc,
};

static int verify_tapp_signature(const struct key_sharing_request *request)
{
    static const uint8_t domain[] = KEY_SHARING_TAPP_AUTH_DOMAIN;
    uint8_t message[(sizeof(domain) - 1) + 2 * KEY_SHARING_FIELD_SIZE];
    EVP_PKEY *public_key = NULL;
    EVP_MD_CTX *ctx = NULL;
    size_t offset = 0;
    int rc = -1;

    memcpy(message + offset, domain, sizeof(domain) - 1);
    offset += sizeof(domain) - 1;
    memcpy(message + offset, request->owner_nonce, KEY_SHARING_FIELD_SIZE);
    offset += KEY_SHARING_FIELD_SIZE;
    memcpy(message + offset, request->owner_ephemeral_public_key,
           KEY_SHARING_FIELD_SIZE);

    public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                             tapp_public_key,
                                             sizeof(tapp_public_key));
    ctx = EVP_MD_CTX_new();
    if (public_key && ctx &&
        EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, public_key) == 1 &&
        EVP_DigestVerify(ctx, request->tapp_signature,
                         sizeof(request->tapp_signature), message,
                         sizeof(message)) == 1) {
        rc = 0;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    return rc;
}

static int generate_x25519_keypair(uint8_t public_key[32],
                                   uint8_t private_key[32])
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    size_t public_key_len = 32;
    size_t private_key_len = 32;
    int rc = -1;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (ctx && EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_keygen(ctx, &key) == 1 &&
        EVP_PKEY_get_raw_public_key(key, public_key, &public_key_len) == 1 &&
        EVP_PKEY_get_raw_private_key(key, private_key, &private_key_len) == 1 &&
        public_key_len == 32 && private_key_len == 32) {
        rc = 0;
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    if (rc != 0) {
        memset(public_key, 0, 32);
        memset(private_key, 0, 32);
    }
    return rc;
}

static int derive_shared_key(const uint8_t private_key[32],
                             const uint8_t owner_public_key[32],
                             const uint8_t owner_nonce[32],
                             uint8_t shared_key[32])
{
    static const uint8_t info[] = KEY_SHARING_KDF_INFO;
    EVP_PKEY *private_pkey = NULL;
    EVP_PKEY *owner_pkey = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    uint8_t shared_secret[32];
    uint8_t prk[32];
    uint8_t expand_input[sizeof(info)];
    size_t shared_secret_len = sizeof(shared_secret);
    unsigned int output_len = 0;
    int rc = -1;

    private_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                private_key, 32);
    owner_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                             owner_public_key, 32);
    derive_ctx = private_pkey ? EVP_PKEY_CTX_new(private_pkey, NULL) : NULL;
    if (!private_pkey || !owner_pkey || !derive_ctx ||
        EVP_PKEY_derive_init(derive_ctx) != 1 ||
        EVP_PKEY_derive_set_peer(derive_ctx, owner_pkey) != 1 ||
        EVP_PKEY_derive(derive_ctx, shared_secret, &shared_secret_len) != 1 ||
        shared_secret_len != sizeof(shared_secret)) {
        goto cleanup;
    }

    if (!HMAC(EVP_sha256(), owner_nonce, 32, shared_secret,
              sizeof(shared_secret), prk, &output_len) || output_len != 32) {
        goto cleanup;
    }
    memcpy(expand_input, info, sizeof(info) - 1);
    expand_input[sizeof(info) - 1] = 1;
    if (!HMAC(EVP_sha256(), prk, sizeof(prk), expand_input,
              sizeof(expand_input), shared_key, &output_len) ||
        output_len != 32) {
        goto cleanup;
    }
    rc = 0;

cleanup:
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(prk, sizeof(prk));
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(owner_pkey);
    EVP_PKEY_free(private_pkey);
    if (rc != 0) {
        memset(shared_key, 0, 32);
    }
    return rc;
}

static int compute_key_confirmation(
    const uint8_t shared_key[32], const struct key_sharing_request *request,
    const uint8_t policy_public_key[32], uint8_t confirmation[32])
{
    static const uint8_t domain[] = KEY_SHARING_CONFIRMATION_DOMAIN;
    uint8_t message[(sizeof(domain) - 1) + 3 * KEY_SHARING_FIELD_SIZE];
    unsigned int confirmation_len = 0;
    size_t offset = 0;

    memcpy(message + offset, domain, sizeof(domain) - 1);
    offset += sizeof(domain) - 1;
    memcpy(message + offset, request->owner_nonce, KEY_SHARING_FIELD_SIZE);
    offset += KEY_SHARING_FIELD_SIZE;
    memcpy(message + offset, request->owner_ephemeral_public_key,
           KEY_SHARING_FIELD_SIZE);
    offset += KEY_SHARING_FIELD_SIZE;
    memcpy(message + offset, policy_public_key, KEY_SHARING_FIELD_SIZE);

    if (!HMAC(EVP_sha256(), shared_key, 32, message, sizeof(message),
              confirmation, &confirmation_len) || confirmation_len != 32) {
        memset(confirmation, 0, 32);
        return -1;
    }
    return 0;
}

static bool key_sharing_condition(struct ssd *ssd,
                                  struct NvmeCommandEvent *event,
                                  struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->is_admin &&
           (event->opcode == KEY_SHARING_SUBMIT_OPCODE ||
            event->opcode == KEY_SHARING_FETCH_OPCODE);
}

static uint64_t key_sharing_callback(struct ssd *ssd,
                                     struct NvmeCommandEvent *event,
                                     struct FtlPolicyAPI *api, void *context)
{
    struct key_sharing_context *ctx = context;
    const KeySharingNvmeCmd *cmd = event->cmd;

    (void)ssd;
    if (!ctx || !cmd || !api || !api->read_cmd_buffer ||
        !api->write_cmd_buffer || !api->sign_key_bootstrap) {
        event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        return 0;
    }

    if (event->opcode == KEY_SHARING_FETCH_OPCODE) {
        if (le32toh(cmd->cdw12) != sizeof(ctx->pending_response) ||
            !ctx->pending_response_valid) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            return 0;
        }
        event->status = api->write_cmd_buffer(event, &ctx->pending_response,
                                              sizeof(ctx->pending_response));
        if (event->status == NVME_SUCCESS) {
            OPENSSL_cleanse(&ctx->pending_response,
                            sizeof(ctx->pending_response));
            ctx->pending_response_valid = false;
        }
        return 0;
    }

    {
        struct key_sharing_request request;
        struct key_sharing_response response;
        uint8_t policy_private_key[32];
        uint8_t new_shared_key[32];
        int rc = -1;

        memset(&request, 0, sizeof(request));
        memset(&response, 0, sizeof(response));
        memset(policy_private_key, 0, sizeof(policy_private_key));
        memset(new_shared_key, 0, sizeof(new_shared_key));

        if (le32toh(cmd->cdw12) != sizeof(request)) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            goto cleanup;
        }
        event->status = api->read_cmd_buffer(event, &request, sizeof(request));
        if (event->status != NVME_SUCCESS) {
            goto cleanup;
        }
        if (verify_tapp_signature(&request) != 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            goto cleanup;
        }
        if (generate_x25519_keypair(response.policy_ephemeral_public_key,
                                    policy_private_key) != 0 ||
            derive_shared_key(policy_private_key,
                              request.owner_ephemeral_public_key,
                              request.owner_nonce, new_shared_key) != 0 ||
            api->sign_key_bootstrap(
                request.owner_nonce, request.owner_ephemeral_public_key,
                response.policy_ephemeral_public_key,
                response.device_signature) != 0 ||
            compute_key_confirmation(
                new_shared_key, &request,
                response.policy_ephemeral_public_key,
                response.key_confirmation) != 0) {
            event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
            goto cleanup;
        }

        OPENSSL_cleanse(ctx->shared_key, sizeof(ctx->shared_key));
        memcpy(ctx->shared_key, new_shared_key, sizeof(ctx->shared_key));
        ctx->shared_key_valid = true;
        ctx->pending_response = response;
        ctx->pending_response_valid = true;
        event->status = NVME_SUCCESS;
        rc = 0;

cleanup:
        OPENSSL_cleanse(policy_private_key, sizeof(policy_private_key));
        OPENSSL_cleanse(new_shared_key, sizeof(new_shared_key));
        OPENSSL_cleanse(&request, sizeof(request));
        if (rc != 0) {
            OPENSSL_cleanse(&response, sizeof(response));
        }
    }
    return 0;
}

int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    int submit_handle;

    if (!ssd || !api || !api->sign_key_bootstrap ||
        !api->register_admin_hook || !api->unregister_admin_hook) {
        return -1;
    }

    memset(&key_sharing_ctx, 0, sizeof(key_sharing_ctx));
    submit_handle = api->register_admin_hook(
        ssd, KEY_SHARING_SUBMIT_OPCODE, key_sharing_condition,
        key_sharing_callback, &key_sharing_ctx);
    if (submit_handle < 0) {
        return -1;
    }
    if (api->register_admin_hook(
            ssd, KEY_SHARING_FETCH_OPCODE, key_sharing_condition,
            key_sharing_callback, &key_sharing_ctx) < 0) {
        api->unregister_admin_hook(ssd, submit_handle);
        return -1;
    }
    return 0;
}
