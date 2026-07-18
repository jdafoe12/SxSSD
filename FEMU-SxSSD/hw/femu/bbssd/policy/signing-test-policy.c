#include "femu_policy.h"

static uint64_t rejected_attestation_callback(struct ssd *ssd,
                                              struct NvmeCommandEvent *event,
                                              struct FtlPolicyAPI *api,
                                              void *context)
{
    (void)ssd;
    (void)event;
    (void)api;
    (void)context;
    return 0;
}

/* Exercise restricted bootstrap signing and reserved attestation opcodes. */
int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    static const uint8_t owner_nonce[32] = { 1 };
    static const uint8_t owner_ephemeral_public_key[32] = { 2 };
    static const uint8_t policy_ephemeral_public_key[32] = { 3 };
    uint8_t signature[64];

    (void)ssd;
    if (!api || !api->sign_key_bootstrap || !api->register_admin_hook ||
        api->register_admin_hook(ssd, 0x9f, NULL,
                                 rejected_attestation_callback, NULL) >= 0 ||
        api->register_admin_hook(ssd, 0x9a, NULL,
                                 rejected_attestation_callback, NULL) >= 0 ||
        api->register_admin_hook(ssd, 0xe0, NULL,
                                 rejected_attestation_callback, NULL) < 0) {
        return -1;
    }
    return api->sign_key_bootstrap(owner_nonce, owner_ephemeral_public_key,
                                   policy_ephemeral_public_key, signature);
}
