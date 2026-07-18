#ifndef SXS_DEVICE_SIGNING_H
#define SXS_DEVICE_SIGNING_H

#include <stddef.h>
#include <stdint.h>

#define SXS_DEVICE_SIGNATURE_SIZE 64
#define SXS_KEY_BOOTSTRAP_FIELD_SIZE 32
#define SXS_KEY_BOOTSTRAP_DOMAIN "SxSSD-Policy-Key-Bootstrap-v1"
#define SXS_KEY_BOOTSTRAP_DOMAIN_SIZE (sizeof(SXS_KEY_BOOTSTRAP_DOMAIN) - 1)
#define SXS_KEY_BOOTSTRAP_MESSAGE_SIZE \
    (SXS_KEY_BOOTSTRAP_DOMAIN_SIZE + 3 * SXS_KEY_BOOTSTRAP_FIELD_SIZE)

/*
 * Policy-visible signer for exactly:
 * domain || owner_nonce || owner_ephemeral_public_key ||
 * policy_ephemeral_public_key.
 */
int sign_policy_key_bootstrap(
    const uint8_t owner_nonce[SXS_KEY_BOOTSTRAP_FIELD_SIZE],
    const uint8_t owner_ephemeral_public_key[SXS_KEY_BOOTSTRAP_FIELD_SIZE],
    const uint8_t policy_ephemeral_public_key[SXS_KEY_BOOTSTRAP_FIELD_SIZE],
    uint8_t signature[SXS_DEVICE_SIGNATURE_SIZE]);

/* Privileged raw signer used only by fixed firmware code. */
int sign_with_attestation_key(const uint8_t *data, size_t data_len,
                              uint8_t signature[SXS_DEVICE_SIGNATURE_SIZE]);

#endif /* SXS_DEVICE_SIGNING_H */
