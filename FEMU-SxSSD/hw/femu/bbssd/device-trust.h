#ifndef SXS_DEVICE_TRUST_H
#define SXS_DEVICE_TRUST_H

#include <stddef.h>
#include <stdint.h>

#define SXS_DEVICE_SIGNATURE_SIZE 64
#define SXS_KEY_BOOTSTRAP_FIELD_SIZE 32
#define SXS_KEY_BOOTSTRAP_DOMAIN "SxSSD-Policy-Key-Bootstrap-v1"
#define SXS_KEY_BOOTSTRAP_DOMAIN_SIZE (sizeof(SXS_KEY_BOOTSTRAP_DOMAIN) - 1)
#define SXS_KEY_BOOTSTRAP_MESSAGE_SIZE \
    (SXS_KEY_BOOTSTRAP_DOMAIN_SIZE + 3 * SXS_KEY_BOOTSTRAP_FIELD_SIZE)

/* Public half of the fixed identity used by the SxSSD simulator. */
static const uint8_t SXS_DEVICE_PUBLIC_KEY[32] = {
    0xfa, 0x8c, 0xfa, 0xd2, 0xd0, 0x39, 0x12, 0x55,
    0xf3, 0x73, 0xa2, 0x4b, 0x1c, 0x1c, 0x58, 0xdc,
    0xbe, 0x52, 0x04, 0x60, 0xa8, 0x2a, 0xde, 0xa6,
    0x94, 0x60, 0xbd, 0xa1, 0xab, 0x3f, 0x7b, 0x6b,
};

/* Sign the one fixed message exposed to ordinary policies. */
int device_trust_sign_policy_key_bootstrap(
    const uint8_t owner_nonce[SXS_KEY_BOOTSTRAP_FIELD_SIZE],
    const uint8_t owner_ephemeral_public_key[SXS_KEY_BOOTSTRAP_FIELD_SIZE],
    const uint8_t policy_ephemeral_public_key[SXS_KEY_BOOTSTRAP_FIELD_SIZE],
    uint8_t signature[SXS_DEVICE_SIGNATURE_SIZE]);

/* Raw device-identity signing available only to privileged firmware policy. */
int device_trust_sign_attestation(
    const uint8_t *data, size_t data_len,
    uint8_t signature[SXS_DEVICE_SIGNATURE_SIZE]);

#endif /* SXS_DEVICE_TRUST_H */
