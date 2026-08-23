/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "device-trust.h"
#include "policy-crypto.h"

#include <string.h>

/* Simulated firmware-owned device identity key. */
static const uint8_t sxs_device_private_key[32] = {
    0xe1, 0xaf, 0xe2, 0x9d, 0x3d, 0x41, 0xa9, 0xa1,
    0x7e, 0x97, 0x0a, 0x4b, 0x33, 0xcc, 0x77, 0x8a,
    0x68, 0xa4, 0xf7, 0x70, 0x01, 0x19, 0x06, 0x99,
    0xff, 0xdb, 0x04, 0xdb, 0xd4, 0xc2, 0xe4, 0xd4,
};

static int sign_with_private_key(
    const uint8_t private_key[32], const uint8_t *data, size_t data_len,
    uint8_t signature[SXS_DEVICE_SIGNATURE_SIZE])
{
    if (!signature || (!data && data_len != 0)) {
        return -1;
    }
    return pe_crypto_ed25519_sign(private_key, data, data_len, signature);
}

int device_trust_sign_policy_key_bootstrap(
    const uint8_t owner_nonce[SXS_KEY_BOOTSTRAP_FIELD_SIZE],
    const uint8_t owner_ephemeral_public_key[SXS_KEY_BOOTSTRAP_FIELD_SIZE],
    const uint8_t policy_ephemeral_public_key[SXS_KEY_BOOTSTRAP_FIELD_SIZE],
    uint8_t signature[SXS_DEVICE_SIGNATURE_SIZE])
{
    uint8_t message[SXS_KEY_BOOTSTRAP_MESSAGE_SIZE];
    size_t offset = 0;

    if (!owner_nonce || !owner_ephemeral_public_key ||
        !policy_ephemeral_public_key || !signature) {
        return -1;
    }

    memcpy(message + offset, SXS_KEY_BOOTSTRAP_DOMAIN,
           SXS_KEY_BOOTSTRAP_DOMAIN_SIZE);
    offset += SXS_KEY_BOOTSTRAP_DOMAIN_SIZE;
    memcpy(message + offset, owner_nonce, SXS_KEY_BOOTSTRAP_FIELD_SIZE);
    offset += SXS_KEY_BOOTSTRAP_FIELD_SIZE;
    memcpy(message + offset, owner_ephemeral_public_key,
           SXS_KEY_BOOTSTRAP_FIELD_SIZE);
    offset += SXS_KEY_BOOTSTRAP_FIELD_SIZE;
    memcpy(message + offset, policy_ephemeral_public_key,
           SXS_KEY_BOOTSTRAP_FIELD_SIZE);

    return sign_with_private_key(sxs_device_private_key, message,
                                 sizeof(message), signature);
}

int device_trust_sign_attestation(const uint8_t *data, size_t data_len,
                              uint8_t signature[SXS_DEVICE_SIGNATURE_SIZE])
{
    return sign_with_private_key(sxs_device_private_key, data,
                                 data_len, signature);
}
