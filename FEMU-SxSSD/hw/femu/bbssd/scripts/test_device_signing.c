/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../device-trust.h"
#include "../policy-crypto.h"
#include "host-crypto.h"

static int verify(const uint8_t public_key[32], const uint8_t *data,
                  size_t data_len, const uint8_t signature[64])
{
    return pe_crypto_ed25519_verify(public_key, data, data_len, signature);
}

static int read_exact_file(const char *path, uint8_t *buffer, size_t size)
{
    FILE *fp = fopen(path, "rb");
    int rc = -1;

    if (fp && fread(buffer, size, 1, fp) == 1 && fgetc(fp) == EOF) {
        rc = 0;
    }
    if (fp) {
        fclose(fp);
    }
    return rc;
}

static int verify_identity_files(char **paths)
{
    uint8_t device_private_key[32];
    uint8_t device_public_key[32];
    uint8_t derived_public_key[32];
    uint8_t manufacturer_private_key[32];
    uint8_t manufacturer_public_key[32];
    uint8_t certified_device_public_key[32];
    uint8_t device_certificate_signature[64];
    uint8_t admin_private_key[32];
    uint8_t admin_public_key[32];
    uint8_t certified_admin_public_key[32];
    uint8_t admin_certificate_signature[64];
    int rc = -1;

    if (sxs_host_read_hex(paths[0], device_private_key, 32) != 0 ||
        sxs_host_read_hex(paths[1], device_public_key, 32) != 0 ||
        pe_crypto_ed25519_public(device_private_key, derived_public_key) != 0 ||
        !pe_crypto_equal(derived_public_key, device_public_key, 32) ||
        !pe_crypto_equal(device_public_key, SXS_DEVICE_PUBLIC_KEY, 32) ||
        read_exact_file(paths[4], certified_device_public_key, 32) != 0 ||
        !pe_crypto_equal(device_public_key, certified_device_public_key, 32)) {
        fprintf(stderr, "device simulation key mismatch\n");
        goto cleanup;
    }

    if (sxs_host_read_hex(paths[2], manufacturer_private_key, 32) != 0 ||
        sxs_host_read_hex(paths[3], manufacturer_public_key, 32) != 0 ||
        pe_crypto_ed25519_public(manufacturer_private_key,
                                  derived_public_key) != 0 ||
        !pe_crypto_equal(derived_public_key, manufacturer_public_key, 32) ||
        read_exact_file(paths[5], device_certificate_signature, 64) != 0 ||
        verify(manufacturer_public_key, certified_device_public_key, 32,
               device_certificate_signature) != 0) {
        fprintf(stderr, "device certificate verification failed\n");
        goto cleanup;
    }

    if (sxs_host_read_hex(paths[6], admin_private_key, 32) != 0 ||
        sxs_host_read_hex(paths[7], admin_public_key, 32) != 0 ||
        pe_crypto_ed25519_public(admin_private_key, derived_public_key) != 0 ||
        !pe_crypto_equal(derived_public_key, admin_public_key, 32) ||
        read_exact_file(paths[8], certified_admin_public_key, 32) != 0 ||
        !pe_crypto_equal(admin_public_key, certified_admin_public_key, 32) ||
        read_exact_file(paths[9], admin_certificate_signature, 64) != 0 ||
        verify(manufacturer_public_key, certified_admin_public_key, 32,
               admin_certificate_signature) != 0) {
        fprintf(stderr, "admin certificate verification failed\n");
        goto cleanup;
    }
    rc = 0;

cleanup:
    pe_crypto_secure_zero(device_private_key, sizeof(device_private_key));
    pe_crypto_secure_zero(manufacturer_private_key,
                           sizeof(manufacturer_private_key));
    pe_crypto_secure_zero(admin_private_key, sizeof(admin_private_key));
    pe_crypto_secure_zero(derived_public_key, sizeof(derived_public_key));
    return rc;
}

int main(int argc, char **argv)
{
    uint8_t owner_nonce[32] = { 1 };
    uint8_t owner_ephemeral_public_key[32] = { 2 };
    uint8_t policy_ephemeral_public_key[32] = { 3 };
    uint8_t bootstrap_message[SXS_KEY_BOOTSTRAP_MESSAGE_SIZE];
    uint8_t attestation_like[] = { 0x01, 0x01, 0x00, 0x00 };
    uint8_t signature[64];
    size_t offset = 0;

    if (argc != 1 && argc != 11) {
        fprintf(stderr,
                "Usage: %s [device-private.hex device-public.hex "
                "manufacturer-private.hex manufacturer-public.hex "
                "certified-device-public.bin device-certificate.bin "
                "admin-private.hex admin-public.hex "
                "certified-admin-public.bin admin-certificate.bin]\n",
                argv[0]);
        return 1;
    }
    if (argc == 11 && verify_identity_files(argv + 1) != 0) {
        return 1;
    }

    memcpy(bootstrap_message + offset, SXS_KEY_BOOTSTRAP_DOMAIN,
           SXS_KEY_BOOTSTRAP_DOMAIN_SIZE);
    offset += SXS_KEY_BOOTSTRAP_DOMAIN_SIZE;
    memcpy(bootstrap_message + offset, owner_nonce, sizeof(owner_nonce));
    offset += sizeof(owner_nonce);
    memcpy(bootstrap_message + offset, owner_ephemeral_public_key,
           sizeof(owner_ephemeral_public_key));
    offset += sizeof(owner_ephemeral_public_key);
    memcpy(bootstrap_message + offset, policy_ephemeral_public_key,
           sizeof(policy_ephemeral_public_key));

    if (device_trust_sign_policy_key_bootstrap(
            owner_nonce, owner_ephemeral_public_key,
            policy_ephemeral_public_key, signature) != 0 ||
        verify(SXS_DEVICE_PUBLIC_KEY, bootstrap_message,
               sizeof(bootstrap_message), signature) != 0 ||
        verify(SXS_DEVICE_PUBLIC_KEY, attestation_like,
               sizeof(attestation_like), signature) == 0) {
        fprintf(stderr, "policy key-bootstrap signing failed\n");
        return 1;
    }
    bootstrap_message[SXS_KEY_BOOTSTRAP_DOMAIN_SIZE] ^= 1;
    if (verify(SXS_DEVICE_PUBLIC_KEY, bootstrap_message,
               sizeof(bootstrap_message), signature) == 0) {
        fprintf(stderr, "modified bootstrap transcript verified unexpectedly\n");
        return 1;
    }
    if (device_trust_sign_attestation(attestation_like,
                                      sizeof(attestation_like),
                                      signature) != 0 ||
        verify(SXS_DEVICE_PUBLIC_KEY, attestation_like,
               sizeof(attestation_like), signature) != 0) {
        fprintf(stderr, "privileged device signing failed\n");
        return 1;
    }
    if (device_trust_sign_policy_key_bootstrap(
            NULL, owner_ephemeral_public_key,
            policy_ephemeral_public_key, signature) == 0 ||
        device_trust_sign_policy_key_bootstrap(
            owner_nonce, NULL, policy_ephemeral_public_key, signature) == 0 ||
        device_trust_sign_policy_key_bootstrap(
            owner_nonce, owner_ephemeral_public_key, NULL, signature) == 0 ||
        device_trust_sign_policy_key_bootstrap(
            owner_nonce, owner_ephemeral_public_key,
            policy_ephemeral_public_key, NULL) == 0 ||
        device_trust_sign_attestation(NULL, 1, signature) == 0 ||
        device_trust_sign_attestation(attestation_like,
                                      sizeof(attestation_like), NULL) == 0) {
        fprintf(stderr, "invalid signing arguments were accepted\n");
        return 1;
    }

    printf("device signing tests passed\n");
    return 0;
}
