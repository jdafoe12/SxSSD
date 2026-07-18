#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../device-identity.h"
#include "../device-signing.h"

static int verify(const uint8_t public_key[32], const uint8_t *data,
                  size_t data_len, const uint8_t signature[64])
{
    static const uint8_t empty = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int rc = -1;

    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                       public_key, 32);
    ctx = EVP_MD_CTX_new();
    if (pkey && ctx &&
        EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(ctx, signature, 64, data ? data : &empty,
                         data_len) == 1) {
        rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
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

static int verify_with_pem_public_key(const char *path, const uint8_t *data,
                                      size_t data_len,
                                      const uint8_t signature[64])
{
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int rc = -1;

    fp = fopen(path, "rb");
    if (!fp) {
        goto cleanup;
    }
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    ctx = EVP_MD_CTX_new();
    if (pkey && ctx &&
        EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(ctx, signature, 64, data, data_len) == 1) {
        rc = 0;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    if (fp) {
        fclose(fp);
    }
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
    uint8_t device_public_key[32];
    uint8_t admin_public_key[32];
    uint8_t device_certificate_signature[64];
    uint8_t admin_certificate_signature[64];
    size_t offset = 0;

    if (argc != 1 && argc != 6) {
        fprintf(stderr,
                "Usage: %s [device-public-key.bin manufacturer-public-key.pem "
                "device-cert-signature.bin admin-public-key.bin "
                "admin-cert-signature.bin]\n",
                argv[0]);
        return 1;
    }
    if (argc == 6) {
        if (read_exact_file(argv[1], device_public_key,
                            sizeof(device_public_key)) != 0 ||
            memcmp(device_public_key, SXS_DEVICE_PUBLIC_KEY,
                   sizeof(device_public_key)) != 0) {
            fprintf(stderr, "device public key mismatch: %s\n", argv[1]);
            return 1;
        }
        if (read_exact_file(argv[3], device_certificate_signature,
                            sizeof(device_certificate_signature)) != 0 ||
            verify_with_pem_public_key(argv[2], device_public_key,
                                       sizeof(device_public_key),
                                       device_certificate_signature) != 0) {
            fprintf(stderr, "device certificate verification failed\n");
            return 1;
        }
        if (read_exact_file(argv[4], admin_public_key,
                            sizeof(admin_public_key)) != 0 ||
            read_exact_file(argv[5], admin_certificate_signature,
                            sizeof(admin_certificate_signature)) != 0 ||
            verify_with_pem_public_key(argv[2], admin_public_key,
                                       sizeof(admin_public_key),
                                       admin_certificate_signature) != 0) {
            fprintf(stderr, "admin certificate verification failed\n");
            return 1;
        }
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

    if (sign_policy_key_bootstrap(owner_nonce, owner_ephemeral_public_key,
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
    if (sign_with_attestation_key(attestation_like, sizeof(attestation_like),
                                  signature) != 0 ||
        verify(SXS_DEVICE_PUBLIC_KEY, attestation_like,
               sizeof(attestation_like), signature) != 0) {
        fprintf(stderr, "privileged device signing failed\n");
        return 1;
    }
    if (sign_policy_key_bootstrap(NULL, owner_ephemeral_public_key,
                                  policy_ephemeral_public_key, signature) == 0 ||
        sign_policy_key_bootstrap(owner_nonce, NULL,
                                  policy_ephemeral_public_key, signature) == 0 ||
        sign_policy_key_bootstrap(owner_nonce, owner_ephemeral_public_key,
                                  NULL, signature) == 0 ||
        sign_policy_key_bootstrap(owner_nonce, owner_ephemeral_public_key,
                                  policy_ephemeral_public_key, NULL) == 0 ||
        sign_with_attestation_key(NULL, 1, signature) == 0 ||
        sign_with_attestation_key(attestation_like,
                                  sizeof(attestation_like), NULL) == 0) {
        fprintf(stderr, "invalid signing arguments were accepted\n");
        return 1;
    }

    printf("device signing tests passed\n");
    return 0;
}
