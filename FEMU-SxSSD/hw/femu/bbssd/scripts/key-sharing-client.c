#include <errno.h>
#include <fcntl.h>
#include <linux/nvme_ioctl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../device-identity.h"
#include "../device-signing.h"
#include "../policy/key-sharing.h"

static int send_admin_cmd(const char *device, uint8_t opcode, void *buffer,
                          uint32_t data_len, int quiet)
{
    struct nvme_admin_cmd cmd = {0};
    int fd;
    int ioctl_rc;
    int rc = -1;

    fd = open(device, O_RDWR);
    if (fd < 0) {
        perror("open device");
        return -1;
    }
    cmd.opcode = opcode;
    cmd.addr = (uintptr_t)buffer;
    cmd.data_len = data_len;
    cmd.cdw12 = data_len;
    ioctl_rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
    if (ioctl_rc < 0) {
        if (!quiet) {
            perror("ioctl");
        }
    } else if (ioctl_rc != 0) {
        if (!quiet) {
            fprintf(stderr, "NVMe opcode 0x%02x failed with status 0x%x\n",
                    opcode, ioctl_rc);
        }
    } else if (cmd.result != 0) {
        fprintf(stderr, "NVMe command failed with result 0x%x\n", cmd.result);
    } else {
        rc = 0;
    }
    close(fd);
    return rc;
}

static int sign_tapp_request(struct key_sharing_request *request,
                             const char *private_key_path)
{
    static const uint8_t domain[] = KEY_SHARING_TAPP_AUTH_DOMAIN;
    uint8_t message[(sizeof(domain) - 1) + 2 * KEY_SHARING_FIELD_SIZE];
    EVP_PKEY *private_key = NULL;
    EVP_MD_CTX *ctx = NULL;
    FILE *key_file = NULL;
    size_t signature_len = sizeof(request->tapp_signature);
    size_t offset = 0;
    int rc = -1;

    memcpy(message + offset, domain, sizeof(domain) - 1);
    offset += sizeof(domain) - 1;
    memcpy(message + offset, request->owner_nonce, KEY_SHARING_FIELD_SIZE);
    offset += KEY_SHARING_FIELD_SIZE;
    memcpy(message + offset, request->owner_ephemeral_public_key,
           KEY_SHARING_FIELD_SIZE);

    key_file = fopen(private_key_path, "r");
    if (!key_file) {
        perror("open TApp private key");
        goto cleanup;
    }
    private_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    ctx = EVP_MD_CTX_new();
    if (!private_key || EVP_PKEY_id(private_key) != EVP_PKEY_ED25519 || !ctx ||
        EVP_DigestSignInit(ctx, NULL, NULL, NULL, private_key) != 1 ||
        EVP_DigestSign(ctx, request->tapp_signature, &signature_len, message,
                       sizeof(message)) != 1 ||
        signature_len != sizeof(request->tapp_signature)) {
        fprintf(stderr, "failed to sign key-sharing request\n");
        goto cleanup;
    }
    rc = 0;

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    if (key_file) {
        fclose(key_file);
    }
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
    return rc;
}

static int derive_shared_key(const uint8_t private_key[32],
                             const uint8_t policy_public_key[32],
                             const uint8_t owner_nonce[32],
                             uint8_t shared_key[32])
{
    static const uint8_t info[] = KEY_SHARING_KDF_INFO;
    EVP_PKEY *private_pkey = NULL;
    EVP_PKEY *policy_pkey = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    EVP_PKEY_CTX *kdf_ctx = NULL;
    uint8_t shared_secret[32];
    size_t shared_secret_len = sizeof(shared_secret);
    size_t shared_key_len = 32;
    int rc = -1;

    private_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                private_key, 32);
    policy_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                              policy_public_key, 32);
    derive_ctx = private_pkey ? EVP_PKEY_CTX_new(private_pkey, NULL) : NULL;
    if (!private_pkey || !policy_pkey || !derive_ctx ||
        EVP_PKEY_derive_init(derive_ctx) != 1 ||
        EVP_PKEY_derive_set_peer(derive_ctx, policy_pkey) != 1 ||
        EVP_PKEY_derive(derive_ctx, shared_secret, &shared_secret_len) != 1 ||
        shared_secret_len != sizeof(shared_secret)) {
        goto cleanup;
    }

    kdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kdf_ctx || EVP_PKEY_derive_init(kdf_ctx) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(kdf_ctx, EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(kdf_ctx, owner_nonce, 32) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(kdf_ctx, shared_secret,
                                   sizeof(shared_secret)) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(kdf_ctx, info, sizeof(info) - 1) != 1 ||
        EVP_PKEY_derive(kdf_ctx, shared_key, &shared_key_len) != 1 ||
        shared_key_len != 32) {
        goto cleanup;
    }
    rc = 0;

cleanup:
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    EVP_PKEY_CTX_free(kdf_ctx);
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(policy_pkey);
    EVP_PKEY_free(private_pkey);
    if (rc != 0) {
        memset(shared_key, 0, 32);
    }
    return rc;
}

static int verify_bootstrap_signature(
    const struct key_sharing_request *request,
    const struct key_sharing_response *response)
{
    uint8_t message[SXS_KEY_BOOTSTRAP_MESSAGE_SIZE];
    EVP_PKEY *public_key = NULL;
    EVP_MD_CTX *ctx = NULL;
    size_t offset = 0;
    int rc = -1;

    memcpy(message + offset, SXS_KEY_BOOTSTRAP_DOMAIN,
           SXS_KEY_BOOTSTRAP_DOMAIN_SIZE);
    offset += SXS_KEY_BOOTSTRAP_DOMAIN_SIZE;
    memcpy(message + offset, request->owner_nonce, 32);
    offset += 32;
    memcpy(message + offset, request->owner_ephemeral_public_key, 32);
    offset += 32;
    memcpy(message + offset, response->policy_ephemeral_public_key, 32);

    public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                             SXS_DEVICE_PUBLIC_KEY, 32);
    ctx = EVP_MD_CTX_new();
    if (public_key && ctx &&
        EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, public_key) == 1 &&
        EVP_DigestVerify(ctx, response->device_signature,
                         sizeof(response->device_signature), message,
                         sizeof(message)) == 1) {
        rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);
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
    memcpy(message + offset, request->owner_nonce, 32);
    offset += 32;
    memcpy(message + offset, request->owner_ephemeral_public_key, 32);
    offset += 32;
    memcpy(message + offset, policy_public_key, 32);
    if (!HMAC(EVP_sha256(), shared_key, 32, message, sizeof(message),
              confirmation, &confirmation_len) || confirmation_len != 32) {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct key_sharing_request request = {0};
    struct key_sharing_response response = {0};
    uint8_t owner_private_key[32] = {0};
    uint8_t shared_key[32] = {0};
    uint8_t expected_confirmation[32] = {0};
    int rc = 1;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <device> <TApp-private-key.pem>\n",
                argv[0]);
        return 1;
    }
    if (RAND_bytes(request.owner_nonce, sizeof(request.owner_nonce)) != 1 ||
        generate_x25519_keypair(request.owner_ephemeral_public_key,
                                owner_private_key) != 0 ||
        sign_tapp_request(&request, argv[2]) != 0 ||
        send_admin_cmd(argv[1], KEY_SHARING_SUBMIT_OPCODE, &request,
                       sizeof(request), 0) != 0 ||
        send_admin_cmd(argv[1], KEY_SHARING_FETCH_OPCODE, &response,
                       sizeof(response), 0) != 0 ||
        verify_bootstrap_signature(&request, &response) != 0 ||
        derive_shared_key(owner_private_key,
                          response.policy_ephemeral_public_key,
                          request.owner_nonce, shared_key) != 0 ||
        compute_key_confirmation(shared_key, &request,
                                 response.policy_ephemeral_public_key,
                                 expected_confirmation) != 0 ||
        CRYPTO_memcmp(expected_confirmation, response.key_confirmation,
                      sizeof(expected_confirmation)) != 0) {
        fprintf(stderr, "key sharing verification failed\n");
        goto cleanup;
    }

    request.tapp_signature[0] ^= 1;
    if (send_admin_cmd(argv[1], KEY_SHARING_SUBMIT_OPCODE, &request,
                       sizeof(request), 1) == 0) {
        fprintf(stderr, "policy accepted an invalid TApp signature\n");
        goto cleanup;
    }

    printf("key sharing passed; invalid TApp authentication rejected\n");
    rc = 0;

cleanup:
    OPENSSL_cleanse(owner_private_key, sizeof(owner_private_key));
    OPENSSL_cleanse(shared_key, sizeof(shared_key));
    OPENSSL_cleanse(expected_confirmation, sizeof(expected_confirmation));
    OPENSSL_cleanse(&request, sizeof(request));
    OPENSSL_cleanse(&response, sizeof(response));
    return rc;
}
