#include <errno.h>
#include <fcntl.h>
#include <linux/nvme_ioctl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../device-identity.h"
#include "../policy-attestation-format.h"

#define NVME_CMD_INIT_SESSION_SUBMIT  0x93
#define NVME_CMD_INIT_SESSION_FETCH   0x94
#define NVME_CMD_INSTALL_POLICY       0x95
#define NVME_CMD_ACTIVATE_POLICY      0x9b
#define NVME_CMD_DEACTIVATE_POLICY    0x97
#define NVME_CMD_UPDATE_POLICY        0x9d
#define NVME_CMD_REMOVE_POLICY        0x99
#define NVME_CMD_POLICY_ATTESTATION_FETCH   0x9a
#define NVME_CMD_POLICY_ATTESTATION_SUBMIT  0x9f

#define SESSION_MODE_NORMAL        0
#define SESSION_MODE_CONFIDENTIAL  1

#define INIT_SESSION_REQUEST_SIZE   105
#define INIT_SESSION_RESPONSE_SIZE  104

#define META_AUTH_HMAC_SIZE 32
#define META_AUTH_TAG_SIZE 16
#define META_ENVELOPE_AUTH_SIZE 32
#define META_ENVELOPE_HEADER_SIZE (8 + META_ENVELOPE_AUTH_SIZE)

#define POLICYCTL_COUNTER_PATH "/tmp/policyctl-session-counter"
#define POLICYCTL_SESSION_STATE_PATH "/tmp/policyctl-session-state"
#define POLICYCTL_MAX_ATTESTATION_SIZE (256U * 1024U * 1024U)
#define POLICYCTL_FETCH_CHUNK_SIZE (1024U * 1024U)

static const uint8_t ADMIN_PRIVATE_KEY[32] = {
    0x52, 0x07, 0xa0, 0x35, 0x1e, 0x25, 0x06, 0xd2, 0x9b, 0x23, 0x79, 0xb8,
    0x46, 0xea, 0x76, 0xd2, 0xbd, 0x4e, 0x9d, 0x6a, 0x51, 0xa8, 0xd1, 0xe7,
    0xd8, 0x51, 0x81, 0x19, 0x57, 0x03, 0xca, 0xb8
};

struct policy_session {
    uint8_t key[32];
    uint8_t mode;
    uint64_t command_counter;
};

struct persisted_policy_session {
    uint8_t key[32];
    uint8_t mode;
    uint8_t reserved[7];
    uint64_t command_counter;
};

struct attestation_view {
    uint8_t report_type;
    uint8_t history_mode;
    uint8_t policy_count;
    uint64_t snapshot_sequence;
    const uint8_t *boot_epoch;
    const uint8_t *nonce;
    const uint8_t *history_head;
    const uint8_t *policies;
    const uint8_t *history;
    size_t policy_entry_size;
    size_t history_count;
};

struct replay_policy {
    uint32_t policy_id;
    uint32_t generation;
    int installed;
    int active;
};

static void encode_u64_le(uint64_t value, uint8_t out[8])
{
    for (size_t i = 0; i < 8; i++) {
        out[i] = (uint8_t)(value >> (8 * i));
    }
}

static uint64_t decode_u64_le(const uint8_t in[8])
{
    uint64_t value = 0;

    for (size_t i = 0; i < 8; i++) {
        value |= ((uint64_t)in[i]) << (8 * i);
    }

    return value;
}

static void encode_u32_le(uint32_t value, uint8_t out[4])
{
    for (size_t i = 0; i < 4; i++) {
        out[i] = (uint8_t)(value >> (8 * i));
    }
}

static uint32_t decode_u32_le(const uint8_t in[4])
{
    uint32_t value = 0;

    for (size_t i = 0; i < 4; i++) {
        value |= ((uint32_t)in[i]) << (8 * i);
    }

    return value;
}

static uint64_t load_persistent_counter(void)
{
    FILE *fp;
    unsigned long long value = 0;

    fp = fopen(POLICYCTL_COUNTER_PATH, "r");
    if (!fp) {
        return 0;
    }
    if (fscanf(fp, "%llu", &value) != 1) {
        value = 0;
    }
    fclose(fp);
    return (uint64_t)value;
}

static int store_persistent_counter(uint64_t counter)
{
    FILE *fp;

    fp = fopen(POLICYCTL_COUNTER_PATH, "w");
    if (!fp) {
        return -1;
    }
    if (fprintf(fp, "%llu\n", (unsigned long long)counter) < 0) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int reserve_session_counter(uint64_t *counter_out)
{
    uint64_t counter;

    if (!counter_out) {
        return -1;
    }

    counter = load_persistent_counter();
    counter++;
    if (store_persistent_counter(counter) != 0) {
        return -1;
    }

    *counter_out = counter;
    return 0;
}

static int save_session_state(const struct policy_session *session)
{
    struct persisted_policy_session persisted = {0};
    FILE *fp;

    if (!session) {
        return -1;
    }

    memcpy(persisted.key, session->key, sizeof(persisted.key));
    persisted.mode = session->mode;
    persisted.command_counter = session->command_counter;

    fp = fopen(POLICYCTL_SESSION_STATE_PATH, "wb");
    if (!fp) {
        return -1;
    }
    if (fwrite(&persisted, sizeof(persisted), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int load_session_state(struct policy_session *session)
{
    struct persisted_policy_session persisted;
    FILE *fp;

    if (!session) {
        return -1;
    }

    fp = fopen(POLICYCTL_SESSION_STATE_PATH, "rb");
    if (!fp) {
        return -1;
    }
    if (fread(&persisted, sizeof(persisted), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    memcpy(session->key, persisted.key, sizeof(session->key));
    session->mode = persisted.mode;
    session->command_counter = persisted.command_counter;
    return 0;
}

static void clear_session_state(void)
{
    unlink(POLICYCTL_SESSION_STATE_PATH);
}

static void build_admin_init_message(const uint8_t *admin_ephem_pub,
                                     uint8_t session_mode,
                                     uint64_t counter,
                                     uint8_t *message_out)
{
    uint8_t counter_le[8];

    message_out[0] = NVME_CMD_INIT_SESSION_SUBMIT;
    memcpy(message_out + 1, admin_ephem_pub, 32);
    message_out[33] = session_mode;
    encode_u64_le(counter, counter_le);
    memcpy(message_out + 34, counter_le, sizeof(counter_le));
}

static void build_ssd_response_message(const uint8_t *admin_ephem_pub,
                                       const uint8_t *ssd_ephem_pub,
                                       uint8_t session_mode,
                                       uint64_t counter,
                                       uint8_t *message_out)
{
    uint8_t counter_le[8];
    size_t offset = 1;

    message_out[0] = NVME_CMD_INIT_SESSION_SUBMIT;
    memcpy(message_out + offset, admin_ephem_pub, 32);
    offset += 32;
    memcpy(message_out + offset, ssd_ephem_pub, 32);
    offset += 32;
    message_out[offset++] = session_mode;
    encode_u64_le(counter, counter_le);
    memcpy(message_out + offset, counter_le, sizeof(counter_le));
}

static int sign_with_admin_private_key(const uint8_t *message, size_t message_len,
                                       uint8_t *sig_out)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    size_t sig_len = 64;
    int rc = -1;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ADMIN_PRIVATE_KEY, 32);
    if (!pkey) {
        goto cleanup;
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        goto cleanup;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
        goto cleanup;
    }
    if (EVP_DigestSign(md_ctx, sig_out, &sig_len, message, message_len) != 1 ||
        sig_len != 64) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return rc;
}

static int generate_ephemeral_keypair(uint8_t *public_key_out, uint8_t *private_key_out)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t len;
    int rc = -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(pctx) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        goto cleanup;
    }

    len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, private_key_out, &len) != 1 || len != 32) {
        goto cleanup;
    }
    len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &len) != 1 || len != 32) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (rc != 0) {
        memset(public_key_out, 0, 32);
        memset(private_key_out, 0, 32);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    return rc;
}

static int verify_ssd_signature(const uint8_t *message, size_t message_len,
                                const uint8_t *sig)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    int rc = -1;

    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                       SXS_DEVICE_PUBLIC_KEY,
                                       sizeof(SXS_DEVICE_PUBLIC_KEY));
    if (!pkey) {
        goto cleanup;
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
        goto cleanup;
    }
    if (EVP_DigestVerify(md_ctx, sig, 64, message, message_len) != 1) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return rc;
}

static int derive_labeled_key(const uint8_t base_key[32], const char *label,
                              uint8_t derived_key[32])
{
    EVP_PKEY_CTX *pctx = NULL;
    size_t derived_len = 32;
    int rc = -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_init(pctx) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, base_key, 32) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)label,
                                    (int)strlen(label)) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_derive(pctx, derived_key, &derived_len) != 1 ||
        derived_len != 32) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (rc != 0) {
        memset(derived_key, 0, 32);
    }
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    return rc;
}

static int derive_session_key(const uint8_t *admin_ephem_priv,
                              const uint8_t *ssd_ephem_pub,
                              const uint8_t *admin_ephem_pub,
                              uint8_t session_mode,
                              uint64_t counter,
                              uint8_t *session_key_out)
{
    EVP_PKEY *admin_priv_pkey = NULL;
    EVP_PKEY *ssd_pub_pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    uint8_t shared_secret[32];
    size_t secret_len = 32;
    size_t session_key_len = 32;
    uint8_t kdf_info[1 + 32 + 32 + 1 + 8];
    uint8_t counter_le[8];
    int rc = -1;

    admin_priv_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, admin_ephem_priv, 32);
    if (!admin_priv_pkey) {
        goto cleanup;
    }
    ssd_pub_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, ssd_ephem_pub, 32);
    if (!ssd_pub_pkey) {
        goto cleanup;
    }
    ctx = EVP_PKEY_CTX_new(admin_priv_pkey, NULL);
    if (!ctx) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_init(ctx) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_set_peer(ctx, ssd_pub_pkey) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) != 1 || secret_len != 32) {
        goto cleanup;
    }

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kctx) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_init(kctx) != 1) {
        goto cleanup;
    }

    kdf_info[0] = NVME_CMD_INIT_SESSION_SUBMIT;
    memcpy(kdf_info + 1, admin_ephem_pub, 32);
    memcpy(kdf_info + 33, ssd_ephem_pub, 32);
    kdf_info[65] = session_mode;
    encode_u64_le(counter, counter_le);
    memcpy(kdf_info + 66, counter_le, sizeof(counter_le));

    if (EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(kctx, shared_secret, 32) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(kctx, kdf_info, sizeof(kdf_info)) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_derive(kctx, session_key_out, &session_key_len) != 1 ||
        session_key_len != 32) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(kdf_info, sizeof(kdf_info));
    OPENSSL_cleanse(counter_le, sizeof(counter_le));
    if (rc != 0) {
        memset(session_key_out, 0, 32);
    }
    if (kctx) {
        EVP_PKEY_CTX_free(kctx);
    }
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (ssd_pub_pkey) {
        EVP_PKEY_free(ssd_pub_pkey);
    }
    if (admin_priv_pkey) {
        EVP_PKEY_free(admin_priv_pkey);
    }
    return rc;
}

static void build_meta_nonce(uint64_t counter, uint8_t nonce[12])
{
    memset(nonce, 0, 12);
    encode_u64_le(counter, nonce + 4);
}

static int compute_meta_hmac(const uint8_t key[32], uint8_t opcode,
                             uint64_t counter, const uint8_t *ciphertext,
                             size_t ciphertext_len,
                             uint8_t out[META_AUTH_HMAC_SIZE])
{
    HMAC_CTX *ctx = NULL;
    uint8_t counter_le[8];
    unsigned int mac_len = 0;
    int rc = -1;

    encode_u64_le(counter, counter_le);
    ctx = HMAC_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (HMAC_Init_ex(ctx, key, 32, EVP_sha256(), NULL) != 1) {
        goto cleanup;
    }
    if (HMAC_Update(ctx, &opcode, 1) != 1) {
        goto cleanup;
    }
    if (HMAC_Update(ctx, counter_le, sizeof(counter_le)) != 1) {
        goto cleanup;
    }
    if (ciphertext_len > 0 &&
        HMAC_Update(ctx, ciphertext, ciphertext_len) != 1) {
        goto cleanup;
    }
    if (HMAC_Final(ctx, out, &mac_len) != 1 || mac_len != META_AUTH_HMAC_SIZE) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    OPENSSL_cleanse(counter_le, sizeof(counter_le));
    if (ctx) {
        HMAC_CTX_free(ctx);
    }
    if (rc != 0) {
        memset(out, 0, META_AUTH_HMAC_SIZE);
    }
    return rc;
}

static int aes256_gcm_encrypt(const uint8_t key[32], uint64_t counter,
                              uint8_t opcode, const uint8_t *plaintext,
                              size_t plaintext_len, uint8_t *ciphertext,
                              uint8_t tag[META_AUTH_TAG_SIZE])
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t nonce[12];
    int len = 0;
    int out_len = 0;
    int rc = -1;

    build_meta_nonce(counter, nonce);
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1) {
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        goto cleanup;
    }
    if (EVP_EncryptUpdate(ctx, NULL, &len, &opcode, 1) != 1) {
        goto cleanup;
    }
    if (plaintext_len > 0 &&
        EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, (int)plaintext_len) != 1) {
        goto cleanup;
    }
    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &len) != 1) {
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, META_AUTH_TAG_SIZE, tag) != 1) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    OPENSSL_cleanse(nonce, sizeof(nonce));
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return rc;
}

static int send_nvme_admin_cmd_ex(const char *device, uint8_t opcode,
                                  void *buffer, uint32_t data_len,
                                  uint32_t cdw12, uint32_t cdw13,
                                  uint32_t cdw14)
{
    struct nvme_admin_cmd cmd = {0};
    int fd;
    int rc = -1;

    fd = open(device, O_RDWR);
    if (fd < 0) {
        perror("open device");
        return -1;
    }

    cmd.opcode = opcode;
    cmd.nsid = 0;
    cmd.addr = (uintptr_t)buffer;
    cmd.data_len = data_len;
    cmd.cdw12 = cdw12;
    cmd.cdw13 = cdw13;
    cmd.cdw14 = cdw14;

    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) != 0) {
        perror("ioctl");
        goto cleanup;
    }
    if (cmd.result != 0) {
        fprintf(stderr, "NVMe command failed with status 0x%x\n", cmd.result);
        goto cleanup;
    }

    rc = 0;

cleanup:
    close(fd);
    return rc;
}

static int send_nvme_admin_cmd(const char *device, uint8_t opcode,
                               void *buffer, uint32_t data_len)
{
    return send_nvme_admin_cmd_ex(device, opcode, buffer, data_len,
                                  data_len, 0, 0);
}

static int establish_session(const char *device, uint8_t session_mode,
                             struct policy_session *session)
{
    uint8_t admin_ephem_pub[32];
    uint8_t admin_ephem_priv[32];
    uint8_t request[INIT_SESSION_REQUEST_SIZE];
    uint8_t response[INIT_SESSION_RESPONSE_SIZE];
    uint8_t admin_init_message[1 + 32 + 1 + 8];
    uint8_t proof_message[1 + 32 + 32 + 1 + 8];
    uint64_t counter;
    uint64_t response_counter;
    int rc = -1;

    if (!device || !session) {
        return -1;
    }
    if (session_mode != SESSION_MODE_NORMAL &&
        session_mode != SESSION_MODE_CONFIDENTIAL) {
        fprintf(stderr, "Invalid session mode %u\n", session_mode);
        return -1;
    }
    if (reserve_session_counter(&counter) != 0) {
        fprintf(stderr, "Failed to reserve session counter\n");
        return -1;
    }
    if (generate_ephemeral_keypair(admin_ephem_pub, admin_ephem_priv) != 0) {
        fprintf(stderr, "Failed to generate ephemeral keypair\n");
        goto cleanup;
    }

    build_admin_init_message(admin_ephem_pub, session_mode, counter, admin_init_message);
    if (sign_with_admin_private_key(admin_init_message, sizeof(admin_init_message),
                                    request + 41) != 0) {
        fprintf(stderr, "Failed to sign session request\n");
        goto cleanup;
    }

    memcpy(request, admin_ephem_pub, 32);
    request[32] = session_mode;
    encode_u64_le(counter, request + 33);

    if (send_nvme_admin_cmd(device, NVME_CMD_INIT_SESSION_SUBMIT,
                         request, INIT_SESSION_REQUEST_SIZE) != 0) {
        fprintf(stderr, "Failed to submit INIT_SESSION request\n");
        goto cleanup;
    }

    memset(response, 0, sizeof(response));
    if (send_nvme_admin_cmd(device, NVME_CMD_INIT_SESSION_FETCH,
                         response, INIT_SESSION_RESPONSE_SIZE) != 0) {
        fprintf(stderr, "Failed to fetch INIT_SESSION response\n");
        goto cleanup;
    }

    response_counter = decode_u64_le(response + 32);
    if (response_counter != counter) {
        fprintf(stderr, "Session counter mismatch in response\n");
        goto cleanup;
    }

    build_ssd_response_message(admin_ephem_pub, response, session_mode, counter,
                               proof_message);
    if (verify_ssd_signature(proof_message, sizeof(proof_message), response + 40) != 0) {
        fprintf(stderr, "SSD signature verification failed\n");
        goto cleanup;
    }

    if (derive_session_key(admin_ephem_priv, response, admin_ephem_pub,
                           session_mode, counter, session->key) != 0) {
        fprintf(stderr, "Failed to derive session key\n");
        goto cleanup;
    }

    session->mode = session_mode;
    session->command_counter = 0;
    rc = 0;

cleanup:
    OPENSSL_cleanse(admin_ephem_priv, sizeof(admin_ephem_priv));
    OPENSSL_cleanse(request, sizeof(request));
    OPENSSL_cleanse(response, sizeof(response));
    OPENSSL_cleanse(admin_init_message, sizeof(admin_init_message));
    OPENSSL_cleanse(proof_message, sizeof(proof_message));
    return rc;
}

static int build_authenticated_envelope(const struct policy_session *session,
                                        uint8_t opcode,
                                        const uint8_t *plaintext,
                                        size_t plaintext_len,
                                        uint64_t counter,
                                        uint8_t **request_out,
                                        uint32_t *request_len_out)
{
    uint8_t *request = NULL;
    uint8_t *ciphertext;
    size_t request_len;
    int rc = -1;

    if (!session || !request_out || !request_len_out || plaintext_len > UINT32_MAX) {
        return -1;
    }

    request_len = META_ENVELOPE_HEADER_SIZE + plaintext_len;
    if (request_len > UINT32_MAX) {
        return -1;
    }

    request = calloc(1, request_len);
    if (!request) {
        return -1;
    }

    encode_u64_le(counter, request);
    ciphertext = request + META_ENVELOPE_HEADER_SIZE;

    if (session->mode == SESSION_MODE_NORMAL) {
        uint8_t mac_key[32];

        if (derive_labeled_key(session->key, "meta-normal-mac", mac_key) != 0) {
            OPENSSL_cleanse(mac_key, sizeof(mac_key));
            goto cleanup;
        }
        memcpy(ciphertext, plaintext, plaintext_len);
        if (compute_meta_hmac(mac_key, opcode, counter, ciphertext, plaintext_len,
                              request + 8) != 0) {
            OPENSSL_cleanse(mac_key, sizeof(mac_key));
            goto cleanup;
        }

        OPENSSL_cleanse(mac_key, sizeof(mac_key));
    } else if (session->mode == SESSION_MODE_CONFIDENTIAL) {
        uint8_t aead_key[32];

        if (derive_labeled_key(session->key, "meta-conf-aead", aead_key) != 0) {
            OPENSSL_cleanse(aead_key, sizeof(aead_key));
            goto cleanup;
        }
        if (aes256_gcm_encrypt(aead_key, counter, opcode, plaintext, plaintext_len,
                               ciphertext, request + 8) != 0) {
            OPENSSL_cleanse(aead_key, sizeof(aead_key));
            goto cleanup;
        }
        OPENSSL_cleanse(aead_key, sizeof(aead_key));
    } else {
        goto cleanup;
    }

    *request_out = request;
    *request_len_out = (uint32_t)request_len;
    request = NULL;
    rc = 0;

cleanup:
    if (request) {
        OPENSSL_cleanse(request, request_len);
        free(request);
    }
    return rc;
}

static int send_authenticated_meta_cmd(const char *device,
                                       struct policy_session *session,
                                       uint8_t opcode,
                                       const uint8_t *plaintext,
                                       size_t plaintext_len)
{
    uint8_t *request = NULL;
    uint32_t request_len = 0;
    uint64_t counter;
    int rc = -1;

    if (!device || !session) {
        return -1;
    }

    counter = session->command_counter + 1;
    if (build_authenticated_envelope(session, opcode, plaintext, plaintext_len,
                                     counter, &request, &request_len) != 0) {
        return -1;
    }

    if (send_nvme_admin_cmd(device, opcode, request, request_len) != 0) {
        goto cleanup;
    }

    session->command_counter = counter;
    if (save_session_state(session) != 0) {
        fprintf(stderr, "Failed to persist session state\n");
        goto cleanup;
    }
    rc = 0;

cleanup:
    if (request) {
        OPENSSL_cleanse(request, request_len);
        free(request);
    }
    return rc;
}

static int sha256_parts(const uint8_t *part1, size_t part1_len,
                        const uint8_t *part2, size_t part2_len,
                        const uint8_t *part3, size_t part3_len,
                        uint8_t out[POLICY_ATTESTATION_HASH_SIZE])
{
    EVP_MD_CTX *ctx = NULL;
    unsigned int digest_len = 0;
    int rc = -1;

    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        (part1_len && EVP_DigestUpdate(ctx, part1, part1_len) != 1) ||
        (part2_len && EVP_DigestUpdate(ctx, part2, part2_len) != 1) ||
        (part3_len && EVP_DigestUpdate(ctx, part3, part3_len) != 1) ||
        EVP_DigestFinal_ex(ctx, out, &digest_len) != 1 ||
        digest_len != POLICY_ATTESTATION_HASH_SIZE) {
        goto cleanup;
    }
    rc = 0;

cleanup:
    EVP_MD_CTX_free(ctx);
    if (rc != 0) {
        memset(out, 0, POLICY_ATTESTATION_HASH_SIZE);
    }
    return rc;
}

static int initial_history_head(
    const uint8_t epoch[POLICY_ATTESTATION_BOOT_EPOCH_SIZE],
    uint8_t out[POLICY_ATTESTATION_HASH_SIZE])
{
    static const uint8_t domain[] = "SxSSD-History-Root-v1";

    return sha256_parts(domain, sizeof(domain) - 1,
                        epoch, POLICY_ATTESTATION_BOOT_EPOCH_SIZE,
                        NULL, 0, out);
}

static int fold_history_record(
    const uint8_t previous[POLICY_ATTESTATION_HASH_SIZE], uint64_t sequence,
    const uint8_t record[POLICY_ATTESTATION_HISTORY_RECORD_SIZE],
    uint8_t out[POLICY_ATTESTATION_HASH_SIZE])
{
    static const uint8_t domain[] = "SxSSD-History-Event-v1";
    uint8_t encoded[8 + POLICY_ATTESTATION_HISTORY_RECORD_SIZE];

    encode_u64_le(sequence, encoded);
    memcpy(encoded + 8, record, POLICY_ATTESTATION_HISTORY_RECORD_SIZE);
    return sha256_parts(domain, sizeof(domain) - 1,
                        previous, POLICY_ATTESTATION_HASH_SIZE,
                        encoded, sizeof(encoded), out);
}

static int parse_attestation(const uint8_t *report, size_t report_len,
                             struct attestation_view *view)
{
    size_t policy_bytes;
    size_t body_len;
    size_t i;
    uint32_t previous_policy_id = 0;

    if (!report || !view ||
        report_len < POLICY_ATTESTATION_RESPONSE_HEADER_SIZE +
                     POLICY_ATTESTATION_SIGNATURE_SIZE ||
        report[0] != POLICY_ATTESTATION_FORMAT_VERSION ||
        (report[1] != POLICY_ATTESTATION_REPORT_SECURITY &&
         report[1] != POLICY_ATTESTATION_REPORT_CONSISTENCY) ||
        (report[2] != POLICY_ATTESTATION_HISTORY_CHECKPOINT &&
         report[2] != POLICY_ATTESTATION_HISTORY_DELTA &&
         report[2] != POLICY_ATTESTATION_HISTORY_FULL) ||
        report[3] > POLICY_ATTESTATION_MAX_POLICIES) {
        return -1;
    }

    memset(view, 0, sizeof(*view));
    view->report_type = report[1];
    view->history_mode = report[2];
    view->policy_count = report[3];
    view->snapshot_sequence = decode_u64_le(report + 4);
    view->boot_epoch = report + 12;
    view->nonce = report + 28;
    view->history_head = report + 44;
    view->policy_entry_size =
        view->report_type == POLICY_ATTESTATION_REPORT_SECURITY ?
        POLICY_ATTESTATION_SECURITY_ENTRY_SIZE :
        POLICY_ATTESTATION_CONSISTENCY_ENTRY_SIZE;

    policy_bytes = (size_t)view->policy_count * view->policy_entry_size;
    if (report_len < POLICY_ATTESTATION_RESPONSE_HEADER_SIZE + policy_bytes +
                     POLICY_ATTESTATION_SIGNATURE_SIZE) {
        return -1;
    }
    body_len = report_len - POLICY_ATTESTATION_RESPONSE_HEADER_SIZE -
               policy_bytes - POLICY_ATTESTATION_SIGNATURE_SIZE;
    if (body_len % POLICY_ATTESTATION_HISTORY_RECORD_SIZE != 0) {
        return -1;
    }
    view->history_count = body_len / POLICY_ATTESTATION_HISTORY_RECORD_SIZE;
    view->policies = report + POLICY_ATTESTATION_RESPONSE_HEADER_SIZE;
    view->history = view->policies + policy_bytes;

    if ((view->history_mode == POLICY_ATTESTATION_HISTORY_CHECKPOINT &&
         view->history_count != 0) ||
        (view->history_mode == POLICY_ATTESTATION_HISTORY_FULL &&
         view->history_count != view->snapshot_sequence) ||
        view->history_count > view->snapshot_sequence) {
        return -1;
    }

    if (verify_ssd_signature(report,
                             report_len - POLICY_ATTESTATION_SIGNATURE_SIZE,
                             report + report_len -
                             POLICY_ATTESTATION_SIGNATURE_SIZE) != 0) {
        return -1;
    }

    for (i = 0; i < view->policy_count; i++) {
        const uint8_t *entry = view->policies + i * view->policy_entry_size;
        uint32_t policy_id = decode_u32_le(entry);
        uint32_t generation = decode_u32_le(entry + 4);

        if (policy_id == 0 || generation == 0 || entry[8] > 1 ||
            (i > 0 && policy_id <= previous_policy_id)) {
            return -1;
        }
        previous_policy_id = policy_id;
    }
    for (i = 0; i < view->history_count; i++) {
        const uint8_t *record = view->history +
            i * POLICY_ATTESTATION_HISTORY_RECORD_SIZE;

        if (record[0] < POLICY_HISTORY_OP_INSTALL ||
            record[0] > POLICY_HISTORY_OP_REMOVE ||
            decode_u32_le(record + 1) == 0 ||
            decode_u32_le(record + 5) == 0) {
            return -1;
        }
    }
    return 0;
}

static int replay_find_policy(const struct replay_policy *policies,
                              size_t count, uint32_t policy_id)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (policies[i].policy_id == policy_id) {
            return (int)i;
        }
    }
    return -1;
}

static int verify_replayed_state(const struct attestation_view *base,
                                 const struct attestation_view *result,
                                 bool full_history)
{
    size_t capacity = result->history_count + (base ? base->policy_count : 0);
    struct replay_policy *policies;
    size_t count = 0;
    size_t installed_count = 0;
    size_t i;
    int rc = -1;

    if (capacity == 0) {
        return result->policy_count == 0 ? 0 : -1;
    }
    if (capacity > SIZE_MAX / sizeof(*policies)) {
        return -1;
    }
    policies = calloc(capacity, sizeof(*policies));
    if (!policies) {
        return -1;
    }

    if (base) {
        for (i = 0; i < base->policy_count; i++) {
            const uint8_t *entry = base->policies + i * base->policy_entry_size;

            policies[count].policy_id = decode_u32_le(entry);
            policies[count].generation = decode_u32_le(entry + 4);
            policies[count].installed = 1;
            policies[count].active = entry[8];
            count++;
        }
    }

    for (i = 0; i < result->history_count; i++) {
        const uint8_t *record = result->history +
            i * POLICY_ATTESTATION_HISTORY_RECORD_SIZE;
        uint8_t operation = record[0];
        uint32_t policy_id = decode_u32_le(record + 1);
        uint32_t generation = decode_u32_le(record + 5);
        int index = replay_find_policy(policies, count, policy_id);

        if (operation == POLICY_HISTORY_OP_INSTALL) {
            if (index >= 0 && policies[index].installed) {
                goto cleanup;
            }
            if (index < 0) {
                index = (int)count++;
                policies[index].policy_id = policy_id;
                if (full_history && generation != 1) {
                    goto cleanup;
                }
            } else if (policies[index].generation == UINT32_MAX ||
                       generation != policies[index].generation + 1) {
                goto cleanup;
            }
            policies[index].generation = generation;
            policies[index].installed = 1;
            policies[index].active = 0;
        } else {
            if (index < 0 || !policies[index].installed ||
                (operation != POLICY_HISTORY_OP_UPDATE &&
                 generation != policies[index].generation)) {
                goto cleanup;
            }
            switch (operation) {
            case POLICY_HISTORY_OP_UPDATE:
                if (policies[index].active ||
                    policies[index].generation == UINT32_MAX ||
                    generation != policies[index].generation + 1) {
                    goto cleanup;
                }
                policies[index].generation = generation;
                break;
            case POLICY_HISTORY_OP_ACTIVATE:
                if (policies[index].active) {
                    goto cleanup;
                }
                policies[index].active = 1;
                break;
            case POLICY_HISTORY_OP_DEACTIVATE:
                if (!policies[index].active) {
                    goto cleanup;
                }
                policies[index].active = 0;
                break;
            case POLICY_HISTORY_OP_REMOVE:
                if (policies[index].active) {
                    goto cleanup;
                }
                policies[index].installed = 0;
                break;
            default:
                goto cleanup;
            }
        }
    }

    for (i = 0; i < count; i++) {
        if (policies[i].installed) {
            int current_index;
            const uint8_t *entry;

            installed_count++;
            current_index = -1;
            for (size_t j = 0; j < result->policy_count; j++) {
                entry = result->policies + j * result->policy_entry_size;
                if (decode_u32_le(entry) == policies[i].policy_id) {
                    current_index = (int)j;
                    break;
                }
            }
            if (current_index < 0) {
                goto cleanup;
            }
            entry = result->policies +
                    (size_t)current_index * result->policy_entry_size;
            if (decode_u32_le(entry + 4) != policies[i].generation ||
                entry[8] != policies[i].active) {
                goto cleanup;
            }
        }
    }
    if (installed_count != result->policy_count) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    free(policies);
    return rc;
}

static int read_entire_file(const char *path, uint8_t **data_out,
                            size_t *length_out)
{
    struct stat st;
    uint8_t *data = NULL;
    int fd = -1;
    size_t offset = 0;

    if (!path || !data_out || !length_out || stat(path, &st) != 0 ||
        st.st_size <= 0 || (uint64_t)st.st_size > POLICYCTL_MAX_ATTESTATION_SIZE) {
        return -1;
    }
    data = malloc((size_t)st.st_size);
    if (!data) {
        return -1;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        free(data);
        return -1;
    }
    while (offset < (size_t)st.st_size) {
        ssize_t n = read(fd, data + offset, (size_t)st.st_size - offset);
        if (n <= 0) {
            close(fd);
            free(data);
            return -1;
        }
        offset += (size_t)n;
    }
    close(fd);
    *data_out = data;
    *length_out = (size_t)st.st_size;
    return 0;
}

static int write_entire_file(const char *path, const uint8_t *data, size_t length)
{
    int fd;
    size_t offset = 0;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }
    while (offset < length) {
        ssize_t n = write(fd, data + offset, length - offset);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)n;
    }
    return close(fd) == 0 ? 0 : -1;
}

static const char *history_operation_name(uint8_t operation)
{
    switch (operation) {
    case POLICY_HISTORY_OP_INSTALL: return "install";
    case POLICY_HISTORY_OP_UPDATE: return "update";
    case POLICY_HISTORY_OP_ACTIVATE: return "activate";
    case POLICY_HISTORY_OP_DEACTIVATE: return "deactivate";
    case POLICY_HISTORY_OP_REMOVE: return "remove";
    default: return "invalid";
    }
}

static void print_hex(const uint8_t *data, size_t length)
{
    size_t i;

    for (i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
}

static int fetch_attestation(const char *device, const uint8_t *request,
                             uint32_t request_len, uint64_t base_sequence,
                             uint8_t **report_out, size_t *report_len_out)
{
    uint8_t header[POLICY_ATTESTATION_RESPONSE_HEADER_SIZE];
    uint64_t snapshot_sequence;
    uint64_t history_count;
    size_t policy_entry_size;
    size_t report_len;
    size_t offset;
    uint8_t *report;

    if (send_nvme_admin_cmd(device, NVME_CMD_POLICY_ATTESTATION_SUBMIT,
                            (void *)request, request_len) != 0 ||
        send_nvme_admin_cmd_ex(device, NVME_CMD_POLICY_ATTESTATION_FETCH,
                               header, sizeof(header), sizeof(header), 0, 0) != 0) {
        return -1;
    }

    if (header[0] != POLICY_ATTESTATION_FORMAT_VERSION ||
        header[3] > POLICY_ATTESTATION_MAX_POLICIES) {
        return -1;
    }
    snapshot_sequence = decode_u64_le(header + 4);
    if (header[2] == POLICY_ATTESTATION_HISTORY_CHECKPOINT) {
        history_count = 0;
    } else if (header[2] == POLICY_ATTESTATION_HISTORY_FULL) {
        history_count = snapshot_sequence;
    } else if (header[2] == POLICY_ATTESTATION_HISTORY_DELTA &&
               snapshot_sequence >= base_sequence) {
        history_count = snapshot_sequence - base_sequence;
    } else {
        return -1;
    }
    policy_entry_size = header[1] == POLICY_ATTESTATION_REPORT_SECURITY ?
        POLICY_ATTESTATION_SECURITY_ENTRY_SIZE :
        POLICY_ATTESTATION_CONSISTENCY_ENTRY_SIZE;
    if (history_count >
        (POLICYCTL_MAX_ATTESTATION_SIZE -
         POLICY_ATTESTATION_RESPONSE_HEADER_SIZE -
         POLICY_ATTESTATION_SIGNATURE_SIZE -
         (size_t)header[3] * policy_entry_size) /
        POLICY_ATTESTATION_HISTORY_RECORD_SIZE) {
        return -1;
    }
    report_len = POLICY_ATTESTATION_RESPONSE_HEADER_SIZE +
                 (size_t)header[3] * policy_entry_size +
                 (size_t)history_count * POLICY_ATTESTATION_HISTORY_RECORD_SIZE +
                 POLICY_ATTESTATION_SIGNATURE_SIZE;
    report = malloc(report_len);
    if (!report) {
        return -1;
    }
    memcpy(report, header, sizeof(header));

    offset = sizeof(header);
    while (offset < report_len) {
        size_t remaining = report_len - offset;
        uint32_t chunk = remaining > POLICYCTL_FETCH_CHUNK_SIZE ?
            POLICYCTL_FETCH_CHUNK_SIZE : (uint32_t)remaining;

        if (send_nvme_admin_cmd_ex(device, NVME_CMD_POLICY_ATTESTATION_FETCH,
                                   report + offset, chunk, chunk,
                                   (uint32_t)offset,
                                   (uint32_t)((uint64_t)offset >> 32)) != 0) {
            free(report);
            return -1;
        }
        offset += chunk;
    }

    *report_out = report;
    *report_len_out = report_len;
    return 0;
}

static int do_attestation(const char *device, uint8_t report_type,
                          uint8_t history_mode, const char *checkpoint_path,
                          const char *save_path)
{
    uint8_t request[POLICY_ATTESTATION_DELTA_REQUEST_SIZE] = {0};
    uint32_t request_len = POLICY_ATTESTATION_REQUEST_SIZE;
    uint8_t *prior_report = NULL;
    size_t prior_report_len = 0;
    struct attestation_view prior_view;
    uint64_t base_sequence = 0;
    uint8_t base_head[POLICY_ATTESTATION_HASH_SIZE] = {0};
    uint8_t base_epoch[POLICY_ATTESTATION_BOOT_EPOCH_SIZE] = {0};
    uint8_t *report = NULL;
    size_t report_len = 0;
    struct attestation_view view;
    uint8_t computed_head[POLICY_ATTESTATION_HASH_SIZE];
    size_t i;
    int rc = -1;

    if (history_mode == POLICY_ATTESTATION_HISTORY_DELTA) {
        if (read_entire_file(checkpoint_path, &prior_report,
                             &prior_report_len) != 0 ||
            parse_attestation(prior_report, prior_report_len, &prior_view) != 0) {
            fprintf(stderr, "Invalid checkpoint file: %s\n", checkpoint_path);
            goto cleanup;
        }
        base_sequence = prior_view.snapshot_sequence;
        memcpy(base_head, prior_view.history_head, sizeof(base_head));
        memcpy(base_epoch, prior_view.boot_epoch, sizeof(base_epoch));
        request_len = POLICY_ATTESTATION_DELTA_REQUEST_SIZE;
        encode_u64_le(base_sequence,
                      request + POLICY_ATTESTATION_REQUEST_SIZE);
    }

    request[0] = POLICY_ATTESTATION_FORMAT_VERSION;
    request[1] = report_type;
    request[2] = history_mode;
    if (RAND_bytes(request + 3, POLICY_ATTESTATION_NONCE_SIZE) != 1) {
        fprintf(stderr, "Failed to generate attestation nonce\n");
        goto cleanup;
    }

    if (fetch_attestation(device, request, request_len, base_sequence,
                          &report, &report_len) != 0 ||
        parse_attestation(report, report_len, &view) != 0 ||
        view.report_type != report_type || view.history_mode != history_mode ||
        CRYPTO_memcmp(view.nonce, request + 3,
                      POLICY_ATTESTATION_NONCE_SIZE) != 0) {
        fprintf(stderr, "Failed to fetch or verify attestation\n");
        goto cleanup;
    }

    if (history_mode == POLICY_ATTESTATION_HISTORY_FULL) {
        if (view.history_count != view.snapshot_sequence ||
            initial_history_head(view.boot_epoch, computed_head) != 0) {
            goto verification_failure;
        }
        base_sequence = 0;
    } else if (history_mode == POLICY_ATTESTATION_HISTORY_DELTA) {
        if (CRYPTO_memcmp(base_epoch, view.boot_epoch,
                          sizeof(base_epoch)) != 0 ||
            view.snapshot_sequence < base_sequence ||
            view.history_count != view.snapshot_sequence - base_sequence) {
            goto verification_failure;
        }
        memcpy(computed_head, base_head, sizeof(computed_head));
    } else {
        if (view.history_count != 0) {
            goto verification_failure;
        }
        memcpy(computed_head, view.history_head, sizeof(computed_head));
        base_sequence = view.snapshot_sequence;
    }

    for (i = 0; i < view.history_count; i++) {
        uint8_t next_head[POLICY_ATTESTATION_HASH_SIZE];
        const uint8_t *record = view.history +
            i * POLICY_ATTESTATION_HISTORY_RECORD_SIZE;

        if (fold_history_record(computed_head,
                                base_sequence + (uint64_t)i + 1,
                                record, next_head) != 0) {
            goto verification_failure;
        }
        memcpy(computed_head, next_head, sizeof(computed_head));
    }
    if (CRYPTO_memcmp(computed_head, view.history_head,
                      sizeof(computed_head)) != 0) {
        goto verification_failure;
    }
    if ((history_mode == POLICY_ATTESTATION_HISTORY_FULL &&
         verify_replayed_state(NULL, &view, true) != 0) ||
        (history_mode == POLICY_ATTESTATION_HISTORY_DELTA &&
         verify_replayed_state(&prior_view, &view, false) != 0)) {
        goto verification_failure;
    }

    printf("report=%s epoch=", report_type == POLICY_ATTESTATION_REPORT_SECURITY ?
           "security" : "consistency");
    print_hex(view.boot_epoch, POLICY_ATTESTATION_BOOT_EPOCH_SIZE);
    printf(" sequence=%llu head=", (unsigned long long)view.snapshot_sequence);
    print_hex(view.history_head, POLICY_ATTESTATION_HASH_SIZE);
    printf(" policies=%u events=%zu\n", view.policy_count, view.history_count);

    for (i = 0; i < view.policy_count; i++) {
        const uint8_t *entry = view.policies + i * view.policy_entry_size;

        printf("policy id=%u generation=%u active=%u",
               decode_u32_le(entry), decode_u32_le(entry + 4), entry[8]);
        if (report_type == POLICY_ATTESTATION_REPORT_CONSISTENCY) {
            printf(" hash=");
            print_hex(entry + 9, POLICY_ATTESTATION_HASH_SIZE);
        }
        printf("\n");
    }
    for (i = 0; i < view.history_count; i++) {
        const uint8_t *record = view.history +
            i * POLICY_ATTESTATION_HISTORY_RECORD_SIZE;

        printf("event sequence=%llu operation=%s policy_id=%u generation=%u\n",
               (unsigned long long)(base_sequence + (uint64_t)i + 1),
               history_operation_name(record[0]),
               decode_u32_le(record + 1), decode_u32_le(record + 5));
    }

    if (save_path && write_entire_file(save_path, report, report_len) != 0) {
        fprintf(stderr, "Failed to save checkpoint: %s\n", save_path);
        goto cleanup;
    }
    rc = 0;
    goto cleanup;

verification_failure:
    fprintf(stderr, "Attestation history verification failed\n");

cleanup:
    if (prior_report) {
        OPENSSL_cleanse(prior_report, prior_report_len);
        free(prior_report);
    }
    if (report) {
        OPENSSL_cleanse(report, report_len);
        free(report);
    }
    OPENSSL_cleanse(request, sizeof(request));
    OPENSSL_cleanse(base_head, sizeof(base_head));
    OPENSSL_cleanse(computed_head, sizeof(computed_head));
    return rc;
}

static int do_session(const char *device, uint8_t session_mode)
{
    struct policy_session session = {0};
    int rc;

    rc = establish_session(device, session_mode, &session);
    if (rc == 0 && save_session_state(&session) != 0) {
        fprintf(stderr, "Failed to persist session state\n");
        rc = -1;
    }
    OPENSSL_cleanse(&session, sizeof(session));
    return rc;
}

static int do_policy_image_cmd(const char *device, uint8_t opcode,
                               const char *policy_path,
                               uint32_t policy_id, uint32_t policy_version)
{
    struct stat st;
    struct policy_session session = {0};
    int policy_fd = -1;
    uint8_t *policy = NULL;
    uint8_t *plaintext = NULL;
    ssize_t read_rc;
    size_t plaintext_len;
    int rc = -1;

    if (stat(policy_path, &st) != 0 || st.st_size <= 0 || st.st_size > UINT32_MAX) {
        fprintf(stderr, "Invalid policy image: %s\n", policy_path);
        return -1;
    }

    if (load_session_state(&session) != 0) {
        fprintf(stderr, "No active session. Run: policyctl --mode normal|confidential session <device>\n");
        return -1;
    }

    policy_fd = open(policy_path, O_RDONLY);
    if (policy_fd < 0) {
        perror("open policy");
        goto cleanup;
    }

    policy = malloc((size_t)st.st_size);
    if (!policy) {
        goto cleanup;
    }
    read_rc = read(policy_fd, policy, (size_t)st.st_size);
    if (read_rc != st.st_size) {
        perror("read policy");
        goto cleanup;
    }

    plaintext_len = 12 + (size_t)st.st_size;
    plaintext = calloc(1, plaintext_len);
    if (!plaintext) {
        goto cleanup;
    }
    encode_u32_le(policy_id, plaintext);
    encode_u32_le(policy_version, plaintext + 4);
    encode_u32_le((uint32_t)st.st_size, plaintext + 8);
    memcpy(plaintext + 12, policy, (size_t)st.st_size);

    rc = send_authenticated_meta_cmd(device, &session, opcode,
                                     plaintext, plaintext_len);

cleanup:
    if (policy_fd >= 0) {
        close(policy_fd);
    }
    if (policy) {
        OPENSSL_cleanse(policy, (size_t)st.st_size);
        free(policy);
    }
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        free(plaintext);
    }
    OPENSSL_cleanse(&session, sizeof(session));
    return rc;
}

static int do_install(const char *device, const char *policy_path,
                      uint32_t policy_id, uint32_t policy_version)
{
    return do_policy_image_cmd(device, NVME_CMD_INSTALL_POLICY, policy_path,
                               policy_id, policy_version);
}

static int do_update(const char *device, const char *policy_path,
                     uint32_t policy_id, uint32_t policy_version)
{
    return do_policy_image_cmd(device, NVME_CMD_UPDATE_POLICY, policy_path,
                               policy_id, policy_version);
}

static int do_simple_opcode(const char *device, uint8_t opcode, uint32_t policy_id)
{
    struct policy_session session = {0};
    uint8_t plaintext[4];
    int rc;

    if (load_session_state(&session) != 0) {
        fprintf(stderr, "No active session. Run: policyctl --mode normal|confidential session <device>\n");
        return -1;
    }

    encode_u32_le(policy_id, plaintext);
    rc = send_authenticated_meta_cmd(device, &session, opcode, plaintext, sizeof(plaintext));
    OPENSSL_cleanse(&session, sizeof(session));
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    return rc;
}

static int do_probe(const char *device, uint8_t opcode, uint32_t cdw10)
{
    struct nvme_admin_cmd command = {0};
    int fd;

    fd = open(device, O_RDWR);
    if (fd < 0) {
        perror("open device");
        return -1;
    }
    command.opcode = opcode;
    command.cdw10 = cdw10;
    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &command) != 0) {
        perror("probe ioctl");
        close(fd);
        return -1;
    }
    close(fd);
    printf("0x%08x\n", command.result);
    return 0;
}

static int parse_mode(const char *arg, uint8_t *mode_out)
{
    if (!arg || !mode_out) {
        return -1;
    }
    if (strcmp(arg, "normal") == 0) {
        *mode_out = SESSION_MODE_NORMAL;
        return 0;
    }
    if (strcmp(arg, "confidential") == 0) {
        *mode_out = SESSION_MODE_CONFIDENTIAL;
        return 0;
    }
    return -1;
}

static int parse_report_type(const char *arg, uint32_t *report_type_out)
{
    if (!arg || !report_type_out) {
        return -1;
    }
    if (strcmp(arg, "security") == 0) {
        *report_type_out = POLICY_ATTESTATION_REPORT_SECURITY;
        return 0;
    }
    if (strcmp(arg, "consistency") == 0) {
        *report_type_out = POLICY_ATTESTATION_REPORT_CONSISTENCY;
        return 0;
    }
    return -1;
}

int main(int argc, char **argv)
{
    uint8_t session_mode = SESSION_MODE_NORMAL;
    uint32_t report_type;
    int argi = 1;

    if (argc > 3 && strcmp(argv[1], "--mode") == 0) {
        if (parse_mode(argv[2], &session_mode) != 0) {
            fprintf(stderr, "Invalid mode: %s\n", argv[2]);
            return 1;
        }
        argi = 3;
    }

    if (argc - argi < 2) {
        fprintf(stderr,
                "Usage:\n"
                "  %s [--mode normal|confidential] session <device>\n"
                "  %s [--mode normal|confidential] install <device> <policy.wasm> <policy_id> <version>\n"
                "  %s [--mode normal|confidential] update <device> <policy.wasm> <policy_id> <version>\n"
                "  %s [--mode normal|confidential] activate <device> <policy_id>\n"
                "  %s [--mode normal|confidential] deactivate <device> <policy_id>\n"
                "  %s [--mode normal|confidential] remove <device> <policy_id>\n"
                "  %s attest <device> <security|consistency> [--history full | --since <checkpoint>] [--save-checkpoint <file>]\n"
                "  %s probe <device> <admin_opcode> <cdw10>\n",
                argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0],
                argv[0]);
        return 1;
    }

    if (strcmp(argv[argi], "session") == 0) {
        if (argc - argi != 2) {
            return 1;
        }
        clear_session_state();
        return do_session(argv[argi + 1], session_mode) == 0 ? 0 : 1;
    }

    if (strcmp(argv[argi], "probe") == 0) {
        if (argc - argi != 4) {
            return 1;
        }
        return do_probe(argv[argi + 1],
                        (uint8_t)strtoul(argv[argi + 2], NULL, 0),
                        (uint32_t)strtoul(argv[argi + 3], NULL, 0)) == 0 ? 0 : 1;
    }

    if (strcmp(argv[argi], "install") == 0) {
        if (argc - argi != 5) {
            return 1;
        }
        return do_install(argv[argi + 1], argv[argi + 2],
                          (uint32_t)strtoul(argv[argi + 3], NULL, 0),
                          (uint32_t)strtoul(argv[argi + 4], NULL, 0)) == 0 ? 0 : 1;
    }

    if (strcmp(argv[argi], "update") == 0) {
        if (argc - argi != 5) {
            return 1;
        }
        return do_update(argv[argi + 1], argv[argi + 2],
                         (uint32_t)strtoul(argv[argi + 3], NULL, 0),
                         (uint32_t)strtoul(argv[argi + 4], NULL, 0)) == 0 ? 0 : 1;
    }

    if (strcmp(argv[argi], "activate") == 0) {
        if (argc - argi != 3) {
            return 1;
        }
        return do_simple_opcode(argv[argi + 1],
                                NVME_CMD_ACTIVATE_POLICY,
                                (uint32_t)strtoul(argv[argi + 2], NULL, 0)) == 0 ? 0 : 1;
    }

    if (strcmp(argv[argi], "deactivate") == 0) {
        if (argc - argi != 3) {
            return 1;
        }
        return do_simple_opcode(argv[argi + 1],
                                NVME_CMD_DEACTIVATE_POLICY,
                                (uint32_t)strtoul(argv[argi + 2], NULL, 0)) == 0 ? 0 : 1;
    }

    if (strcmp(argv[argi], "remove") == 0) {
        if (argc - argi != 3) {
            return 1;
        }
        return do_simple_opcode(argv[argi + 1],
                                NVME_CMD_REMOVE_POLICY,
                                (uint32_t)strtoul(argv[argi + 2], NULL, 0)) == 0 ? 0 : 1;
    }

    if (strcmp(argv[argi], "attest") == 0) {
        uint8_t history_mode = POLICY_ATTESTATION_HISTORY_CHECKPOINT;
        const char *checkpoint_path = NULL;
        const char *save_path = NULL;
        int option;

        if (argc - argi < 3) {
            return 1;
        }
        if (parse_report_type(argv[argi + 2], &report_type) != 0) {
            fprintf(stderr, "Invalid report type: %s\n", argv[argi + 2]);
            return 1;
        }
        for (option = argi + 3; option < argc; option++) {
            if (strcmp(argv[option], "--history") == 0 &&
                option + 1 < argc &&
                strcmp(argv[option + 1], "full") == 0) {
                if (checkpoint_path) {
                    fprintf(stderr, "--history full and --since are mutually exclusive\n");
                    return 1;
                }
                history_mode = POLICY_ATTESTATION_HISTORY_FULL;
                option++;
            } else if (strcmp(argv[option], "--since") == 0 &&
                       option + 1 < argc) {
                if (history_mode == POLICY_ATTESTATION_HISTORY_FULL ||
                    checkpoint_path) {
                    fprintf(stderr, "--history full and --since are mutually exclusive\n");
                    return 1;
                }
                checkpoint_path = argv[++option];
                history_mode = POLICY_ATTESTATION_HISTORY_DELTA;
            } else if (strcmp(argv[option], "--save-checkpoint") == 0 &&
                       option + 1 < argc && !save_path) {
                save_path = argv[++option];
            } else {
                fprintf(stderr, "Invalid attestation option: %s\n", argv[option]);
                return 1;
            }
        }
        return do_attestation(argv[argi + 1], (uint8_t)report_type,
                              history_mode, checkpoint_path, save_path) == 0 ? 0 : 1;
    }

    fprintf(stderr, "Unknown command: %s\n", argv[argi]);
    return 1;
}
