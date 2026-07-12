/*
 * Admin Simulation - INIT_SESSION client implementation
 * 
 * Build: gcc -o admin-simulation admin-simulation.c -lssl -lcrypto -I../..
 * Usage: ./admin-simulation /dev/nvme0n1
 */

#include "admin-simulation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/nvme_ioctl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

static uint64_t g_admin_session_counter = 0;

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    size_t i;

    printf("[Admin] %s (%zu bytes): ", label, len);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

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

static bool reserve_session_counter(uint64_t *counter_out)
{
    g_admin_session_counter++;
    *counter_out = g_admin_session_counter;
    return true;
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

/* ========================================================================== */
/* Cryptographic Functions */
/* ========================================================================== */

/* Ed25519 signature generation using ADMIN_PRIVATE_KEY */
static bool sign_with_admin_private_key(const uint8_t *message, size_t message_len,
                                        uint8_t *sig_out)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    size_t sig_len = 64;
    bool result = false;
    
    /* Create private key from raw bytes */
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ADMIN_PRIVATE_KEY, 32);
    if (!pkey) {
        fprintf(stderr, "[Admin] Failed to create admin private key\n");
        goto cleanup;
    }
    
    /* Create message digest context */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "[Admin] Failed to create MD context\n");
        goto cleanup;
    }
    
    /* Initialize signing (NULL digest for Ed25519) */
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
        fprintf(stderr, "[Admin] Failed to init signing\n");
        goto cleanup;
    }
    
    /* Sign message (one-shot for Ed25519) */
    if (EVP_DigestSign(md_ctx, sig_out, &sig_len, message, message_len) != 1 || sig_len != 64) {
        fprintf(stderr, "[Admin] Failed to sign message\n");
        goto cleanup;
    }
    
    result = true;
    
cleanup:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return result;
}

/* X25519 ephemeral keypair generation */
static bool generate_ephemeral_keypair(uint8_t *public_key_out, uint8_t *private_key_out)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t len;
    bool result = false;
    
    /* Create keygen context for X25519 */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) {
        fprintf(stderr, "[Admin] Failed to create X25519 context\n");
        goto cleanup;
    }
    
    /* Initialize keygen */
    if (EVP_PKEY_keygen_init(pctx) != 1) {
        fprintf(stderr, "[Admin] Failed to init keygen\n");
        goto cleanup;
    }
    
    /* Generate keypair */
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        fprintf(stderr, "[Admin] Failed to generate keypair\n");
        goto cleanup;
    }
    
    /* Extract raw private key */
    len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, private_key_out, &len) != 1 || len != 32) {
        fprintf(stderr, "[Admin] Failed to extract private key\n");
        goto cleanup;
    }
    
    /* Extract raw public key */
    len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &len) != 1 || len != 32) {
        fprintf(stderr, "[Admin] Failed to extract public key\n");
        goto cleanup;
    }
    
    result = true;
    
cleanup:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    return result;
}

/* Ed25519 signature verification using SSD_PUBLIC_KEY */
static bool verify_ssd_signature(const uint8_t *message, size_t message_len,
                                const uint8_t *sig)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    bool result = false;
    
    /* Create public key from raw bytes */
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, SSD_PUBLIC_KEY, 32);
    if (!pkey) {
        fprintf(stderr, "[Admin] Failed to create SSD public key\n");
        goto cleanup;
    }
    
    /* Create message digest context */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "[Admin] Failed to create MD context\n");
        goto cleanup;
    }
    
    /* Initialize verification (NULL digest for Ed25519) */
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
        fprintf(stderr, "[Admin] Failed to init verification\n");
        goto cleanup;
    }
    
    /* Verify signature (one-shot for Ed25519) */
    if (EVP_DigestVerify(md_ctx, sig, 64, message, message_len) == 1) {
        result = true;
    } else {
        fprintf(stderr, "[Admin] SSD signature verification failed\n");
    }
    
cleanup:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return result;
}

/* X25519 ECDH + HKDF to derive 32-byte session key */
static bool derive_session_key(const uint8_t *admin_ephem_priv,
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
    uint8_t kdf_info[1 + 32 + 32 + 1 + 8];
    uint8_t counter_le[8];
    bool result = false;
    
    /* Create EVP_PKEY for admin ephemeral private key */
    admin_priv_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, admin_ephem_priv, 32);
    if (!admin_priv_pkey) {
        fprintf(stderr, "[Admin] Failed to create admin ephemeral private key\n");
        goto cleanup;
    }
    
    /* Create EVP_PKEY for SSD ephemeral public key */
    ssd_pub_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, ssd_ephem_pub, 32);
    if (!ssd_pub_pkey) {
        fprintf(stderr, "[Admin] Failed to create SSD ephemeral public key\n");
        goto cleanup;
    }
    
    /* Create context for ECDH derivation */
    ctx = EVP_PKEY_CTX_new(admin_priv_pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "[Admin] Failed to create ECDH context\n");
        goto cleanup;
    }
    
    /* Initialize derivation */
    if (EVP_PKEY_derive_init(ctx) != 1) {
        fprintf(stderr, "[Admin] Failed to init ECDH derivation\n");
        goto cleanup;
    }
    
    /* Set peer public key */
    if (EVP_PKEY_derive_set_peer(ctx, ssd_pub_pkey) != 1) {
        fprintf(stderr, "[Admin] Failed to set peer public key\n");
        goto cleanup;
    }
    
    /* Derive shared secret */
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) != 1 || secret_len != 32) {
        fprintf(stderr, "[Admin] Failed to derive shared secret\n");
        goto cleanup;
    }
    
    /* Apply HKDF to derive the transcript-bound session key. */
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kctx) {
        fprintf(stderr, "[Admin] Failed to create KDF context\n");
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(kctx) != 1) {
        fprintf(stderr, "[Admin] Failed to init HKDF\n");
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) != 1) {
        fprintf(stderr, "[Admin] Failed to set HKDF digest\n");
        goto cleanup;
    }

    kdf_info[0] = NVME_CMD_INIT_SESSION_SUBMIT;
    memcpy(kdf_info + 1, admin_ephem_pub, 32);
    memcpy(kdf_info + 33, ssd_ephem_pub, 32);
    kdf_info[65] = session_mode;
    encode_u64_le(counter, counter_le);
    memcpy(kdf_info + 66, counter_le, sizeof(counter_le));

    if (EVP_PKEY_CTX_set1_hkdf_key(kctx, shared_secret, sizeof(shared_secret)) != 1) {
        fprintf(stderr, "[Admin] Failed to set HKDF key\n");
        goto cleanup;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(kctx, kdf_info, sizeof(kdf_info)) != 1) {
        fprintf(stderr, "[Admin] Failed to set HKDF info\n");
        goto cleanup;
    }

    /* Derive 32-byte session key. */
    if (EVP_PKEY_derive(kctx, session_key_out, &secret_len) != 1 || secret_len != 32) {
        fprintf(stderr, "[Admin] Failed to derive session key\n");
        goto cleanup;
    }
    
    result = true;
    
cleanup:
    /* Clear sensitive data */
    OPENSSL_cleanse(shared_secret, 32);
    OPENSSL_cleanse(kdf_info, sizeof(kdf_info));
    
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
    return result;
}

/* ========================================================================== */
/* NVMe Communication */
/* ========================================================================== */

static int send_nvme_session_cmd(const char *device, uint8_t opcode,
                                 uint8_t *buffer, uint32_t data_len)
{
    int fd = -1;
    struct nvme_passthru_cmd cmd;
    int ret = -1;
    
    /* Open NVMe device */
    fd = open(device, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[Admin] Failed to open device %s: %s\n", device, strerror(errno));
        return -1;
    }
    
    /* Prepare NVMe passthrough command */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = opcode;
    cmd.nsid = 1;  /* Namespace ID */
    cmd.addr = (uint64_t)(uintptr_t)buffer;
    cmd.data_len = data_len;
    
    /* Send command via I/O passthrough ioctl. */
    ret = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
    if (ret < 0) {
        fprintf(stderr, "[Admin] NVME_IOCTL_IO_CMD failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    /* Check NVMe status code */
    if (cmd.result != 0) {
        fprintf(stderr, "[Admin] NVMe command failed with status: 0x%x\n", cmd.result);
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

/* ========================================================================== */
/* Main Library Function */
/* ========================================================================== */

/* Establish session with SSD and derive shared session key */
int admin_establish_session(const char *device, uint8_t session_mode,
                            uint8_t *session_key_out)
{
    uint8_t admin_ephem_pub[32];
    uint8_t admin_ephem_priv[32];
    uint8_t request[INIT_SESSION_REQUEST_SIZE];
    uint8_t response[INIT_SESSION_RESPONSE_SIZE];
    uint8_t admin_init_message[1 + 32 + 1 + 8];
    uint8_t proof_message[1 + 32 + 32 + 1 + 8];
    uint64_t counter;
    uint64_t response_counter;
    uint8_t *ssd_ephem_pub;
    uint8_t *proof_sig;
    
    if (!reserve_session_counter(&counter)) {
        fprintf(stderr, "[Admin] Failed to reserve session counter\n");
        goto error;
    }
    
    /* Step 1: Generate admin ephemeral keypair (X25519) */
    if (!generate_ephemeral_keypair(admin_ephem_pub, admin_ephem_priv)) {
        fprintf(stderr, "[Admin] Failed to generate ephemeral keypair\n");
        goto error;
    }
    
    /* Step 2: Sign the admin transcript fragment, including the replay counter. */
    build_admin_init_message(admin_ephem_pub, session_mode, counter,
                             admin_init_message);
    if (!sign_with_admin_private_key(admin_init_message, sizeof(admin_init_message),
                                     request + 41)) {
        fprintf(stderr, "[Admin] Failed to sign session request\n");
        goto error;
    }
    
    /* Step 3: Build request */
    memcpy(request, admin_ephem_pub, 32);
    request[32] = session_mode;
    encode_u64_le(counter, request + 33);
    /* The final layout of request is:
     * [admin_ephem_pub (32)] [mode (1)] [counter (8)] [admin_sig (64)] = 105 bytes.
     */
    
    /* Step 4: Send INIT_SESSION NVMe command */
    if (send_nvme_session_cmd(device, NVME_CMD_INIT_SESSION_SUBMIT,
                              request,
                              INIT_SESSION_REQUEST_SIZE) < 0) {
        fprintf(stderr, "[Admin] Failed to submit INIT_SESSION request\n");
        goto error;
    }

    memset(response, 0, sizeof(response));
    if (send_nvme_session_cmd(device, NVME_CMD_INIT_SESSION_FETCH,
                              response,
                              INIT_SESSION_RESPONSE_SIZE) < 0) {
        fprintf(stderr, "[Admin] Failed to fetch INIT_SESSION response\n");
        goto error;
    }
    
    /* Step 5: Extract response */
    ssd_ephem_pub = response;
    response_counter = decode_u64_le(response + 32);
    proof_sig = response + 40;
    /* The final layout of response is:
     * [ssd_ephem_pub (32)] [counter (8)] [proof_sig (64)] = 104 bytes.
     */

    if (response_counter != counter) {
        fprintf(stderr, "[Admin] SSD echoed mismatched session counter\n");
        goto error;
    }
    
    /* Step 6: Build proof message for verification */
    build_ssd_response_message(admin_ephem_pub, ssd_ephem_pub, session_mode,
                               counter, proof_message);
    
    /* Step 7: Verify SSD's proof signature */
    if (!verify_ssd_signature(proof_message, sizeof(proof_message), proof_sig)) {
        fprintf(stderr, "[Admin] SSD signature verification failed\n");
        goto error;
    }
    
    /* Step 8: Derive session key (ECDH + HKDF) */
    if (!derive_session_key(admin_ephem_priv, ssd_ephem_pub, admin_ephem_pub,
                            session_mode,
                            counter, session_key_out)) {
        fprintf(stderr, "[Admin] Failed to derive session key\n");
        goto error;
    }
    
    /* Step 9: Security cleanup */
    OPENSSL_cleanse(admin_ephem_priv, 32);
    OPENSSL_cleanse(request, INIT_SESSION_REQUEST_SIZE);
    OPENSSL_cleanse(response, INIT_SESSION_RESPONSE_SIZE);
    OPENSSL_cleanse(admin_init_message, sizeof(admin_init_message));
    OPENSSL_cleanse(proof_message, sizeof(proof_message));
    
    return 0;
    
error:
    OPENSSL_cleanse(admin_ephem_priv, 32);
    OPENSSL_cleanse(request, INIT_SESSION_REQUEST_SIZE);
    OPENSSL_cleanse(response, INIT_SESSION_RESPONSE_SIZE);
    OPENSSL_cleanse(admin_init_message, sizeof(admin_init_message));
    OPENSSL_cleanse(proof_message, sizeof(proof_message));
    OPENSSL_cleanse(session_key_out, 32);
    return -1;
}

int main(int argc, char **argv)
{
    uint8_t session_key[32];
    const char *device;
    
    printf("=================================================\n");
    printf("Admin Session Establishment with FEMU SSD\n");
    printf("=================================================\n\n");
    
    /* Parse command line arguments */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <nvme_device>\n", argv[0]);
        fprintf(stderr, "Example: %s /dev/nvme0n1\n", argv[0]);
        return 1;
    }
    
    device = argv[1];
    
    /* Establish session */
    if (admin_establish_session(device, SESSION_MODE_NORMAL, session_key) < 0) {
        fprintf(stderr, "\n[Admin] Session establishment failed\n");
        return 1;
    }
    
    /* Print session key */
    printf("\n");
    print_hex("Session Key", session_key, 32);
    
    printf("\n=================================================\n");
    printf("Session establishment complete\n");
    printf("=================================================\n");
    
    /* Zero session key before exit */
    OPENSSL_cleanse(session_key, 32);
    
    return 0;
}
    if (session_mode != SESSION_MODE_NORMAL &&
        session_mode != SESSION_MODE_CONFIDENTIAL) {
        fprintf(stderr, "[Admin] Invalid session mode %u\n", session_mode);
        goto error;
    }
