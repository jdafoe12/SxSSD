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
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/nvme_ioctl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/err.h>

/* INIT_SESSION opcode (from meta-interface-policy.h) */
#define NVME_CMD_INIT_SESSION  0x93

/* Request and response sizes */
#define INIT_SESSION_REQUEST_SIZE   96
#define INIT_SESSION_RESPONSE_SIZE  96

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
                               uint8_t *session_key_out)
{
    EVP_PKEY *admin_priv_pkey = NULL;
    EVP_PKEY *ssd_pub_pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    uint8_t shared_secret[32];
    size_t secret_len = 32;
    OSSL_PARAM params[4];
    const char *digest = "SHA256";
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
    
    /* Apply HKDF to derive session key from shared secret */
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        fprintf(stderr, "[Admin] Failed to fetch HKDF\n");
        goto cleanup;
    }
    
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        fprintf(stderr, "[Admin] Failed to create KDF context\n");
        goto cleanup;
    }
    
    /* Set up HKDF parameters: mode=extract-and-expand, digest=SHA256, key=shared_secret, info="" */
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", shared_secret, 32);
    params[2] = OSSL_PARAM_construct_octet_string("info", (void *)"", 0);
    params[3] = OSSL_PARAM_construct_end();
    
    /* Derive 32-byte session key */
    if (EVP_KDF_derive(kctx, session_key_out, 32, params) != 1) {
        fprintf(stderr, "[Admin] Failed to derive session key\n");
        goto cleanup;
    }
    
    result = true;
    
cleanup:
    /* Clear sensitive data */
    OPENSSL_cleanse(shared_secret, 32);
    
    if (kctx) {
        EVP_KDF_CTX_free(kctx);
    }
    if (kdf) {
        EVP_KDF_free(kdf);
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

/* Send INIT_SESSION NVMe IO command via ioctl */
static int send_init_session_nvme_cmd(const char *device, uint8_t *buffer)
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
    cmd.opcode = NVME_CMD_INIT_SESSION;
    cmd.nsid = 1;  /* Namespace ID */
    cmd.addr = (uint64_t)(uintptr_t)buffer;
    cmd.data_len = INIT_SESSION_REQUEST_SIZE;
    
    /* Send command via ioctl (IO command, not admin) */
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
int admin_establish_session(const char *device, uint8_t *session_key_out)
{
    uint8_t admin_ephem_pub[32];
    uint8_t admin_ephem_priv[32];
    uint8_t request[INIT_SESSION_REQUEST_SIZE];
    uint8_t response[INIT_SESSION_RESPONSE_SIZE];
    uint8_t proof_message[64];
    uint8_t *admin_sig;
    uint8_t *ssd_ephem_pub;
    uint8_t *proof_sig;
    
    printf("[Admin] Starting session establishment...\n");
    
    /* Step 1: Generate admin ephemeral keypair (X25519) */
    printf("[Admin] Generating ephemeral keypair...\n");
    if (!generate_ephemeral_keypair(admin_ephem_pub, admin_ephem_priv)) {
        fprintf(stderr, "[Admin] Failed to generate ephemeral keypair\n");
        goto error;
    }
    
    /* Step 2: Sign admin_ephem_pub with admin private key (Ed25519) */
    printf("[Admin] Signing ephemeral public key...\n");
    admin_sig = request + 32;
    if (!sign_with_admin_private_key(admin_ephem_pub, 32, admin_sig)) {
        fprintf(stderr, "[Admin] Failed to sign ephemeral public key\n");
        goto error;
    }
    
    /* Step 3: Build request */
    memcpy(request, admin_ephem_pub, 32);
    /* admin_sig already written to request + 32 */
    
    /* Step 4: Send INIT_SESSION NVMe command */
    printf("[Admin] Sending INIT_SESSION command to %s...\n", device);
    memcpy(response, request, INIT_SESSION_REQUEST_SIZE);  /* Response uses same buffer */
    if (send_init_session_nvme_cmd(device, response) < 0) {
        fprintf(stderr, "[Admin] Failed to send INIT_SESSION command\n");
        goto error;
    }
    
    /* Step 5: Extract response */
    ssd_ephem_pub = response;
    proof_sig = response + 32;
    
    /* Step 6: Build proof message for verification */
    memcpy(proof_message, admin_ephem_pub, 32);
    memcpy(proof_message + 32, ssd_ephem_pub, 32);
    
    /* Step 7: Verify SSD's proof signature */
    printf("[Admin] Verifying SSD signature...\n");
    if (!verify_ssd_signature(proof_message, 64, proof_sig)) {
        fprintf(stderr, "[Admin] SSD signature verification failed\n");
        goto error;
    }
    
    /* Step 8: Derive session key (ECDH + HKDF) */
    printf("[Admin] Deriving session key...\n");
    if (!derive_session_key(admin_ephem_priv, ssd_ephem_pub, session_key_out)) {
        fprintf(stderr, "[Admin] Failed to derive session key\n");
        goto error;
    }
    
    /* Step 9: Security cleanup */
    OPENSSL_cleanse(admin_ephem_priv, 32);
    OPENSSL_cleanse(request, INIT_SESSION_REQUEST_SIZE);
    OPENSSL_cleanse(response, INIT_SESSION_RESPONSE_SIZE);
    
    printf("[Admin] Session established successfully\n");
    return 0;
    
error:
    OPENSSL_cleanse(admin_ephem_priv, 32);
    OPENSSL_cleanse(request, INIT_SESSION_REQUEST_SIZE);
    OPENSSL_cleanse(response, INIT_SESSION_RESPONSE_SIZE);
    return -1;
}

/* ========================================================================== */
/* Test main() Function */
/* ========================================================================== */

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len) {
            printf("\n%*s", (int)strlen(label) + 2, "");
        }
    }
    printf("\n");
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
    if (admin_establish_session(device, session_key) < 0) {
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
