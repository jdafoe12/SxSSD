#include "ftl.h"
#include "bbm.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include "meta-interface-policy.h"

/* ========================================================================== */
/* SSD/FTL Private Key (for proving identity during INIT_SESSION) */
/* ========================================================================== */



/* ========================================================================== */
/* Type Definitions */
/* ========================================================================== */

struct meta_policy_context {
    uint8_t session_key[32];
    bool session_established;
    int mode;            // TODO: Not used yet.
    int session_counter; // TODO: Not used yet.
};

static struct meta_policy_context *g_meta_ctx = NULL;

/* ========================================================================== */
/* Cryptographic Function Stubs */
/* ========================================================================== */

/* Ed25519 signature verification using ADMIN_PUBLIC_KEY */
static bool verify_admin_signature(const uint8_t *message, size_t message_len,
                                  const uint8_t *sig)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    bool result = false;
    
    /* Create public key from raw bytes */
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, ADMIN_PUBLIC_KEY, 32);
    if (!pkey) {
        goto cleanup;
    }
    
    /* Create message digest context */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        goto cleanup;
    }
    
    /* Initialize verification (NULL digest for Ed25519) */
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
        goto cleanup;
    }
    
    /* Verify signature (one-shot for Ed25519) */
    if (EVP_DigestVerify(md_ctx, sig, 64, message, message_len) == 1) {
        result = true;
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

/* X25519 ephemeral keypair generation */
static void generate_ephemeral_keypair(uint8_t *public_key_out, uint8_t *private_key_out)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t len;
    
    /* Create keygen context for X25519 */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) {
        goto error;
    }
    
    /* Initialize keygen */
    if (EVP_PKEY_keygen_init(pctx) != 1) {
        goto error;
    }
    
    /* Generate keypair */
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        goto error;
    }
    
    /* Extract raw private key */
    len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, private_key_out, &len) != 1 || len != 32) {
        goto error;
    }
    
    /* Extract raw public key */
    len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &len) != 1 || len != 32) {
        goto error;
    }
    
    goto cleanup;
    
error:
    /* On error, zero the output buffers */
    memset(public_key_out, 0, 32);
    memset(private_key_out, 0, 32);
    
cleanup:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
}

/* Ed25519 signature generation using SSD_PRIVATE_KEY */
static void sign_with_ssd_private_key(const uint8_t *message, size_t message_len,
                                     uint8_t *sig_out)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    size_t sig_len = 64;
    
    /* Create private key from raw bytes */
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, SSD_PRIVATE_KEY, 32);
    if (!pkey) {
        goto error;
    }
    
    /* Create message digest context */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        goto error;
    }
    
    /* Initialize signing (NULL digest for Ed25519) */
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
        goto error;
    }
    
    /* Sign message (one-shot for Ed25519) */
    if (EVP_DigestSign(md_ctx, sig_out, &sig_len, message, message_len) != 1 || sig_len != 64) {
        goto error;
    }
    
    goto cleanup;
    
error:
    /* On error, zero the signature output */
    memset(sig_out, 0, 64);
    
cleanup:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
}

/* X25519 ECDH + HKDF to derive 32-byte session key */
static void derive_session_key(const uint8_t *admin_ephem_pub,
                               const uint8_t *ssd_ephem_priv,
                               uint8_t *session_key_out)
{
    EVP_PKEY *ssd_priv_pkey = NULL;
    EVP_PKEY *admin_pub_pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    uint8_t shared_secret[32];
    size_t secret_len = 32;
    OSSL_PARAM params[4];
    const char *digest = "SHA256";
    
    /* Create EVP_PKEY for SSD ephemeral private key */
    ssd_priv_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, ssd_ephem_priv, 32);
    if (!ssd_priv_pkey) {
        goto error;
    }
    
    /* Create EVP_PKEY for admin ephemeral public key */
    admin_pub_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, admin_ephem_pub, 32);
    if (!admin_pub_pkey) {
        goto error;
    }
    
    /* Create context for ECDH derivation */
    ctx = EVP_PKEY_CTX_new(ssd_priv_pkey, NULL);
    if (!ctx) {
        goto error;
    }
    
    /* Initialize derivation */
    if (EVP_PKEY_derive_init(ctx) != 1) {
        goto error;
    }
    
    /* Set peer public key */
    if (EVP_PKEY_derive_set_peer(ctx, admin_pub_pkey) != 1) {
        goto error;
    }
    
    /* Derive shared secret */
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) != 1 || secret_len != 32) {
        goto error;
    }
    
    /* Apply HKDF to derive session key from shared secret */
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        goto error;
    }
    
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        goto error;
    }
    
    /* Set up HKDF parameters: mode=extract-and-expand, digest=SHA256, key=shared_secret, info="" */
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", shared_secret, 32);
    params[2] = OSSL_PARAM_construct_octet_string("info", (void *)"", 0);
    params[3] = OSSL_PARAM_construct_end();
    
    /* Derive 32-byte session key */
    if (EVP_KDF_derive(kctx, session_key_out, 32, params) != 1) {
        goto error;
    }
    
    goto cleanup;
    
error:
    /* On error, zero the session key output */
    memset(session_key_out, 0, 32);
    
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
    if (admin_pub_pkey) {
        EVP_PKEY_free(admin_pub_pkey);
    }
    if (ssd_priv_pkey) {
        EVP_PKEY_free(ssd_priv_pkey);
    }
}

/* ========================================================================== */
/* INIT_SESSION NVMe Command Hook */
/* ========================================================================== */

static bool init_session_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                  struct FtlPolicyAPI *api, void *context)
{
    (void)ssd; (void)api; (void)context;
    return event->opcode == NVME_CMD_INIT_SESSION;
}

static uint64_t init_session_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                      struct FtlPolicyAPI *api, void *context)
{
    (void)ssd; (void)api;  /* unused */
    struct meta_policy_context *ctx = (struct meta_policy_context *)context;
    NvmeRequest *req = event->req;
    FemuCtrl *n = req->sq->ctrl;
    uint64_t prp1 = le64_to_cpu(req->cmd.dptr.prp1);
    uint64_t prp2 = le64_to_cpu(req->cmd.dptr.prp2);
    
    #define INIT_SESSION_REQUEST_SIZE  96   /* admin_ephem_pub (32) + admin_sig (64); admin signs ephem_pub, we verify with ADMIN_PUBLIC_KEY */
    #define INIT_SESSION_RESPONSE_SIZE 96   /* ssd_ephem_pub (32) + proof_sig (64); admin already has SSD cert */
    uint8_t request[INIT_SESSION_REQUEST_SIZE];
    uint8_t response[INIT_SESSION_RESPONSE_SIZE];
    uint8_t ssd_ephem_pub[32], ssd_ephem_priv[32];
    
    /* Read request: admin_ephem_pub (32) + admin_sig (64). We already have admin cert (ADMIN_PUBLIC_KEY) in firmware. */
    if (dma_read_prp(n, request, INIT_SESSION_REQUEST_SIZE, prp1, prp2) != NVME_SUCCESS) {
        req->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
        return 0;
    }
    
    /* Verify admin signed their ephemeral public key (proves request is from admin) */
    if (!verify_admin_signature(request, 32, request + 32)) {
        req->status = NVME_INVALID_OPCODE | NVME_DNR;
        return 0;
    }
    
    /* Generate SSD ephemeral key (TODO: real X25519) */
    generate_ephemeral_keypair(ssd_ephem_pub, ssd_ephem_priv);
    
    /* Proof of possession: sign (admin_ephem_pub || ssd_ephem_pub); admin verifies with stored SSD_PUBLIC_KEY */
    const uint8_t *admin_ephem_pub = request;  /* first 32 bytes of request */
    uint8_t proof_message[64];
    memcpy(proof_message, admin_ephem_pub, 32);
    memcpy(proof_message + 32, ssd_ephem_pub, 32);
    sign_with_ssd_private_key(proof_message, sizeof(proof_message), response + 32);
    
    /* Response: ssd_ephem_pub (32) + proof_sig (64) = 96 bytes. No cert — admin already has it. */
    memcpy(response, ssd_ephem_pub, 32);
    
    if (dma_write_prp(n, response, INIT_SESSION_RESPONSE_SIZE, prp1, prp2) != NVME_SUCCESS) {
        req->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
        return 0;
    }
    
    /* Derive session key (TODO: real ECDH + KDF) */
    derive_session_key(admin_ephem_pub, ssd_ephem_priv, ctx->session_key);
    ctx->session_established = true;
    
    req->status = NVME_SUCCESS;
    return 1000;  /* 1µs placeholder latency */
}

/* ========================================================================== */
/* Meta Interface Policy Initialization */
/* ========================================================================== */

int m_interface_policy_init(struct ssd *ssd)
{
    struct meta_policy_context *ctx = g_malloc0(sizeof(struct meta_policy_context));
    ctx->session_established = false;
    
    g_meta_ctx = ctx;
    
    /* Register INIT_SESSION NVMe hook */
    if (ftl_register_nvme_hook(ssd, NVME_CMD_INIT_SESSION,
                               init_session_condition,
                               init_session_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register INIT_SESSION hook\n");
        return -1;
    }
    
    printf("[Meta] INIT_SESSION hook registered\n");
    return 0;
}

