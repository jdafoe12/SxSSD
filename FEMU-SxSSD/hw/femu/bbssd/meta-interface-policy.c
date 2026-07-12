#include "ftl.h"
#include "bbm.h"
#include "policy-engine.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
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

#define META_AUTH_HMAC_SIZE 32
#define META_AUTH_TAG_SIZE 16
#define META_ENVELOPE_AUTH_SIZE 32
#define META_ENVELOPE_HEADER_SIZE (8 + META_ENVELOPE_AUTH_SIZE)

struct meta_policy_context {
    uint8_t session_key[32];
    uint8_t pending_response[INIT_SESSION_RESPONSE_SIZE];
    uint8_t pending_attestation_response[META_ENVELOPE_HEADER_SIZE +
                                         POLICY_ATTESTATION_RESPONSE_PLAINTEXT_SIZE];
    bool session_established;
    bool pending_response_valid;
    bool pending_attestation_response_valid;
    int mode;            // TODO: Not used yet.
    uint64_t active_session_counter; // This is ctr0 in the paper. This is for replay protection within the session.
    uint64_t session_counter;        // This is for replay protection of session initialization.
    uint64_t next_policy_alloc_index;
    struct {
        uint32_t policy_id;
        uint32_t policy_version;
        uint32_t policy_size_bytes;
        uint32_t policy_size_pages;
        uint32_t block_count;
        struct pba *blocks;
        bool active;
        bool in_use;
    } installed_policies[16];
};

static struct meta_policy_context *g_meta_ctx = NULL;

struct meta_encrypted_request {
    uint64_t counter;
    uint8_t auth[META_ENVELOPE_AUTH_SIZE];
    const uint8_t *ciphertext;
    size_t ciphertext_len;
};

struct policy_attestation_report {
    uint32_t policy_id;
    uint32_t report_type;
    uint8_t installed;
    uint8_t active;
    uint8_t reserved[2];
    uint8_t hash[POLICY_ATTESTATION_RESPONSE_HASH_SIZE];
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

static uint32_t decode_u32_le(const uint8_t in[4])
{
    uint32_t value = 0;

    for (size_t i = 0; i < 4; i++) {
        value |= ((uint32_t)in[i]) << (8 * i);
    }

    return value;
}

static void encode_u32_le(uint32_t value, uint8_t out[4])
{
    for (size_t i = 0; i < 4; i++) {
        out[i] = (uint8_t)(value >> (8 * i));
    }
}

static void build_meta_nonce(uint64_t counter, uint8_t nonce[12])
{
    memset(nonce, 0, 12);
    encode_u64_le(counter, nonce + 4);
}

static int derive_labeled_key(const uint8_t base_key[32], const char *label,
                              uint8_t derived_key[32])
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4];
    const char *digest = "SHA256";
    int rc = -1;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        goto cleanup;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", (void *)base_key, 32);
    params[2] = OSSL_PARAM_construct_octet_string("info", (void *)label, strlen(label));
    params[3] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, derived_key, 32, params) != 1) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (rc != 0) {
        memset(derived_key, 0, 32);
    }
    if (kctx) {
        EVP_KDF_CTX_free(kctx);
    }
    if (kdf) {
        EVP_KDF_free(kdf);
    }
    return rc;
}

static int compute_meta_hmac(const uint8_t key[32], uint8_t opcode,
                             uint64_t counter, const uint8_t *ciphertext,
                             size_t ciphertext_len,
                             uint8_t out[META_AUTH_HMAC_SIZE])
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    uint8_t counter_le[8];
    size_t mac_len = 0;
    int rc = -1;

    encode_u64_le(counter, counter_le);
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        return -1;
    }
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, 32, params) != 1) {
        goto cleanup;
    }
    if (EVP_MAC_update(ctx, &opcode, 1) != 1) {
        goto cleanup;
    }
    if (EVP_MAC_update(ctx, counter_le, sizeof(counter_le)) != 1) {
        goto cleanup;
    }
    if (ciphertext_len > 0 &&
        EVP_MAC_update(ctx, ciphertext, ciphertext_len) != 1) {
        goto cleanup;
    }
    if (EVP_MAC_final(ctx, out, &mac_len, META_AUTH_HMAC_SIZE) != 1 ||
        mac_len != META_AUTH_HMAC_SIZE) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    OPENSSL_cleanse(counter_le, sizeof(counter_le));
    if (ctx) {
        EVP_MAC_CTX_free(ctx);
    }
    if (mac) {
        EVP_MAC_free(mac);
    }
    if (rc != 0) {
        memset(out, 0, META_AUTH_HMAC_SIZE);
    }
    return rc;
}

static int aes256_gcm_decrypt(const uint8_t key[32], uint64_t counter,
                              uint8_t opcode, const uint8_t *ciphertext,
                              size_t ciphertext_len, const uint8_t tag[16],
                              uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t nonce[12];
    int len = 0;
    int rc = -1;

    build_meta_nonce(counter, nonce);
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1) {
        goto cleanup;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        goto cleanup;
    }
    if (EVP_DecryptUpdate(ctx, NULL, &len, &opcode, 1) != 1) {
        goto cleanup;
    }
    if (ciphertext_len > 0 &&
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, META_AUTH_TAG_SIZE, (void *)tag) != 1) {
        goto cleanup;
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
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

static int aes256_gcm_encrypt(const uint8_t key[32], uint64_t counter,
                              uint8_t opcode, const uint8_t *plaintext,
                              size_t plaintext_len, uint8_t *ciphertext,
                              uint8_t tag[16])
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
        EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        goto cleanup;
    }
    out_len += len;
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

static int compute_policy_sha256(const uint8_t *payload, size_t payload_len,
                                 uint8_t out[POLICY_ATTESTATION_RESPONSE_HASH_SIZE])
{
    EVP_MD_CTX *md_ctx = NULL;
    unsigned int digest_len = 0;
    int rc = -1;

    if (!payload || !out) {
        return -1;
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return -1;
    }
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
        goto cleanup;
    }
    if (payload_len > 0 && EVP_DigestUpdate(md_ctx, payload, payload_len) != 1) {
        goto cleanup;
    }
    if (EVP_DigestFinal_ex(md_ctx, out, &digest_len) != 1 ||
        digest_len != POLICY_ATTESTATION_RESPONSE_HASH_SIZE) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (rc != 0) {
        memset(out, 0, POLICY_ATTESTATION_RESPONSE_HASH_SIZE);
    }
    return rc;
}

static int parse_meta_envelope(const uint8_t *buffer, size_t buffer_len,
                               struct meta_encrypted_request *req)
{
    if (!buffer || !req || buffer_len < META_ENVELOPE_HEADER_SIZE) {
        return -1;
    }

    req->counter = decode_u64_le(buffer);
    memcpy(req->auth, buffer + 8, META_ENVELOPE_AUTH_SIZE);
    req->ciphertext = buffer + META_ENVELOPE_HEADER_SIZE;
    req->ciphertext_len = buffer_len - META_ENVELOPE_HEADER_SIZE;
    return 0;
}

static int authenticate_meta_request(struct meta_policy_context *ctx,
                                     struct NvmeCommandEvent *event,
                                     struct FtlPolicyAPI *api,
                                     uint64_t *counter_out,
                                     uint8_t **plaintext_out,
                                     size_t *plaintext_len_out)
{
    uint32_t request_len;
    uint8_t *request_buf = NULL;
    uint8_t *plaintext = NULL;
    struct meta_encrypted_request req;
    uint8_t opcode;
    int rc = -1;

    if (!ctx || !event || !api || !event->cmd || !plaintext_out ||
        !plaintext_len_out) {
        return -1;
    }
    if (!ctx->session_established) {
        return -1;
    }

    request_len = le32_to_cpu(event->cmd->cdw12);
    if (request_len < META_ENVELOPE_HEADER_SIZE) {
        return -1;
    }
    opcode = event->opcode;

    request_buf = g_malloc0(request_len);
    if (api->read_cmd_buffer(event, request_buf, request_len) != NVME_SUCCESS) {
        goto cleanup;
    }
    if (parse_meta_envelope(request_buf, request_len, &req) != 0) {
        goto cleanup;
    }
    if (req.counter <= ctx->active_session_counter) {
        goto cleanup;
    }

    plaintext = g_malloc0(req.ciphertext_len);

    if (ctx->mode == SESSION_MODE_NORMAL) {
        uint8_t mac_key[32];
        uint8_t computed_mac[META_AUTH_HMAC_SIZE];

        if (derive_labeled_key(ctx->session_key, "meta-normal-mac", mac_key) != 0) {
            OPENSSL_cleanse(mac_key, sizeof(mac_key));
            goto cleanup;
        }
        if (compute_meta_hmac(mac_key, opcode, req.counter,
                              req.ciphertext, req.ciphertext_len,
                              computed_mac) != 0) {
            OPENSSL_cleanse(mac_key, sizeof(mac_key));
            OPENSSL_cleanse(computed_mac, sizeof(computed_mac));
            goto cleanup;
        }
        if (CRYPTO_memcmp(computed_mac, req.auth, META_AUTH_HMAC_SIZE) != 0) {
            OPENSSL_cleanse(mac_key, sizeof(mac_key));
            OPENSSL_cleanse(computed_mac, sizeof(computed_mac));
            goto cleanup;
        }
        memcpy(plaintext, req.ciphertext, req.ciphertext_len);
        OPENSSL_cleanse(mac_key, sizeof(mac_key));
        OPENSSL_cleanse(computed_mac, sizeof(computed_mac));
    } else if (ctx->mode == SESSION_MODE_CONFIDENTIAL) {
        uint8_t aead_key[32];

        if (derive_labeled_key(ctx->session_key, "meta-conf-aead", aead_key) != 0) {
            OPENSSL_cleanse(aead_key, sizeof(aead_key));
            goto cleanup;
        }
        if (aes256_gcm_decrypt(aead_key, req.counter, opcode,
                               req.ciphertext, req.ciphertext_len,
                               req.auth, plaintext) != 0) {
            OPENSSL_cleanse(aead_key, sizeof(aead_key));
            goto cleanup;
        }
        OPENSSL_cleanse(aead_key, sizeof(aead_key));
    } else {
        goto cleanup;
    }

    ctx->active_session_counter = req.counter;
    if (counter_out) {
        *counter_out = req.counter;
    }
    *plaintext_out = plaintext;
    *plaintext_len_out = req.ciphertext_len;
    plaintext = NULL;
    rc = 0;

cleanup:
    if (request_buf) {
        OPENSSL_cleanse(request_buf, request_len);
        g_free(request_buf);
    }
    if (plaintext) {
        OPENSSL_cleanse(plaintext, request_len >= META_ENVELOPE_HEADER_SIZE ?
                                   request_len - META_ENVELOPE_HEADER_SIZE : 0);
        g_free(plaintext);
    }
    return rc;
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
                               const uint8_t *ssd_ephem_pub,
                               uint8_t session_mode,
                               uint64_t counter,
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
    uint8_t kdf_info[1 + 32 + 32 + 1 + 8];
    uint8_t counter_le[8];
    
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
    
    kdf_info[0] = NVME_CMD_INIT_SESSION_SUBMIT;
    memcpy(kdf_info + 1, admin_ephem_pub, 32);
    memcpy(kdf_info + 33, ssd_ephem_pub, 32);
    kdf_info[65] = session_mode;
    encode_u64_le(counter, counter_le);
    memcpy(kdf_info + 66, counter_le, sizeof(counter_le));

    /* Bind the derived key to the opcode, transcript, and replay counter. */
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", shared_secret, 32);
    params[2] = OSSL_PARAM_construct_octet_string("info", kdf_info, sizeof(kdf_info));
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
    OPENSSL_cleanse(kdf_info, sizeof(kdf_info));
    
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

static uint32_t page_size_bytes(struct ssd *ssd)
{
    return ssd->fb->sp.secs_per_pg * ssd->fb->sp.secsz;
}

static uint32_t pages_per_block(struct ssd *ssd)
{
    return ssd->fb->sp.pgs_per_blk;
}

static int find_policy_slot(struct meta_policy_context *ctx, uint32_t policy_id)
{
    int i;

    for (i = 0; i < 16; i++) {
        if (ctx->installed_policies[i].in_use &&
            ctx->installed_policies[i].policy_id == policy_id) {
            return i;
        }
    }

    return -1;
}

static int find_free_policy_slot(struct meta_policy_context *ctx)
{
    int i;

    for (i = 0; i < 16; i++) {
        if (!ctx->installed_policies[i].in_use) {
            return i;
        }
    }

    return -1;
}

static void fill_policy_storage_desc(const struct meta_policy_context *ctx, int slot,
                                     struct policy_storage_desc *desc)
{
    desc->policy_id = ctx->installed_policies[slot].policy_id;
    desc->policy_version = ctx->installed_policies[slot].policy_version;
    desc->policy_size_bytes = ctx->installed_policies[slot].policy_size_bytes;
    desc->block_count = ctx->installed_policies[slot].block_count;
    desc->blocks = ctx->installed_policies[slot].blocks;
    desc->expected_payload = NULL;
}

static void reset_policy_slot_record(struct meta_policy_context *ctx, int slot)
{
    memset(&ctx->installed_policies[slot], 0,
           sizeof(ctx->installed_policies[slot]));
}

static int select_policy_blocks(struct ssd *ssd,
                                struct meta_policy_context *ctx,
                                uint32_t block_count,
                                struct pba *blocks_out)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    uint64_t total_candidates;
    uint32_t found = 0;
    uint64_t scan;

    total_candidates = (uint64_t)ssd->bbm->reserved_per_lun *
                       geom->nchs * geom->luns_per_ch * geom->pls_per_lun;
    if (total_candidates == 0) {
        return -1;
    }

    for (scan = 0; scan < total_candidates; scan++) {
        uint64_t linear = (ctx->next_policy_alloc_index + scan) % total_candidates;
        uint64_t per_block_slice = (uint64_t)geom->nchs * geom->luns_per_ch * geom->pls_per_lun;
        uint32_t blk_off = linear / per_block_slice;
        uint64_t rem = linear % per_block_slice;
        uint32_t ch = rem / (geom->luns_per_ch * geom->pls_per_lun);
        rem %= (geom->luns_per_ch * geom->pls_per_lun);
        uint32_t lun = rem / geom->pls_per_lun;
        uint32_t pl = rem % geom->pls_per_lun;
        struct pba candidate = {0};

        candidate.g.ch = ch;
        candidate.g.lun = lun;
        candidate.g.pl = pl;
        candidate.g.blk = geom->blks_per_pl_log + blk_off;

        if (bbm_is_excluded_phys_blk(ssd->bbm, &candidate)) {
            continue;
        }

        blocks_out[found++] = candidate;
        if (found == block_count) {
            ctx->next_policy_alloc_index = (linear + 1) % total_candidates;
            return 0;
        }
    }

    return -1;
}

static int exclude_policy_blocks(struct ssd *ssd,
                                 const struct pba *blocks,
                                 uint32_t block_count)
{
    uint32_t i;

    for (i = 0; i < block_count; i++) {
        if (bbm_exclude_phys_blk_from_mapping(ssd->bbm, &blocks[i]) < 0) {
            while (i > 0) {
                i--;
                bbm_include_phys_blk_in_mapping(ssd->bbm, &blocks[i]);
            }
            return -1;
        }
    }

    return 0;
}

static void unexclude_policy_blocks(struct ssd *ssd,
                                    const struct pba *blocks,
                                    uint32_t block_count)
{
    uint32_t i;

    for (i = 0; i < block_count; i++) {
        bbm_include_phys_blk_in_mapping(ssd->bbm, &blocks[i]);
    }
}

static int erase_policy_blocks(struct ssd *ssd,
                               const struct pba *blocks,
                               uint32_t block_count)
{
    struct pba *erase_list;
    int rc;

    if (!blocks || block_count == 0) {
        return 0;
    }

    erase_list = g_malloc0(sizeof(struct pba) * block_count);
    memcpy(erase_list, blocks, sizeof(struct pba) * block_count);
    rc = ftl_backend_raw_erase(ssd->fb, erase_list, block_count, NULL);
    g_free(erase_list);
    return rc;
}

static int reclaim_policy_storage(struct ssd *ssd,
                                  const struct pba *blocks,
                                  uint32_t block_count)
{
    if (erase_policy_blocks(ssd, blocks, block_count) != 0) {
        return -1;
    }

    unexclude_policy_blocks(ssd, blocks, block_count);
    return 0;
}

static void free_policy_slot_resources(struct meta_policy_context *ctx, int slot)
{
    g_free(ctx->installed_policies[slot].blocks);
    reset_policy_slot_record(ctx, slot);
}

static int write_policy_payload(struct ssd *ssd,
                                const uint8_t *payload,
                                uint32_t policy_size_bytes,
                                const struct pba *blocks,
                                uint32_t block_count)
{
    uint32_t page_size = page_size_bytes(ssd);
    uint32_t ppb = pages_per_block(ssd);
    uint32_t page_count = (policy_size_bytes + page_size - 1) / page_size;
    uint8_t *paged_payload = NULL;
    struct ppa *ppa_list = NULL;
    struct pba *erase_list = NULL;
    uint32_t i;
    int rc = -1;

    paged_payload = g_malloc0((size_t)page_count * page_size);
    memcpy(paged_payload, payload, policy_size_bytes);

    erase_list = g_malloc0(sizeof(struct pba) * block_count);
    memcpy(erase_list, blocks, sizeof(struct pba) * block_count);
    if (ftl_backend_raw_erase(ssd->fb, erase_list, block_count, NULL) != 0) {
        goto cleanup;
    }

    ppa_list = g_malloc0(sizeof(struct ppa) * page_count);
    for (i = 0; i < page_count; i++) {
        uint32_t block_index = i / ppb;
        uint32_t page_index = i % ppb;

        ppa_list[i].g.ch = blocks[block_index].g.ch;
        ppa_list[i].g.lun = blocks[block_index].g.lun;
        ppa_list[i].g.pl = blocks[block_index].g.pl;
        ppa_list[i].g.blk = blocks[block_index].g.blk;
        ppa_list[i].g.pg = page_index;
        ppa_list[i].g.sec = 0;
    }

    if (ftl_backend_raw_write(ssd->fb, paged_payload, ppa_list, page_count, page_size,
                              NULL, 0, 0, NULL) != 0) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    g_free(erase_list);
    g_free(ppa_list);
    g_free(paged_payload);
    return rc;
}

static bool install_policy_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                     struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->is_admin && event->opcode == NVME_CMD_INSTALL_POLICY;
}

static uint64_t install_policy_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                        struct FtlPolicyAPI *api, void *context)
{
    struct meta_policy_context *ctx = (struct meta_policy_context *)context;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint32_t policy_id;
    uint32_t policy_version;
    uint32_t policy_size_bytes;
    uint32_t page_size = page_size_bytes(ssd);
    uint32_t ppb = pages_per_block(ssd);
    uint32_t page_count;
    uint32_t block_count;
    uint8_t *payload = NULL;
    struct pba *blocks = NULL;
    int slot;
    if (authenticate_meta_request(ctx, event, api,
                                  NULL,
                                  &plaintext, &plaintext_len) != 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }
    if (plaintext_len < 12) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    policy_id = decode_u32_le(plaintext);
    policy_version = decode_u32_le(plaintext + 4);
    policy_size_bytes = decode_u32_le(plaintext + 8);

    if (policy_id == 0 || policy_version == 0 || policy_size_bytes == 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }
    if (plaintext_len != (size_t)12 + policy_size_bytes) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    if (find_policy_slot(ctx, policy_id) >= 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    slot = find_free_policy_slot(ctx);
    if (slot < 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    page_count = (policy_size_bytes + page_size - 1) / page_size;
    block_count = (page_count + ppb - 1) / ppb;

    payload = g_malloc0(policy_size_bytes);
    memcpy(payload, plaintext + 12, policy_size_bytes);

    blocks = g_malloc0(sizeof(struct pba) * block_count);
    if (select_policy_blocks(ssd, ctx, block_count, blocks) < 0) {
        g_free(blocks);
        g_free(payload);
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    if (exclude_policy_blocks(ssd, blocks, block_count) < 0) {
        g_free(blocks);
        g_free(payload);
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    if (write_policy_payload(ssd, payload, policy_size_bytes, blocks, block_count) < 0) {
        unexclude_policy_blocks(ssd, blocks, block_count);
        g_free(blocks);
        g_free(payload);
        event->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
        goto cleanup;
    }

    ctx->installed_policies[slot].policy_id = policy_id;
    ctx->installed_policies[slot].policy_version = policy_version;
    ctx->installed_policies[slot].policy_size_bytes = policy_size_bytes;
    ctx->installed_policies[slot].policy_size_pages = page_count;
    ctx->installed_policies[slot].block_count = block_count;
    ctx->installed_policies[slot].blocks = blocks;
    ctx->installed_policies[slot].active = false;
    ctx->installed_policies[slot].in_use = true;

    printf("[Meta] Installed policy id=%u version=%u size=%u bytes blocks=%u\n",
           policy_id, policy_version, policy_size_bytes, block_count);

    g_free(payload);
    event->status = NVME_SUCCESS;
cleanup:
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        g_free(plaintext);
    }
    return 0;
}

static int authenticate_inactive_policy_request(struct meta_policy_context *ctx,
                                                struct NvmeCommandEvent *event,
                                                struct FtlPolicyAPI *api,
                                                uint8_t expected_opcode,
                                                uint8_t **plaintext_out,
                                                size_t *plaintext_len_out,
                                                uint32_t *policy_id_out,
                                                int *slot_out)
{
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint32_t policy_id;
    int slot;

    if (!ctx || !event || !plaintext_out || !plaintext_len_out ||
        !policy_id_out || !slot_out) {
        return -1;
    }
    if (event->opcode != expected_opcode) {
        return -1;
    }
    if (authenticate_meta_request(ctx, event, api,
                                  NULL,
                                  &plaintext, &plaintext_len) != 0) {
        return -1;
    }
    if (plaintext_len < 4) {
        goto fail;
    }

    policy_id = decode_u32_le(plaintext);
    if (policy_id == 0) {
        goto fail;
    }

    slot = find_policy_slot(ctx, policy_id);
    if (slot < 0 || ctx->installed_policies[slot].active) {
        goto fail;
    }

    *plaintext_out = plaintext;
    *plaintext_len_out = plaintext_len;
    *policy_id_out = policy_id;
    *slot_out = slot;
    return 0;

fail:
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        g_free(plaintext);
    }
    return -1;
}

static bool update_policy_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                    struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->is_admin && event->opcode == NVME_CMD_UPDATE_POLICY;
}

static uint64_t update_policy_callback(struct ssd *ssd,
                                       struct NvmeCommandEvent *event,
                                       struct FtlPolicyAPI *api,
                                       void *context)
{
    struct meta_policy_context *ctx = (struct meta_policy_context *)context;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint32_t policy_id;
    int slot;

    (void)api;

    if (authenticate_inactive_policy_request(ctx, event, api, NVME_CMD_UPDATE_POLICY,
                                             &plaintext, &plaintext_len,
                                             &policy_id, &slot) != 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }

    {
        uint32_t policy_version;
        uint32_t policy_size_bytes;
        uint32_t page_size = page_size_bytes(ssd);
        uint32_t ppb = pages_per_block(ssd);
        uint32_t page_count;
        uint32_t block_count;
        uint8_t *payload = NULL;
        struct pba *new_blocks = NULL;
        struct pba *old_blocks;
        uint32_t old_block_count;

        if (plaintext_len < 12) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            goto cleanup;
        }

        policy_version = decode_u32_le(plaintext + 4);
        policy_size_bytes = decode_u32_le(plaintext + 8);

        if (policy_version == 0 || policy_size_bytes == 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            goto cleanup;
        }
        if (plaintext_len != (size_t)12 + policy_size_bytes) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            goto cleanup;
        }

        page_count = (policy_size_bytes + page_size - 1) / page_size;
        block_count = (page_count + ppb - 1) / ppb;

        payload = g_malloc0(policy_size_bytes);
        memcpy(payload, plaintext + 12, policy_size_bytes);

        new_blocks = g_malloc0(sizeof(struct pba) * block_count);
        if (select_policy_blocks(ssd, ctx, block_count, new_blocks) < 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            goto update_cleanup;
        }
        if (exclude_policy_blocks(ssd, new_blocks, block_count) < 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            goto update_cleanup;
        }
        if (write_policy_payload(ssd, payload, policy_size_bytes,
                                 new_blocks, block_count) < 0) {
            unexclude_policy_blocks(ssd, new_blocks, block_count);
            event->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
            goto update_cleanup;
        }

        old_blocks = ctx->installed_policies[slot].blocks;
        old_block_count = ctx->installed_policies[slot].block_count;

        if (reclaim_policy_storage(ssd, old_blocks, old_block_count) != 0) {
            reclaim_policy_storage(ssd, new_blocks, block_count);
            event->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
            goto update_cleanup;
        }

        ctx->installed_policies[slot].policy_version = policy_version;
        ctx->installed_policies[slot].policy_size_bytes = policy_size_bytes;
        ctx->installed_policies[slot].policy_size_pages = page_count;
        ctx->installed_policies[slot].block_count = block_count;
        ctx->installed_policies[slot].blocks = new_blocks;

        g_free(old_blocks);
        g_free(payload);

        printf("[Meta] Updated policy id=%u version=%u size=%u bytes blocks=%u\n",
               policy_id, policy_version, policy_size_bytes, block_count);

        event->status = NVME_SUCCESS;
        goto cleanup;

update_cleanup:
        g_free(new_blocks);
        g_free(payload);
        goto cleanup;
    }

cleanup:
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        g_free(plaintext);
    }
    return 0;
}

static bool remove_policy_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                    struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->is_admin && event->opcode == NVME_CMD_REMOVE_POLICY;
}

static uint64_t remove_policy_callback(struct ssd *ssd,
                                       struct NvmeCommandEvent *event,
                                       struct FtlPolicyAPI *api,
                                       void *context)
{
    struct meta_policy_context *ctx = (struct meta_policy_context *)context;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint32_t policy_id;
    int slot;

    (void)api;

    if (authenticate_inactive_policy_request(ctx, event, api, NVME_CMD_REMOVE_POLICY,
                                             &plaintext, &plaintext_len,
                                             &policy_id, &slot) != 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }
    if (plaintext_len != 4) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }
    if (reclaim_policy_storage(ssd,
                               ctx->installed_policies[slot].blocks,
                               ctx->installed_policies[slot].block_count) != 0) {
        event->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
        goto cleanup;
    }

    free_policy_slot_resources(ctx, slot);
    printf("[Meta] Removed policy id=%u\n", policy_id);
    event->status = NVME_SUCCESS;

cleanup:
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        g_free(plaintext);
    }
    return 0;
}

static bool activate_policy_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                      struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->is_admin &&
           (event->opcode == NVME_CMD_ACTIVATE_POLICY ||
            event->opcode == NVME_CMD_DEACTIVATE_POLICY);
}

static uint64_t activate_policy_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                         struct FtlPolicyAPI *api, void *context)
{
    struct meta_policy_context *ctx = (struct meta_policy_context *)context;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint32_t policy_id;
    int slot;

    (void)api;

    if (authenticate_meta_request(ctx, event, api,
                                  NULL,
                                  &plaintext, &plaintext_len) != 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }
    if (plaintext_len != 4) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    policy_id = decode_u32_le(plaintext);
    if (policy_id == 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    slot = find_policy_slot(ctx, policy_id);
    if (slot < 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    if (event->opcode == NVME_CMD_ACTIVATE_POLICY) {
        struct policy_storage_desc desc;

        if (ctx->installed_policies[slot].active) {
            event->status = NVME_SUCCESS;
            goto cleanup;
        }

        fill_policy_storage_desc(ctx, slot, &desc);
        if (pe_activate_stored_policy(ssd->policy_engine, ssd, &desc) != 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            goto cleanup;
        }
        ctx->installed_policies[slot].active = true;
        printf("[Meta] Activated policy id=%u\n", policy_id);
    } else {
        if (!ctx->installed_policies[slot].active) {
            event->status = NVME_SUCCESS;
            goto cleanup;
        }

        if (pe_deactivate_policy(ssd->policy_engine, policy_id) != 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            goto cleanup;
        }
        ctx->installed_policies[slot].active = false;
        printf("[Meta] Deactivated policy id=%u\n", policy_id);
    }

    event->status = NVME_SUCCESS;
cleanup:
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        g_free(plaintext);
    }
    return 0;
}

static int build_attestation_response_envelope(struct meta_policy_context *ctx,
                                               uint8_t opcode,
                                               uint64_t counter,
                                               const uint8_t *plaintext,
                                               size_t plaintext_len,
                                               uint8_t **response_out,
                                               uint32_t *response_len_out)
{
    uint8_t *response = NULL;
    uint8_t *ciphertext;
    size_t response_len;
    int rc = -1;

    if (!ctx || !plaintext || !response_out || !response_len_out ||
        plaintext_len > UINT32_MAX) {
        return -1;
    }

    response_len = META_ENVELOPE_HEADER_SIZE + plaintext_len;
    if (response_len > UINT32_MAX) {
        return -1;
    }
    response = g_malloc0(response_len);
    encode_u64_le(counter, response);
    ciphertext = response + META_ENVELOPE_HEADER_SIZE;

    if (ctx->mode == SESSION_MODE_NORMAL) {
        uint8_t mac_key[32];

        if (derive_labeled_key(ctx->session_key, "meta-normal-response-mac", mac_key) != 0) {
            OPENSSL_cleanse(mac_key, sizeof(mac_key));
            goto cleanup;
        }
        memcpy(ciphertext, plaintext, plaintext_len);
        if (compute_meta_hmac(mac_key, opcode, counter, ciphertext, plaintext_len,
                              response + 8) != 0) {
            OPENSSL_cleanse(mac_key, sizeof(mac_key));
            goto cleanup;
        }
        OPENSSL_cleanse(mac_key, sizeof(mac_key));
    } else if (ctx->mode == SESSION_MODE_CONFIDENTIAL) {
        uint8_t aead_key[32];

        if (derive_labeled_key(ctx->session_key, "meta-conf-response-aead", aead_key) != 0) {
            OPENSSL_cleanse(aead_key, sizeof(aead_key));
            goto cleanup;
        }
        if (aes256_gcm_encrypt(aead_key, counter, opcode, plaintext, plaintext_len,
                               ciphertext, response + 8) != 0) {
            OPENSSL_cleanse(aead_key, sizeof(aead_key));
            goto cleanup;
        }
        OPENSSL_cleanse(aead_key, sizeof(aead_key));
    } else {
        goto cleanup;
    }

    *response_out = response;
    *response_len_out = (uint32_t)response_len;
    response = NULL;
    rc = 0;

cleanup:
    if (response) {
        OPENSSL_cleanse(response, response_len);
        g_free(response);
    }
    return rc;
}

static bool policy_attestation_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                         struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->is_admin &&
           (event->opcode == NVME_CMD_POLICY_ATTESTATION_SUBMIT ||
            event->opcode == NVME_CMD_POLICY_ATTESTATION_FETCH);
}

static uint64_t policy_attestation_callback(struct ssd *ssd,
                                            struct NvmeCommandEvent *event,
                                            struct FtlPolicyAPI *api,
                                            void *context)
{
    struct meta_policy_context *ctx = (struct meta_policy_context *)context;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint64_t request_counter = 0;
    uint32_t policy_id;
    uint32_t report_type;
    int slot;
    struct policy_attestation_report report = {0};
    uint8_t response_plaintext[POLICY_ATTESTATION_RESPONSE_PLAINTEXT_SIZE];
    uint8_t *response = NULL;
    uint8_t *policy_payload = NULL;
    struct policy_storage_desc desc;
    uint32_t response_len = 0;

    if (event->opcode == NVME_CMD_POLICY_ATTESTATION_FETCH) {
        if (!ctx->pending_attestation_response_valid) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            return 0;
        }

        event->status = api->write_cmd_buffer(
            event,
            ctx->pending_attestation_response,
            sizeof(ctx->pending_attestation_response));
        if (event->status != NVME_SUCCESS) {
            return 0;
        }

        ctx->pending_attestation_response_valid = false;
        event->status = NVME_SUCCESS;
        return 0;
    }

    if (authenticate_meta_request(ctx, event, api, &request_counter,
                                  &plaintext, &plaintext_len) != 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }
    if (plaintext_len != POLICY_ATTESTATION_REQUEST_PLAINTEXT_SIZE) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }
    policy_id = decode_u32_le(plaintext);
    report_type = decode_u32_le(plaintext + 4);
    if (policy_id == 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }
    if (report_type != POLICY_ATTESTATION_REPORT_SECURITY &&
        report_type != POLICY_ATTESTATION_REPORT_CONSISTENCY) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    slot = find_policy_slot(ctx, policy_id);

    report.policy_id = policy_id;
    report.report_type = report_type;
    report.installed = (slot >= 0) ? 1 : 0;
    report.active = pe_is_policy_active(ssd->policy_engine, policy_id) ? 1 : 0;

    if (report_type == POLICY_ATTESTATION_REPORT_CONSISTENCY && slot >= 0) {
        fill_policy_storage_desc(ctx, slot, &desc);
        if (pe_read_policy_payload(ssd, &desc, &policy_payload) != 0) {
            event->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
            goto cleanup;
        }
        if (compute_policy_sha256(policy_payload,
                                  desc.policy_size_bytes,
                                  report.hash) != 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            goto cleanup;
        }
    }

    memset(response_plaintext, 0, sizeof(response_plaintext));
    encode_u32_le(report.policy_id, response_plaintext);
    encode_u32_le(report.report_type, response_plaintext + 4);
    response_plaintext[8] = report.installed;
    response_plaintext[9] = report.active;
    memcpy(response_plaintext + 12, report.hash, sizeof(report.hash));

    if (build_attestation_response_envelope(ctx, NVME_CMD_POLICY_ATTESTATION_SUBMIT,
                                            request_counter,
                                            response_plaintext,
                                            sizeof(response_plaintext),
                                            &response, &response_len) != 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        goto cleanup;
    }

    memcpy(ctx->pending_attestation_response, response, response_len);
    ctx->pending_attestation_response_valid = true;
    event->status = NVME_SUCCESS;

cleanup:
    OPENSSL_cleanse(response_plaintext, sizeof(response_plaintext));
    if (policy_payload) {
        OPENSSL_cleanse(policy_payload, desc.policy_size_bytes);
        g_free(policy_payload);
    }
    if (response) {
        OPENSSL_cleanse(response, response_len);
        g_free(response);
    }
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        g_free(plaintext);
    }
    return 0;
}

static bool init_session_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                   struct FtlPolicyAPI *api, void *context)
{
    (void)ssd; (void)api; (void)context;
    return event->is_admin &&
           (event->opcode == NVME_CMD_INIT_SESSION_SUBMIT ||
            event->opcode == NVME_CMD_INIT_SESSION_FETCH);
}

static uint64_t init_session_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                      struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    struct meta_policy_context *ctx = (struct meta_policy_context *)context;
    uint8_t request[INIT_SESSION_REQUEST_SIZE];
    uint8_t response[INIT_SESSION_RESPONSE_SIZE];
    uint8_t admin_init_message[1 + 32 + 1 + 8];
    uint8_t proof_message[1 + 32 + 32 + 1 + 8];
    uint8_t ssd_ephem_pub[32], ssd_ephem_priv[32];
    const uint8_t *admin_ephem_pub;
    uint8_t session_mode;
    uint64_t counter;
    
    if (event->opcode == NVME_CMD_INIT_SESSION_SUBMIT) {
        /* Read request: admin_ephem_pub (32) + mode (1) + counter (8) + admin_sig (64). */
        event->status = api->read_cmd_buffer(event, request, INIT_SESSION_REQUEST_SIZE);
        if (event->status != NVME_SUCCESS) {
            return 0;
        }

        admin_ephem_pub = request;
        session_mode = request[32];
        counter = decode_u64_le(request + 33);

        if (session_mode != SESSION_MODE_NORMAL &&
            session_mode != SESSION_MODE_CONFIDENTIAL) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            return 0;
        }

        if (counter <= ctx->session_counter) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            return 0;
        }

        /* Verify the admin signed the transcript fragment that carries the replay counter. */
        build_admin_init_message(admin_ephem_pub, session_mode, counter, admin_init_message);
        if (!verify_admin_signature(admin_init_message, sizeof(admin_init_message), request + 41)) {
            event->status = NVME_INVALID_OPCODE | NVME_DNR;
            return 0;
        }

        /* Generate SSD ephemeral key (TODO: real X25519) */
        generate_ephemeral_keypair(ssd_ephem_pub, ssd_ephem_priv);

        /* Sign the full transcript fragment, including the replay counter. */
        build_ssd_response_message(admin_ephem_pub, ssd_ephem_pub, session_mode,
                                   counter, proof_message);
        sign_with_ssd_private_key(proof_message, sizeof(proof_message), response + 40);

        /* Response: ssd_ephem_pub (32) + counter (8) + proof_sig (64). */
        memcpy(response, ssd_ephem_pub, 32);
        encode_u64_le(counter, response + 32);

        memcpy(ctx->pending_response, response, sizeof(ctx->pending_response));
        ctx->pending_response_valid = true;

        derive_session_key(admin_ephem_pub, ssd_ephem_priv, ssd_ephem_pub,
                           session_mode, counter,
                           ctx->session_key);
        ctx->session_counter = counter;
        ctx->mode = session_mode;
        ctx->active_session_counter = 0;
        ctx->pending_attestation_response_valid = false;
        ctx->session_established = true;
    } else if (event->opcode == NVME_CMD_INIT_SESSION_FETCH) {
        if (!ctx->pending_response_valid) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            return 0;
        }

        event->status = api->write_cmd_buffer(event, ctx->pending_response,
                                              INIT_SESSION_RESPONSE_SIZE);
        if (event->status != NVME_SUCCESS) {
            return 0;
        }
        ctx->pending_response_valid = false;
    } else {
        event->status = NVME_INVALID_OPCODE | NVME_DNR;
        return 0;
    }

    event->status = NVME_SUCCESS;
    return 0;
}

/* ========================================================================== */
/* Meta Interface Policy Initialization */
/* ========================================================================== */

int m_interface_policy_init(struct ssd *ssd)
{
    struct meta_policy_context *ctx = g_malloc0(sizeof(struct meta_policy_context));
    struct FtlPolicyAPI *api = ssd ? ssd->policy_api : NULL;
    ctx->session_established = false;
    ctx->pending_response_valid = false;
    ctx->pending_attestation_response_valid = false;
    ctx->session_counter = 0;

    g_meta_ctx = ctx;

    if (!api) {
        return -1;
    }

    if (api->register_admin_hook(ssd, NVME_CMD_INIT_SESSION_SUBMIT,
                               init_session_condition,
                               init_session_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register INIT_SESSION submit hook\n");
        return -1;
    }

    if (api->register_admin_hook(ssd, NVME_CMD_INIT_SESSION_FETCH,
                               init_session_condition,
                               init_session_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register INIT_SESSION fetch hook\n");
        return -1;
    }

    if (api->register_admin_hook(ssd, NVME_CMD_INSTALL_POLICY,
                               install_policy_condition,
                               install_policy_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register INSTALL_POLICY hook\n");
        return -1;
    }

    if (api->register_admin_hook(ssd, NVME_CMD_ACTIVATE_POLICY,
                               activate_policy_condition,
                               activate_policy_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register ACTIVATE_POLICY hook\n");
        return -1;
    }

    if (api->register_admin_hook(ssd, NVME_CMD_DEACTIVATE_POLICY,
                               activate_policy_condition,
                               activate_policy_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register DEACTIVATE_POLICY hook\n");
        return -1;
    }

    if (api->register_admin_hook(ssd, NVME_CMD_UPDATE_POLICY,
                               update_policy_condition,
                               update_policy_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register UPDATE_POLICY hook\n");
        return -1;
    }

    if (api->register_admin_hook(ssd, NVME_CMD_REMOVE_POLICY,
                               remove_policy_condition,
                               remove_policy_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register REMOVE_POLICY hook\n");
        return -1;
    }

    if (api->register_admin_hook(ssd, NVME_CMD_POLICY_ATTESTATION_SUBMIT,
                               policy_attestation_condition,
                               policy_attestation_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register POLICY_ATTESTATION_SUBMIT hook\n");
        return -1;
    }

    if (api->register_admin_hook(ssd, NVME_CMD_POLICY_ATTESTATION_FETCH,
                               policy_attestation_condition,
                               policy_attestation_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register POLICY_ATTESTATION_FETCH hook\n");
        return -1;
    }

    return 0;
}
