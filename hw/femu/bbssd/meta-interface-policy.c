#include "ftl.h"
#include "bbm.h"
#include "policy-engine.h"
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
    uint8_t pending_response[INIT_SESSION_RESPONSE_SIZE];
    bool session_established;
    bool pending_response_valid;
    int mode;            // TODO: Not used yet.
    uint64_t session_counter;
    uint64_t next_policy_alloc_index;
    struct {
        uint32_t policy_id;
        uint32_t policy_version;
        uint32_t policy_size_bytes;
        uint32_t policy_size_pages;
        uint32_t block_count;
        struct pba *blocks;
        uint8_t *payload_copy;
        bool active;
        bool in_use;
    } installed_policies[16];
};

static struct meta_policy_context *g_meta_ctx = NULL;

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

static void build_admin_init_message(const uint8_t *admin_ephem_pub, uint64_t counter,
                                     uint8_t *message_out)
{
    uint8_t counter_le[8];

    message_out[0] = NVME_CMD_INIT_SESSION_SUBMIT;
    memcpy(message_out + 1, admin_ephem_pub, 32);
    encode_u64_le(counter, counter_le);
    memcpy(message_out + 33, counter_le, sizeof(counter_le));
}

static void build_ssd_response_message(const uint8_t *admin_ephem_pub,
                                       const uint8_t *ssd_ephem_pub,
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
    uint8_t kdf_info[1 + 32 + 32 + 8];
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
    encode_u64_le(counter, counter_le);
    memcpy(kdf_info + 65, counter_le, sizeof(counter_le));

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
    desc->expected_payload = ctx->installed_policies[slot].payload_copy;
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

    if (ftl_backend_raw_write(ssd->fb, paged_payload, ppa_list, page_count, page_size, NULL) != 0) {
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
    return !event->is_admin && event->opcode == NVME_CMD_INSTALL_POLICY;
}

static uint64_t install_policy_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                        struct FtlPolicyAPI *api, void *context)
{
    struct meta_policy_context *ctx = (struct meta_policy_context *)context;
    FemuCtrl *n = event->ctrl;
    NvmeCmd *cmd = event->cmd;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint32_t policy_id = le32_to_cpu(cmd->cdw10);
    uint32_t policy_version = le32_to_cpu(cmd->cdw11);
    uint32_t policy_size_bytes = le32_to_cpu(cmd->cdw12);
    uint32_t page_size = page_size_bytes(ssd);
    uint32_t ppb = pages_per_block(ssd);
    uint32_t page_count;
    uint32_t block_count;
    uint8_t *payload = NULL;
    struct pba *blocks = NULL;
    int slot;

    (void)api;

    if (policy_id == 0 || policy_version == 0 || policy_size_bytes == 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }

    if (find_policy_slot(ctx, policy_id) >= 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }

    slot = find_free_policy_slot(ctx);
    if (slot < 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }

    page_count = (policy_size_bytes + page_size - 1) / page_size;
    block_count = (page_count + ppb - 1) / ppb;

    payload = g_malloc0(policy_size_bytes);
    if (dma_write_prp(n, payload, policy_size_bytes, prp1, prp2) != NVME_SUCCESS) {
        g_free(payload);
        event->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
        return 0;
    }

    blocks = g_malloc0(sizeof(struct pba) * block_count);
    if (select_policy_blocks(ssd, ctx, block_count, blocks) < 0) {
        g_free(blocks);
        g_free(payload);
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }

    if (exclude_policy_blocks(ssd, blocks, block_count) < 0) {
        g_free(blocks);
        g_free(payload);
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }

    if (write_policy_payload(ssd, payload, policy_size_bytes, blocks, block_count) < 0) {
        unexclude_policy_blocks(ssd, blocks, block_count);
        g_free(blocks);
        g_free(payload);
        event->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
        return 0;
    }

    ctx->installed_policies[slot].policy_id = policy_id;
    ctx->installed_policies[slot].policy_version = policy_version;
    ctx->installed_policies[slot].policy_size_bytes = policy_size_bytes;
    ctx->installed_policies[slot].policy_size_pages = page_count;
    ctx->installed_policies[slot].block_count = block_count;
    ctx->installed_policies[slot].blocks = blocks;
    ctx->installed_policies[slot].payload_copy = g_memdup2(payload, policy_size_bytes);
    ctx->installed_policies[slot].active = false;
    ctx->installed_policies[slot].in_use = true;

    printf("[Meta] Installed policy id=%u version=%u size=%u bytes blocks=%u\n",
           policy_id, policy_version, policy_size_bytes, block_count);

    g_free(payload);
    event->status = NVME_SUCCESS;
    return 0;
}

static bool activate_policy_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                      struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return !event->is_admin &&
           (event->opcode == NVME_CMD_ACTIVATE_POLICY ||
            event->opcode == NVME_CMD_DEACTIVATE_POLICY);
}

static uint64_t activate_policy_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                         struct FtlPolicyAPI *api, void *context)
{
    struct meta_policy_context *ctx = (struct meta_policy_context *)context;
    NvmeCmd *cmd = event->cmd;
    uint32_t policy_id = le32_to_cpu(cmd->cdw10);
    int slot;

    (void)api;

    if (policy_id == 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }

    slot = find_policy_slot(ctx, policy_id);
    if (slot < 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }

    if (event->opcode == NVME_CMD_ACTIVATE_POLICY) {
        struct policy_storage_desc desc;

        if (ctx->installed_policies[slot].active) {
            event->status = NVME_SUCCESS;
            return 0;
        }

        fill_policy_storage_desc(ctx, slot, &desc);
        if (pe_activate_stored_policy(ssd->policy_engine, ssd, &desc) != 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            return 0;
        }
        ctx->installed_policies[slot].active = true;
        printf("[Meta] Activated policy id=%u\n", policy_id);
    } else {
        if (!ctx->installed_policies[slot].active) {
            event->status = NVME_SUCCESS;
            return 0;
        }

        if (pe_deactivate_policy(ssd->policy_engine, policy_id) != 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            return 0;
        }
        ctx->installed_policies[slot].active = false;
        printf("[Meta] Deactivated policy id=%u\n", policy_id);
    }

    event->status = NVME_SUCCESS;
    return 0;
}

static bool init_session_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                   struct FtlPolicyAPI *api, void *context)
{
    (void)ssd; (void)api; (void)context;
    return !event->is_admin &&
           (event->opcode == NVME_CMD_INIT_SESSION_SUBMIT ||
            event->opcode == NVME_CMD_INIT_SESSION_FETCH);
}

static uint64_t init_session_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                      struct FtlPolicyAPI *api, void *context)
{
    (void)ssd; (void)api;
    struct meta_policy_context *ctx = (struct meta_policy_context *)context;
    FemuCtrl *n = event->ctrl;
    NvmeCmd *cmd = event->cmd;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint8_t request[INIT_SESSION_REQUEST_SIZE];
    uint8_t response[INIT_SESSION_RESPONSE_SIZE];
    uint8_t admin_init_message[1 + 32 + 8];
    uint8_t proof_message[1 + 32 + 32 + 8];
    uint8_t ssd_ephem_pub[32], ssd_ephem_priv[32];
    const uint8_t *admin_ephem_pub;
    uint64_t counter;
    
    if (event->opcode == NVME_CMD_INIT_SESSION_SUBMIT) {
        /* Read request: admin_ephem_pub (32) + counter (8) + admin_sig (64). */
        if (dma_write_prp(n, request, INIT_SESSION_REQUEST_SIZE, prp1, prp2) != NVME_SUCCESS) {
            event->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
            return 0;
        }

        admin_ephem_pub = request;
        counter = decode_u64_le(request + 32);

        if (counter <= ctx->session_counter) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            return 0;
        }

        /* Verify the admin signed the transcript fragment that carries the replay counter. */
        build_admin_init_message(admin_ephem_pub, counter, admin_init_message);
        if (!verify_admin_signature(admin_init_message, sizeof(admin_init_message), request + 40)) {
            event->status = NVME_INVALID_OPCODE | NVME_DNR;
            return 0;
        }

        /* Generate SSD ephemeral key (TODO: real X25519) */
        generate_ephemeral_keypair(ssd_ephem_pub, ssd_ephem_priv);

        /* Sign the full transcript fragment, including the replay counter. */
        build_ssd_response_message(admin_ephem_pub, ssd_ephem_pub, counter, proof_message);
        sign_with_ssd_private_key(proof_message, sizeof(proof_message), response + 40);

        /* Response: ssd_ephem_pub (32) + counter (8) + proof_sig (64). */
        memcpy(response, ssd_ephem_pub, 32);
        encode_u64_le(counter, response + 32);

        memcpy(ctx->pending_response, response, sizeof(ctx->pending_response));
        ctx->pending_response_valid = true;

        derive_session_key(admin_ephem_pub, ssd_ephem_priv, ssd_ephem_pub, counter,
                           ctx->session_key);
        ctx->session_counter = counter;
        ctx->session_established = true;
    } else if (event->opcode == NVME_CMD_INIT_SESSION_FETCH) {
        if (!ctx->pending_response_valid) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            return 0;
        }

        if (dma_read_prp(n, ctx->pending_response, INIT_SESSION_RESPONSE_SIZE, prp1, prp2)
            != NVME_SUCCESS) {
            event->status = NVME_DATA_TRAS_ERROR | NVME_DNR;
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
    ctx->session_established = false;
    ctx->pending_response_valid = false;
    ctx->session_counter = 0;
    
    g_meta_ctx = ctx;

    if (ftl_register_nvme_hook(ssd, NVME_CMD_INIT_SESSION_SUBMIT,
                               init_session_condition,
                               init_session_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register INIT_SESSION submit hook\n");
        return -1;
    }

    if (ftl_register_nvme_hook(ssd, NVME_CMD_INIT_SESSION_FETCH,
                               init_session_condition,
                               init_session_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register INIT_SESSION fetch hook\n");
        return -1;
    }

    if (ftl_register_nvme_hook(ssd, NVME_CMD_INSTALL_POLICY,
                               install_policy_condition,
                               install_policy_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register INSTALL_POLICY hook\n");
        return -1;
    }

    if (ftl_register_nvme_hook(ssd, NVME_CMD_ACTIVATE_POLICY,
                               activate_policy_condition,
                               activate_policy_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register ACTIVATE_POLICY hook\n");
        return -1;
    }

    if (ftl_register_nvme_hook(ssd, NVME_CMD_DEACTIVATE_POLICY,
                               activate_policy_condition,
                               activate_policy_callback, ctx) < 0) {
        fprintf(stderr, "[Meta] Failed to register DEACTIVATE_POLICY hook\n");
        return -1;
    }

    printf("[Meta] INIT_SESSION, INSTALL_POLICY, ACTIVATE_POLICY, and DEACTIVATE_POLICY hooks registered\n");
    return 0;
}
