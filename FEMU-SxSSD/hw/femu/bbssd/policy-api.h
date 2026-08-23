/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Derived in part from the FEMU BBSSD ftl.h implementation.
 * SxSSD modifications by Josh Dafoe: 2025-12-16 through 2026-08-23.
 */

#ifndef FEMU_SXSSD_POLICY_API_H
#define FEMU_SXSSD_POLICY_API_H

#include "../nvme.h"
#include "./bbm.h"
#include "policy/include/policy-privileged-wasm-abi.h"
#include "policy/include/policy-wasm-abi.h"

struct policy_engine;

struct RawFlash;
struct FemuCtrl;

/*
 * Native flash-subsystem data model.
 *
 * These types describe FEMU's in-process SSD state. They are not WebAssembly
 * ABI types and are never copied directly into policy memory.
 */
#define INVALID_PPA     (~(0ULL))
#define INVALID_LPN     (~(0ULL))
#define UNMAPPED_PPA    (~(0ULL))

enum eswd_striping_level {
    ESWD_STRIPE_CHANNEL,
    ESWD_STRIPE_LUN,
    ESWD_STRIPE_PLANE,
    ESWD_STRIPE_BLOCK,
};

struct eswd_config {
    enum eswd_striping_level striping_level;
    uint32_t blocks_per_eswd;
};

struct eswd_layout {
    uint32_t tt_eswds;
    uint32_t blks_per_eswd;
    uint32_t pgs_per_eswd;
    enum eswd_striping_level striping_level;
    /* Ordered pseudo-block members, indexed [eswd_id * blks_per_eswd + slot]. */
    PseudoPba *members;
    /* Reverse owner map indexed by pseudo-block; -1 denotes an unassigned block. */
    int32_t *pseudo_block_owner;
    uint32_t tt_pl;
    uint32_t blks_per_pl;
};

struct NamespacePersonalityConfig {
    uint8_t csi;
    uint64_t nsze;
    uint64_t ncap;
    uint64_t nuse;
    uint32_t noiob;
    const void *ns_csi_data;
    size_t ns_csi_data_len;
    const void *ctrl_csi_data;
    size_t ctrl_csi_data_len;
};

/* Internal event record copied into the pointer-free WebAssembly context. */
struct NvmeCommandEvent {
    uint8_t opcode;         /* NVMe command opcode (e.g. NVME_CMD_READ, NVME_CMD_WRITE) */
    bool is_admin;          /* true for admin-queue commands, false for I/O queue commands */
    uint64_t lba;
    uint64_t nsecs;
    uint64_t start_lpn;
    uint64_t end_lpn;
    uint64_t lpn_cnt;
    NvmeRequest *req;
    NvmeCmd *cmd;           /* Raw command pointer for generic/custom handlers */
    NvmeCqe *cqe;           /* Completion entry for admin commands. */
    FemuCtrl *ctrl;         /* Controller context for DMA-backed handlers */
    uint64_t stime;
    uint64_t lat;
    uint16_t status;        /* NVMe completion status for generic/custom handlers */
};

struct ssd;

/* Runtime controls accepted by bb_flip(). */
enum {
    FEMU_ENABLE_GC_DELAY = 1,
    FEMU_DISABLE_GC_DELAY = 2,

    FEMU_ENABLE_DELAY_EMU = 3,
    FEMU_DISABLE_DELAY_EMU = 4,

    FEMU_RESET_ACCT = 5,
    FEMU_ENABLE_LOG = 6,
    FEMU_DISABLE_LOG = 7,
};


struct nand_lun {
    uint64_t next_lun_avail_time;
    bool busy;
    uint64_t gc_endtime;
};

struct ssd_channel {
    struct nand_lun *lun;
    int nluns;
    uint64_t next_ch_avail_time;
    bool busy;
    uint64_t gc_endtime;
};

/* eSWDs are mechanisms. Policies own queue and victim-selection decisions. */
struct eswd {
    uint32_t id;
    bool active;
    int vpc;           /* valid page count in this eSWD */
    int ipc;           /* invalid page count in this eSWD */
    uint32_t wp_page_index;  /* next page to write in this eSWD (0..pgs_per_eswd-1) */
    uint64_t wp_lba;         /* host-visible sequential write pointer for this eSWD */
    /* Per-eSWD staging buffer: accumulates sub-page LBAs until a full page is ready */
};

struct ssd {
    char *ssdname;
    struct FemuCtrl *ctrl;
    struct RawFlash *raw_flash;
    struct bbm *bbm;
    struct ssd_channel *ch;

    /* eSWD state (mechanism owns eSWD structs and layout) */
    struct eswd *eswds;
    uint32_t tt_eswds;
    struct eswd_config eswd_config;
    struct eswd_layout eswd_layout;
    bool eswd_config_set;
    bool eswd_layout_finalized;

    /* lockless ring for communication with NVMe IO thread */
    struct rte_ring **to_ftl;
    struct rte_ring **to_poller;
    bool *dataplane_started_ptr;
    QemuThread worker_thread;

    /* Common runtime and dispatcher for installed and built-in policies. */
    struct policy_engine *policy_engine;

};

/*
 * Native integration hooks.
 *
 * The policy engine uses the flash_subsystem_* functions while validating and
 * committing initialization. bb.c uses policy_event_from_nvme_request() to
 * construct the native event that the policy engine later snapshots for WASM.
 * None of these functions is a WebAssembly import.
 */
bool flash_subsystem_eswd_config_valid(const struct eswd_config *config,
                                       uint32_t nchs,
                                       uint32_t luns_per_ch,
                                       uint32_t pls_per_lun,
                                       uint32_t blks_per_lun_log);
int flash_subsystem_eswd_layout_compute(struct eswd_layout *layout,
                                        const struct eswd_config *config,
                                        const struct bbm_geom *geometry);
void flash_subsystem_eswd_layout_cleanup(struct eswd_layout *layout);
void flash_subsystem_set_eswd_config(struct ssd *ssd,
                                     const struct eswd_config *config);
int flash_subsystem_finalize(struct ssd *ssd);
int flash_subsystem_configure_namespace(
    struct ssd *ssd, const struct NamespacePersonalityConfig *config);
int flash_subsystem_register_oob_region(struct ssd *ssd, const char *name,
                                        uint32_t size, int *handle_out);
void policy_event_from_nvme_request(struct ssd *ssd, NvmeRequest *req,
                                    struct NvmeCommandEvent *event);

struct pe_policy_execution;

/*
 * Host semantic boundary for WebAssembly policy imports.
 *
 * policy-wamr.c validates policy pointers and translates WAMR calling
 * conventions, then calls these functions with the current execution. These
 * functions define the meaning and permitted execution phase of each import.
 * The four event snapshot getters are implemented directly in policy-wamr.c.
 */

/* Initialization: record the events that will invoke this policy. */
int32_t policy_api_subscribe(struct pe_policy_execution *execution,
                         uint32_t event_kind, uint32_t selector,
                         uint32_t pair_id, uint32_t flags);

/* Read-only views of the current backend event and flash geometry/state. */
int32_t policy_api_backend_status_get(struct pe_policy_execution *execution,
                                  uint64_t index, int32_t *destination);
int32_t policy_api_geometry_get(struct pe_policy_execution *execution,
                            struct sxs_geometry *destination);
int32_t policy_api_layout_get(struct pe_policy_execution *execution,
                          struct sxs_layout *destination);
int32_t policy_api_eswd_get(struct pe_policy_execution *execution, uint32_t eswd_id,
                        struct sxs_eswd *destination);
int32_t policy_api_eswd_from_ppa(struct pe_policy_execution *execution,
                             uint64_t ppa,
                             struct sxs_eswd_location *destination);
int32_t policy_api_ppa_validate(struct pe_policy_execution *execution,
                            uint64_t ppa);
int64_t policy_api_ppa_to_page_index(struct pe_policy_execution *execution,
                                 uint64_t ppa);
int32_t policy_api_page_status_get(struct pe_policy_execution *execution,
                               uint64_t ppa);
int32_t policy_api_pswd_get(struct pe_policy_execution *execution,
                            uint64_t ppa, struct sxs_pswd_event *destination);
int32_t policy_api_pswd_retire(struct pe_policy_execution *execution,
                               uint64_t ppa);
int32_t policy_api_pswd_remap(struct pe_policy_execution *execution,
                              uint64_t ppa);

/* Access to the current NVMe request, command, DSM ranges, and completion. */
int32_t policy_api_request_read(struct pe_policy_execution *execution,
                            uint64_t request_offset, void *destination,
                            uint32_t length);
int32_t policy_api_request_write(struct pe_policy_execution *execution,
                             uint64_t request_offset, const void *source,
                             uint32_t length);
int32_t policy_api_command_read(struct pe_policy_execution *execution,
                            uint32_t command_offset, void *destination,
                            uint32_t length);
int32_t policy_api_command_write(struct pe_policy_execution *execution,
                             uint32_t command_offset, const void *source,
                             uint32_t length);
int32_t policy_api_dsm_range_get(struct pe_policy_execution *execution,
                             uint32_t index, struct sxs_dsm_range *destination);
int32_t policy_api_completion_status_set(struct pe_policy_execution *execution,
                                     uint32_t status);
int32_t policy_api_completion_result_set(struct pe_policy_execution *execution,
                                     uint64_t result);

/* Host time exposed as data rather than as flash or request state. */
uint64_t policy_api_time_now_ns(struct pe_policy_execution *execution);

/* Transactional flash and namespace configuration staged during init. */
int32_t policy_api_eswd_config_stage(struct pe_policy_execution *execution,
                                 const struct sxs_eswd_config *source);
int32_t
policy_api_namespace_config_stage(struct pe_policy_execution *execution,
                              const struct sxs_namespace_config *source);
int32_t policy_api_eswd_layout_finalize_stage(
    struct pe_policy_execution *execution);
int32_t policy_api_oob_register_stage(struct pe_policy_execution *execution,
                                  uint32_t object_id, uint32_t bytes_per_page);

/* eSWD queries and address conversion. */
int64_t policy_api_eswd_wp_get(struct pe_policy_execution *execution,
                           uint32_t eswd_id);
int64_t policy_api_eswd_to_ppa(struct pe_policy_execution *execution,
                           uint32_t eswd_id, uint32_t page_index);
int32_t policy_api_ppa_to_eswd(struct pe_policy_execution *execution, uint64_t ppa,
                           struct sxs_eswd_location *destination);
int32_t policy_api_eswd_member_get(struct pe_policy_execution *execution,
                                   uint32_t eswd_id, uint32_t member_index,
                                   uint64_t *ppa_out);
int32_t policy_api_eswd_release(struct pe_policy_execution *execution,
                                uint32_t eswd_id);
int32_t policy_api_eswd_rebind(struct pe_policy_execution *execution,
                               uint32_t eswd_id, const uint64_t *members,
                               uint32_t member_count);

/* Physical-page and eSWD data operations performed during an action. */
int32_t policy_api_page_read(struct pe_policy_execution *execution,
                         const struct sxs_page_read_request *request,
                         void *data, uint32_t data_length, void *oob,
                         uint32_t oob_length, struct sxs_page_result *result);
int32_t policy_api_page_append(struct pe_policy_execution *execution,
                           const struct sxs_page_append_request *request,
                           const void *data, uint32_t data_length,
                           const void *oob, uint32_t oob_length,
                           struct sxs_page_result *result);
int32_t policy_api_page_invalidate(struct pe_policy_execution *execution,
                               uint64_t ppa);
int32_t policy_api_eswd_reset(struct pe_policy_execution *execution,
                          uint32_t eswd_id);
int32_t policy_api_eswd_advance_wp(struct pe_policy_execution *execution,
                               uint32_t eswd_id);
uint64_t policy_api_eswd_erase(struct pe_policy_execution *execution,
                           uint32_t eswd_id);
int32_t policy_api_page_migrate(struct pe_policy_execution *execution,
                            uint64_t source_ppa, uint32_t destination_eswd_id,
                            struct sxs_page_result *result);

/* Variable-sized namespace/controller data staged during initialization. */
int32_t policy_api_namespace_blob_stage(struct pe_policy_execution *execution,
                                    uint32_t kind, uint32_t destination_offset,
                                    const void *source, uint32_t length);

/* Cryptographic operations implemented by the trusted host environment. */
int32_t policy_api_crypto_random(struct pe_policy_execution *execution,
                             void *output, uint32_t length);
int32_t
policy_api_crypto_ed25519_verify(struct pe_policy_execution *execution,
                             const void *public_key, uint32_t public_key_length,
                             const void *message, uint32_t message_length,
                             const void *signature, uint32_t signature_length);
int32_t policy_api_crypto_x25519_public(struct pe_policy_execution *execution,
                                    const void *private_key,
                                    uint32_t private_key_length,
                                    void *public_key,
                                    uint32_t public_key_length);
int32_t policy_api_crypto_x25519_shared(struct pe_policy_execution *execution,
                                    const void *private_key,
                                    uint32_t private_key_length,
                                    const void *peer_key,
                                    uint32_t peer_key_length, void *output,
                                    uint32_t output_length);
int32_t policy_api_crypto_hmac_sha256(struct pe_policy_execution *execution,
                                  const void *key, uint32_t key_length,
                                  const void *message, uint32_t message_length,
                                  void *output, uint32_t output_length);
int32_t policy_api_crypto_sha256(struct pe_policy_execution *execution,
                             const void *message, uint32_t message_length,
                             void *output, uint32_t output_length);
int32_t policy_api_crypto_hkdf_sha256(struct pe_policy_execution *execution,
                                  const void *key, uint32_t key_length,
                                  const void *info, uint32_t info_length,
                                  void *output, uint32_t output_length);
int32_t policy_api_crypto_aes256_gcm_decrypt(
    struct pe_policy_execution *execution,
    const void *key, uint32_t key_length,
    const void *nonce, uint32_t nonce_length,
    const void *aad, uint32_t aad_length,
    const void *ciphertext, uint32_t ciphertext_length,
    const void *tag, uint32_t tag_length,
    void *plaintext, uint32_t plaintext_length);
int32_t policy_api_sign_key_bootstrap(struct pe_policy_execution *execution,
                                  const uint8_t owner_nonce[32],
                                  const uint8_t owner_public[32],
                                  const uint8_t policy_public[32],
                                  uint8_t signature[64]);

/* Protected storage, policy lifecycle, state removal, and attestation. */
int32_t policy_api_privileged_storage_geometry_get(
    struct pe_policy_execution *execution,
    struct sxs_policy_storage_geometry *geometry);
int32_t policy_api_privileged_block_is_claimed(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *block);
int32_t policy_api_privileged_block_claim(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *block);
int32_t policy_api_privileged_block_release(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *block);
int32_t policy_api_privileged_storage_read(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *blocks, uint32_t block_count,
    void *data, uint32_t length);
int32_t policy_api_privileged_storage_write(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *blocks, uint32_t block_count,
    const void *data, uint32_t length);
int32_t policy_api_privileged_storage_erase(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *blocks, uint32_t block_count);
int32_t policy_api_privileged_policy_validate_image(
    struct pe_policy_execution *execution,
    const void *image, uint32_t image_size);
int32_t policy_api_privileged_policy_activate_stored(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t policy_version, uint32_t generation,
    uint32_t policy_size,
    const struct sxs_physical_block *blocks, uint32_t block_count);
int32_t policy_api_privileged_policy_deactivate(
    struct pe_policy_execution *execution, uint32_t policy_id);
int32_t policy_api_privileged_policy_can_remove(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t generation);
int32_t policy_api_privileged_policy_remove(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t generation);
int32_t policy_api_privileged_device_attestation_sign(
    struct pe_policy_execution *execution,
    const void *message, uint32_t message_length,
    void *signature, uint32_t signature_length);

#endif /* FEMU_SXSSD_POLICY_API_H */
