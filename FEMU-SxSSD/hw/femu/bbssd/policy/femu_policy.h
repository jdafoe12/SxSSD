#ifndef FEMU_POLICY_H
#define FEMU_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define INVALID_PPA  (~(0ULL))
#define INVALID_LPN  (~(0ULL))
#define UNMAPPED_PPA (~(0ULL))

#define BLK_BITS (16)
#define PG_BITS  (16)
#define SEC_BITS (8)
#define PL_BITS  (8)
#define LUN_BITS (8)
#define CH_BITS  (7)

enum {
    NVME_SUCCESS = 0x0000,
    NVME_INVALID_FIELD = 0x0002,
    NVME_INTERNAL_DEV_ERROR = 0x0006,
    NVME_DATA_TRAS_ERROR = 0x0004,
    NVME_LBA_RANGE = 0x0080,
    NVME_ZONE_BOUNDARY_ERROR = 0x01b8,
    NVME_ZONE_FULL = 0x01b9,
    NVME_ZONE_READ_ONLY = 0x01ba,
    NVME_ZONE_OFFLINE = 0x01bb,
    NVME_ZONE_INVALID_WRITE = 0x01bc,
    NVME_ZONE_TOO_MANY_ACTIVE = 0x01bd,
    NVME_ZONE_TOO_MANY_OPEN = 0x01be,
    NVME_ZONE_INVAL_TRANSITION = 0x01bf,
    NVME_DNR = 0x4000,
};

enum {
    NVME_CMD_WRITE = 0x01,
    NVME_CMD_READ = 0x02,
    NVME_CMD_DSM = 0x09,
    NVME_CMD_ZONE_MGMT_SEND = 0x79,
    NVME_CMD_ZONE_MGMT_RECV = 0x7a,
    NVME_CMD_ZONE_APPEND = 0x7d,
};

enum {
    NVME_CSI_NVM = 0x00,
    NVME_CSI_ZONED = 0x02,
};

struct ppa {
    union {
        struct {
            uint64_t blk : BLK_BITS;
            uint64_t pg  : PG_BITS;
            uint64_t sec : SEC_BITS;
            uint64_t pl  : PL_BITS;
            uint64_t lun : LUN_BITS;
            uint64_t ch  : CH_BITS;
            uint64_t rsv : 1;
        } g;

        uint64_t ppa;
    };
};

struct pba {
    union {
        struct {
            uint64_t blk : BLK_BITS;
            uint64_t pl  : PL_BITS;
            uint64_t lun : LUN_BITS;
            uint64_t ch  : CH_BITS;
            uint64_t rsv : (64 - BLK_BITS - PL_BITS - LUN_BITS - CH_BITS);
        } g;

        uint64_t pba;
    };
};

typedef struct ppa PseudoPpa;
typedef struct pba PseudoPba;

typedef struct NvmeDsmRange {
    uint32_t cattr;
    uint32_t nlb;
    uint64_t slba;
} NvmeDsmRange;

enum backend_page_status {
    PG_FREE = 0,
    PG_INVALID = 1,
    PG_VALID = 2,
};

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

struct bbm_geom {
    uint32_t blks_per_pl_log;
    uint32_t blks_per_lun_log;
    uint32_t blks_per_ch_log;
    uint64_t tt_blks_log;
    uint32_t pgs_per_blk;
    uint32_t pgs_per_pl;
    uint32_t pgs_per_lun;
    uint32_t pgs_per_ch;
    uint64_t tt_pgs_log;
    uint32_t blks_per_line;
    uint32_t pgs_per_line;
    uint32_t tt_lines;
    uint32_t pls_per_lun;
    uint32_t luns_per_ch;
    uint32_t nchs;
    uint32_t tt_luns;
    uint32_t secs_per_pg;
    uint32_t secsz;
};

struct eswd_layout {
    uint32_t tt_eswds;
    uint32_t blks_per_eswd;
    uint32_t pgs_per_eswd;
    enum eswd_striping_level striping_level;
    uint32_t *eswd_to_starting_block;
    uint32_t tt_pl;
    uint32_t blks_per_pl;
};

struct eswd {
    uint32_t id;
    int vpc;
    int ipc;
    uint32_t wp_page_index;
    uint64_t wp_lba;
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

/* Per-run statistics counters; reset/dumped via bb_flip FEMU_STATS_RESET/DUMP. */
struct ssd_stats {
    /* Host I/O command counts */
    uint64_t host_read_cmds;
    uint64_t host_write_cmds;
    uint64_t host_trim_cmds;
    /* Host I/O sector counts */
    uint64_t host_read_sectors;
    uint64_t host_write_sectors;
    uint64_t host_trim_sectors;
    /* Physical page / block operations */
    uint64_t phys_page_reads;
    uint64_t phys_page_programs;
    uint64_t block_erases;
    /* GC activity */
    uint64_t gc_invocations;
    uint64_t gc_pages_migrated;
    uint64_t foreground_gc_count;
    uint64_t background_gc_count;
    uint64_t gc_time_ns;
    bool     gc_active;
    /* Policy-engine overhead */
    uint64_t policy_dispatch_time_ns;
    /* Data copy volume */
    uint64_t bytes_copied;
};

struct ssd;
struct bbm;
struct BbmPolicyAPI;
struct FtlBackend;
struct FtlBackendEvent;
struct FtlPolicyAPI;
struct PswdStateTransitionEvent;
struct NvmeRequest;
struct nand_lun;
struct ssd_channel;

struct BackgroundEvent {
    struct ssd *ssd;
};

struct NvmeCommandEvent {
    uint8_t opcode;
    bool is_admin;
    uint64_t lba;
    uint64_t nsecs;
    uint64_t start_lpn;
    uint64_t end_lpn;
    uint64_t lpn_cnt;
    struct NvmeRequest *req;
    void *cmd;
    void *ctrl;
    uint64_t stime;
    uint64_t lat;
    uint16_t status;
};

typedef bool (*MigrationValidityCallback)(uint32_t src_eswd_id, uint32_t page_index,
                                          PseudoPpa *src_ppa, void *context);
typedef void (*MigrationResultCallback)(uint64_t lpn, PseudoPpa *old_ppa,
                                        PseudoPpa *new_ppa, void *context);
typedef bool (*ReadPpaResolver)(void *ctx, struct ssd *ssd, uint64_t lpn, PseudoPpa *out);
typedef void (*WritePpaCommitCallback)(void *ctx, struct ssd *ssd, uint64_t lpn,
                                       const PseudoPpa *new_ppa);
typedef void (*WritePageOobCallback)(void *ctx, struct ssd *ssd, uint64_t lpn,
                                     void *oob_buf, uint32_t oob_len);

typedef bool (*NvmeHookCondition)(struct ssd *ssd,
                                  struct NvmeCommandEvent *event,
                                  struct FtlPolicyAPI *api,
                                  void *context);
typedef uint64_t (*NvmeHookCallback)(struct ssd *ssd,
                                     struct NvmeCommandEvent *event,
                                     struct FtlPolicyAPI *api,
                                     void *context);

typedef bool (*BackendEventHookCondition)(struct FtlBackendEvent *event,
                                          struct BbmPolicyAPI *api,
                                          void *context);
typedef void (*BackendEventHookCallback)(struct FtlBackend *fb,
                                         const struct bbm *ctx,
                                         struct FtlBackendEvent *event,
                                         struct BbmPolicyAPI *api,
                                         void *context);

typedef bool (*PswdTransitionHookCondition)(const struct PswdStateTransitionEvent *event,
                                            struct BbmPolicyAPI *api,
                                            void *context);
typedef void (*PswdTransitionHookCallback)(struct FtlBackend *fb,
                                           const struct bbm *ctx,
                                           const struct PswdStateTransitionEvent *event,
                                           struct BbmPolicyAPI *api,
                                           void *context);

typedef bool (*BackgroundHookCondition)(struct ssd *ssd,
                                        struct BackgroundEvent *event,
                                        struct FtlPolicyAPI *api,
                                        void *context);
typedef void (*BackgroundHookCallback)(struct ssd *ssd,
                                       struct BackgroundEvent *event,
                                       struct FtlPolicyAPI *api,
                                       void *context);

struct FtlMigrationCallbacks {
    bool (*should_migrate)(void *policy_ctx, bool force);
    int (*select_victim)(void *policy_ctx, bool force, uint32_t *victim_id);
    int (*get_destination)(void *policy_ctx, uint32_t *dest_id);
    bool (*is_page_valid)(uint32_t src_id, uint32_t page_idx,
                          PseudoPpa *src_ppa, void *policy_ctx);
    void (*on_page_migrated)(uint64_t lpn, PseudoPpa *old_ppa,
                             PseudoPpa *new_ppa, void *policy_ctx);
    void (*on_complete)(void *policy_ctx, uint32_t victim_id, int pages_moved);
    void (*on_failed)(void *policy_ctx, uint32_t victim_id, int error_code);
    int (*on_destination_full)(void *policy_ctx, uint32_t current_dest_id, uint32_t *new_dest_id);
};

struct FtlPolicyAPI {
    uint32_t version;
    /* Sign only the fixed, domain-separated policy key-bootstrap transcript:
       "SxSSD-Policy-Key-Bootstrap-v1" || owner_nonce[32] ||
       owner_ephemeral_public_key[32] || policy_ephemeral_public_key[32]. */
    int (*sign_key_bootstrap)(
        const uint8_t owner_nonce[32],
        const uint8_t owner_ephemeral_public_key[32],
        const uint8_t policy_ephemeral_public_key[32],
        uint8_t signature[64]);
    struct eswd *(*get_eswd_by_id)(struct ssd *ssd, uint32_t eswd_id);
    struct eswd *(*get_eswd_by_ppa)(struct ssd *ssd, PseudoPpa *ppa);
    void (*get_eswd_vpc_ipc)(struct ssd *ssd, uint32_t eswd_id, int *vpc, int *ipc);
    uint32_t (*get_eswd_wp_index)(struct ssd *ssd, uint32_t eswd_id);
    uint32_t (*get_total_eswds)(struct ssd *ssd);
    uint64_t (*get_total_logical_pages)(struct ssd *ssd);
    uint64_t (*get_advertised_nsze_lbas)(struct ssd *ssd);
    const struct bbm_geom *(*get_bbm_geom)(struct ssd *ssd);
    const struct eswd_layout *(*get_eswd_layout)(struct ssd *ssd);
    void (*eswd_set_vpc_ipc)(struct ssd *ssd, uint32_t eswd_id, int vpc, int ipc);
    void (*eswd_increment_wp)(struct ssd *ssd, uint32_t eswd_id);
    void (*eswd_reset)(struct ssd *ssd, uint32_t eswd_id);
    uint64_t (*eswd_get_wp_lba)(struct ssd *ssd, uint32_t eswd_id);
    uint16_t (*eswd_check_seq_write)(struct ssd *ssd, uint32_t eswd_id,
                                     uint64_t slba, uint32_t nlb);
    uint16_t (*eswd_check_read_range)(struct ssd *ssd, uint32_t eswd_id,
                                      uint64_t slba, uint32_t nlb);
    uint64_t (*read_page_buffer)(struct ssd *ssd, const PseudoPpa *ppa,
                                 uint8_t *buffer,
                                 int oob_handle, void *oob_buf,
                                 int64_t stime_ns);
    int (*eswd_advance_wp_to_end)(struct ssd *ssd, uint32_t eswd_id);
    uint64_t (*eswd_erase_physical)(struct ssd *ssd, uint32_t eswd_id, int64_t stime_ns);
    int (*eswd_id_to_ppa)(struct ssd *ssd, uint32_t eswd_id, uint32_t page_index, PseudoPpa *ppa);
    int (*ppa_to_eswd_id)(struct ssd *ssd, const PseudoPpa *ppa, uint32_t *eswd_id, uint32_t *page_index);
    int (*eswd_block_to_ppa)(struct ssd *ssd, uint32_t eswd_id, uint32_t block_index, PseudoPpa *ppa);
    int (*migrate_eswd_pages)(struct ssd *ssd,
                              uint32_t src_eswd_id,
                              uint32_t dst_eswd_id,
                              MigrationValidityCallback is_valid,
                              MigrationResultCallback on_migrated,
                              void *context,
                              struct FtlMigrationCallbacks *callbacks,
                              void *policy_ctx);
    int (*run_migration)(struct ssd *ssd,
                         struct FtlMigrationCallbacks *callbacks,
                         void *policy_ctx,
                         bool force);
    int (*remap_eswd_to_physical)(struct ssd *ssd,
                                  uint32_t eswd_id,
                                  uint8_t target_ch,
                                  uint8_t target_lun,
                                  uint8_t target_pl,
                                  uint16_t target_blk_start);
    void (*mark_page_valid)(struct ssd *ssd, PseudoPpa *ppa);
    void (*mark_page_invalid)(struct ssd *ssd, PseudoPpa *ppa);
    void (*mark_block_free)(struct ssd *ssd, PseudoPpa *ppa);
    bool (*valid_ppa)(struct ssd *ssd, PseudoPpa *ppa);
    bool (*mapped_ppa)(PseudoPpa *ppa);
    uint64_t (*ppa_to_pgidx)(struct ssd *ssd, PseudoPpa *ppa);
    struct nand_lun *(*get_lun)(struct ssd *ssd, PseudoPpa *ppa);
    struct ssd_channel *(*get_ch)(struct ssd *ssd, PseudoPpa *ppa);
    uint64_t (*get_request_buffer_size)(struct NvmeRequest *req);
    uint8_t *(*copy_request_data)(struct NvmeRequest *req, uint64_t offset,
                                  uint64_t length, uint64_t *out_size);
    uint64_t (*write_request_data)(struct NvmeRequest *req, const uint8_t *buffer,
                                   uint64_t offset, uint64_t length);
    const NvmeDsmRange *(*get_dsm_ranges)(struct NvmeRequest *req, int *nr_ranges);
    uint16_t (*read_cmd_buffer)(struct NvmeCommandEvent *event, void *dst,
                                uint32_t length);
    uint16_t (*write_cmd_buffer)(struct NvmeCommandEvent *event, const void *src,
                                 uint32_t length);
    void (*set_completion_result_u64)(struct NvmeCommandEvent *event,
                                      uint64_t value);
    
    int (*get_page_status)(struct ssd *ssd, const PseudoPpa *ppa);
    int (*register_oob_region)(struct ssd *ssd, const char *name,
                               uint32_t size, int *handle_out);
    int (*register_nvme_hook)(struct ssd *ssd, uint8_t opcode,
                              NvmeHookCondition condition,
                              NvmeHookCallback callback,
                              void *context);
    int (*unregister_nvme_hook)(struct ssd *ssd, int hook_handle);
    int (*inactivate_nvme_hook)(struct ssd *ssd, int hook_handle);
    int (*reactivate_nvme_hook)(struct ssd *ssd, int hook_handle);
    int (*register_admin_hook)(struct ssd *ssd, uint8_t opcode,
                               NvmeHookCondition condition,
                               NvmeHookCallback callback,
                               void *context);
    int (*unregister_admin_hook)(struct ssd *ssd, int hook_handle);
    int (*inactivate_admin_hook)(struct ssd *ssd, int hook_handle);
    int (*reactivate_admin_hook)(struct ssd *ssd, int hook_handle);
    int (*register_backend_hook)(struct ssd *ssd, BackendEventHookCondition condition,
                                 BackendEventHookCallback callback, void *context);
    int (*unregister_backend_hook)(struct ssd *ssd, int hook_handle);
    int (*inactivate_backend_hook)(struct ssd *ssd, int hook_handle);
    int (*reactivate_backend_hook)(struct ssd *ssd, int hook_handle);
    int (*register_pswd_transition_hook)(struct ssd *ssd, PswdTransitionHookCondition condition,
                                         PswdTransitionHookCallback callback, void *context);
    int (*unregister_pswd_transition_hook)(struct ssd *ssd, int hook_handle);
    int (*inactivate_pswd_transition_hook)(struct ssd *ssd, int hook_handle);
    int (*reactivate_pswd_transition_hook)(struct ssd *ssd, int hook_handle);
    int (*register_background_hook)(struct ssd *ssd, BackgroundHookCondition condition,
                                    BackgroundHookCallback callback, void *context);
    int (*unregister_background_hook)(struct ssd *ssd, int hook_handle);
    int (*inactivate_background_hook)(struct ssd *ssd, int hook_handle);
    int (*reactivate_background_hook)(struct ssd *ssd, int hook_handle);
    void (*set_eswd_config)(struct ssd *ssd, const struct eswd_config *config);
    int (*finalize_ftl_init)(struct ssd *ssd);
    int (*configure_namespace_personality)(struct ssd *ssd,
                                           const struct NamespacePersonalityConfig *config);
    uint64_t (*read_user_request)(struct ssd *ssd, struct NvmeCommandEvent *event,
                                  ReadPpaResolver resolve_ppa, void *resolve_ctx);
    /*
     * Unified host-write API shared by block and ZNS policies.
     *
     * If resolve_old_ppa is NULL, the write follows sequential/ZNS semantics:
     * full-page sequential ranges may be written directly while partial pages are
     * staged until full. If resolve_old_ppa is non-NULL, each touched logical page
     * is committed immediately; partial-page writes are reconstructed into a full
     * page image by reading the currently mapped page through resolve_old_ppa and
     * overlaying the incoming host bytes. on_page_commit (may be NULL) fires once
     * per committed page.
     */
    uint64_t (*write_host_lbas)(struct ssd *ssd, uint32_t eswd_id,
                                uint64_t slba, const uint8_t *buf, uint32_t nlb,
                                ReadPpaResolver resolve_old_ppa,
                                void *resolve_ctx,
                                int oob_handle,
                                WritePageOobCallback fill_oob,
                                void *oob_ctx,
                                WritePpaCommitCallback on_page_commit,
                                void *commit_ctx, int64_t stime_ns);
    /*
     * Unified sequential write API: stages nlb LBAs from buf (at slba) into the
     * per-eSWD staging buffer and programs pages to flash when they become full.
     * ppa_out (may be NULL) receives the last PseudoPpa written by this call.
     * The returned latency preserves request-visible semantics: it is 0 if no page
     * is committed, otherwise the maximum latency among pages committed by the call.
     */
    uint64_t (*write_seq_lbas)(struct ssd *ssd, uint32_t eswd_id,
                               uint64_t slba, const uint8_t *buf, uint32_t nlb,
                               int oob_handle,
                               WritePageOobCallback fill_oob,
                               void *oob_ctx,
                               PseudoPpa *ppa_out, int64_t stime_ns);
    /*
     * Staged-aware page read: serves from the eSWD staging buffer if the requested
     * page is currently staged; otherwise reads the committed page from flash.
     */
    uint64_t (*read_eswd_page)(struct ssd *ssd, uint32_t eswd_id,
                               uint64_t page_lba, uint8_t *buf_out,
                               int64_t stime_ns);
    /*
     * Effective write pointer: wp_lba + any partially-staged LBAs not yet on flash.
     * Use instead of eswd_get_wp_lba when comparing against host-visible write state.
     */
    uint64_t (*eswd_get_effective_wp_lba)(struct ssd *ssd, uint32_t eswd_id);
    /* struct BbmPolicyAPI *bbm_api; */

    /* Stats accessor: returns a pointer to the live ssd_stats counter block. */
    struct ssd_stats *(*get_stats)(struct ssd *ssd);
};

typedef int (*policy_init_fn)(struct ssd *ssd, struct FtlPolicyAPI *api);

#endif /* FEMU_POLICY_H */
