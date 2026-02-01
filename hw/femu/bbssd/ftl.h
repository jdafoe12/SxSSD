#ifndef __FEMU_FTL_H
#define __FEMU_FTL_H

#include "../nvme.h"
#include "./bbm.h" // we have access to PseudoPpa and PseudoPba through this.
#include "eswd-config.h"
#include "eswd-layout.h"

struct policy_engine;

struct FtlBackend;
struct FtlPolicyAPI;  /* Forward declaration */

#define INVALID_PPA     (~(0ULL))
#define INVALID_LPN     (~(0ULL))
#define UNMAPPED_PPA    (~(0ULL))

#define MAX_FTL_EVENT_HOOKS (256)
#define MAX_NVME_HOOKS (256)

enum FtlEventCmd {
    FTL_WRITE_EVENT,
    FTL_READ_EVENT,
    FTL_TRIM_EVENT
};

struct FtlEvent {
    enum FtlEventCmd cmd;
    
    /* Address range information */
    uint64_t lba;           /* Starting logical block address (sector number) */
    uint64_t nsecs;         /* Number of sectors in this operation */
    uint64_t start_lpn;     /* Starting logical page number */
    uint64_t end_lpn;       /* Ending logical page number */
    uint64_t lpn_cnt;       /* Number of pages affected */
    
    /* Request and buffer information */
    NvmeRequest *req;       /* Original NVMe request containing data buffer and metadata */
    
    /* Timing information Josh: TODO: Do we need this in the event info? */
    uint64_t stime;         /* Start time of the operation */
    uint64_t lat;           /* Latency to be filled in by handler */
};

/*
 * NVMe command event: same semantic info as FtlEvent plus opcode.
 * Used by policy engine for opcode-keyed hooks (condition + callback).
 */
struct NvmeCommandEvent {
    uint8_t opcode;         /* NVMe command opcode (e.g. NVME_CMD_READ, NVME_CMD_WRITE) */
    uint64_t lba;
    uint64_t nsecs;
    uint64_t start_lpn;
    uint64_t end_lpn;
    uint64_t lpn_cnt;
    NvmeRequest *req;
    uint64_t stime;
    uint64_t lat;
};

struct ssd; /* Forward declaration */

/*
 * Event condition function type - determines if an event should trigger a hook.
 * Policies implement this to specify complex event matching criteria.
 * 
 * Parameters:
 *   - ssd: FTL context
 *   - event: the FTL event to evaluate
 *   - api: pointer to FTL policy API (if needed for condition evaluation)
 *   - context: opaque policy-specific data passed during registration
 * 
 * Returns: true if the hook should fire for this event, false otherwise
 * 
 * Example conditions:
 *   - Writes to specific LPN ranges
 *   - Reads that span multiple pages
 *   - Operations during GC
 *   - Any arbitrary function of event->lba, event->lpn_cnt, etc.
 */
typedef bool (*FtlEventHookCondition)(struct ssd *ssd,
                                      struct FtlEvent *event,
                                      struct FtlPolicyAPI *api,
                                      void *context);

/* 
 * FTL Event hook callback function type.
 * Policies implement this callback to handle FTL events (read/write requests).
 * 
 * Parameters:
 *   - ssd: pointer to the FTL/SSD context
 *   - event: the FTL event that triggered this hook
 *   - api: pointer to FTL policy API (for making FTL calls)
 *   - context: opaque policy-specific data passed during registration
 * 
 * Returns: latency in nanoseconds for this operation
 * 
 * Note: Policies should use the provided API functions rather than directly
 * accessing ssd internals for better encapsulation and future compatibility.
 */
typedef uint64_t (*FtlEventHookCallback)(struct ssd *ssd,
                                         struct FtlEvent *event,
                                         struct FtlPolicyAPI *api,
                                         void *context);

/*
 * Event hook structure for extensible FTL policy attachment.
 * Policies register hooks during initialization, specifying:
 *   - A condition function (when to trigger)
 *   - What function to call (action)
 *   - Any policy-specific data needed (context)
 * 
 * The condition function allows arbitrary complexity in event matching.
 * If condition is NULL, the hook fires for all events of that type.
 */
struct FtlEventHook {
    FtlEventHookCondition condition;   /* Optional: when should this hook fire? */
    FtlEventHookCallback callback;     /* What function to call on event */
    void *context;                     /* Opaque policy-specific data */
    bool active;                       /* Is this hook slot in use? */
};

/*
 * NVMe hook: condition + callback keyed by opcode. Same design as FTL event hooks.
 * Condition/callback receive NvmeCommandEvent (same info as FtlEvent plus opcode).
 */
typedef bool (*NvmeHookCondition)(struct ssd *ssd,
                                  struct NvmeCommandEvent *event,
                                  struct FtlPolicyAPI *api,
                                  void *context);
typedef uint64_t (*NvmeHookCallback)(struct ssd *ssd,
                                     struct NvmeCommandEvent *event,
                                     struct FtlPolicyAPI *api,
                                     void *context);
struct NvmeHook {
    uint8_t opcode;
    NvmeHookCondition condition;
    NvmeHookCallback callback;
    void *context;
    bool active;
};

/*
 * Read PPA resolver: policy provides this so the FTL can perform a user read
 * through BBM. For each LPN in the request range, the resolver returns true
 * and fills *out with a valid mapped PPA to read, or false to skip that LPN.
 * Used by read_user_request() to build the PPA list and call BBM read.
 */
typedef bool (*ReadPpaResolver)(void *ctx, struct ssd *ssd, uint64_t lpn, PseudoPpa *out);

// enum {
//     NAND_READ =  0,
//     NAND_WRITE = 1,
//     NAND_ERASE = 2,

//     NAND_READ_LATENCY = 40000,
//     NAND_PROG_LATENCY = 200000,
//     NAND_ERASE_LATENCY = 2000000,
// }; // probably remove... I think no need to add to ftl-backend - not even used in ftl.c! 

/* enum {
    USER_IO = 0,
    GC_IO = 1,
};*/

/* Page/sector status: use backend enum (PG_FREE, PG_INVALID, PG_VALID from ftl-backend.h via bbm.h). */

enum { // these things should be done in backend, or no? may be policy level.? TODO: Remove. It definitely seems this information is policy level.
       // GC_DELAY is always enabled ipmplicitly. 
    FEMU_ENABLE_GC_DELAY = 1,
    FEMU_DISABLE_GC_DELAY = 2,

    FEMU_ENABLE_DELAY_EMU = 3,
    FEMU_DISABLE_DELAY_EMU = 4,

    FEMU_RESET_ACCT = 5,
    FEMU_ENABLE_LOG = 6,
    FEMU_DISABLE_LOG = 7,
};


// #define BLK_BITS    (16)
// #define PG_BITS     (16)
// #define SEC_BITS    (8)
// #define PL_BITS     (8)
// #define LUN_BITS    (8)
// #define CH_BITS     (7)


// /* describe a physical page addr */
// struct ppa { // ppa shoudl be moved to backend / BBM mapping engine layer.
//     union {
//         struct {
//             uint64_t blk : BLK_BITS;
//             uint64_t pg  : PG_BITS;
//             uint64_t sec : SEC_BITS;
//             uint64_t pl  : PL_BITS;
//             uint64_t lun : LUN_BITS;
//             uint64_t ch  : CH_BITS;
//             uint64_t rsv : 1;
//         } g;

//         uint64_t ppa;
//     };
// };

/* Per-page validity and block vpc/ipc live in the backend. FTL keeps line-level vpc/ipc for victim selection. */

struct nand_lun {
    /* Timing only; no pl/blk/pg arrays - validity is in backend. */
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

// struct ssdparams {
//     int secsz;        /* sector size in bytes */
//     int secs_per_pg;  /* # of sectors per page */
//     int pgs_per_blk;  /* # of NAND pages per block */
//     int blks_per_pl;  /* # of blocks per plane */
//     int pls_per_lun;  /* # of planes per LUN (Die) */
//     int luns_per_ch;  /* # of LUNs per channel */
//     int nchs;         /* # of channels in the SSD */

//     int pg_rd_lat;    /* NAND page read latency in nanoseconds */
//     int pg_wr_lat;    /* NAND page program latency in nanoseconds */
//     int blk_er_lat;   /* NAND block erase latency in nanoseconds */
//     int ch_xfer_lat;  /* channel transfer latency for one page in nanoseconds
//                        * this defines the channel bandwith
//                        */

//    // double gc_thres_pcent;
//    // int gc_thres_lines;
//    // double gc_thres_pcent_high;
//    // int gc_thres_lines_high;
//    // bool enable_gc_delay;

//     /* below are all calculated values */
//     int secs_per_blk; /* # of sectors per block */
//     int secs_per_pl;  /* # of sectors per plane */
//     int secs_per_lun; /* # of sectors per LUN */
//     int secs_per_ch;  /* # of sectors per channel */
//     int tt_secs;      /* # of sectors in the SSD */

//     int pgs_per_pl;   /* # of pages per plane */
//     int pgs_per_lun;  /* # of pages per LUN (Die) */
//     int pgs_per_ch;   /* # of pages per channel */
//     int tt_pgs;       /* total # of pages in the SSD */

//     int blks_per_lun; /* # of blocks per LUN */
//     int blks_per_ch;  /* # of blocks per channel */
//     int tt_blks;      /* total # of blocks in the SSD */

//     int secs_per_line;
//     int pgs_per_line;
//     int blks_per_line;
//     int tt_lines;

//     int pls_per_ch;   /* # of planes per channel */
//     int tt_pls;       /* total # of planes in the SSD */

//     int tt_luns;      /* total # of LUNs in the SSD */
// };

/*
 * eSWD (exposed SWD): mechanism only. No list/queue membership—queues are policy, built on top.
 */
struct eswd {
    uint32_t id;
    int vpc;           /* valid page count in this eSWD */
    int ipc;           /* invalid page count in this eSWD */
    uint32_t wp_page_index;  /* next page to write in this eSWD (0..pgs_per_eswd-1) */
};

/*struct nand_cmd {
    int type;
    int cmd;
    int64_t stime; 
};*/

/*
 * Migration validity callback: policy decides if a page should be migrated.
 * Returns true if the page at (src_eswd_id, page_index) should be copied.
 */
typedef bool (*MigrationValidityCallback)(uint32_t src_eswd_id, uint32_t page_index, 
                                          PseudoPpa *src_ppa, void *context);

/*
 * Migration result callback: called for each successfully migrated page.
 * Provides old and new PPAs so policy can update its mapping table.
 */
typedef void (*MigrationResultCallback)(uint64_t lpn, PseudoPpa *old_ppa, 
                                        PseudoPpa *new_ppa, void *context);

/*
 * ============================================================================
 * GENERIC MIGRATION FRAMEWORK
 * ============================================================================
 * Callbacks structure for generic migration operations (GC, wear leveling, 
 * compaction, refresh, etc.). Provides a unified interface for any space
 * management operation that needs to move data.
 */
struct FtlMigrationCallbacks {
    /* Required: Check if migration should proceed */
    bool (*should_migrate)(void *policy_ctx, bool force);
    
    /* Required: Select victim for migration */
    int (*select_victim)(void *policy_ctx, bool force, uint32_t *victim_id);
    
    /* Required: Get destination for migrated data */
    int (*get_destination)(void *policy_ctx, uint32_t *dest_id);
    
    /* Optional: Check if a specific page should be migrated */
    bool (*is_page_valid)(uint32_t src_id, uint32_t page_idx, 
                          PseudoPpa *src_ppa, void *policy_ctx);
    
    /* Optional: Notify policy after successful page migration */
    void (*on_page_migrated)(uint64_t lpn, PseudoPpa *old_ppa, 
                            PseudoPpa *new_ppa, void *policy_ctx);
    
    /* Optional: Notify policy after complete migration */
    void (*on_complete)(void *policy_ctx, uint32_t victim_id, int pages_moved);
    
    /* Optional: Notify policy of failure */
    void (*on_failed)(void *policy_ctx, uint32_t victim_id, int error_code);

    /* Optional: Destination eSWD is full (wp at pgs_per_eswd). Policy moves it to
     * full_list or victim_pq, switches to next free eSWD, sets *new_dest_id, returns 0.
     * Must not increment wp (mechanism already did). Return -1 if no free eSWD. */
    int (*on_destination_full)(void *policy_ctx, uint32_t current_dest_id, uint32_t *new_dest_id);
};

/*
 * FTL Policy API - Mechanism-level primitives for policies
 * 
 * This structure provides ONLY mechanism operations: eSWD primitives, migration,
 * validity tracking, and hook registration. Policies implement their own mapping
 * layer, I/O handlers, GC logic, and allocation strategy on top of these primitives.
 * 
 * Mechanism = eSWD + migration infrastructure (stable, reusable)
 * Policy = translation layer + I/O + GC + allocation (pluggable, varied)
 */
struct FtlPolicyAPI {
    uint32_t version;  /* API version for compatibility checking */
    
    /* eSWD query operations (mechanism exposes eSWD state, policy decides how to use) */
    struct eswd *(*get_eswd_by_id)(struct ssd *ssd, uint32_t eswd_id);
    struct eswd *(*get_eswd_by_ppa)(struct ssd *ssd, PseudoPpa *ppa);
    void (*get_eswd_vpc_ipc)(struct ssd *ssd, uint32_t eswd_id, int *vpc, int *ipc);
    uint32_t (*get_eswd_wp_index)(struct ssd *ssd, uint32_t eswd_id);
    uint32_t (*get_total_eswds)(struct ssd *ssd);
    uint64_t (*get_total_logical_pages)(struct ssd *ssd);
    
    /* eSWD state modification (mechanism updates eSWD struct, policy tracks queues) */
    void (*eswd_set_vpc_ipc)(struct ssd *ssd, uint32_t eswd_id, int vpc, int ipc);
    void (*eswd_increment_wp)(struct ssd *ssd, uint32_t eswd_id);
    void (*eswd_reset)(struct ssd *ssd, uint32_t eswd_id);  /* Reset to initial state (for free) */
    
    /* eSWD layout query (mechanism owns layout, policy uses for translation) */
    int (*eswd_id_to_ppa)(struct ssd *ssd, uint32_t eswd_id, uint32_t page_index, PseudoPpa *ppa);
    int (*ppa_to_eswd_id)(struct ssd *ssd, const PseudoPpa *ppa, uint32_t *eswd_id, uint32_t *page_index);
    int (*eswd_block_to_ppa)(struct ssd *ssd, uint32_t eswd_id, uint32_t block_index, PseudoPpa *ppa);
    
    /* Migration API (mechanism performs copy, policy decides when/which/validity).
     * callbacks and policy_ctx may be NULL; if set, on_destination_full used when dest full. */
    int (*migrate_eswd_pages)(struct ssd *ssd,
                              uint32_t src_eswd_id,
                              uint32_t dst_eswd_id,
                              MigrationValidityCallback is_valid,
                              MigrationResultCallback on_migrated,
                              void *context,
                              struct FtlMigrationCallbacks *callbacks,
                              void *policy_ctx);
    
    /* Remapping API (mechanism updates eSWD→physical mapping for wear leveling) */
    int (*remap_eswd_to_physical)(struct ssd *ssd,
                                  uint32_t eswd_id,
                                  uint8_t target_ch,
                                  uint8_t target_lun,
                                  uint8_t target_pl,
                                  uint16_t target_blk_start);
    
    /* Validity tracking (mechanism updates backend validity, policy calls these) */
    void (*mark_page_valid)(struct ssd *ssd, PseudoPpa *ppa);
    void (*mark_page_invalid)(struct ssd *ssd, PseudoPpa *ppa);
    void (*mark_block_free)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Address validation (mechanism checks PPA against geometry) */
    bool (*valid_ppa)(struct ssd *ssd, PseudoPpa *ppa);
    bool (*mapped_ppa)(PseudoPpa *ppa);
    
    /* Hardware accessors (mechanism provides access to channels/LUNs) */
    struct nand_lun *(*get_lun)(struct ssd *ssd, PseudoPpa *ppa);
    struct ssd_channel *(*get_ch)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Buffer helpers (mechanism provides request data access) */
    uint64_t (*get_request_buffer_size)(NvmeRequest *req);
    uint8_t *(*copy_request_data)(NvmeRequest *req, uint64_t offset, 
                                   uint64_t length, uint64_t *out_size);
    uint64_t (*write_request_data)(NvmeRequest *req, const uint8_t *buffer,
                                    uint64_t offset, uint64_t length);

    /* Hook registration (mechanism provides event system, policy attaches handlers) */
    int (*register_nvme_hook)(struct ssd *ssd, uint8_t opcode,
                             NvmeHookCondition condition,
                             NvmeHookCallback callback,
                             void *context);
    int (*unregister_nvme_hook)(struct ssd *ssd, int hook_handle);
    int (*inactivate_nvme_hook)(struct ssd *ssd, int hook_handle);
    int (*reactivate_nvme_hook)(struct ssd *ssd, int hook_handle);
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

    /* eSWD config (policy sets at init to define striping and layout) */
    void (*set_eswd_config)(struct ssd *ssd, const struct eswd_config *config);

    /* GC mapping update (policy provides; mechanism calls when migrating a page in legacy GC path) */
    void (*gc_update_mapping)(struct ssd *ssd, PseudoPpa *old_ppa, PseudoPpa *new_ppa);

    /*
     * User read through BBM: builds PPA list from event LPN range using the policy's
     * resolve callback, performs BBM read (pseudo→physical, backend I/O, event dispatch),
     * and returns latency. The event is passed in so stime/lat and policy context are used.
     */
    uint64_t (*read_user_request)(struct ssd *ssd, struct NvmeCommandEvent *event,
                                  ReadPpaResolver resolve_ppa, void *resolve_ctx);
    uint64_t (*write_user_request)(struct ssd *ssd, NvmeRequest *req,
                                  PseudoPpa *ppa_list, uint64_t ppa_cnt);

    /* BBM API pass-through (mechanism provides backend I/O and validity operations) */
    struct BbmPolicyAPI *bbm_api;
};

struct ssd { // This needs to be dissected and probably renamed
    char *ssdname;
    struct FtlBackend *fb; /* backend timing/error model */
    struct bbm *bbm;     /* bad block manager / OP mapping context */
   // struct ssdparams sp;
    struct ssd_channel *ch;
    
    /* Policy-owned context (opaque to mechanism) */
    void *policy_private;
    
    /* DEPRECATED: These will be moved to policy context */
    PseudoPpa *maptbl; /* page level mapping table */

    /* eSWD state (mechanism owns eSWD structs and layout) */
    struct eswd *eswds;
    uint32_t tt_eswds;
    struct eswd_config eswd_config;
    struct eswd_layout eswd_layout;
    bool eswd_config_set;
    
    /* DEPRECATED: Policy-level fields, will be moved to policy_private */
    struct eswd *cur_eswd;
    void *eswd_policy_ctx;  /* opaque; policy may use for its own context */

    /* lockless ring for communication with NVMe IO thread */
    struct rte_ring **to_ftl;
    struct rte_ring **to_poller;
    bool *dataplane_started_ptr;
    QemuThread ftl_thread;

    /* Policy engine (holds FTL/backend/pSWD hook arrays; dispatch runs there) */
    struct policy_engine *policy_engine;
    
    /*
     * FTL Policy API - function pointer table for policies.
     * Initialized at ssd_init() to point to implementation functions.
     * Policies receive this API to interact with FTL layer.
     */
    struct FtlPolicyAPI *policy_api;
};

void ssd_init(FemuCtrl *n);

/* Block interface policy: apply eSWD config (call before eswd_layout_compute) */
void block_interface_policy_apply_eswd_config(struct ssd *ssd);

/* Block interface policy initialization */
int init_block_interface_policy(struct ssd *ssd);

/* eSWD config – call from init_policy to define striping and size before lines/wp are inited */
void set_eswd_config(struct ssd *ssd, const struct eswd_config *config);

/* Event filling helpers */
void ftl_fill_nvme_event(struct ssd *ssd, NvmeRequest *req, struct NvmeCommandEvent *event);
uint64_t ftl_read_user_request(struct ssd *ssd, struct NvmeCommandEvent *event,
                               ReadPpaResolver resolve_ppa, void *resolve_ctx);
uint64_t ftl_write_user_request(struct ssd *ssd, NvmeRequest *req,
                                PseudoPpa *ppa_list, uint64_t ppa_cnt);

/* ========== Mechanism API: eSWD query and state operations ========== */
struct eswd *get_eswd_by_id(struct ssd *ssd, uint32_t eswd_id);
struct eswd *get_eswd_by_ppa(struct ssd *ssd, PseudoPpa *ppa);
void get_eswd_vpc_ipc(struct ssd *ssd, uint32_t eswd_id, int *vpc, int *ipc);
uint32_t get_eswd_wp_index(struct ssd *ssd, uint32_t eswd_id);
uint32_t get_total_eswds(struct ssd *ssd);
void eswd_set_vpc_ipc(struct ssd *ssd, uint32_t eswd_id, int vpc, int ipc);
void eswd_increment_wp(struct ssd *ssd, uint32_t eswd_id);
void eswd_reset(struct ssd *ssd, uint32_t eswd_id);

/* eSWD layout query wrappers */
int eswd_id_to_ppa_wrapper(struct ssd *ssd, uint32_t eswd_id, uint32_t page_index, PseudoPpa *ppa);
int ppa_to_eswd_id_wrapper(struct ssd *ssd, const PseudoPpa *ppa, uint32_t *eswd_id, uint32_t *page_index);
int eswd_block_to_ppa_wrapper(struct ssd *ssd, uint32_t eswd_id, uint32_t block_index, PseudoPpa *ppa);

/* eSWD migration and remapping.
 * If callbacks and policy_ctx are non-NULL, on_destination_full may be used when
 * destination runs out of space; otherwise migration fails when destination is full. */
int migrate_eswd_pages(struct ssd *ssd,
                       uint32_t src_eswd_id,
                       uint32_t dst_eswd_id,
                       MigrationValidityCallback is_valid,
                       MigrationResultCallback on_migrated,
                       void *context,
                       struct FtlMigrationCallbacks *callbacks,
                       void *policy_ctx);

/* Generic migration framework (high-level orchestration) */
int ftl_run_migration(struct ssd *ssd,
                      struct FtlMigrationCallbacks *callbacks,
                      void *policy_ctx,
                      bool force);

int ftl_run_migration_loop(struct ssd *ssd,
                           struct FtlMigrationCallbacks *callbacks,
                           void *policy_ctx,
                           bool force,
                           int max_iterations);

int remap_eswd_to_physical(struct ssd *ssd,
                           uint32_t eswd_id,
                           uint8_t target_ch,
                           uint8_t target_lun,
                           uint8_t target_pl,
                           uint16_t target_blk_start);

/* PPA to physical page index (for policy rmap; index in [0, tt_pgs_log)) */
uint64_t ppa_to_pgidx(struct ssd *ssd, PseudoPpa *ppa);

/* ========== DEPRECATED: Policy-level operations (will be removed) ========== */
/* Mapping table operations */
PseudoPpa get_maptbl_ent(struct ssd *ssd, uint64_t lpn);
void set_maptbl_ent(struct ssd *ssd, uint64_t lpn, PseudoPpa *ppa);
uint64_t get_total_logical_pages(struct ssd *ssd);

/* Address validation */
bool valid_lpn(struct ssd *ssd, uint64_t lpn);
bool valid_ppa(struct ssd *ssd, PseudoPpa *ppa);
bool mapped_ppa(PseudoPpa *ppa);

/* Metadata management */
void mark_page_valid(struct ssd *ssd, PseudoPpa *ppa);
void mark_page_invalid(struct ssd *ssd, PseudoPpa *ppa);
void mark_block_free(struct ssd *ssd, PseudoPpa *ppa);

/* eSWD/channel accessors (page/block validity via BBM API: bbm_api->get_page_status, bbm_api->get_block_vpc_ipc) */
struct eswd *get_eswd(struct ssd *ssd, PseudoPpa *ppa);
struct nand_lun *get_lun(struct ssd *ssd, PseudoPpa *ppa);
struct ssd_channel *get_ch(struct ssd *ssd, PseudoPpa *ppa);

/* Helper functions for FTL policies to access request data */

/**
 * ftl_get_request_buffer_size - Get total size of data in request
 * @req: NVMe request
 * 
 * Returns: Total number of bytes in the scatter-gather list
 */
uint64_t ftl_get_request_buffer_size(NvmeRequest *req);

/**
 * ftl_copy_request_data - Copy data from NVMe request to contiguous buffer
 * @req: NVMe request (must be a write request with valid data)
 * @offset: Byte offset to start copying from
 * @length: Number of bytes to copy (0 = copy all remaining data from offset)
 * @out_size: Output parameter - actual number of bytes copied
 * 
 * Allocates and returns a buffer containing the requested data from the
 * scatter-gather list. Caller must free the returned buffer with g_free().
 * 
 * Returns: Newly allocated buffer with copied data, or NULL on error
 */
uint8_t *ftl_copy_request_data(NvmeRequest *req, uint64_t offset, 
                                uint64_t length, uint64_t *out_size);

/**
 * ftl_write_request_data - Write data back into NVMe request buffer
 * @req: NVMe request
 * @buffer: Source buffer containing data to write
 * @offset: Byte offset in request buffer to start writing to
 * @length: Number of bytes to write
 * 
 * Writes data from a contiguous buffer into the scatter-gather list.
 * This modifies the actual request data that will be seen by the host.
 * Useful for policies that want to transform data (e.g., permute reads,
 * compress/encrypt data, etc.)
 * 
 * Returns: Number of bytes actually written, or 0 on error
 */
uint64_t ftl_write_request_data(NvmeRequest *req, const uint8_t *buffer,
                                 uint64_t offset, uint64_t length);

/* NVMe hook management (opcode-keyed, condition + callback) */
int ftl_register_nvme_hook(struct ssd *ssd, uint8_t opcode,
                           NvmeHookCondition condition,
                           NvmeHookCallback callback,
                           void *context);
int ftl_unregister_nvme_hook(struct ssd *ssd, int hook_handle);
int ftl_inactivate_nvme_hook(struct ssd *ssd, int hook_handle);
int ftl_reactivate_nvme_hook(struct ssd *ssd, int hook_handle);

/* Background hook management */
int ftl_register_background_hook(struct ssd *ssd, BackgroundHookCondition condition,
                                 BackgroundHookCallback callback, void *context);
int ftl_unregister_background_hook(struct ssd *ssd, int hook_handle);
int ftl_inactivate_background_hook(struct ssd *ssd, int hook_handle);
int ftl_reactivate_background_hook(struct ssd *ssd, int hook_handle);

#ifdef FEMU_DEBUG_FTL
#define ftl_debug(fmt, ...) \
    do { printf("[FEMU] FTL-Dbg: " fmt, ## __VA_ARGS__); } while (0)
#else
#define ftl_debug(fmt, ...) \
    do { } while (0)
#endif

#define ftl_err(fmt, ...) \
    do { fprintf(stderr, "[FEMU] FTL-Err: " fmt, ## __VA_ARGS__); } while (0)

#define ftl_log(fmt, ...) \
    do { printf("[FEMU] FTL-Log: " fmt, ## __VA_ARGS__); } while (0)


/* FEMU assert() */
#ifdef FEMU_DEBUG_FTL
#define ftl_assert(expression) assert(expression)
#else
#define ftl_assert(expression)
#endif

/*
 * ============================================================================
 * FTL POLICY EXAMPLE
 * ============================================================================
 * 
 * Below is an example of how to implement an FTL policy using the hook system.
 * This example shows a simple address permutation policy for reads.
 * 
 * Example: Read Permutation Policy
 * ---------------------------------
 * This policy intercepts read requests and reads data from permuted physical
 * addresses, demonstrating how to transform I/O operations.
 * 
 * struct PermutationContext {
 *     uint64_t seed;
 *     // ... other policy state
 * };
 * 
 * // Condition: only apply to multi-page reads (and check it's a read event)
 * bool permutation_condition(struct ssd *ssd, struct FtlEvent *event, 
 *                            struct FtlPolicyAPI *api, void *ctx)
 * {
 *     // Check event type AND other conditions
 *     return (event->cmd == FTL_READ_EVENT) && (event->lpn_cnt > 1);
 * }
 * 
 * // Policy callback
 * uint64_t permutation_read_policy(struct ssd *ssd, struct FtlEvent *event, 
 *                                   struct FtlPolicyAPI *api, void *ctx)
 * {
 *     struct PermutationContext *pctx = (struct PermutationContext *)ctx;
 *     const struct bbm_geom *geom = ssd->bbm->geom;
 *     const struct ssdparams *spp = &ssd->fb->sp;
 *     uint64_t page_size = spp->secs_per_pg * spp->secsz;
 *     
 *     // Allocate buffers for permuted pages
 *     uint8_t **page_buffers = g_malloc0(sizeof(uint8_t*) * event->lpn_cnt);
 *     PseudoPpa *permuted_ppas = g_malloc0(sizeof(PseudoPpa) * event->lpn_cnt);
 *     
 *     // Apply permutation logic using API
 *     for (uint64_t i = 0; i < event->lpn_cnt; i++) {
 *         uint64_t lpn = event->start_lpn + i;
 *         // Get mapping using API
 *         PseudoPpa original_ppa = api->get_maptbl_ent(ssd, lpn);
 *         // Your custom permutation function
 *         permuted_ppas[i] = your_permutation_func(ssd, original_ppa, pctx->seed);
 *         page_buffers[i] = g_malloc(page_size);
 *     }
 *     
 *     // Read from permuted locations using raw read
 *     struct BbmEvent bbm_event = {
 *         .cmd = BBM_EVENT_READ,
 *         .type = BBM_EVENT_USER_IO,
 *         .count = event->lpn_cnt,
 *         .status_list = g_malloc0(sizeof(int) * event->lpn_cnt),
 *         .stime = event->stime,
 *         .lat = 0
 *     };
 *     
 *     // Use BBM API through FTL API
 *     for (uint64_t i = 0; i < event->lpn_cnt; i++) {
 *         api->bbm_api->raw_read(ssd->fb, ssd->bbm, page_buffers[i], 
 *                                &permuted_ppas[i], 1, page_size, &bbm_event);
 *     }
 *     
 *     // Write data back to request buffer in correct order using API
 *     uint64_t offset = 0;
 *     for (uint64_t i = 0; i < event->lpn_cnt; i++) {
 *         api->write_request_data(event->req, page_buffers[i], 
 *                                 offset, page_size);
 *         offset += page_size;
 *         g_free(page_buffers[i]);
 *     }
 *     
 *     g_free(page_buffers);
 *     g_free(permuted_ppas);
 *     g_free(bbm_event.status_list);
 *     
 *     return bbm_event.lat;
 * }
 * 
 * // Policy registration (during initialization)
 * void register_permutation_policy(struct ssd *ssd)
 * {
 *     struct PermutationContext *ctx = g_malloc0(sizeof(struct PermutationContext));
 *     ctx->seed = 0x12345;
 *     
 *     // Register NVMe opcode hook for reads
 *     int handle = ftl_register_nvme_hook(ssd, NVME_CMD_READ, permutation_condition,
 *                                         permutation_read_policy, ctx);
 *     if (handle < 0) {
 *         ftl_err("Failed to register permutation policy\n");
 *         g_free(ctx);
 *     }
 * }
 * 
 * // Note: Multiple policies can be registered to the same hooks array.
 * // The condition function determines which events each policy handles.
 * // For example, a write compression policy would check:
 * //   if (event->cmd == FTL_WRITE_EVENT && should_compress(event))
 * // This allows flexible policy composition without separate hook arrays.
 * 
 * ============================================================================
 */

#endif
