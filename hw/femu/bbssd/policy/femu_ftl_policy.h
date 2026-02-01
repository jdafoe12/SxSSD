#ifndef FEMU_FTL_POLICY_H
#define FEMU_FTL_POLICY_H

#include "femu_policy_types.h"
#include "../policy-engine-types.h"
#include "../../nvme.h"

/*
 * FEMU FTL Policy API - Public interface for external policy .so files
 * 
 * This header provides the complete API needed to write custom FTL policies
 * that can be dynamically loaded into FEMU at runtime.
 */

/* Maximum number of FTL event hooks that can be registered */
#define MAX_FTL_EVENT_HOOKS (256)
#define MAX_NVME_HOOKS (256)

/* FTL event command types */
enum FtlEventCmd {
    FTL_WRITE_EVENT,
    FTL_READ_EVENT,
    FTL_TRIM_EVENT
};

/*
 * FTL Event structure - passed to policy hooks on I/O operations
 * 
 * Contains all information about a read/write/trim operation including
 * address ranges, data buffers (via req), and timing information.
 */
struct FtlEvent {
    enum FtlEventCmd cmd;
    
    /* Address range information */
    uint64_t lba;           /* Starting logical block address (sector number) */
    uint64_t nsecs;         /* Number of sectors in this operation */
    uint64_t start_lpn;     /* Starting logical page number */
    uint64_t end_lpn;       /* Ending logical page number */
    uint64_t lpn_cnt;       /* Number of pages affected */
    
    /* Request and buffer information (opaque to policy) */
    struct NvmeRequest *req;  /* Original NVMe request - use API buffer functions */
    
    /* Timing information */
    uint64_t stime;         /* Start time of the operation */
    uint64_t lat;           /* Latency to be filled in by handler */
};

/* Forward declarations */
struct FtlPolicyAPI;
struct BbmPolicyAPI;
struct FtlMigrationCallbacks;
struct NvmeCommandEvent;

/*
 * FTL Event Hook Condition Function Type
 * 
 * Determines if an event should trigger your policy hook.
 * 
 * Parameters:
 *   - ssd: FTL context (mostly opaque, use API functions)
 *   - event: the FTL event to evaluate
 *   - api: pointer to FTL policy API
 *   - context: your policy-specific data passed during registration
 * 
 * Returns: true if the hook should fire for this event, false otherwise
 * 
 * Example:
 *   bool my_condition(struct ssd *ssd, struct FtlEvent *event,
 *                     struct FtlPolicyAPI *api, void *context) {
 *       return event->cmd == FTL_WRITE_EVENT && event->start_lpn < 1000;
 *   }
 */
typedef bool (*FtlEventHookCondition)(struct ssd *ssd,
                                      struct FtlEvent *event,
                                      struct FtlPolicyAPI *api,
                                      void *context);

/*
 * FTL Event Hook Callback Function Type
 * 
 * Your policy's handler for matched events. This function performs the
 * actual I/O operation and returns the latency.
 * 
 * Parameters:
 *   - ssd: FTL context
 *   - event: the FTL event that triggered this hook
 *   - api: pointer to FTL policy API for performing operations
 *   - context: your policy-specific data passed during registration
 * 
 * Returns: Total latency of the operation in nanoseconds
 * 
 * Example:
 *   uint64_t my_callback(struct ssd *ssd, struct FtlEvent *event,
 *                        struct FtlPolicyAPI *api, void *context) {
 *       // Custom write logic here
 *       return api->default_write(ssd, event->req);
 *   }
 */
typedef uint64_t (*FtlEventHookCallback)(struct ssd *ssd,
                                         struct FtlEvent *event,
                                         struct FtlPolicyAPI *api,
                                         void *context);

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
 * Read PPA resolver: policy provides this so the FTL can perform a user read
 * through BBM. For each LPN in the request range, the resolver returns true
 * and fills *out with a valid mapped PPA to read, or false to skip that LPN.
 */
typedef bool (*ReadPpaResolver)(void *ctx, struct ssd *ssd, uint64_t lpn, PseudoPpa *out);

/*
 * FTL Policy API - Mechanism-level primitives for policies
 * 
 * This structure provides ONLY mechanism operations: eSWD primitives, migration,
 * validity tracking, and hook registration. Policies implement their own mapping
 * layer, I/O handlers, GC logic, and allocation strategy on top of these primitives.
 * 
 * Mechanism = eSWD + migration infrastructure (stable, reusable)
 * Policy = translation layer + I/O + GC + allocation (pluggable, varied)
 * 
 * Example: Block interface policy owns LPN→PPA mapping and implements read/write/trim.
 *          ZNS policy would not have LPN→PPA at all, working directly with eSWDs.
 */
struct FtlPolicyAPI {
    uint32_t version;  /* API version for compatibility checking */
    
    /* === eSWD Query Operations (mechanism exposes eSWD state) === */
    
    /* Get eSWD by ID (returns internal struct eswd*) */
    void *(*get_eswd_by_id)(struct ssd *ssd, uint32_t eswd_id);
    
    /* Get eSWD containing this PPA (returns internal struct eswd*) */
    void *(*get_eswd_by_ppa)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Get eSWD valid/invalid page counts */
    void (*get_eswd_vpc_ipc)(struct ssd *ssd, uint32_t eswd_id, int *vpc, int *ipc);
    
    /* Get eSWD write pointer index (0..pgs_per_eswd-1) */
    uint32_t (*get_eswd_wp_index)(struct ssd *ssd, uint32_t eswd_id);
    
    /* Get total number of eSWDs */
    uint32_t (*get_total_eswds)(struct ssd *ssd);
    
    /* Get total logical pages (after overprovisioning) */
    uint64_t (*get_total_logical_pages)(struct ssd *ssd);
    
    /* === eSWD State Modification (mechanism updates eSWD struct) === */
    
    /* Set eSWD valid/invalid page counts (policy tracks this for queues) */
    void (*eswd_set_vpc_ipc)(struct ssd *ssd, uint32_t eswd_id, int vpc, int ipc);
    
    /* Increment eSWD write pointer */
    void (*eswd_increment_wp)(struct ssd *ssd, uint32_t eswd_id);
    
    /* Reset eSWD to initial state (vpc=ipc=wp=0, for marking free) */
    void (*eswd_reset)(struct ssd *ssd, uint32_t eswd_id);
    
    /* === eSWD Layout Query (mechanism owns layout, policy uses for translation) === */
    
    /* Convert (eSWD ID, page index) → PPA */
    int (*eswd_id_to_ppa)(struct ssd *ssd, uint32_t eswd_id, uint32_t page_index, PseudoPpa *ppa);
    
    /* Convert PPA → (eSWD ID, page index) */
    int (*ppa_to_eswd_id)(struct ssd *ssd, const PseudoPpa *ppa, uint32_t *eswd_id, uint32_t *page_index);
    
    /* Get first-page PPA of block within eSWD (for GC iteration) */
    int (*eswd_block_to_ppa)(struct ssd *ssd, uint32_t eswd_id, uint32_t block_index, PseudoPpa *ppa);
    
    /* === Migration API (mechanism performs copy, policy decides when/which/validity) === */
    
    /* Migrate valid pages from src_eswd to dst_eswd
     * - is_valid callback: policy decides if page should be migrated
     * - on_migrated callback: policy updates mapping after each page migration
     * - callbacks, policy_ctx: optional; if set, on_destination_full used when dest full
     * Returns: number of pages migrated, or -1 on error */
    int (*migrate_eswd_pages)(struct ssd *ssd,
                              uint32_t src_eswd_id,
                              uint32_t dst_eswd_id,
                              MigrationValidityCallback is_valid,
                              MigrationResultCallback on_migrated,
                              void *context,
                              struct FtlMigrationCallbacks *callbacks,
                              void *policy_ctx);
    
    /* === Remapping API (mechanism updates eSWD→physical mapping for wear leveling) === */
    
    /* Remap an eSWD to different physical blocks (for wear leveling, bad block avoidance)
     * Returns: 0 on success, -1 on error */
    int (*remap_eswd_to_physical)(struct ssd *ssd,
                                  uint32_t eswd_id,
                                  uint8_t target_ch,
                                  uint8_t target_lun,
                                  uint8_t target_pl,
                                  uint16_t target_blk_start);
    
    /* === Validity Tracking (mechanism updates backend validity) === */
    
    /* Mark a physical page as valid (contains current data) */
    void (*mark_page_valid)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Mark a physical page as invalid (stale data, can be GC'd) */
    void (*mark_page_invalid)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Mark a block as free (after erase, can be written) */
    void (*mark_block_free)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* === Address Validation (mechanism checks against geometry) === */
    
    /* Check if a physical page address is valid */
    bool (*valid_ppa)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Check if a physical page is mapped (not UNMAPPED_PPA) */
    bool (*mapped_ppa)(PseudoPpa *ppa);
    
    /* === Hardware Accessors (mechanism provides access to channels/LUNs) === */
    
    /* Get LUN metadata (internal struct nand_lun*) */
    void *(*get_lun)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Get channel metadata (internal struct ssd_channel*) */
    void *(*get_ch)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* === Buffer Helpers (mechanism provides request data access) === */
    
    /* Get the total buffer size of a request */
    uint64_t (*get_request_buffer_size)(struct NvmeRequest *req);
    
    /* Copy data from request buffer (returns allocated buffer, caller must free) */
    uint8_t *(*copy_request_data)(struct NvmeRequest *req, uint64_t offset,
                                   uint64_t length, uint64_t *out_size);
    
    /* Write data to request buffer */
    uint64_t (*write_request_data)(struct NvmeRequest *req, const uint8_t *buffer,
                                    uint64_t offset, uint64_t length);

    /* === Hook Registration (mechanism provides event system) === */
    
    /* NVMe command hooks (opcode-keyed) */
    int (*register_nvme_hook)(struct ssd *ssd, uint8_t opcode,
                             NvmeHookCondition condition,
                             NvmeHookCallback callback,
                             void *context);
    int (*unregister_nvme_hook)(struct ssd *ssd, int hook_handle);
    int (*inactivate_nvme_hook)(struct ssd *ssd, int hook_handle);
    int (*reactivate_nvme_hook)(struct ssd *ssd, int hook_handle);
    
    /* Backend event hooks */
    int (*register_backend_hook)(struct ssd *ssd, BackendEventHookCondition condition,
                                 BackendEventHookCallback callback, void *context);
    int (*unregister_backend_hook)(struct ssd *ssd, int hook_handle);
    int (*inactivate_backend_hook)(struct ssd *ssd, int hook_handle);
    int (*reactivate_backend_hook)(struct ssd *ssd, int hook_handle);
    
    /* pSWD state transition hooks */
    int (*register_pswd_transition_hook)(struct ssd *ssd, PswdTransitionHookCondition condition,
                                         PswdTransitionHookCallback callback, void *context);
    int (*unregister_pswd_transition_hook)(struct ssd *ssd, int hook_handle);
    int (*inactivate_pswd_transition_hook)(struct ssd *ssd, int hook_handle);
    int (*reactivate_pswd_transition_hook)(struct ssd *ssd, int hook_handle);
    
    /* Background hooks (e.g. periodic GC check) */
    int (*register_background_hook)(struct ssd *ssd, BackgroundHookCondition condition,
                                    BackgroundHookCallback callback, void *context);
    int (*unregister_background_hook)(struct ssd *ssd, int hook_handle);
    int (*inactivate_background_hook)(struct ssd *ssd, int hook_handle);
    int (*reactivate_background_hook)(struct ssd *ssd, int hook_handle);

    /* === eSWD Config (policy sets at init to define striping and layout) === */
    void (*set_eswd_config)(struct ssd *ssd, const struct eswd_config *config);

    /* === GC mapping update (policy provides; mechanism calls when migrating a page in legacy GC path) === */
    void (*gc_update_mapping)(struct ssd *ssd, PseudoPpa *old_ppa, PseudoPpa *new_ppa); // TODO: definitely remove this.

    /* === User read through BBM (mechanism builds PPA list via policy resolver and calls BBM) === */
    uint64_t (*read_user_request)(struct ssd *ssd, struct NvmeCommandEvent *event,
                                  ReadPpaResolver resolve_ppa, void *resolve_ctx);
    /* === User write through BBM (mechanism performs BBM write for policy-supplied PPA list) === */
    uint64_t (*write_user_request)(struct ssd *ssd, NvmeRequest *req,
                                   PseudoPpa *ppa_list, uint64_t ppa_cnt);

    /* === BBM API Pass-through (mechanism provides backend I/O and validity operations) === */
    struct BbmPolicyAPI *bbm_api;
};

/*
 * === Policy Entry Point ===
 * 
 * Every policy .so file MUST implement this function.
 * FEMU calls this during policy initialization.
 * 
 * Parameters:
 *   - ssd: FTL context to register hooks on
 *   - api: Complete FTL policy API function table
 * 
 * Returns: 0 on success, non-zero on failure
 * 
 * Example:
 *   int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api) {
 *       // Register NVMe opcode hooks, e.g. api->register_nvme_hook(ssd, NVME_CMD_READ, ...)
 *       return 0;
 *   }
 */
typedef int (*policy_init_fn)(struct ssd *ssd, struct FtlPolicyAPI *api);

#endif /* FEMU_FTL_POLICY_H */

