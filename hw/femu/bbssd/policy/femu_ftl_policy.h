#ifndef FEMU_FTL_POLICY_H
#define FEMU_FTL_POLICY_H

#include "femu_policy_types.h"

/*
 * FEMU FTL Policy API - Public interface for external policy .so files
 * 
 * This header provides the complete API needed to write custom FTL policies
 * that can be dynamically loaded into FEMU at runtime.
 */

/* Maximum number of FTL event hooks that can be registered */
#define MAX_FTL_EVENT_HOOKS (256)

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
 * FTL Policy API - Function pointer table provided to policies
 * 
 * This structure contains all functions your policy can call to interact
 * with the FTL layer. It's passed to your init_policy() function and
 * to all hook callbacks.
 */
struct FtlPolicyAPI {
    uint32_t version;  /* API version for compatibility checking */
    
    /* === Mapping Operations === */
    
    /* Get the physical address for a logical page */
    PseudoPpa (*get_maptbl_ent)(struct ssd *ssd, uint64_t lpn);
    
    /* Set the physical address for a logical page */
    void (*set_maptbl_ent)(struct ssd *ssd, uint64_t lpn, PseudoPpa *ppa);
    
    /* Get the logical page number that maps to a physical address */
    uint64_t (*get_rmap_ent)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Set reverse mapping entry */
    void (*set_rmap_ent)(struct ssd *ssd, uint64_t lpn, PseudoPpa *ppa);
    
    /* === Address Validation === */
    
    /* Check if a logical page number is valid */
    bool (*valid_lpn)(struct ssd *ssd, uint64_t lpn);
    
    /* Check if a physical page address is valid */
    bool (*valid_ppa)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Check if a physical page is mapped (not UNMAPPED_PPA) */
    bool (*mapped_ppa)(PseudoPpa *ppa);
    
    /* === Page Allocation === */
    
    /* Allocate a new physical page for writing */
    PseudoPpa (*get_new_page)(struct ssd *ssd);
    
    /* Advance the write pointer after allocation */
    void (*advance_write_pointer)(struct ssd *ssd);
    
    /* Get the next free line for writing (internal struct line*) */
    void *(*get_next_free_line)(struct ssd *ssd);
    
    /* === Metadata Management === */
    
    /* Mark a physical page as valid (contains current data) */
    void (*mark_page_valid)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Mark a physical page as invalid (stale data, can be GC'd) */
    void (*mark_page_invalid)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Mark a block as free (can be erased and reused) */
    void (*mark_block_free)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Mark an entire line as free */
    void (*mark_line_free)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* === Garbage Collection === */
    
    /* Check if GC should be triggered (low threshold) */
    bool (*should_gc)(struct ssd *ssd);
    
    /* Check if GC should be triggered urgently (high threshold) */
    bool (*should_gc_high)(struct ssd *ssd);
    
    /* Perform garbage collection (force=true to GC even if not needed) */
    int (*do_gc)(struct ssd *ssd, bool force);
    
    /* Select a victim line for garbage collection (internal struct line*) */
    void *(*select_victim_line)(struct ssd *ssd, bool force);
    
    /* Clean (garbage collect) one block */
    void (*clean_one_block)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* === Block/Page Accessors === */
    /* Note: These return internal FEMU structures (opaque pointers) */
    
    /* Get block metadata (internal struct nand_block*) */
    void *(*get_blk)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Get line metadata (internal struct line*) */
    void *(*get_line)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Get page metadata (internal struct nand_page*) */
    void *(*get_pg)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Get LUN metadata (internal struct nand_lun*) */
    void *(*get_lun)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Get channel metadata (internal struct ssd_channel*) */
    void *(*get_ch)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* === Buffer Helpers (for NvmeRequest data access) === */
    
    /* Get the total buffer size of a request */
    uint64_t (*get_request_buffer_size)(struct NvmeRequest *req);
    
    /* Copy data from request buffer (returns allocated buffer, caller must free) */
    uint8_t *(*copy_request_data)(struct NvmeRequest *req, uint64_t offset,
                                   uint64_t length, uint64_t *out_size);
    
    /* Write data to request buffer */
    uint64_t (*write_request_data)(struct NvmeRequest *req, const uint8_t *buffer,
                                    uint64_t offset, uint64_t length);
    
    /* === Default FTL Implementations === */
    
    /* Default read implementation - call this if you just want standard behavior */
    uint64_t (*default_read)(struct ssd *ssd, struct NvmeRequest *req);
    
    /* Default write implementation - call this if you just want standard behavior */
    uint64_t (*default_write)(struct ssd *ssd, struct NvmeRequest *req);
    
    /* Get total logical pages (after overprovisioning) */
    uint64_t (*get_total_logical_pages)(struct ssd *ssd);
    
    /* Hook registration */
    int (*register_hook)(struct ssd *ssd,
                         FtlEventHookCondition condition,
                         FtlEventHookCallback callback,
                         void *context);
    
    /* BBM API pass-through (for convenience) */
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
 *       // Register your hooks here
 *       int handle = api->register_hook(ssd, my_condition, my_callback, NULL);
 *       if (handle < 0) {
 *           return -1;  // Registration failed
 *       }
 *       return 0;
 *   }
 */
typedef int (*policy_init_fn)(struct ssd *ssd, struct FtlPolicyAPI *api);

#endif /* FEMU_FTL_POLICY_H */

