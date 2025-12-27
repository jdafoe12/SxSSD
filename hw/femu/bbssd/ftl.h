#ifndef __FEMU_FTL_H
#define __FEMU_FTL_H

#include "../nvme.h"
#include "./bbm.h" // we have access to PseudoPpa and PseudoPba through this.

struct FtlBackend;
struct FtlPolicyAPI;  /* Forward declaration */

#define INVALID_PPA     (~(0ULL))
#define INVALID_LPN     (~(0ULL))
#define UNMAPPED_PPA    (~(0ULL))

#define MAX_FTL_EVENT_HOOKS (256)

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

enum {
    SEC_FREE = 0,
    SEC_INVALID = 1,
    SEC_VALID = 2,

    PG_FREE = 0,
    PG_INVALID = 1,
    PG_VALID = 2
};

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

typedef int nand_sec_status_t;

struct nand_page { // the nand_page, nand_block and such shoudl stay in the ftl. This is becuase they purely track the metadata at different granularities.
                   // the geometry needed by the backend is mostly the things currently in the ssd struct.
    nand_sec_status_t *sec;
    int nsecs;
    int status;
};

struct nand_block {
    struct nand_page *pg;
    int npgs;
    int ipc; /* invalid page count */
    int vpc; /* valid page count */
   // int erase_cnt;
    int wp; /* current write pointer */
};

struct nand_plane {
    struct nand_block *blk;
    int nblks;
};

struct nand_lun {
    struct nand_plane *pl;
    int npls;
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

typedef struct line {
    int id;  /* line id, the same as corresponding block id */
    int ipc; /* invalid page count in this line */
    int vpc; /* valid page count in this line */
    QTAILQ_ENTRY(line) entry; /* in either {free,victim,full} list */
    /* position in the priority queue for victim lines */
    size_t                  pos;
} line;

/* wp: record next write addr */
struct write_pointer {
    struct line *curline;
    int ch;
    int lun;
    int pg;
    int blk;
    int pl;
};

struct line_mgmt {
    struct line *lines;
    /* free line list, we only need to maintain a list of blk numbers */
    QTAILQ_HEAD(free_line_list, line) free_line_list;
    pqueue_t *victim_line_pq;
    //QTAILQ_HEAD(victim_line_list, line) victim_line_list;
    QTAILQ_HEAD(full_line_list, line) full_line_list;
    int tt_lines;
    int free_line_cnt;
    int victim_line_cnt;
    int full_line_cnt;
};

/*struct nand_cmd {
    int type;
    int cmd;
    int64_t stime; 
};*/

/*
 * FTL Policy API - Function pointer table for FTL operations
 * 
 * This structure provides a stable interface for policies to interact with
 * the FTL layer without requiring access to internal implementation details.
 * Plugins receive this API at runtime and use it to perform FTL operations.
 */
  /* TODO: I need to more carefully define what is exposed via this API. 
          Some of these functions should be internal! (i.e. only exposed internally to ftl.c) */
struct FtlPolicyAPI {
    uint32_t version;  /* API version for compatibility checking */
    
    /* Mapping operations */
    PseudoPpa (*get_maptbl_ent)(struct ssd *ssd, uint64_t lpn);
    void (*set_maptbl_ent)(struct ssd *ssd, uint64_t lpn, PseudoPpa *ppa);
    uint64_t (*get_rmap_ent)(struct ssd *ssd, PseudoPpa *ppa);
    void (*set_rmap_ent)(struct ssd *ssd, uint64_t lpn, PseudoPpa *ppa);
    
    /* Address validation */
    bool (*valid_lpn)(struct ssd *ssd, uint64_t lpn);
    bool (*valid_ppa)(struct ssd *ssd, PseudoPpa *ppa);
    bool (*mapped_ppa)(PseudoPpa *ppa);
    
    /* Page allocation */
    PseudoPpa (*get_new_page)(struct ssd *ssd);
    void (*advance_write_pointer)(struct ssd *ssd);
    struct line *(*get_next_free_line)(struct ssd *ssd);
    
    /* Metadata management */
    void (*mark_page_valid)(struct ssd *ssd, PseudoPpa *ppa);
    void (*mark_page_invalid)(struct ssd *ssd, PseudoPpa *ppa);
    void (*mark_block_free)(struct ssd *ssd, PseudoPpa *ppa);
    void (*mark_line_free)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Garbage collection */
    bool (*should_gc)(struct ssd *ssd);
    bool (*should_gc_high)(struct ssd *ssd);
    int (*do_gc)(struct ssd *ssd, bool force);
    struct line *(*select_victim_line)(struct ssd *ssd, bool force);
    void (*clean_one_block)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Block/page accessors */
    struct nand_block *(*get_blk)(struct ssd *ssd, PseudoPpa *ppa);
    struct line *(*get_line)(struct ssd *ssd, PseudoPpa *ppa);
    struct nand_page *(*get_pg)(struct ssd *ssd, PseudoPpa *ppa);
    struct nand_lun *(*get_lun)(struct ssd *ssd, PseudoPpa *ppa);
    struct ssd_channel *(*get_ch)(struct ssd *ssd, PseudoPpa *ppa);
    
    /* Buffer helpers (from request) */
    uint64_t (*get_request_buffer_size)(NvmeRequest *req);
    uint8_t *(*copy_request_data)(NvmeRequest *req, uint64_t offset, 
                                   uint64_t length, uint64_t *out_size);
    uint64_t (*write_request_data)(NvmeRequest *req, const uint8_t *buffer,
                                    uint64_t offset, uint64_t length);
    
    /* Default FTL implementations (for policies to call or wrap) */
    uint64_t (*default_read)(struct ssd *ssd, NvmeRequest *req);
    uint64_t (*default_write)(struct ssd *ssd, NvmeRequest *req);
    
    /* BBM API pass-through (for convenience) */
    struct BbmPolicyAPI *bbm_api;
};

struct ssd { // This needs to be dissected and probably renamed
    char *ssdname;
    struct FtlBackend *fb; /* backend timing/error model */
    struct bbm *bbm;     /* bad block manager / OP mapping context */
   // struct ssdparams sp;
    struct ssd_channel *ch;
    PseudoPpa *maptbl; /* page level mapping table */
    uint64_t *rmap;     /* reverse mapptbl, assume it's stored in OOB */
    struct write_pointer wp;
    struct line_mgmt lm;

    /* lockless ring for communication with NVMe IO thread */
    struct rte_ring **to_ftl;
    struct rte_ring **to_poller;
    bool *dataplane_started_ptr;
    QemuThread ftl_thread;

    /* 
     * Event hook registry for FTL policy extensibility.
     * Policies register hooks during initialization to intercept I/O events.
     * When I/O operations arrive, ftl_event_handle() iterates through
     * this array and invokes active hooks whose conditions match the event.
     * 
     * Note: Single unified array for all event types (read/write/trim).
     * The condition function filters events by type (event->cmd) and other criteria.
     */
    struct FtlEventHook hooks[MAX_FTL_EVENT_HOOKS];
    
    /*
     * FTL Policy API - function pointer table for policies.
     * Initialized at ssd_init() to point to implementation functions.
     * Policies receive this API to interact with FTL layer.
     */
    struct FtlPolicyAPI *policy_api;
};

void ssd_init(FemuCtrl *n);

/* Bootstrap policy initialization */
int init_policy(struct ssd *ssd);

/* FTL entry points (called from ftl_thread) */
uint64_t ftl_read(struct ssd *ssd, NvmeRequest *req);
uint64_t ftl_write(struct ssd *ssd, NvmeRequest *req);

/* Event filling helpers */
void ftl_fill_read_event(struct ssd *ssd, NvmeRequest *req, struct FtlEvent *event);
void ftl_fill_write_event(struct ssd *ssd, NvmeRequest *req, struct FtlEvent *event);

/* Mapping table operations */
PseudoPpa get_maptbl_ent(struct ssd *ssd, uint64_t lpn);
void set_maptbl_ent(struct ssd *ssd, uint64_t lpn, PseudoPpa *ppa);
uint64_t get_rmap_ent(struct ssd *ssd, PseudoPpa *ppa);
void set_rmap_ent(struct ssd *ssd, uint64_t lpn, PseudoPpa *ppa);

/* Address validation */
bool valid_lpn(struct ssd *ssd, uint64_t lpn);
bool valid_ppa(struct ssd *ssd, PseudoPpa *ppa);
bool mapped_ppa(PseudoPpa *ppa);

/* Page allocation */
PseudoPpa get_new_page(struct ssd *ssd);
void ssd_advance_write_pointer(struct ssd *ssd);
struct line *get_next_free_line(struct ssd *ssd);

/* Metadata management */
void mark_page_valid(struct ssd *ssd, PseudoPpa *ppa);
void mark_page_invalid(struct ssd *ssd, PseudoPpa *ppa);
void mark_block_free(struct ssd *ssd, PseudoPpa *ppa);
void mark_line_free(struct ssd *ssd, PseudoPpa *ppa);

/* Garbage collection */
bool should_gc(struct ssd *ssd);
bool should_gc_high(struct ssd *ssd);
int do_gc(struct ssd *ssd, bool force);
struct line *select_victim_line(struct ssd *ssd, bool force);
void clean_one_block(struct ssd *ssd, PseudoPpa *ppa);

/* Block/page accessors */
struct nand_block *get_blk(struct ssd *ssd, PseudoPpa *ppa);
struct line *get_line(struct ssd *ssd, PseudoPpa *ppa);
struct nand_page *get_pg(struct ssd *ssd, PseudoPpa *ppa);
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

/* FTL Event Handling and Policy Infrastructure */

/**
 * ftl_event_handle - Dispatch an FTL event to registered policy hooks
 * @ssd: SSD/FTL context
 * @event: The FTL event (read/write) to process
 * 
 * Iterates through registered hooks for the event type (read or write),
 * evaluates their conditions, and invokes matching callbacks.
 * If no hooks handle the event, falls back to default behavior.
 * 
 * Returns: Latency in nanoseconds for the operation
 * 
 * Note: Passing the entire SSD struct conforms with Bell-LaPadula as policies
 * are trusted code running at the FTL level. TODO: Make sure we can enforce Bell-LaPadula throughout the design???? maybe? 
 */
uint64_t ftl_event_handle(struct ssd *ssd, struct FtlEvent *event);

/* FTL Event hook management */

/**
 * ftl_register_hook - Register a policy hook for read events
 * @ssd: SSD/FTL context
 * @condition: function that determines if event should trigger hook (NULL = always trigger)
 * @callback: function to invoke when event condition is met
 * @context: opaque policy-specific data passed to both condition and callback
 * 
 * Returns: hook handle (>= 0) on success, -1 on failure (e.g., no slots available)
 * 
 * Example usage:
 *   // Hook that fires on reads spanning multiple pages
 *   bool multi_page_condition(struct ssd *ssd, struct FtlEvent *event, void *ctx) {
 *       return event->lpn_cnt > 1;
 *   }
 *   ftl_register_hook(ssd, multi_page_condition, my_callback, my_context);
 */
int ftl_register_hook(struct ssd *ssd,
                           FtlEventHookCondition condition,
                           FtlEventHookCallback callback,
                           void *context);


/**
 * ftl_unregister_read_hook - Unregister a hook
 * @ssd: SSD/FTL context
 * @hook_handle: handle returned by ftl_register_hook
 * 
 * Returns: 0 on success, -1 on failure
 */
int ftl_unregister_hook(struct ssd *ssd, int hook_handle);

/**
 * ftl_inactivate_hook - Temporarily disable a hook
 * @ssd: SSD/FTL context
 * @hook_handle: handle returned by ftl_register_hook
 * 
 * Returns: 0 on success, -1 on failure
 */
int ftl_inactivate_hook(struct ssd *ssd, int hook_handle);

int ftl_reactivate_hook(struct ssd *ssd, int hook_handle);


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
 *     // Register the hook - condition function will filter for read events
 *     int handle = ftl_register_hook(ssd, permutation_condition, 
 *                                    permutation_read_policy, ctx);
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
