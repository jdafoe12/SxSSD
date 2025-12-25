#ifndef BBM_H
#define BBM_H

#include "../nvme.h"
#include "../backend/ftl-backend.h"

#define MAX_BACKEND_EVENT_HOOKS (256) // Very large for now. Probably can be much smaller.

// The essense of this layer is to 
// provide a pseudophysical block address layer

// Essentially, this layer is completely built on top of layer 0
// which is the FTL-backend.

// the complete FUNCTIONAL implementation of this layer is
// that it will respond to events from the backend. 
// These events are failure reports from the backend.

// The events are completely defined in the backend,
// and the pseudophysical block INTERFACE is standard.
// The extensibility, to support different policies,
// is achieved by providing specific functions that can be used to handle events.
// The policy calls this api to handle events.

// I think TABLES are key to the extensibility. 


// Should provide a lightweight read/write/erase interface which wraps the raw interface.
// The only difference is that the BBM is invoked.. This means that the operations are performed
// over the pseudophysical blocks.

// This is for the bbm backend. i.e. the "mapping engine".
// It should map from pseudophysical address to ppa. 


// IMPORTANT NOTE: we want to maintain parallelism. Thus, the "replaced" blocks should be in same (lun/channel?) as previous? 
// Something like this. double think/check.




/*
 * Pseudo-physical address types are aliases of the backend physical address
 * structs. BBM is responsible for translating between pseudo and physical.
 */
typedef struct ppa PseudoPpa;
typedef struct pba PseudoPba;

struct bbm;

/*
 * Event condition function type - determines if an event should trigger a hook.
 * Policies implement this to specify complex event matching criteria.
 * 
 * Parameters:
 *   - event: the backend event to evaluate
 *   - context: opaque policy-specific data passed during registration
 * 
 * Returns: true if the hook should fire for this event, false otherwise
 * 
 * Example conditions:
 *   - Reads with bit error count > threshold
 *   - Writes that failed
 *   - Erases on blocks with high erase count
 *   - Any arbitrary function of event->status_list, event->cmd, etc.
 */
typedef bool (*BackendEventHookCondition)(struct FtlBackendEvent *event,
                                   void *context);

/* 
 * BBM Event hook callback function type.
 * Policies implement this callback to handle backend events at the BBM level.
 * Parameters:
 *   - fb: pointer to the FTL backend
 *   - ctx: pointer to the BBM context
 *   - event: the backend event that triggered this hook
 *   - context: opaque policy-specific data passed during registration
 *   JOSH: Do we need this (context - maybe this can contain some kind of
                            data structures persistant across hooks/calls)? 
 */
typedef void (*BackendEventHookCallback)(struct FtlBackend *fb,
                                      const struct bbm *ctx,
                                      struct FtlBackendEvent *event,
                                      void *context);

/*
 * Event hook structure for extensible BBM policy attachment.
 * Policies register hooks during initialization, specifying:
 *   - An optional condition function (when to trigger)
 *   - What function to call (action)
 *   - Any policy-specific data needed (context)
 * 
 * The condition function allows arbitrary complexity in event matching.
 * If condition is NULL, the hook fires for all events.
 */
struct BackendEventHook {
    BackendEventHookCondition condition;   /* Optional: when should this hook fire? */
    BackendEventHookCallback callback; /* What function to call on event */
    void *context;                 /* Opaque policy-specific data */
    bool active;                   /* Is this hook slot in use? This is 
                                      important so that policies can be turned on and off
                                      at runtime */
                                                                 
};

/* Logical geometry (after OP/bad-block) maintained by BBM. */
struct bbm_geom {
    /* Block counts (logical, after overprovisioning) */
    uint32_t blks_per_pl_log;
    uint32_t blks_per_lun_log;
    uint32_t blks_per_ch_log;
    uint64_t tt_blks_log;

    /* Page counts (logical) */
    uint32_t pgs_per_blk;
    uint32_t pgs_per_pl;
    uint32_t pgs_per_lun;
    uint32_t pgs_per_ch;
    uint64_t tt_pgs_log;

    /* Line-level counts (for FTL striping) */
    uint32_t blks_per_line;
    uint32_t pgs_per_line;
    uint32_t tt_lines;

    /* Channel/LUN/Plane topology */
    uint32_t pls_per_lun;
    uint32_t luns_per_ch;
    uint32_t nchs;
    uint32_t tt_luns;

    uint32_t secs_per_pg;
    uint32_t secsz;
};

/* Simple BBM context tracking reserved (OP) blocks per LUN. */
struct bbm {
    /* Reserved blocks per LUN for overprovisioning */
    uint32_t reserved_per_lun;

    /* Flattened map: index = ((ch * luns_per_ch + lun) * blks_per_lun_log) + blk */
    /* Since the mapping level is blocks, a pseudoppa can be mapped by a ppa by 
     * changing only the block number. Since we keep overprovisioned blocks in each plane, 
     * this is all that needs to change. */
    struct pba *maptbl;

    /* Logical geometry (after overprovisioning) */
    struct bbm_geom *geom;

    /* 
     * Event hook registry for BBM policy extensibility.
     * Policies register hooks during initialization to respond to backend events.
     * When backend operations complete, backend_event_handle() iterates through
     * this array and invokes active hooks whose event_type matches the event.
     */
    struct BackendEventHook hooks[MAX_BACKEND_EVENT_HOOKS];
};

int bbm_init(struct bbm *ctx, const BbCtrlParams *bbp, const struct ssdparams *phys);
uint32_t bbm_blks_per_pl_log(const struct bbm *ctx);
struct pba bbm_get_maptbl_entry(const struct bbm *ctx,
                                const PseudoPba *ppba);
static inline bool bbm_is_reserved_blk(const struct bbm *ctx,
                                       uint32_t blk)
{
    return blk >= ctx->geom->blks_per_lun_log;
}

// Need raw functions and non-raw functions, like in the backend. (raw serve policies, while non-raw serve the host.)

enum BbmEventCmd {
    BBM_EVENT_READ,
    BBM_EVENT_WRITE,
    BBM_EVENT_ERASE,
};

enum BbmEventType {
    BBM_EVENT_POLICY_IO = 0,
    BBM_EVENT_USER_IO   = 1,
};

/* Event visible to FTL; BBM internally maps to backend events. */
struct BbmEvent {
    enum BbmEventCmd cmd;
    enum BbmEventType type;
    uint32_t count;
    int *status_list;    /* optional per-op status; allocated by caller if wanted */
    int64_t stime;       /* request start time */
    int64_t lat;         /* end-to-end latency as seen by BBM/FTL */
};

/* These are for serving NVMe requests directly. */
int bbm_read(struct FtlBackend *fb, const struct bbm *ctx,
             struct NvmeRequest *req, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
int bbm_write(struct FtlBackend *fb, const struct bbm *ctx,
              struct NvmeRequest *req, PseudoPpa *ppas,
              uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);

/* These are for direct operations on the FTL backend, without involving the host. */
int bbm_raw_read(struct FtlBackend *fb, const struct bbm *ctx,
                 uint8_t *buffer, PseudoPpa *ppas,
                 uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
int bbm_raw_write(struct FtlBackend *fb, const struct bbm *ctx,
                  uint8_t *buffer, PseudoPpa *ppas,
                  uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
int bbm_raw_erase(struct FtlBackend *fb, const struct bbm *ctx,
                  PseudoPba *pbns, uint64_t blk_count,
                  struct BbmEvent *event);

/*
 * Query erase count for a *pseudo* block address.
 * BBM translates pseudo -> physical and delegates to backend.
 * Returns >= 0 on success, -1 on invalid input.
 */
int bbm_get_erase_cnt(const struct FtlBackend *fb, const struct bbm *ctx,
                      const PseudoPba *ppba);

/* Josh: Now, need to present an interface to the upper layer in order
 * to implement the bbm policy layer. This interface needs to be general enouph 
 * to support any concievable bbm policy.*/


 /* BBM policy interface */
 /* This interface can be extended by the host, by
    writing a .so file that implements the extended interface to the 
    SSD. This is done by the host, and loaded into the SSD at runtime. */
int backend_event_handle(struct FtlBackend *fb, struct bbm *ctx,
                     struct FtlBackendEvent *event);

/* BBM Event hook management */
/*
 * Register a BBM event hook for a policy.
 * Policies call this during initialization to attach handlers to backend events.
 * 
 * Parameters:
 *   - ctx: BBM context
 *   - condition: function that determines if event should trigger hook (NULL = always trigger)
 *   - callback: function to invoke when event condition is met
 *   - context: opaque policy-specific data passed to both condition and callback
 * 
 * Returns: hook handle (>= 0) on success, -1 on failure (e.g., no slots available)
 * 
 * Example usage:
 *   // Hook that fires on reads with > 50 bit errors
 *   bool high_ber_condition(struct FtlBackend *fb, const struct bbm *ctx,
 *                           struct FtlBackendEvent *event, void *context) {
 *       if (event->cmd != FTL_BACKEND_EVENT_READ) return false;
 *       for (int i = 0; i < event->count; i++) {
 *           if (event->status_list[i] > 50) return true;
 *       }
 *       return false;
 *   }
 *   bbm_register_hook(ctx, high_ber_condition, my_callback, my_context);
 */
int bbm_register_hook(struct bbm *ctx,
                      BackendEventHookCondition condition,
                      BackendEventHookCallback callback,
                      void *context);

/*
 * Unregister a BBM event hook.
 * Returns: 0 on success, -1 on failure
 */
int bbm_unregister_hook(struct bbm *ctx, int hook_handle);

int bbm_mark_block_bad(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_sanitize_block(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_remap_block(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_shrink_ssd(struct FtlBackend *fb, const struct bbm *ctx);
// Need to see what is the ZNS / OCSSD strategy for BBM?

int bbm_read_retry(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_move_valid_data(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_move_all_data(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);


// I should actually have some "compiler" type thing.
// It will take conditions on function calls and translate to 
// events - so that all relevant events have the relevant functions called.

#endif
