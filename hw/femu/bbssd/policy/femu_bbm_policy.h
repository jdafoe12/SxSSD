#ifndef FEMU_BBM_POLICY_H
#define FEMU_BBM_POLICY_H

#include "femu_policy_types.h"

/*
 * FEMU BBM (Bad Block Management) Policy API
 * 
 * This header provides the BBM-layer interface for policies that need
 * to interact with bad block management, physical I/O, or respond to
 * backend events (bit errors, write failures, etc.).
 */

/* Backend event command types */
enum FtlBackendEventCmd {
    FTL_BACKEND_EVENT_READ,
    FTL_BACKEND_EVENT_WRITE,
    FTL_BACKEND_EVENT_ERASE
};

/* Backend event I/O type */
enum FtlBackendEventType {
    POLICY_IO = 0,  /* I/O initiated by policy/GC */
    USER_IO   = 1   /* I/O initiated by host */
};

/*
 * Backend Event Structure
 * 
 * Reported to BBM policies after physical I/O operations complete.
 * Contains error information and status for each page/block.
 */
struct FtlBackendEvent {
    enum FtlBackendEventCmd cmd;
    enum FtlBackendEventType type;
    uint32_t count;       /* Number of pages/blocks in operation */
    int *status_list;     /* Status array (interpretation depends on cmd):
                           * READ:  status_list[i] = bit error count for page i
                           * WRITE: status_list[i] = 0 (success) or 1 (failure)
                           * ERASE: status_list[i] = 0 (success) or 1 (failure) */
    int64_t stime;        /* Request start time */
    int64_t lat;          /* Total latency of operation */
};

/*
 * BBM Event Structure
 * 
 * Event structure visible to FTL policies for BBM operations.
 */
enum BbmEventCmd {
    BBM_EVENT_READ,
    BBM_EVENT_WRITE,
    BBM_EVENT_ERASE,
};

enum BbmEventType {
    BBM_EVENT_POLICY_IO = 0,
    BBM_EVENT_USER_IO   = 1,
};

struct BbmEvent {
    enum BbmEventCmd cmd;
    enum BbmEventType type;
    uint32_t count;
    int *status_list;    /* Optional per-op status; allocated by caller if wanted */
    int64_t stime;       /* Request start time */
    int64_t lat;         /* End-to-end latency as seen by BBM/FTL */
};

/*
 * BBM Policy API - Function pointer table for BBM operations
 * 
 * Provides stable interface for policies to perform low-level operations
 * like raw reads/writes, bad block management, and metadata queries.
 */
struct BbmPolicyAPI {
    uint32_t version;  /* API version for compatibility checking */
    
    /* === Address Translation === */
    
    /* Get the physical block address for a pseudo-physical block */
    struct pba (*get_maptbl_entry)(const struct bbm *ctx, const PseudoPba *ppba);
    
    /* Check if a block number is in the reserved (overprovisioning) area */
    bool (*is_reserved_blk)(const struct bbm *ctx, uint32_t blk);
    
    /* === I/O Operations (for host requests) === */
    
    /* Read using NVMe request (host I/O path) */
    int (*read)(struct FtlBackend *fb, const struct bbm *ctx,
                struct NvmeRequest *req, PseudoPpa *ppas,
                uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
    
    /* Write using NVMe request (host I/O path) */
    int (*write)(struct FtlBackend *fb, const struct bbm *ctx,
                 struct NvmeRequest *req, PseudoPpa *ppas,
                 uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
    
    /* === Raw I/O Operations (for policy/GC use) === */
    
    /* Raw read to buffer (for GC, scrubbing, etc.) */
    int (*raw_read)(struct FtlBackend *fb, const struct bbm *ctx,
                    uint8_t *buffer, PseudoPpa *ppas,
                    uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
    
    /* Raw write from buffer (for GC, etc.) */
    int (*raw_write)(struct FtlBackend *fb, const struct bbm *ctx,
                     uint8_t *buffer, PseudoPpa *ppas,
                     uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
    
    /* Raw block erase */
    int (*raw_erase)(struct FtlBackend *fb, const struct bbm *ctx,
                     PseudoPba *pbns, uint64_t blk_count, struct BbmEvent *event);
    #ifndef FEMU_BBM_POLICY_H
#define FEMU_BBM_POLICY_H

#include "femu_policy_types.h"

/*
 * FEMU BBM (Bad Block Management) Policy API
 * 
 * This header provides the BBM-layer interface for policies that need
 * to interact with bad block management, physical I/O, or respond to
 * backend events (bit errors, write failures, etc.).
 */

/* Backend event command types */
enum FtlBackendEventCmd {
    FTL_BACKEND_EVENT_READ,
    FTL_BACKEND_EVENT_WRITE,
    FTL_BACKEND_EVENT_ERASE
};

/* Backend event I/O type */
enum FtlBackendEventType {
    POLICY_IO = 0,  /* I/O initiated by policy/GC */
    USER_IO   = 1   /* I/O initiated by host */
};

/*
 * Backend Event Structure
 * 
 * Reported to BBM policies after physical I/O operations complete.
 * Contains error information and status for each page/block.
 */
struct FtlBackendEvent {
    enum FtlBackendEventCmd cmd;
    enum FtlBackendEventType type;
    uint32_t count;       /* Number of pages/blocks in operation */
    int *status_list;     /* Status array (interpretation depends on cmd):
                           * READ:  status_list[i] = bit error count for page i
                           * WRITE: status_list[i] = 0 (success) or 1 (failure)
                           * ERASE: status_list[i] = 0 (success) or 1 (failure) */
    int64_t stime;        /* Request start time */
    int64_t lat;          /* Total latency of operation */
};

/*
 * BBM Event Structure
 * 
 * Event structure visible to FTL policies for BBM operations.
 */
enum BbmEventCmd {
    BBM_EVENT_READ,
    BBM_EVENT_WRITE,
    BBM_EVENT_ERASE,
};

enum BbmEventType {
    BBM_EVENT_POLICY_IO = 0,
    BBM_EVENT_USER_IO   = 1,
};

struct BbmEvent {
    enum BbmEventCmd cmd;
    enum BbmEventType type;
    uint32_t count;
    int *status_list;    /* Optional per-op status; allocated by caller if wanted */
    int64_t stime;       /* Request start time */
    int64_t lat;         /* End-to-end latency as seen by BBM/FTL */
};

/*
 * BBM Policy API - Function pointer table for BBM operations
 * 
 * Provides stable interface for policies to perform low-level operations
 * like raw reads/writes, bad block management, and metadata queries.
 */
struct BbmPolicyAPI {
    uint32_t version;  /* API version for compatibility checking */
    
    /* === Address Translation === */
    
    /* Get the physical block address for a pseudo-physical block */
    struct pba (*get_maptbl_entry)(const struct bbm *ctx, const PseudoPba *ppba);
    
    /* Check if a block number is in the reserved (overprovisioning) area */
    bool (*is_reserved_blk)(const struct bbm *ctx, uint32_t blk);
    
    /* === I/O Operations (for host requests) === */
    
    /* Read using NVMe request (host I/O path) */
    int (*read)(struct FtlBackend *fb, const struct bbm *ctx,
                struct NvmeRequest *req, PseudoPpa *ppas,
                uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
    
    /* Write using NVMe request (host I/O path) */
    int (*write)(struct FtlBackend *fb, const struct bbm *ctx,
                 struct NvmeRequest *req, PseudoPpa *ppas,
                 uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
    
    /* === Metadata Queries === */
    
    /* Get erase count for a pseudo-physical block */
    int (*get_erase_cnt)(const struct FtlBackend *fb, const struct bbm *ctx,
                         const PseudoPba *ppba);
    
    /* === Bad Block Management Operations === */
    
    /* Mark a block as bad (permanent failure) */
    int (*mark_block_bad)(struct FtlBackend *fb, const struct bbm *ctx,
                          const struct ppa *ppa);
    
    /* Sanitize a block (attempt recovery) */
    int (*sanitize_block)(struct FtlBackend *fb, const struct bbm *ctx,
                          const struct ppa *ppa);
    
    /* Remap a block to a spare in the OP area */
    int (*remap_block)(struct FtlBackend *fb, const struct bbm *ctx,
                       const struct ppa *ppa);
};

/*
 * === Backend Event Hook Types ===
 * 
 * For policies that want to respond to low-level backend events
 * (bit errors, write failures, etc.)
 */

/* Backend event hook condition function */
typedef bool (*BackendEventHookCondition)(struct FtlBackendEvent *event,
                                          struct BbmPolicyAPI *api,
                                          void *context);

/* Backend event hook callback function */
typedef void (*BackendEventHookCallback)(struct FtlBackend *fb,
                                         const struct bbm *ctx,
                                         struct FtlBackendEvent *event,
                                         struct BbmPolicyAPI *api,
                                         void *context);

/*
 * Hook registration (backend events, pSWD state transitions) is done via the
 * FTL policy API, not via BBM. In init_policy(ssd, api), use:
 *   api->register_backend_hook(ssd, condition, callback, context);
 *   api->register_pswd_transition_hook(ssd, condition, callback, context);
 * and the corresponding unregister/inactivate/reactivate functions.
 * bbm_api is for I/O and validity only (raw_read, get_page_status, get_block_vpc_ipc, etc.).
 */

#endif /* FEMU_BBM_POLICY_H */

