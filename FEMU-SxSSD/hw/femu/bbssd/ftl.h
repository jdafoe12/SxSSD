#ifndef __FEMU_FTL_H
#define __FEMU_FTL_H

#include "../nvme.h"
#include "./bbm.h" // we have access to PseudoPpa and PseudoPba through this.
#include "eswd-config.h"
#include "eswd-layout.h"

struct policy_engine;

struct FtlBackend;
struct FtlPolicyAPI;  /* Forward declaration */
struct FemuCtrl;

#define INVALID_PPA     (~(0ULL))
#define INVALID_LPN     (~(0ULL))
#define UNMAPPED_PPA    (~(0ULL))

#define MAX_FTL_EVENT_HOOKS (256)
#define MAX_NVME_HOOKS (256)

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

/*
 * Internal event record copied into the pointer-free uBPF context. The native
 * pointer is visible only to trusted helpers and the built-in meta-interface.
 */
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

struct ssd; /* Forward declaration */

/* Trusted callback type used only by the fixed meta-interface table. */
typedef bool (*NvmeHookCondition)(struct ssd *ssd,
                                  struct NvmeCommandEvent *event,
                                  struct FtlPolicyAPI *api,
                                  void *context);
typedef uint64_t (*NvmeHookCallback)(struct ssd *ssd,
                                     struct NvmeCommandEvent *event,
                                     struct FtlPolicyAPI *api,
                                     void *context);
struct AdminHook {
    uint8_t opcode;
    NvmeHookCondition condition;
    NvmeHookCallback callback;
    void *context;
    bool active;
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

    FEMU_STATS_RESET = 8,
    FEMU_STATS_DUMP  = 9,
};

#define FEMU_STATS_DIR_ENV "FEMU_STATS_DIR"

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
    uint64_t wp_lba;         /* host-visible sequential write pointer for this eSWD */
    /* Per-eSWD staging buffer: accumulates sub-page LBAs until a full page is ready */
    uint8_t  *staged_page_buf;
    uint64_t  staged_page_lba;   /* absolute LBA of the page currently being staged */
    uint32_t  staged_valid_lbas; /* number of LBAs written into staged_page_buf so far */
};

/*struct nand_cmd {
    int type;
    int cmd;
    int64_t stime; 
};*/

/*
 * Private interface for the built-in meta-interface policy.  This is not the
 * ordinary-policy ABI: installed policies receive only policy-bpf-abi.h and
 * reach FTL mechanisms through phase-checked uBPF helpers.
 */
struct FtlPolicyAPI {
    uint32_t version;
    uint16_t (*read_cmd_buffer)(struct NvmeCommandEvent *event, void *dst,
                                uint32_t length);
    uint16_t (*write_cmd_buffer)(struct NvmeCommandEvent *event, const void *src,
                                 uint32_t length);
};

struct ssd { // This needs to be dissected and probably renamed
    char *ssdname;
    struct FemuCtrl *ctrl;
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
    bool eswd_layout_finalized;
    
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
    
    /* Private bridge used only by the built-in meta-interface policy. */
    struct FtlPolicyAPI *policy_api;

    /*
     * CPU frequency scaling factor: host_mhz / ctrl_mhz.
     * Applied to policy dispatch wall-clock time to model a slower SSD
     * controller CPU.
     */
    double cpu_scale_factor;

    /* Per-run statistics counters; reset/dumped via FEMU_STATS_RESET/DUMP flip */
    struct ssd_stats stats;
};

void ssd_init(FemuCtrl *n);
void ssd_stats_reset(struct ssd *ssd);
void ssd_stats_dump_json(struct ssd *ssd, uint32_t run_id);

/* Trusted boot-time FTL configuration, committed during policy activation. */
void set_eswd_config(struct ssd *ssd, const struct eswd_config *config);
int finalize_ftl_init(struct ssd *ssd);
int configure_namespace_personality(struct ssd *ssd,
                                    const struct NamespacePersonalityConfig *config);

/* Event filling helpers */
void ftl_fill_nvme_event(struct ssd *ssd, NvmeRequest *req, struct NvmeCommandEvent *event);
void ftl_fill_admin_nvme_event(struct ssd *ssd, FemuCtrl *n, NvmeCmd *cmd,
                               struct NvmeCommandEvent *event);
uint64_t ftl_write_seq_lbas(struct ssd *ssd, uint32_t eswd_id,
                            uint64_t slba, const uint8_t *buf, uint32_t nlb,
                            PseudoPpa *ppa_out, int64_t stime_ns);
uint64_t ftl_read_eswd_page(struct ssd *ssd, uint32_t eswd_id,
                            uint64_t page_lba, uint8_t *buf_out,
                            int64_t stime_ns);
uint64_t ftl_eswd_get_effective_wp_lba(struct ssd *ssd, uint32_t eswd_id);

/* Pointer-free-policy helper primitives. These never call into a policy VM. */
int ftl_policy_page_append(struct ssd *ssd, uint32_t eswd_id,
                           const uint8_t *page_data, int oob_handle,
                           const uint8_t *oob_data, uint32_t oob_length,
                           PseudoPpa *ppa_out, uint64_t *latency_out,
                           int64_t stime_ns);
int ftl_policy_page_migrate(struct ssd *ssd, const PseudoPpa *source,
                            uint32_t destination_eswd_id,
                            PseudoPpa *destination_out,
                            uint64_t *latency_out);

/* ========== Mechanism API: eSWD query and state operations ========== */
struct eswd *get_eswd_by_id(struct ssd *ssd, uint32_t eswd_id);
struct eswd *get_eswd_by_ppa(struct ssd *ssd, PseudoPpa *ppa);
void get_eswd_vpc_ipc(struct ssd *ssd, uint32_t eswd_id, int *vpc, int *ipc);
uint32_t get_eswd_wp_index(struct ssd *ssd, uint32_t eswd_id);
uint32_t get_total_eswds(struct ssd *ssd);
const struct bbm_geom *get_bbm_geom(struct ssd *ssd);
const struct eswd_layout *get_eswd_layout(struct ssd *ssd);
void eswd_set_vpc_ipc(struct ssd *ssd, uint32_t eswd_id, int vpc, int ipc);
void eswd_increment_wp(struct ssd *ssd, uint32_t eswd_id);
void eswd_reset(struct ssd *ssd, uint32_t eswd_id);
uint64_t eswd_get_wp_lba(struct ssd *ssd, uint32_t eswd_id);
uint16_t eswd_check_seq_write(struct ssd *ssd, uint32_t eswd_id,
                              uint64_t slba, uint32_t nlb);
uint16_t eswd_check_read_range(struct ssd *ssd, uint32_t eswd_id,
                               uint64_t slba, uint32_t nlb);
uint64_t read_page_buffer(struct ssd *ssd, const PseudoPpa *ppa,
                          uint8_t *buffer,
                          int oob_handle, void *oob_buf,
                          int64_t stime_ns);

/* eSWD layout query wrappers */
int eswd_id_to_ppa_wrapper(struct ssd *ssd, uint32_t eswd_id, uint32_t page_index, PseudoPpa *ppa);
int ppa_to_eswd_id_wrapper(struct ssd *ssd, const PseudoPpa *ppa, uint32_t *eswd_id, uint32_t *page_index);
int eswd_block_to_ppa_wrapper(struct ssd *ssd, uint32_t eswd_id, uint32_t block_index, PseudoPpa *ppa);
int ftl_eswd_advance_wp_to_end(struct ssd *ssd, uint32_t eswd_id);
uint64_t ftl_eswd_erase_physical(struct ssd *ssd, uint32_t eswd_id, int64_t stime_ns);

/* PPA to physical page index (for policy rmap; index in [0, tt_pgs_log)) */
uint64_t ppa_to_pgidx(struct ssd *ssd, PseudoPpa *ppa);

/* ========== DEPRECATED: Policy-level operations (will be removed) ========== */
/* Mapping table operations */
PseudoPpa get_maptbl_ent(struct ssd *ssd, uint64_t lpn);
void set_maptbl_ent(struct ssd *ssd, uint64_t lpn, PseudoPpa *ppa);
uint64_t get_total_logical_pages(struct ssd *ssd);
uint64_t get_advertised_nsze_lbas(struct ssd *ssd);

/* Address validation */
bool valid_lpn(struct ssd *ssd, uint64_t lpn);
bool valid_ppa(struct ssd *ssd, PseudoPpa *ppa);
bool mapped_ppa(PseudoPpa *ppa);

/* Metadata management */
void mark_page_valid(struct ssd *ssd, PseudoPpa *ppa);
void mark_page_invalid(struct ssd *ssd, PseudoPpa *ppa);
void mark_block_free(struct ssd *ssd, PseudoPpa *ppa);

/* eSWD/channel accessors (page/block validity lives in BBM/backend mechanism code) */
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
const NvmeDsmRange *ftl_get_dsm_ranges(NvmeRequest *req, int *nr_ranges);
uint16_t ftl_read_cmd_buffer(struct NvmeCommandEvent *event, void *dst,
                             uint32_t length);
uint16_t ftl_write_cmd_buffer(struct NvmeCommandEvent *event, const void *src,
                              uint32_t length);
void ftl_set_completion_result_u64(struct NvmeCommandEvent *event,
                                   uint64_t value);
int ftl_get_page_status(struct ssd *ssd, const PseudoPpa *ppa);
int ftl_register_oob_region(struct ssd *ssd, const char *name,
                            uint32_t size, int *handle_out);

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

#endif
