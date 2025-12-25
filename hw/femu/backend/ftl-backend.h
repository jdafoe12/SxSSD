#ifndef FTL_BACKEND_H
#define FTL_BACKEND_H

#include "../nvme.h"
#include "./dram.h"

// TODO: need to enforce an erase-before-write policy.

/* 
 * In the backend, events are generated on each operation that is exposed to the upper layer, essentially returning the status of the operation.
 * Any metadata updates or important status updates are reported.
 * The events are passed to the upper layer, where some policy may or may not be attached to a given event.
 * Regardless, the upper layer indexes into a lookup table for what to do on each event.
 * The lookup table is loaded from storage, compiled, and formed into a actual functions pointers.
 * In this case, the upper layer is a bad block manager. 
 *
 * For reads, the event is an integer for each page, indicating the number of bit errors corrected by ECC.
 *   Thus, the event is an array of integers.
 * For writes, the event is binary for each page: success or failure.
 *   Thus, the event is an array of booleans (implemented as integers).
 * For erasures, the event is binary for each block: success or failure.
 *   Thus, the event is an array of booleans (implemented as integers).
 * lower layers should be read-only, as in the uppper layer cannot change the state of the lower layer.
 * This prevents issues with the ordering of events.
 */


/*
 * TODO: does the ftl backend need to be aware of internal ssd geometry? 
 * At least for error simulation, it think this is needed. For example,
 * we shoudl probably simulate errors based on the erase count of the block. 
 * but, we are given page numbers in the request. We need the ability to convert this.
 * we can see what the FTL will actually call. The direct call will be to bad block management functions,
 * since this provides the pseudophysical address space. 
 * Maybe erase count is handled in the bad block management layer?
 */

 
// in addition to keeping track of the geometry (and such low level metadata currently tracked by the FTL),
// we need the erase count here instead of in the FTL.

// the geometry and timing should be here, because it is generated here. Note that we have
// read-down, so that the FTL can be aware of the geometry.








#define BLK_BITS    (16)
#define PG_BITS     (16)
#define SEC_BITS    (8)
#define PL_BITS     (8)
#define LUN_BITS    (8)
#define CH_BITS     (7)

#define MAX_OOB_POLICIES (16)


/* describe a physical page addr */
struct ppa { // ppa shoudl be moved to backend / BBM mapping engine layer.
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
            uint64_t blk : BLK_BITS;  /* block within plane */
            uint64_t pl  : PL_BITS;   /* plane within LUN  */
            uint64_t lun : LUN_BITS;  /* die within chan   */
            uint64_t ch  : CH_BITS;   /* channel           */
            uint64_t rsv : (64 - BLK_BITS - PL_BITS - LUN_BITS - CH_BITS);
        } g;

        uint64_t pba;
    };
};

enum FtlBackendEventCmd {
    FTL_BACKEND_EVENT_READ,
    FTL_BACKEND_EVENT_WRITE,
    FTL_BACKEND_EVENT_ERASE
};

// add a latency enum?

enum FtlBackendEventType {
    POLICY_IO = 0,
    USER_IO  = 1,
};

struct FtlBackendTiming {
    uint64_t *lun_next_avail;
    uint64_t *ch_next_avail;
  //  uint64_t *lun_policy_end;
  //  uint64_t *ch_policy_end;
};



struct FtlBackendEvent {
    enum FtlBackendEventCmd cmd; 
    enum FtlBackendEventType type; // may not be important?
    uint32_t count; 
    int *status_list; /* for read, status_list[i] = bit error count for page i */
                   /* for write, status_list[i] = 0/1 success for page i */
                   /* for erase, status_list[i] = 0/1 success for block i */
                   /* As far as I understand, this models errors closely to a real SSD.
                    * We will simply use a probabilistic model for the errors. */
                    // 0 is success. Non-zero is failure.
    int64_t stime; /* Request arrival time. */
    int64_t lat;   /* latency. May not need this here. Delete if not used? 
                    * I think it belongs here. It needs to be reported to upper layers */
    // need to report updates to erase count
};

struct ssdparams {
    int secsz;        /* sector size in bytes */
    int secs_per_pg;  /* # of sectors per page */
    int pgs_per_blk;  /* # of NAND pages per block */
    int blks_per_pl;  /* # of blocks per plane */
    int pls_per_lun;  /* # of planes per LUN (Die) */
    int luns_per_ch;  /* # of LUNs per channel */
    int nchs;         /* # of channels in the SSD */

    int pg_rd_lat;    /* NAND page read latency in nanoseconds */
    int pg_wr_lat;    /* NAND page program latency in nanoseconds */
    int blk_er_lat;   /* NAND block erase latency in nanoseconds */
    int ch_xfer_lat;  /* channel transfer latency for one page in nanoseconds
                       * this defines the channel bandwith
                       */

    /* GC configuration. For now we can keep this, but it will be migrated to policy level. */
    double gc_thres_pcent;
    int gc_thres_lines;
    double gc_thres_pcent_high;
    int gc_thres_lines_high;
    bool enable_gc_delay;

    /* below are all calculated values */
    int secs_per_blk; /* # of sectors per block */
    int secs_per_pl;  /* # of sectors per plane */
    int secs_per_lun; /* # of sectors per LUN */
    int secs_per_ch;  /* # of sectors per channel */
    int tt_secs;      /* # of sectors in the SSD */

    int pgs_per_pl;   /* # of pages per plane */
    int pgs_per_lun;  /* # of pages per LUN (Die) */
    int pgs_per_ch;   /* # of pages per channel */
    int tt_pgs;       /* total # of pages in the SSD */

    int blks_per_lun; /* # of blocks per LUN */
    int blks_per_ch;  /* # of blocks per channel */
    int tt_blks;      /* total # of blocks in the SSD */

    int secs_per_line;
    int pgs_per_line;
    int blks_per_line;
    int tt_lines;

    int pls_per_ch;   /* # of planes per channel */
    int tt_pls;       /* total # of planes in the SSD */

    int tt_luns;      /* total # of LUNs in the SSD */
};


struct OobPolicyRegistration {
    const char *policy_name;
    size_t required_size;
    size_t offset;
    bool active;
};


struct FtlBackend {
    /* Backing store for physical bytes (e.g., DRAM-backed). */
    SsdDramBackend *mbe;

    /* OOB management */
    uint8_t *oob_buf;
    size_t oob_size_per_page;        /* total bytes per page */
    size_t oob_used_per_page;        /* bytes currently allocated to policies */
    
    struct OobPolicyRegistration oob_policies[MAX_OOB_POLICIES];
    int oob_policy_count;

    int *erase_cnt; // indexed in bbm, by physical block number. 
                    // bbm should have a "getter" function for the "translated erase count" - given a pseudophysical block address.
    struct ssdparams sp;
    struct FtlBackendTiming bt; 
};

int ftl_backend_init(struct FtlBackend *fb, SsdDramBackend *mbe, const BbCtrlParams *bbp);

// Note: the below functions should directly recieve PPA from bbm, not ppn_list.

/* These are for serving NVMe requests directly. */
// note that we do not break bell-lapadula by passing
// requests down. The usual communication paradigm is to pass requsets down
// and responses up.

int ftl_backend_read(struct FtlBackend *fb, NvmeRequest *req, struct ppa *ppa_list,
                     uint64_t lpn_count, uint64_t page_size, struct FtlBackendEvent *event);
int ftl_backend_write(struct FtlBackend *fb, NvmeRequest *req, struct ppa *ppa_list,
                      uint64_t lpn_count, uint64_t page_size, struct FtlBackendEvent *event);

/* These are for direct operations on the FTL backend, without involving the host. */
int ftl_backend_raw_read(struct FtlBackend *fb, uint8_t *buffer, struct ppa *ppa_list,
                         uint64_t ppn_count, uint64_t page_size, struct FtlBackendEvent *event);
int ftl_backend_raw_write(struct FtlBackend *fb, uint8_t *buffer, struct ppa *ppa_list,
                          uint64_t ppn_count, uint64_t page_size, struct FtlBackendEvent *event);
int ftl_backend_raw_erase(struct FtlBackend *fb, struct pba *pbn, uint64_t block_count,
                          struct FtlBackendEvent *event);

/*
 * Query physical erase count for a physical block address (PBA).
 * Returns >= 0 on success, -1 on invalid input/out-of-range/uninitialized.
 */
int ftl_backend_get_erase_cnt(const struct FtlBackend *fb, const struct pba *pba);

/* OOB management */
/* Policies call this during initialization to reserve OOB space */
int ftl_backend_register_oob_policy(struct FtlBackend *fb, 
    const char *policy_name,
    size_t required_size,
    int *policy_handle_out);

/* Policies use this to access their OOB section */
void* ftl_backend_get_oob_for_policy(struct FtlBackend *fb, 
     struct ppa *ppa,
     int policy_handle);

#endif