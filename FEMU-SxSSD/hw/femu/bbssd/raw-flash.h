/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Derived in part from the FEMU BBSSD FTL through the former
 * hw/femu/backend/ftl-backend.h implementation.
 * SxSSD modifications by Josh Dafoe: 2025-12-04 through 2026-08-23.
 */

#ifndef FEMU_SXSSD_RAW_FLASH_H
#define FEMU_SXSSD_RAW_FLASH_H

#include "../nvme.h"
#include "../backend/dram.h"

/*
 * Raw flash owns physical geometry, media bytes, OOB bytes, physical program
 * state, erase counts, and NAND timing. Its callers use physical
 * addresses. Pseudo-to-physical translation belongs to BBM.
 */
#define BLK_BITS    (16)
#define PG_BITS     (16)
#define SEC_BITS    (8)
#define PL_BITS     (8)
#define LUN_BITS    (8)
#define CH_BITS     (7)

#define MAX_OOB_POLICIES (16)


/* describe a physical page addr */
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
            uint64_t blk : BLK_BITS;  /* block within plane */
            uint64_t pl  : PL_BITS;   /* plane within LUN  */
            uint64_t lun : LUN_BITS;  /* die within chan   */
            uint64_t ch  : CH_BITS;   /* channel           */
            uint64_t rsv : (64 - BLK_BITS - PL_BITS - LUN_BITS - CH_BITS);
        } g;

        uint64_t pba;
    };
};

/* Page validity status for physical media pages. */
enum RawFlashPageStatus {
    PG_FREE = 0,
    PG_INVALID = 1,
    PG_VALID = 2
};

/* Shared logical pSWD state values.  The state itself is owned by BBM. */
enum pswd_block_state {
    PSWD_FREE,
    PSWD_OPEN,
    PSWD_CLOSED,
    PSWD_BAD
};

/*
 * Raw per-physical-block state.  This deliberately mirrors enough NAND
 * programming state to enforce physical sequential writes, but it is not a
 * pSWD: a pSWD has a stable pseudo-physical identity and lives in BBM.
 */
struct raw_block_ctx {
    enum pswd_block_state state;
    int wp;         /* current write pointer (next page to write) */
    int erase_cnt;  /* erase count for this block */
    int vpc;        /* valid page count in this block */
    int ipc;        /* invalid page count in this block */
};

enum RawFlashEventCommand {
    RAW_FLASH_EVENT_READ,
    RAW_FLASH_EVENT_WRITE,
    RAW_FLASH_EVENT_ERASE
};

// add a latency enum?

enum RawFlashEventType {
    RAW_FLASH_IO_POLICY = 0,
    RAW_FLASH_IO_USER = 1,
};

struct RawFlashTiming {
    uint64_t *lun_next_avail;
    uint64_t *ch_next_avail;
  //  uint64_t *lun_policy_end;
  //  uint64_t *ch_policy_end;
};



struct RawFlashEvent {
    enum RawFlashEventCommand cmd;
    enum RawFlashEventType type;
    uint32_t count;
    int *status_list; /* for read, status_list[i] = bit error count for page i */
                   /* for write, status_list[i] = 0/1 success for page i */
                   /* for erase, status_list[i] = 0/1 success for block i */
                   /* As far as I understand, this models errors closely to a real SSD.
                    * We will simply use a probabilistic model for the errors. */
                    // 0 is success. Non-zero is failure.
    int64_t stime; /* Request arrival time. */
    int64_t lat;
};

/* Test-only deterministic primitive-operation failure injection. */
struct RawFlashFaultInjection {
    bool active;
    bool one_shot;
    enum RawFlashEventCommand command;
    struct pba block;
    int status;
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
    char *policy_name;
    size_t required_size;
    size_t offset;
    bool active;
};


struct RawFlash {
    /* Backing store for physical bytes (e.g., DRAM-backed). */
    SsdDramBackend *mbe;

    /* OOB management */
    uint8_t *oob_buf;
    size_t oob_size_per_page;        /* total bytes per page */
    size_t oob_used_per_page;        /* bytes currently allocated to policies */

    /* Reused by page migration on the single BBSSD worker. */
    uint8_t *migration_page_buf;
    size_t migration_page_buf_size;
    uint8_t *migration_oob_buf;
    size_t migration_oob_buf_size;

    struct OobPolicyRegistration oob_policies[MAX_OOB_POLICIES];
    int oob_policy_count;

    /* Physical state per physical block; length sp.tt_blks. */
    struct raw_block_ctx *physical_state;
    /* Per-page validity indexed by physical block and page. */
    uint8_t *page_validity;

    struct ssdparams sp;
    struct RawFlashTiming bt;
    struct RawFlashFaultInjection test_fault;
};

int raw_flash_init(struct RawFlash *fb, SsdDramBackend *mbe,
                   const BbCtrlParams *bbp);
int raw_flash_read(struct RawFlash *fb, uint8_t *buffer,
                   struct ppa *ppa_list, uint64_t page_count,
                   uint64_t page_size, void *oob_buf, size_t oob_offset,
                   size_t oob_len, struct RawFlashEvent *event);
int raw_flash_write(struct RawFlash *fb, const uint8_t *buffer,
                    struct ppa *ppa_list, uint64_t page_count,
                    uint64_t page_size, const void *oob_buf,
                    size_t oob_offset, size_t oob_len,
                    struct RawFlashEvent *event);
int raw_flash_erase(struct RawFlash *fb, struct pba *pba_list,
                    uint64_t block_count, struct RawFlashEvent *event);

/*
 * Query physical erase count for a physical block address (PBA).
 * Returns >= 0 on success, -1 on invalid input/out-of-range/uninitialized.
 */
int raw_flash_get_erase_cnt(const struct RawFlash *fb, const struct pba *pba);

/* OOB management */
/* Policies call this during initialization to reserve OOB space */
int raw_flash_register_oob_policy(struct RawFlash *fb,
    const char *policy_name,
    size_t required_size,
    int *policy_handle_out);
int raw_flash_unregister_oob_policy(struct RawFlash *fb,
    int policy_handle);
int raw_flash_can_register_oob_policies(const struct RawFlash *fb,
    const uint32_t *required_sizes, uint32_t required_count);
int raw_flash_get_oob_policy_info(struct RawFlash *fb,
    int policy_handle,
    size_t *offset_out,
    size_t *size_out);

/* Policies use this to access their OOB section */
void* raw_flash_get_oob_for_policy(struct RawFlash *fb,
     struct ppa *ppa,
     int policy_handle);

/* Physical-page validity and physical block accounting. */
void raw_flash_mark_page_valid(struct RawFlash *fb, const struct ppa *ppa);
void raw_flash_mark_page_invalid(struct RawFlash *fb, const struct ppa *ppa);
void raw_flash_mark_block_free(struct RawFlash *fb, const struct pba *pba);
int raw_flash_get_page_status(const struct RawFlash *fb, const struct ppa *ppa);
void raw_flash_get_block_vpc_ipc(const struct RawFlash *fb, const struct pba *pba, int *vpc, int *ipc);

int raw_flash_mark_block_bad(struct RawFlash *fb, const struct pba *pba);
bool raw_flash_block_is_bad(const struct RawFlash *fb, const struct pba *pba);
void raw_flash_test_inject_failure(struct RawFlash *fb,
                                   enum RawFlashEventCommand command,
                                   const struct pba *block, int status,
                                   bool one_shot);

#endif /* FEMU_SXSSD_RAW_FLASH_H */
