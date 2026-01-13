#ifndef FEMU_POLICY_TYPES_H
#define FEMU_POLICY_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Basic address structure definitions for FEMU policies.
 * These types provide a stable ABI for external policy .so files.
 */

/* Physical address bit field sizes */
#define BLK_BITS    (16)
#define PG_BITS     (16)
#define SEC_BITS    (8)
#define PL_BITS     (8)
#define LUN_BITS    (8)
#define CH_BITS     (7)

/* Physical Page Address (PPA) */
struct ppa {
    union {
        struct {
            uint64_t blk : BLK_BITS;  /* block within plane */
            uint64_t pg  : PG_BITS;   /* page within block */
            uint64_t sec : SEC_BITS;  /* sector within page */
            uint64_t pl  : PL_BITS;   /* plane within LUN */
            uint64_t lun : LUN_BITS;  /* LUN within channel */
            uint64_t ch  : CH_BITS;   /* channel */
            uint64_t rsv : 1;         /* reserved */
        } g;
        uint64_t ppa;  /* raw 64-bit address */
    };
};

/* Physical Block Address (PBA) */
struct pba {
    union {
        struct {
            uint64_t blk : BLK_BITS;  /* block within plane */
            uint64_t pl  : PL_BITS;   /* plane within LUN */
            uint64_t lun : LUN_BITS;  /* LUN within channel */
            uint64_t ch  : CH_BITS;   /* channel */
            uint64_t rsv : (64 - BLK_BITS - PL_BITS - LUN_BITS - CH_BITS);
        } g;
        uint64_t pba;  /* raw block address */
    };
};

/* Pseudo-physical address types (BBM layer abstractions) */
typedef struct ppa PseudoPpa;
typedef struct pba PseudoPba;

/* Address validation constants */
#define INVALID_PPA     (~(0ULL))
#define INVALID_LPN     (~(0ULL))
#define UNMAPPED_PPA    (~(0ULL))

/* BBM logical geometry (after overprovisioning) */
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

/* Forward declarations for opaque types */
struct NvmeRequest;
struct FtlBackend;
struct BbmEvent;

/* Opaque forward declarations - use API functions instead of direct access */
struct bbm;
struct ssd;

#endif /* FEMU_POLICY_TYPES_H */

