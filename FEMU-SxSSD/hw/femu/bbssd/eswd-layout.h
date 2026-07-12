#ifndef ESWD_LAYOUT_H
#define ESWD_LAYOUT_H

#include "eswd-config.h"
#include "bbm.h"

/*
 * Derived eSWD layout: computed from eswd_config + device geometry.
 * FTL uses this for eSWD count, blocks/pages per eSWD, and write-pointer advance.
 */
struct eswd_layout {
    uint32_t tt_eswds;        /* number of eSWDs */
    uint32_t blks_per_eswd;   /* primitive SWDs (blocks) per eSWD */
    uint32_t pgs_per_eswd;    /* pages per eSWD */
    enum eswd_striping_level striping_level;  /* advance order within eSWD */
    
    /* Explicit eSWD → starting block mapping */
    uint32_t *eswd_to_starting_block;  /* Array[tt_eswds]: maps eswd_id → starting block # */
    uint32_t tt_pl;                     /* tt_luns * pls_per_lun (cached) */
    uint32_t blks_per_pl;               /* blks_per_eswd / tt_pl (cached) */
};

/* Compute derived layout from config and device geometry. Returns 0 on success, -1 if invalid. */
int eswd_layout_compute(struct eswd_layout *layout,
                        const struct eswd_config *config,
                        const struct bbm_geom *geom);

/* Map a pseudo PPA to the eSWD id that contains it. */
int eswd_ppa_to_eswd_id(const struct eswd_layout *layout,
                        const struct bbm_geom *geom,
                        const PseudoPpa *ppa);

/* Per-eSWD mapping: (eswd_id, page_index) <-> PPA. Striping order depends on layout->striping_level. */

/* Forward: (eswd_id, page_index) -> PPA. page_index in [0, pgs_per_eswd). Returns 0 on success, -1 on error. */
int eswd_page_to_ppa(const struct eswd_layout *layout,
                     const struct bbm_geom *geom,
                     uint32_t eswd_id,
                     uint32_t page_index,
                     PseudoPpa *ppa);

/* Inverse: PPA -> (eswd_id, page_index). Returns 0 on success, -1 on error. */
int eswd_ppa_to_page(const struct eswd_layout *layout,
                     const struct bbm_geom *geom,
                     const PseudoPpa *ppa,
                     uint32_t *out_eswd_id,
                     uint32_t *out_page_index);

/* Block enumeration for GC: return first-page PPA of block_index-th block in eSWD (block_index in [0, blks_per_eswd)). */
int eswd_block_to_ppa(const struct eswd_layout *layout,
                      const struct bbm_geom *geom,
                      uint32_t eswd_id,
                      uint32_t block_index,
                      PseudoPpa *ppa);

/* Free resources allocated by eswd_layout_compute() */
void eswd_layout_cleanup(struct eswd_layout *layout);

#endif /* ESWD_LAYOUT_H */
