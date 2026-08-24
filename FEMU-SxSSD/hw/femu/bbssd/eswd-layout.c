/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "eswd-layout.h"
#include <assert.h>
#include <string.h>
#include <glib.h>

int eswd_layout_compute(struct eswd_layout *layout,
                        const struct eswd_config *config,
                        const struct bbm_geom *geom)
{
    if (!layout || !config || !geom) {
        return -1;
    }
    uint32_t tt_luns = geom->nchs * geom->luns_per_ch;
    uint32_t blocks_per_eswd = config->blocks_per_eswd;
    if (blocks_per_eswd == 0) {
        blocks_per_eswd = tt_luns;
    }
    uint64_t total_blocks = (uint64_t)geom->blks_per_lun_log * tt_luns;
    if (total_blocks % (uint64_t)blocks_per_eswd != 0) {
        return -1;
    }
    layout->blks_per_eswd = blocks_per_eswd;
    layout->tt_eswds = (uint32_t)(total_blocks / (uint64_t)blocks_per_eswd);
    layout->pgs_per_eswd = layout->blks_per_eswd * geom->pgs_per_blk;
    layout->striping_level = config->striping_level;
    
    /* Initialize eSWD → starting block mapping (identity by default) */
    layout->tt_pl = tt_luns * geom->pls_per_lun;
    layout->blks_per_pl = layout->blks_per_eswd / layout->tt_pl;
    layout->eswd_to_starting_block = g_malloc0(sizeof(uint32_t) * layout->tt_eswds);
    
    for (uint32_t i = 0; i < layout->tt_eswds; i++) {
        layout->eswd_to_starting_block[i] = i * layout->blks_per_pl;
    }
    
    return 0;
}

int eswd_ppa_to_eswd_id(const struct eswd_layout *layout,
                        const struct bbm_geom *geom,
                        const PseudoPpa *ppa)
{
    if (!layout || !geom || !ppa) {
        return -1;
    }
    uint32_t tt_luns = geom->nchs * geom->luns_per_ch;
    uint32_t blk = ppa->g.blk;
    uint32_t eswd_id = blk * tt_luns / layout->blks_per_eswd;
    if (eswd_id >= layout->tt_eswds) {
        return -1;
    }
    return (int)eswd_id;
}

/* PLANE striping: pl first, then ch, lun, block_slot. */
static void blkoff_plane(uint32_t block_offset, uint32_t tt_luns, uint32_t nchs,
    uint32_t pls_per_lun, uint32_t *ch, uint32_t *lun, uint32_t *pl, uint32_t *block_slot)
{
    uint32_t tt_pl = tt_luns * pls_per_lun;
    *block_slot = block_offset / tt_pl;
    uint32_t rem = block_offset % tt_pl;
    *pl = rem / tt_luns;
    rem %= tt_luns;
    *ch = rem % nchs;
    *lun = rem / nchs;
}

int eswd_page_to_ppa(const struct eswd_layout *layout,
                     const struct bbm_geom *geom,
                     uint32_t eswd_id,
                     uint32_t page_index,
                     PseudoPpa *ppa)
{
    if (!layout || !geom || !ppa || eswd_id >= layout->tt_eswds) {
        return -1;
    }
    if (page_index >= layout->pgs_per_eswd) {
        return -1;
    }
    uint32_t tt_luns = geom->nchs * geom->luns_per_ch;
    uint32_t nchs = geom->nchs;
    uint32_t luns_per_ch = geom->luns_per_ch;
    uint32_t pls_per_lun = geom->pls_per_lun;
    uint32_t pgs_per_blk = geom->pgs_per_blk;

    uint32_t ch, lun, pl, block_slot, pg;

    /* Order: striping dimension fastest (ch or lun), then pg, then block_slot for parallelism. */
    switch (layout->striping_level) {
    case ESWD_STRIPE_CHANNEL: {
        /* Striping order: ch, pl, lun, block_slot, pg */
        ch = page_index % nchs;
        pl = (page_index / nchs) % pls_per_lun;
        lun = (page_index / (nchs * pls_per_lun)) % luns_per_ch;
        uint32_t rem = page_index / (tt_luns * pls_per_lun);
        block_slot = rem / pgs_per_blk;
        pg = rem % pgs_per_blk; // This should match the pSWD write pointer.
        break;
    }
    case ESWD_STRIPE_LUN: {
        /* Striping order: lun, pl, ch, block_slot, pg */
        lun = page_index % luns_per_ch;
        pl = (page_index / luns_per_ch) % pls_per_lun;
        ch = (page_index / (luns_per_ch * pls_per_lun)) % nchs;
        uint32_t rem = page_index / (tt_luns * pls_per_lun);
        block_slot = rem / pgs_per_blk;
        pg = rem % pgs_per_blk; // This should match the pSWD write pointer.
        break;
    }
    case ESWD_STRIPE_PLANE: {
        if (pls_per_lun == 0) {
            return -1;
        }
        uint32_t block_offset = page_index / pgs_per_blk;
        pg = page_index % pgs_per_blk; // This should match the pSWD write pointer.
        blkoff_plane(block_offset, tt_luns, nchs, pls_per_lun, &ch, &lun, &pl, &block_slot);
        break;
    }
    case ESWD_STRIPE_BLOCK:
    default:
        return -1;
    }

    /* Look up starting block from mapping table */
    uint32_t starting_block = layout->eswd_to_starting_block[eswd_id];
    
    /* Add block_slot offset within this eSWD */
    uint32_t blk = starting_block + block_slot;

    memset(ppa, 0, sizeof(PseudoPpa));
    ppa->g.ch = ch;
    ppa->g.lun = lun;
    ppa->g.pl = pl;
    ppa->g.blk = blk;
    ppa->g.pg = pg;
    return 0;
}

int eswd_ppa_to_page(const struct eswd_layout *layout,
                     const struct bbm_geom *geom,
                     const PseudoPpa *ppa,
                     uint32_t *out_eswd_id,
                     uint32_t *out_page_index)
{
    if (!layout || !geom || !ppa || !out_eswd_id || !out_page_index) {
        return -1;
    }
    int eswd_id_ret = eswd_ppa_to_eswd_id(layout, geom, ppa);
    if (eswd_id_ret < 0) {
        return -1;
    }
    *out_eswd_id = (uint32_t)eswd_id_ret;

    uint32_t tt_luns = geom->nchs * geom->luns_per_ch;
    uint32_t nchs = geom->nchs;
    uint32_t luns_per_ch = geom->luns_per_ch;
    uint32_t pls_per_lun = geom->pls_per_lun;
    uint32_t pgs_per_blk = geom->pgs_per_blk;
    uint32_t blk = ppa->g.blk;
    uint32_t ch = ppa->g.ch;
    uint32_t lun = ppa->g.lun;
    uint32_t pl = ppa->g.pl;
    uint32_t pg = ppa->g.pg;

    uint32_t eswd_id = (uint32_t)eswd_id_ret;
    
    /* Extract block_slot using mapping table */
    uint32_t starting_block = layout->eswd_to_starting_block[eswd_id];
    uint32_t block_slot = blk - starting_block;
    
    /* Validate block is within this eSWD */
    if (block_slot >= layout->blks_per_pl) {
        return -1;
    }

    /* Inverse of page_to_ppa: page_index = rem*(tt_luns*pls_per_lun) + (ch,lun,pl)_ordinal, rem = block_slot*pgs_per_blk+pg */
    uint32_t rem = block_slot * pgs_per_blk + pg;
    uint32_t ord;
    switch (layout->striping_level) {
    case ESWD_STRIPE_CHANNEL:
        /* Inverse: page_index has ch fastest, then pl, then lun */
        ord = ch + pl * nchs + lun * (nchs * pls_per_lun);
        break;
    case ESWD_STRIPE_LUN:
        /* Inverse: page_index has lun fastest, then pl, then ch */
        ord = lun + pl * luns_per_ch + ch * (luns_per_ch * pls_per_lun);
        break;
    case ESWD_STRIPE_PLANE: {
        uint32_t tt_pl = tt_luns * pls_per_lun;
        ord = block_slot * tt_pl + pl * tt_luns + ch + lun * nchs;
        *out_page_index = ord * pgs_per_blk + pg;
        goto check;
    }
    case ESWD_STRIPE_BLOCK:
    default:
        return -1;
    }
    *out_page_index = rem * (tt_luns * pls_per_lun) + ord;
check:
    if (*out_page_index >= layout->pgs_per_eswd) {
        return -1;
    }
    return 0;
}

int eswd_block_to_ppa(const struct eswd_layout *layout,
                      const struct bbm_geom *geom,
                      uint32_t eswd_id,
                      uint32_t block_index,
                      PseudoPpa *ppa)
{
    if (!layout || !geom || !ppa || eswd_id >= layout->tt_eswds || block_index >= layout->blks_per_eswd) {
        return -1;
    }
    
    uint32_t tt_luns = geom->nchs * geom->luns_per_ch;
    uint32_t nchs = geom->nchs;
    uint32_t luns_per_ch = geom->luns_per_ch;
    uint32_t pls_per_lun = geom->pls_per_lun;
    
    /* With page-level striping, block_index maps to a (ch, lun, pl) tuple.
     * Each "eSWD block" represents all pages on one (ch, lun, pl) within this eSWD. */
    uint32_t ch, lun, pl, blk;
    
    switch (layout->striping_level) {
    case ESWD_STRIPE_CHANNEL:
        /* block_index maps: ch, then pl, then lun */
        ch = block_index % nchs;
        pl = (block_index / nchs) % pls_per_lun;
        lun = block_index / (nchs * pls_per_lun);
        break;
    case ESWD_STRIPE_LUN:
        /* block_index maps: lun, then pl, then ch */
        lun = block_index % luns_per_ch;
        pl = (block_index / luns_per_ch) % pls_per_lun;
        ch = block_index / (luns_per_ch * pls_per_lun);
        break;
    case ESWD_STRIPE_PLANE:
        if (pls_per_lun == 0) {
            return -1;
        }
        /* block_index maps: pl, then ch, then lun */
        pl = block_index / tt_luns;
        {
            uint32_t rem = block_index % tt_luns;
            ch = rem % nchs;
            lun = rem / nchs;
        }
        break;
    case ESWD_STRIPE_BLOCK:
    default:
        return -1;
    }
    
    /* Look up starting block from mapping table */
    uint32_t starting_block = layout->eswd_to_starting_block[eswd_id];
    uint32_t tt_pl = layout->tt_pl;
    
    /* Each block_index maps to a (ch, lun, pl) tuple.
     * Multiple tuples may share the same physical block when blks_per_eswd > tt_pl. */
    uint32_t block_offset_within_eswd = block_index / tt_pl;
    blk = starting_block + block_offset_within_eswd;
    
    memset(ppa, 0, sizeof(PseudoPpa));
    ppa->g.ch = ch;
    ppa->g.lun = lun;
    ppa->g.pl = pl;
    ppa->g.blk = blk;
    ppa->g.pg = 0;  /* First page of the block */
    return 0;
}

void eswd_layout_cleanup(struct eswd_layout *layout)
{
    if (layout && layout->eswd_to_starting_block) {
        g_free(layout->eswd_to_starting_block);
        layout->eswd_to_starting_block = NULL;
    }
}
