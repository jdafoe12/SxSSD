/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef ESWD_CONFIG_H
#define ESWD_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/*
 * Exposed SWD (eSWD) configuration: policy defines striping and size at init.
 * These determine how many eSWDs exist, which blocks belong to which eSWD,
 * and how the write pointer advances within an eSWD.
 */

enum eswd_striping_level {
    ESWD_STRIPE_CHANNEL,  /* advance channel first, then lun, then page (default) */
    ESWD_STRIPE_LUN,      /* advance lun first, then channel, then page */
    ESWD_STRIPE_PLANE,    /* advance plane first, then ch, lun, page */
    ESWD_STRIPE_BLOCK     /* reserve for future */
};

struct eswd_config {
    enum eswd_striping_level striping_level;
    uint32_t blocks_per_eswd;  /* primitive SWDs (blocks) per eSWD; 0 = use default (tt_luns) */
};

/* Return true if config is valid for given geometry (nchs, luns_per_ch, etc.). */
bool eswd_config_valid(const struct eswd_config *config,
                       uint32_t nchs, uint32_t luns_per_ch, uint32_t pls_per_lun,
                       uint32_t blks_per_lun_log);

#endif /* ESWD_CONFIG_H */
