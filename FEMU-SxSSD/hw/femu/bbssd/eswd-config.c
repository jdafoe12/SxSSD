#include "eswd-config.h"

bool eswd_config_valid(const struct eswd_config *config,
                       uint32_t nchs, uint32_t luns_per_ch, uint32_t pls_per_lun,
                       uint32_t blks_per_lun_log)
{
    if (!config || nchs == 0 || luns_per_ch == 0) {
        return false;
    }
    uint32_t tt_luns = nchs * luns_per_ch;
    uint32_t blocks_per_eswd = config->blocks_per_eswd;
    if (blocks_per_eswd == 0) {
        blocks_per_eswd = tt_luns;  /* default */
    }
    /* blocks_per_eswd must be a positive multiple of tt_luns for simple mapping */
    if (blocks_per_eswd % tt_luns != 0) {
        return false;
    }
    uint64_t total_blocks = (uint64_t)blks_per_lun_log * tt_luns;
    if (total_blocks % (uint64_t)blocks_per_eswd != 0) {
        return false;
    }
    switch (config->striping_level) {
    case ESWD_STRIPE_CHANNEL:
    case ESWD_STRIPE_LUN:
        break;
    case ESWD_STRIPE_PLANE:
        if (pls_per_lun == 0) {
            return false;
        }
        break;
    case ESWD_STRIPE_BLOCK:
        return false;  /* not yet supported */
    default:
        return false;
    }
    return true;
}
