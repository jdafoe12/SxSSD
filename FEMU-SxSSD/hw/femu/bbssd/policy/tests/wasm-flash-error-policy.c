/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "policy-wasm-abi.h"

/* Focused fixture for the primitive-error and pSWD-repair ABI. */
#define FLASH_ERROR_PAIR 1U

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    return sxs_subscribe(SXS_EVENT_FLASH_ERROR, SXS_WASM_SELECTOR_ANY,
                         FLASH_ERROR_PAIR, 0);
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    return pair_id == FLASH_ERROR_PAIR && sxs_context_get(&context) == 0 &&
           context.event_kind == SXS_EVENT_FLASH_ERROR;
}

SXS_EXPORT_ACTION
sxs_s64 sxs_policy_action(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (pair_id != FLASH_ERROR_PAIR || sxs_context_get(&context) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    /* A policy selects recovery; the initiating I/O has already failed. */
    return sxs_pswd_remap(context.event.flash_error.ppa) == 0 ? 0 :
           SXS_WASM_ACTION_ERROR;
}
