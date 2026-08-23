/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "policy-wasm-abi.h"

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    for (sxs_u32 pair = 1;
         pair <= SXS_WASM_MAX_SUBSCRIPTIONS_PER_POLICY; pair++) {
        if (sxs_subscribe(SXS_EVENT_BACKEND,
                          SXS_WASM_SELECTOR_ANY, pair, 0) != 0) {
            return -SXS_WASM_EIO;
        }
        if (pair == 1 &&
            sxs_subscribe(SXS_EVENT_BACKEND, SXS_WASM_SELECTOR_ANY,
                          pair, 0) != -SXS_WASM_EEXIST) {
            return -SXS_WASM_EIO;
        }
    }
    return sxs_subscribe(SXS_EVENT_BACKEND, SXS_WASM_SELECTOR_ANY,
                         SXS_WASM_MAX_SUBSCRIPTIONS_PER_POLICY + 1, 0) ==
           -SXS_WASM_ENOSPC ? 0 : -SXS_WASM_EIO;
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{ (void)pair_id; return 0; }

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{ (void)pair_id; return 0; }
