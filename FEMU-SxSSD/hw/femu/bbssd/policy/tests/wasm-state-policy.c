/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "policy-wasm-abi.h"

#define STATE_OPCODE 0xe8U
#define STATE_PAIR 1U
#define STATE_RESULT_BASE 0x53540000U

static sxs_u64 state_value;

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    return sxs_subscribe(SXS_EVENT_NVME_ADMIN, STATE_OPCODE,
                         STATE_PAIR, 0) == 0 ? 0 : -SXS_WASM_EIO;
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    return pair_id == STATE_PAIR;
}

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    if (pair_id != STATE_PAIR) {
        return SXS_WASM_ACTION_ERROR;
    }
    state_value++;
    if (sxs_completion_result_set(STATE_RESULT_BASE |
                                  (state_value & 0xffffU)) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    return 0;
}
