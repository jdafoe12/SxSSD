/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "policy-privileged-wasm-abi.h"

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    return sxs_subscribe(SXS_EVENT_NVME_ADMIN, 0xe2U, 1, 0);
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    return pair_id == 1 && sxs_context_get(&context) == 0;
}

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    return pair_id == 1 ? sxs_privileged_policy_deactivate(1) :
                          SXS_WASM_ACTION_ERROR;
}
