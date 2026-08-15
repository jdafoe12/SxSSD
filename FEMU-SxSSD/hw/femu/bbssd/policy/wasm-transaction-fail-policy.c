#include "policy-wasm-abi.h"

#define TRANSACTION_OPCODE 0xe9U

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    if (sxs_oob_register_stage(1, 1) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_ADMIN, TRANSACTION_OPCODE, 1, 0) != 0) {
        return -SXS_WASM_EIO;
    }
    return -SXS_WASM_EIO;
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{ return pair_id == 1; }

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    return pair_id == 1 && sxs_completion_result_set(0x42414400U) == 0 ?
           0 : SXS_WASM_ACTION_ERROR;
}
