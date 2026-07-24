#include "policy-wasm-abi.h"

#define ORDER_OPCODE 0xeaU
#define ORDER_PAIR 1U

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    return sxs_subscribe(SXS_EVENT_NVME_ADMIN, ORDER_OPCODE,
                         ORDER_PAIR, 0);
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{ return pair_id == ORDER_PAIR; }

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (pair_id != ORDER_PAIR || sxs_context_get(&context) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    return sxs_completion_result_set(context.policy_version) == 0 ?
           0 : SXS_WASM_ACTION_ERROR;
}
