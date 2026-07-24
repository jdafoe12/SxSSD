#include "policy-wasm-abi.h"

#define SMOKE_ADMIN_OPCODE 0xe1U
#define SMOKE_PAIR_ID 1U
#define SMOKE_MATCH_VALUE 0xc0deU
#define SMOKE_RESULT 0x535853535741534dULL

static sxs_u64 smoke_init(void)
{
    return sxs_subscribe(SXS_EVENT_NVME_ADMIN, SMOKE_ADMIN_OPCODE,
                         SMOKE_PAIR_ID, 0) == 0 ? 0 :
           SXS_WASM_ACTION_ERROR;
}

static sxs_u64 smoke_condition(const struct sxs_policy_context *context)
{
    return context->pair_id == SMOKE_PAIR_ID &&
           context->event.nvme.cdw10 == SMOKE_MATCH_VALUE;
}

static sxs_u64 smoke_action(void)
{
    if (sxs_completion_result_set(SMOKE_RESULT) != 0 ||
        sxs_completion_status_set(0) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    return 0;
}

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    return (sxs_s32)smoke_init();
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 || context.pair_id != pair_id) {
        return -SXS_WASM_EINVAL;
    }
    return (sxs_s32)smoke_condition(&context);
}

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    return pair_id == SMOKE_PAIR_ID ? smoke_action() : SXS_WASM_ACTION_ERROR;
}
