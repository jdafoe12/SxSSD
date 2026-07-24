#include "policy-wasm-abi.h"

#define STATE_OPCODE 0xe8U
#define STATE_PAIR 1U
#define STATE_OBJECT 1U
#define STATE_RESULT_BASE 0x53540000U

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    return sxs_state_create(STATE_OBJECT, sizeof(sxs_u64), 1, 0, 0) == 0 &&
           sxs_subscribe(SXS_EVENT_NVME_ADMIN, STATE_OPCODE,
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
    sxs_u64 value;

    if (pair_id != STATE_PAIR ||
        sxs_state_read(STATE_OBJECT, 0, 0, &value, sizeof(value)) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    value++;
    if (sxs_state_write(STATE_OBJECT, 0, 0, &value, sizeof(value)) != 0 ||
        sxs_completion_result_set(STATE_RESULT_BASE |
                                  (value & 0xffffU)) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    return 0;
}
