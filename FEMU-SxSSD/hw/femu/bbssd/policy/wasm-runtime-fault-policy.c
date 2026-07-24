#include "policy-wasm-abi.h"

#define OOB_OPCODE 0xe6U
#define LOOP_OPCODE 0xe7U
#define RECOVERY_OPCODE 0xebU
#define RECOVERY_RESULT 0x5245434fU

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    return sxs_subscribe(SXS_EVENT_NVME_ADMIN, OOB_OPCODE, 1, 0) == 0 &&
           sxs_subscribe(SXS_EVENT_NVME_ADMIN, LOOP_OPCODE, 2, 0) == 0 &&
           sxs_subscribe(SXS_EVENT_NVME_ADMIN, RECOVERY_OPCODE, 3, 0) == 0 ?
           0 : -SXS_WASM_EIO;
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{ return pair_id == 1 || pair_id == 2 || pair_id == 3; }

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    if (pair_id == 1) {
        volatile sxs_u8 *outside = (volatile sxs_u8 *)(sxs_u32)65536U;
        return *outside;
    }
    if (pair_id == 2) {
        volatile sxs_u64 counter = 0;

        for (;;) {
            counter++;
        }
    }
    if (pair_id == 3) {
        return sxs_completion_result_set(RECOVERY_RESULT) == 0 ?
               0 : SXS_WASM_ACTION_ERROR;
    }
    return SXS_WASM_ACTION_ERROR;
}
