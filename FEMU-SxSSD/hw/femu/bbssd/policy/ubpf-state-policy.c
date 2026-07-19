#include "policy-bpf-abi.h"

#define STATE_OPCODE 0xe8U
#define STATE_PAIR 1U
#define STATE_OBJECT 1U
#define STATE_RESULT_BASE 0x53540000U

sxs_u64 policy_main(void *memory, sxs_u64 memory_size)
{
    struct sxs_bpf_context *context = memory;
    sxs_u64 *value;

    if (!context || memory_size != sizeof(*context) ||
        context->abi_version != SXS_BPF_ABI_VERSION ||
        context->context_size != sizeof(*context)) {
        return SXS_BPF_ACTION_ERROR;
    }
    switch (context->phase) {
    case SXS_BPF_PHASE_INIT:
        return sxs_state_create(STATE_OBJECT, sizeof(sxs_u64), 1,
                                0, 0) == 0 &&
                       sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN,
                                     STATE_OPCODE, STATE_PAIR,
                                     0, 0) == 0 ?
                   0 : SXS_BPF_ACTION_ERROR;
    case SXS_BPF_PHASE_CONDITION:
        return context->pair_id == STATE_PAIR;
    case SXS_BPF_PHASE_ACTION:
        value = (sxs_u64 *)context->scratch;
        if (sxs_state_read(STATE_OBJECT, 0, 0, 0, sizeof(*value)) != 0) {
            return SXS_BPF_ACTION_ERROR;
        }
        (*value)++;
        if (sxs_state_write(STATE_OBJECT, 0, 0, 0, sizeof(*value)) != 0 ||
            sxs_completion_result_set(STATE_RESULT_BASE |
                                          (*value & 0xffffU),
                                      0, 0, 0, 0) != 0) {
            return SXS_BPF_ACTION_ERROR;
        }
        return 0;
    default:
        return SXS_BPF_ACTION_ERROR;
    }
}
