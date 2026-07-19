#include "policy-bpf-abi.h"

#define TRANSACTION_OPCODE 0xe9U

sxs_u64 policy_main(void *memory, sxs_u64 memory_size)
{
    struct sxs_bpf_context *context = memory;

    if (!context || memory_size != sizeof(*context) ||
        context->abi_version != SXS_BPF_ABI_VERSION ||
        context->context_size != sizeof(*context)) {
        return SXS_BPF_ACTION_ERROR;
    }
    if (context->phase == SXS_BPF_PHASE_INIT) {
        if (sxs_state_create(1, sizeof(sxs_u64), 1024, 0, 0) != 0 ||
            sxs_oob_register_stage(1, 1, 0, 0, 0) != 0 ||
            sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN,
                          TRANSACTION_OPCODE, 1, 0, 0) != 0) {
            return SXS_BPF_ACTION_ERROR;
        }
        return SXS_BPF_ACTION_ERROR;
    }
    if (context->phase == SXS_BPF_PHASE_CONDITION) {
        return 1;
    }
    if (context->phase == SXS_BPF_PHASE_ACTION) {
        return sxs_completion_result_set(0x42414400U, 0, 0, 0, 0) == 0 ?
                   0 : SXS_BPF_ACTION_ERROR;
    }
    return SXS_BPF_ACTION_ERROR;
}
