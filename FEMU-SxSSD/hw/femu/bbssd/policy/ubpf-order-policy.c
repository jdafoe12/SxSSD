#include "policy-bpf-abi.h"

#define ORDER_OPCODE 0xeaU
#define ORDER_PAIR 1U

sxs_u64 policy_main(void *memory, sxs_u64 memory_size)
{
    struct sxs_bpf_context *context = memory;

    if (!context || memory_size != sizeof(*context) ||
        context->abi_version != SXS_BPF_ABI_VERSION ||
        context->context_size != sizeof(*context)) {
        return SXS_BPF_ACTION_ERROR;
    }
    switch (context->phase) {
    case SXS_BPF_PHASE_INIT:
        return sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN, ORDER_OPCODE,
                             ORDER_PAIR, 0, 0) == 0 ?
                   0 : SXS_BPF_ACTION_ERROR;
    case SXS_BPF_PHASE_CONDITION:
        return context->pair_id == ORDER_PAIR;
    case SXS_BPF_PHASE_ACTION:
        return sxs_completion_result_set(context->policy_version,
                                         0, 0, 0, 0) == 0 ?
                   0 : SXS_BPF_ACTION_ERROR;
    default:
        return SXS_BPF_ACTION_ERROR;
    }
}
