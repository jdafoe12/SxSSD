#include "policy-bpf-abi.h"

#define SMOKE_ADMIN_OPCODE 0xe1U
#define SMOKE_PAIR_ID 1U
#define SMOKE_MATCH_VALUE 0xc0deU
#define SMOKE_RESULT 0x5358535342504601ULL

static sxs_u64 smoke_init(void)
{
    return sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN, SMOKE_ADMIN_OPCODE,
                         SMOKE_PAIR_ID, 0, 0) == 0 ? 0 :
           SXS_BPF_ACTION_ERROR;
}

static sxs_u64 smoke_condition(const struct sxs_bpf_context *context)
{
    return context->pair_id == SMOKE_PAIR_ID &&
           context->event.nvme.cdw10 == SMOKE_MATCH_VALUE;
}

static sxs_u64 smoke_action(void)
{
    if (sxs_completion_result_set(SMOKE_RESULT, 0, 0, 0, 0) != 0 ||
        sxs_completion_status_set(0, 0, 0, 0, 0) != 0) {
        return SXS_BPF_ACTION_ERROR;
    }
    return 0;
}

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
        return smoke_init();
    case SXS_BPF_PHASE_CONDITION:
        return smoke_condition(context);
    case SXS_BPF_PHASE_ACTION:
        return smoke_action();
    default:
        return SXS_BPF_ACTION_ERROR;
    }
}
