#include "policy-bpf-abi.h"

sxs_u64 policy_main(void *memory, sxs_u64 memory_size)
{
    struct sxs_bpf_context *context = memory;

    if (!context || memory_size != sizeof(*context) ||
        context->abi_version != SXS_BPF_ABI_VERSION ||
        context->context_size != sizeof(*context)) {
        return SXS_BPF_ACTION_ERROR;
    }
    if (context->phase == SXS_BPF_PHASE_INIT) {
        for (sxs_u32 pair = 1;
             pair <= SXS_BPF_MAX_SUBSCRIPTIONS_PER_POLICY; pair++) {
            if (sxs_subscribe(SXS_BPF_EVENT_BACKEND,
                              SXS_BPF_SELECTOR_ANY, pair, 0, 0) != 0) {
                return SXS_BPF_ACTION_ERROR;
            }
            if (pair == 1 &&
                sxs_subscribe(SXS_BPF_EVENT_BACKEND,
                              SXS_BPF_SELECTOR_ANY, pair, 0, 0) !=
                    -SXS_BPF_EEXIST) {
                return SXS_BPF_ACTION_ERROR;
            }
        }
        if (sxs_subscribe(SXS_BPF_EVENT_BACKEND,
                          SXS_BPF_SELECTOR_ANY,
                          SXS_BPF_MAX_SUBSCRIPTIONS_PER_POLICY + 1,
                          0, 0) != -SXS_BPF_ENOSPC) {
            return SXS_BPF_ACTION_ERROR;
        }
        return 0;
    }
    if (context->phase == SXS_BPF_PHASE_CONDITION) {
        return 0;
    }
    return context->phase == SXS_BPF_PHASE_ACTION ? 0 :
           SXS_BPF_ACTION_ERROR;
}
