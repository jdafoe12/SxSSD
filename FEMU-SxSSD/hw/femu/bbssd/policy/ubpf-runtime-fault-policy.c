#include "policy-bpf-abi.h"

#define OOB_OPCODE 0xe6U
#define LOOP_OPCODE 0xe7U

sxs_u64 policy_main(void *memory, sxs_u64 memory_size)
{
    struct sxs_bpf_context *context = memory;

    if (!context || memory_size != sizeof(*context) ||
        context->abi_version != SXS_BPF_ABI_VERSION ||
        context->context_size != sizeof(*context)) {
        return SXS_BPF_ACTION_ERROR;
    }
    if (context->phase == SXS_BPF_PHASE_INIT) {
        return sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN,
                             OOB_OPCODE, 1, 0, 0) == 0 &&
                       sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN,
                                     LOOP_OPCODE, 2, 0, 0) == 0 ?
                   0 : SXS_BPF_ACTION_ERROR;
    }
    if (context->phase == SXS_BPF_PHASE_CONDITION) {
        return context->pair_id == 1 || context->pair_id == 2;
    }
    if (context->phase != SXS_BPF_PHASE_ACTION) {
        return SXS_BPF_ACTION_ERROR;
    }
    if (context->pair_id == 1) {
        volatile sxs_u8 *outside =
            (volatile sxs_u8 *)memory + sizeof(*context);
        return *outside;
    }
    if (context->pair_id == 2) {
        volatile sxs_u64 counter = 0;

        for (;;) {
            counter++;
        }
    }
    return SXS_BPF_ACTION_ERROR;
}
