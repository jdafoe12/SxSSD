#include "policy-bpf-abi.h"

/* This symbol is deliberately absent from the helper allowlist. */
extern sxs_u64 pe_test_forbidden_host_function(void);

sxs_u64 policy_main(void *memory, sxs_u64 memory_size)
{
    struct sxs_bpf_context *context = memory;

    if (!context || memory_size != sizeof(*context) ||
        context->abi_version != SXS_BPF_ABI_VERSION) {
        return SXS_BPF_ACTION_ERROR;
    }
    return pe_test_forbidden_host_function();
}
