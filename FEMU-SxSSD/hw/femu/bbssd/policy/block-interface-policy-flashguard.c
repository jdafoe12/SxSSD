#include "flashguard-bpf-core.h"

sxs_u64 policy_main(void *memory, sxs_u64 memory_size)
{
    return block_policy_dispatch(memory, memory_size);
}
