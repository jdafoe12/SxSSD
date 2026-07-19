#include "policy-bpf-abi.h"

#define SIGNING_TEST_OPCODE 0xe4U
#define SIGNING_TEST_PAIR_ID 1U
#define RESERVED_META_OPCODE 0x95U
#define SIGNING_TEST_RESULT 0x5349474e50415353ULL

static sxs_u64 signing_test_init(void)
{
    sxs_s64 result;

    result = sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN,
                           RESERVED_META_OPCODE, 2, 0, 0);
    if (result != -SXS_BPF_EPERM) {
        return SXS_BPF_ACTION_ERROR;
    }
    return sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN,
                         SIGNING_TEST_OPCODE, SIGNING_TEST_PAIR_ID,
                         0, 0) == 0 ? 0 : SXS_BPF_ACTION_ERROR;
}

static sxs_u64 signing_test_condition(struct sxs_bpf_context *context)
{
    sxs_s64 result;

    if (context->pair_id != SIGNING_TEST_PAIR_ID) {
        return 0;
    }
    result = sxs_sign_key_bootstrap(0, 0, 0, 0, 0);
    return result == -SXS_BPF_EPERM;
}

static sxs_u64 signing_test_action(struct sxs_bpf_context *context)
{
    struct sxs_bpf_bootstrap_sign_request *request =
        (struct sxs_bpf_bootstrap_sign_request *)context->scratch;

    for (sxs_u32 i = 0; i < 32; i++) {
        request->owner_nonce[i] = (sxs_u8)i;
        request->owner_ephemeral_public_key[i] = (sxs_u8)(i + 32);
        request->policy_ephemeral_public_key[i] = (sxs_u8)(i + 64);
    }
    if (sxs_sign_key_bootstrap(0, 0, 0, 0, 0) != 0 ||
        sxs_completion_result_set(SIGNING_TEST_RESULT, 0, 0, 0, 0) != 0) {
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
        return signing_test_init();
    case SXS_BPF_PHASE_CONDITION:
        return signing_test_condition(context);
    case SXS_BPF_PHASE_ACTION:
        return signing_test_action(context);
    default:
        return SXS_BPF_ACTION_ERROR;
    }
}
