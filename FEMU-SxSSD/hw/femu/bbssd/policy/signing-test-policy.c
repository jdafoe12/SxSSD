#include "policy-wasm-abi.h"

#define SIGNING_TEST_OPCODE 0xe4U
#define SIGNING_TEST_PAIR_ID 1U
#define RESERVED_META_OPCODE 0x95U
#define SIGNING_TEST_RESULT 0x5349474e50415353ULL

static sxs_u64 signing_test_init(void)
{
    sxs_s64 result;

    result = sxs_subscribe(SXS_EVENT_NVME_ADMIN,
                           RESERVED_META_OPCODE, 2, 0);
    if (result != -SXS_WASM_EPERM) {
        return SXS_WASM_ACTION_ERROR;
    }
    return sxs_subscribe(SXS_EVENT_NVME_ADMIN,
                         SIGNING_TEST_OPCODE, SIGNING_TEST_PAIR_ID,
                         0) == 0 ? 0 : SXS_WASM_ACTION_ERROR;
}

static sxs_u64 signing_test_condition(struct sxs_policy_context *context)
{
    sxs_s64 result;

    if (context->pair_id != SIGNING_TEST_PAIR_ID) {
        return 0;
    }
    {
        sxs_u8 zero[32] = {0};
        sxs_u8 signature[64];

        result = sxs_sign_key_bootstrap(zero, zero, zero, signature);
    }
    return result == -SXS_WASM_EPERM;
}

static sxs_u64 signing_test_action(struct sxs_policy_context *context)
{
    sxs_u8 owner_nonce[32];
    sxs_u8 owner_public[32];
    sxs_u8 policy_public[32];
    sxs_u8 signature[64];

    (void)context;

    for (sxs_u32 i = 0; i < 32; i++) {
        owner_nonce[i] = (sxs_u8)i;
        owner_public[i] = (sxs_u8)(i + 32);
        policy_public[i] = (sxs_u8)(i + 64);
    }
    if (sxs_sign_key_bootstrap(owner_nonce, owner_public, policy_public,
                               signature) != 0 ||
        sxs_completion_result_set(SIGNING_TEST_RESULT) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    return 0;
}

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    return (sxs_s32)signing_test_init();
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 || context.pair_id != pair_id) {
        return -SXS_WASM_EINVAL;
    }
    return (sxs_s32)signing_test_condition(&context);
}

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 || context.pair_id != pair_id) {
        return SXS_WASM_ACTION_ERROR;
    }
    return signing_test_action(&context);
}
