/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "policy-wasm-abi.h"

#define ISOLATION_OPCODE 0xe5U
#define ISOLATION_PAIR 1U
#define ISOLATION_OOB_OBJECT 1U
#define ISOLATION_PASS 0x49534f4cU
#define ISOLATION_FORBIDDEN_EFFECT 0x42414400U

static sxs_u64 condition_memory_probe;

static sxs_u64 attempt_forbidden_effects(struct sxs_policy_context *context)
{
    sxs_u64 value = 0xfeedfaceULL;
    struct sxs_eswd_config config = {0};
    sxs_u8 byte = 0;
    sxs_u8 nonce[32] = {0};
    sxs_u8 crypto_output[32];
    sxs_u8 signature[64];

    (void)context;
    condition_memory_probe = value;

    if (sxs_completion_result_set(ISOLATION_FORBIDDEN_EFFECT) !=
            -SXS_WASM_EPERM ||
        sxs_completion_status_set(0) != -SXS_WASM_EPERM ||
        sxs_command_write(0, &byte, 1) != -SXS_WASM_EPERM ||
        sxs_request_write(0, &byte, 1) != -SXS_WASM_EPERM ||
        sxs_page_invalidate(0) != -SXS_WASM_EPERM ||
        sxs_eswd_reset(0) != -SXS_WASM_EPERM ||
        sxs_oob_register_stage(ISOLATION_OOB_OBJECT, 1) !=
            -SXS_WASM_EPERM ||
        sxs_eswd_config_stage(&config) != -SXS_WASM_EPERM ||
        sxs_eswd_layout_finalize_stage() != -SXS_WASM_EPERM ||
        sxs_crypto_random(&byte, 1) != -SXS_WASM_EPERM ||
        sxs_crypto_x25519_public(nonce, 32, crypto_output, 32) !=
            -SXS_WASM_EPERM ||
        sxs_crypto_x25519_shared(nonce, 32, nonce, 32,
                                 crypto_output, 32) != -SXS_WASM_EPERM ||
        sxs_sign_key_bootstrap(nonce, nonce, nonce, signature) !=
            -SXS_WASM_EPERM) {
        return 0;
    }
    /* HMAC is side-effect-free outside policy-owned linear memory. */
    if (sxs_crypto_hmac_sha256(nonce, 32, nonce, 32,
                               crypto_output, 32) != 0) {
        return 0;
    }
    return 1;
}

static sxs_u64 isolation_init(void)
{
    return sxs_oob_register_stage(ISOLATION_OOB_OBJECT, 1) == 0 &&
                   sxs_subscribe(SXS_EVENT_NVME_ADMIN,
                                 ISOLATION_OPCODE, ISOLATION_PAIR,
                                 0) == 0 ?
               0 : SXS_WASM_ACTION_ERROR;
}

static sxs_u64 isolation_condition(struct sxs_policy_context *context)
{
    if (context->pair_id != ISOLATION_PAIR) {
        return 0;
    }

    /* Public identity is writable VM input, but it is never authoritative. */
    context->phase = SXS_PHASE_ACTION;
    context->policy_id = 0xffffffffU;
    context->generation = 0xffffffffU;
    context->event_kind = SXS_EVENT_NONE;
    return attempt_forbidden_effects(context);
}

static sxs_u64 isolation_action(struct sxs_policy_context *context)
{
    (void)context;
    if (condition_memory_probe != 0xfeedfaceULL ||
        sxs_completion_result_set(ISOLATION_PASS) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    return 0;
}

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    return (sxs_s32)isolation_init();
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 || context.pair_id != pair_id) {
        return -SXS_WASM_EINVAL;
    }
    return (sxs_s32)isolation_condition(&context);
}

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 || context.pair_id != pair_id) {
        return SXS_WASM_ACTION_ERROR;
    }
    return isolation_action(&context);
}
