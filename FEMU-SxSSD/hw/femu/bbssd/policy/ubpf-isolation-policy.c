#include "policy-bpf-abi.h"

#define ISOLATION_OPCODE 0xe5U
#define ISOLATION_PAIR 1U
#define ISOLATION_STATE_OBJECT 1U
#define ISOLATION_OOB_OBJECT 1U
#define ISOLATION_PASS 0x49534f4cU
#define ISOLATION_FORBIDDEN_EFFECT 0x42414400U

static sxs_u64 attempt_forbidden_effects(struct sxs_bpf_context *context)
{
    *(sxs_u64 *)context->scratch = 0xfeedfaceULL;

    if (sxs_state_write(ISOLATION_STATE_OBJECT, 0, 0, 0,
                        sizeof(sxs_u64)) != -SXS_BPF_EPERM ||
        sxs_state_fill_u64(ISOLATION_STATE_OBJECT, 1, 0, 0, 0) !=
            -SXS_BPF_EPERM ||
        sxs_completion_result_set(ISOLATION_FORBIDDEN_EFFECT,
                                  0, 0, 0, 0) != -SXS_BPF_EPERM ||
        sxs_completion_status_set(0, 0, 0, 0, 0) != -SXS_BPF_EPERM ||
        sxs_command_write(0, 0, 1, 0, 0) != -SXS_BPF_EPERM ||
        sxs_request_write(0, 0, 1, 0, 0) != -SXS_BPF_EPERM ||
        sxs_page_invalidate(0, 0, 0, 0, 0) != -SXS_BPF_EPERM ||
        sxs_eswd_reset(0, 0, 0, 0, 0) != -SXS_BPF_EPERM ||
        sxs_oob_register_stage(ISOLATION_OOB_OBJECT, 1, 0, 0, 0) !=
            -SXS_BPF_EPERM ||
        sxs_eswd_config_stage(0, 0, 0, 0, 0) != -SXS_BPF_EPERM ||
        sxs_crypto_random(0, 1, 0, 0, 0) != -SXS_BPF_EPERM ||
        sxs_sign_key_bootstrap(0, 0, 0, 0, 0) != -SXS_BPF_EPERM) {
        return 0;
    }
    return 1;
}

static sxs_u64 isolation_init(void)
{
    return sxs_state_create(ISOLATION_STATE_OBJECT, sizeof(sxs_u64), 1,
                            0, 0) == 0 &&
                   sxs_oob_register_stage(ISOLATION_OOB_OBJECT, 1,
                                          0, 0, 0) == 0 &&
                   sxs_subscribe(SXS_BPF_EVENT_NVME_ADMIN,
                                 ISOLATION_OPCODE, ISOLATION_PAIR,
                                 0, 0) == 0 ?
               0 : SXS_BPF_ACTION_ERROR;
}

static sxs_u64 isolation_condition(struct sxs_bpf_context *context)
{
    if (context->pair_id != ISOLATION_PAIR) {
        return 0;
    }

    /* Public identity is writable VM input, but it is never authoritative. */
    context->phase = SXS_BPF_PHASE_ACTION;
    context->policy_id = 0xffffffffU;
    context->generation = 0xffffffffU;
    context->event_kind = SXS_BPF_EVENT_NONE;
    return attempt_forbidden_effects(context);
}

static sxs_u64 isolation_action(struct sxs_bpf_context *context)
{
    if (sxs_state_read(ISOLATION_STATE_OBJECT, 0, 0, 0,
                       sizeof(sxs_u64)) != 0 ||
        *(sxs_u64 *)context->scratch != 0 ||
        sxs_completion_result_set(ISOLATION_PASS, 0, 0, 0, 0) != 0) {
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
        return isolation_init();
    case SXS_BPF_PHASE_CONDITION:
        return isolation_condition(context);
    case SXS_BPF_PHASE_ACTION:
        return isolation_action(context);
    default:
        return SXS_BPF_ACTION_ERROR;
    }
}
