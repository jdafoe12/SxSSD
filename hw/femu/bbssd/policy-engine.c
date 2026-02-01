#include "policy-engine.h"
#include <stdbool.h>
#include <string.h>

struct policy_engine *policy_engine_create(void)
{
    struct policy_engine *pe = g_malloc0(sizeof(struct policy_engine));
    for (int i = 0; i < MAX_NVME_HOOKS; i++) {
        pe->nvme_hooks[i].active = false;
        pe->nvme_hooks[i].opcode = 0;
        pe->nvme_hooks[i].condition = NULL;
        pe->nvme_hooks[i].callback = NULL;
        pe->nvme_hooks[i].context = NULL;
    }
    for (int i = 0; i < MAX_BACKEND_EVENT_HOOKS; i++) {
        pe->backend_hooks[i].active = false;
        pe->backend_hooks[i].condition = NULL;
        pe->backend_hooks[i].callback = NULL;
        pe->backend_hooks[i].context = NULL;
    }
    for (int i = 0; i < MAX_PSWD_TRANSITION_HOOKS; i++) {
        pe->pswd_transition_hooks[i].active = false;
        pe->pswd_transition_hooks[i].condition = NULL;
        pe->pswd_transition_hooks[i].callback = NULL;
        pe->pswd_transition_hooks[i].context = NULL;
    }
    for (int i = 0; i < MAX_BACKGROUND_HOOKS; i++) {
        pe->background_hooks[i].active = false;
        pe->background_hooks[i].condition = NULL;
        pe->background_hooks[i].callback = NULL;
        pe->background_hooks[i].context = NULL;
    }
    pe->bbm_ctx = NULL;
    return pe;
}

void policy_engine_set_bbm(struct policy_engine *pe, struct bbm *ctx)
{
    if (pe) {
        pe->bbm_ctx = ctx;
    }
}

uint64_t policy_engine_dispatch_nvme_cmd(struct policy_engine *pe, struct ssd *ssd, struct NvmeCommandEvent *event)
{
    if (!pe || !ssd || !event) {
        return 0;
    }
    /* Iterate in reverse so newest-registered (policy) hooks are tried before defaults */
    for (int i = MAX_NVME_HOOKS - 1; i >= 0; i--) {
        struct NvmeHook *hook = &pe->nvme_hooks[i];
        if (!hook->active || !hook->callback || hook->opcode != event->opcode) {
            continue;
        }
        bool should_fire = (hook->condition == NULL) ||
            hook->condition(ssd, event, ssd->policy_api, hook->context);
        if (should_fire) {
            event->lat = hook->callback(ssd, event, ssd->policy_api, hook->context);
            return event->lat;
        }
    }
    /* No hook matched (e.g. unknown opcode); return 0 */
    event->lat = 0;
    return 0;
}

void policy_engine_dispatch_backend_event(struct policy_engine *pe, struct FtlBackend *fb,
                                          struct bbm *ctx, struct FtlBackendEvent *event)
{
    if (!pe || !fb || !ctx || !event) {
        return;
    }
    for (int i = 0; i < MAX_BACKEND_EVENT_HOOKS; i++) {
        struct BackendEventHook *hook = &pe->backend_hooks[i];
        if (!hook->active || !hook->callback) {
            continue;
        }
        bool should_fire = (hook->condition == NULL) ||
            hook->condition(event, ctx->policy_api, hook->context);
        if (should_fire) {
            hook->callback(fb, ctx, event, ctx->policy_api, hook->context);
        }
    }
}

void policy_engine_dispatch_pswd_transition(struct FtlBackend *fb,
                                             const struct PswdStateTransitionEvent *event,
                                             void *notify_ctx)
{
    struct policy_engine *pe = (struct policy_engine *)notify_ctx;
    if (!pe || !fb || !event) {
        return;
    }
    struct bbm *ctx = pe->bbm_ctx;
    if (!ctx) {
        return;
    }
    for (int i = 0; i < MAX_PSWD_TRANSITION_HOOKS; i++) {
        struct PswdTransitionHook *hook = &pe->pswd_transition_hooks[i];
        if (!hook->active || !hook->callback) {
            continue;
        }
        bool should_fire = (hook->condition == NULL) ||
            hook->condition(event, ctx->policy_api, hook->context);
        if (should_fire) {
            hook->callback(fb, ctx, event, ctx->policy_api, hook->context);
        }
    }
}

void policy_engine_dispatch_background_event(struct policy_engine *pe, struct ssd *ssd)
{
    if (!pe || !ssd) {
        return;
    }
    struct BackgroundEvent event = { .ssd = ssd };
    for (int i = 0; i < MAX_BACKGROUND_HOOKS; i++) {
        struct BackgroundHook *hook = &pe->background_hooks[i];
        if (!hook->active || !hook->callback) {
            continue;
        }
        bool should_fire = (hook->condition == NULL) ||
            hook->condition(ssd, &event, ssd->policy_api, hook->context);
        if (should_fire) {
            hook->callback(ssd, &event, ssd->policy_api, hook->context);
            return;  /* first match wins */
        }
    }
}

/* NVMe hook registration */
int policy_engine_register_nvme_hook(struct policy_engine *pe, uint8_t opcode,
                                     NvmeHookCondition condition,
                                     NvmeHookCallback callback,
                                     void *context)
{
    if (!pe || !callback) {
        return -1;
    }
    for (int i = 0; i < MAX_NVME_HOOKS; i++) {
        if (!pe->nvme_hooks[i].callback) {
            pe->nvme_hooks[i].opcode = opcode;
            pe->nvme_hooks[i].condition = condition;
            pe->nvme_hooks[i].callback = callback;
            pe->nvme_hooks[i].context = context;
            pe->nvme_hooks[i].active = true;
            return i;
        }
    }
    return -1;
}

int policy_engine_unregister_nvme_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_NVME_HOOKS) {
        return -1;
    }
    pe->nvme_hooks[hook_handle].active = false;
    pe->nvme_hooks[hook_handle].opcode = 0;
    pe->nvme_hooks[hook_handle].condition = NULL;
    pe->nvme_hooks[hook_handle].callback = NULL;
    pe->nvme_hooks[hook_handle].context = NULL;
    return 0;
}

int policy_engine_inactivate_nvme_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_NVME_HOOKS) {
        return -1;
    }
    pe->nvme_hooks[hook_handle].active = false;
    return 0;
}

int policy_engine_reactivate_nvme_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_NVME_HOOKS) {
        return -1;
    }
    if (pe->nvme_hooks[hook_handle].callback) {
        pe->nvme_hooks[hook_handle].active = true;
        return 0;
    }
    return -1;
}

/* Backend hook registration */
int policy_engine_register_backend_hook(struct policy_engine *pe,
                                        BackendEventHookCondition condition,
                                        BackendEventHookCallback callback,
                                        void *context)
{
    if (!pe || !callback) {
        return -1;
    }
    for (int i = 0; i < MAX_BACKEND_EVENT_HOOKS; i++) {
        if (!pe->backend_hooks[i].callback) {
            pe->backend_hooks[i].condition = condition;
            pe->backend_hooks[i].callback = callback;
            pe->backend_hooks[i].context = context;
            pe->backend_hooks[i].active = true;
            return i;
        }
    }
    return -1;
}

int policy_engine_unregister_backend_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKEND_EVENT_HOOKS) {
        return -1;
    }
    pe->backend_hooks[hook_handle].active = false;
    pe->backend_hooks[hook_handle].condition = NULL;
    pe->backend_hooks[hook_handle].callback = NULL;
    pe->backend_hooks[hook_handle].context = NULL;
    return 0;
}

int policy_engine_inactivate_backend_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKEND_EVENT_HOOKS) {
        return -1;
    }
    pe->backend_hooks[hook_handle].active = false;
    return 0;
}

int policy_engine_reactivate_backend_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKEND_EVENT_HOOKS) {
        return -1;
    }
    pe->backend_hooks[hook_handle].active = true;
    return 0;
}

/* pSWD transition hook registration */
int policy_engine_register_pswd_transition_hook(struct policy_engine *pe,
                                                PswdTransitionHookCondition condition,
                                                PswdTransitionHookCallback callback,
                                                void *context)
{
    if (!pe || !callback) {
        return -1;
    }
    for (int i = 0; i < MAX_PSWD_TRANSITION_HOOKS; i++) {
        if (!pe->pswd_transition_hooks[i].callback) {
            pe->pswd_transition_hooks[i].condition = condition;
            pe->pswd_transition_hooks[i].callback = callback;
            pe->pswd_transition_hooks[i].context = context;
            pe->pswd_transition_hooks[i].active = true;
            return i;
        }
    }
    return -1;
}

int policy_engine_unregister_pswd_transition_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_PSWD_TRANSITION_HOOKS) {
        return -1;
    }
    pe->pswd_transition_hooks[hook_handle].active = false;
    pe->pswd_transition_hooks[hook_handle].condition = NULL;
    pe->pswd_transition_hooks[hook_handle].callback = NULL;
    pe->pswd_transition_hooks[hook_handle].context = NULL;
    return 0;
}

int policy_engine_inactivate_pswd_transition_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_PSWD_TRANSITION_HOOKS) {
        return -1;
    }
    pe->pswd_transition_hooks[hook_handle].active = false;
    return 0;
}

int policy_engine_reactivate_pswd_transition_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_PSWD_TRANSITION_HOOKS) {
        return -1;
    }
    pe->pswd_transition_hooks[hook_handle].active = true;
    return 0;
}

/* Background hook registration */
int policy_engine_register_background_hook(struct policy_engine *pe,
                                          BackgroundHookCondition condition,
                                          BackgroundHookCallback callback,
                                          void *context)
{
    if (!pe || !callback) {
        return -1;
    }
    for (int i = 0; i < MAX_BACKGROUND_HOOKS; i++) {
        if (!pe->background_hooks[i].callback) {
            pe->background_hooks[i].condition = condition;
            pe->background_hooks[i].callback = callback;
            pe->background_hooks[i].context = context;
            pe->background_hooks[i].active = true;
            return i;
        }
    }
    return -1;
}

int policy_engine_unregister_background_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKGROUND_HOOKS) {
        return -1;
    }
    pe->background_hooks[hook_handle].active = false;
    pe->background_hooks[hook_handle].condition = NULL;
    pe->background_hooks[hook_handle].callback = NULL;
    pe->background_hooks[hook_handle].context = NULL;
    return 0;
}

int policy_engine_inactivate_background_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKGROUND_HOOKS) {
        return -1;
    }
    pe->background_hooks[hook_handle].active = false;
    return 0;
}

int policy_engine_reactivate_background_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKGROUND_HOOKS) {
        return -1;
    }
    pe->background_hooks[hook_handle].active = true;
    return 0;
}

bool policy_engine_has_nvme_hook(struct policy_engine *pe, uint8_t opcode)
{
    if (!pe) {
        return false;
    }
    for (int i = 0; i < MAX_NVME_HOOKS; i++) {
        if (pe->nvme_hooks[i].active && 
            pe->nvme_hooks[i].callback && 
            pe->nvme_hooks[i].opcode == opcode) {
            return true;
        }
    }
    return false;
}
