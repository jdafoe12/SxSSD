#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include "policy-engine-types.h"
#include "ftl.h"
#include "bbm.h"

/*
 * Policy engine: single place for NVMe command events, backend (BBM) events, and pSWD
 * state transition events. Holds all hook arrays and runs dispatch loops.
 * FTL and BBM hold a pointer to the policy_engine and delegate to it.
 */
struct policy_engine {
    struct NvmeHook nvme_hooks[MAX_NVME_HOOKS];
    struct BackendEventHook backend_hooks[MAX_BACKEND_EVENT_HOOKS];
    struct PswdTransitionHook pswd_transition_hooks[MAX_PSWD_TRANSITION_HOOKS];
    struct BackgroundHook background_hooks[MAX_BACKGROUND_HOOKS];
    struct bbm *bbm_ctx;  /* for pSWD dispatch: pass bbm and api to callbacks */
};

/* NVMe command dispatch: call from ftl_thread with pre-filled NvmeCommandEvent. Returns latency. */
uint64_t policy_engine_dispatch_nvme_cmd(struct policy_engine *pe, struct ssd *ssd, struct NvmeCommandEvent *event);
void policy_engine_dispatch_backend_event(struct policy_engine *pe, struct FtlBackend *fb, struct bbm *ctx, struct FtlBackendEvent *event);
/* Backend pSWD notify callback: signature matches PswdTransitionNotifyFn; notify_ctx is struct policy_engine * */
void policy_engine_dispatch_pswd_transition(struct FtlBackend *fb, const struct PswdStateTransitionEvent *event, void *notify_ctx);
/* Background event: call from ftl_thread (e.g. after each I/O); first matching hook runs */
void policy_engine_dispatch_background_event(struct policy_engine *pe, struct ssd *ssd);

/* NVMe hooks (opcode-keyed, condition + callback) */
int policy_engine_register_nvme_hook(struct policy_engine *pe, uint8_t opcode,
                                   NvmeHookCondition condition,
                                   NvmeHookCallback callback,
                                   void *context);
int policy_engine_unregister_nvme_hook(struct policy_engine *pe, int hook_handle);
int policy_engine_inactivate_nvme_hook(struct policy_engine *pe, int hook_handle);
int policy_engine_reactivate_nvme_hook(struct policy_engine *pe, int hook_handle);

/* Backend (BBM) hooks */
int policy_engine_register_backend_hook(struct policy_engine *pe, BackendEventHookCondition condition, BackendEventHookCallback callback, void *context);
int policy_engine_unregister_backend_hook(struct policy_engine *pe, int hook_handle);
int policy_engine_inactivate_backend_hook(struct policy_engine *pe, int hook_handle);
int policy_engine_reactivate_backend_hook(struct policy_engine *pe, int hook_handle);

/* pSWD transition hooks */
int policy_engine_register_pswd_transition_hook(struct policy_engine *pe, PswdTransitionHookCondition condition, PswdTransitionHookCallback callback, void *context);
int policy_engine_unregister_pswd_transition_hook(struct policy_engine *pe, int hook_handle);
int policy_engine_inactivate_pswd_transition_hook(struct policy_engine *pe, int hook_handle);
int policy_engine_reactivate_pswd_transition_hook(struct policy_engine *pe, int hook_handle);

/* Background hooks */
int policy_engine_register_background_hook(struct policy_engine *pe, BackgroundHookCondition condition, BackgroundHookCallback callback, void *context);
int policy_engine_unregister_background_hook(struct policy_engine *pe, int hook_handle);
int policy_engine_inactivate_background_hook(struct policy_engine *pe, int hook_handle);
int policy_engine_reactivate_background_hook(struct policy_engine *pe, int hook_handle);

/* Check if any active hooks exist for this opcode (for fast-path filtering in bb_io_cmd) */
bool policy_engine_has_nvme_hook(struct policy_engine *pe, uint8_t opcode);

/* Create and init */
struct policy_engine *policy_engine_create(void);
void policy_engine_set_bbm(struct policy_engine *pe, struct bbm *ctx);

#endif /* POLICY_ENGINE_H */
