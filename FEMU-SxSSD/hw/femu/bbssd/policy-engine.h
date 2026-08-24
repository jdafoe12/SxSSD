/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include "policy-engine-types.h"
#include "ftl.h"
#include "bbm.h"

#define MAX_RUNTIME_POLICIES (16)

struct policy_storage_desc {
    uint32_t policy_id;
    uint32_t policy_version;
    uint32_t policy_size_bytes;
    uint32_t block_count;
    const struct pba *blocks;
    const uint8_t *expected_payload;
};

struct runtime_policy_record {
    uint32_t policy_id;
    uint32_t policy_version;
    bool active;
    void *loader_ctx;
    int nvme_hook_handles[MAX_NVME_HOOKS];
    int nvme_hook_count;
    int admin_hook_handles[MAX_ADMIN_HOOKS];
    int admin_hook_count;
    int backend_hook_handles[MAX_BACKEND_EVENT_HOOKS];
    int backend_hook_count;
    int pswd_hook_handles[MAX_PSWD_TRANSITION_HOOKS];
    int pswd_hook_count;
    int background_hook_handles[MAX_BACKGROUND_HOOKS];
    int background_hook_count;
};

/*
 * Policy engine: single place for NVMe command events, backend (BBM) events, and pSWD
 * state transition events. Holds all hook arrays and runs dispatch loops.
 * FTL and BBM hold a pointer to the policy_engine and delegate to it.
 */
struct policy_engine {
    struct NvmeHook nvme_hooks[MAX_NVME_HOOKS];
    struct AdminHook admin_hooks[MAX_ADMIN_HOOKS];
    struct BackendEventHook backend_hooks[MAX_BACKEND_EVENT_HOOKS];
    struct PswdTransitionHook pswd_transition_hooks[MAX_PSWD_TRANSITION_HOOKS];
    struct BackgroundHook background_hooks[MAX_BACKGROUND_HOOKS];
    struct bbm *bbm_ctx;  /* for pSWD dispatch: pass bbm and api to callbacks */
    struct runtime_policy_record runtime_policies[MAX_RUNTIME_POLICIES];
    int current_loading_policy;
};

/* NVMe command dispatch: call from ftl_thread with pre-filled NvmeCommandEvent. Returns latency. */
uint64_t pe_dispatch_nvme_cmd(struct policy_engine *pe, struct ssd *ssd, struct NvmeCommandEvent *event);
uint64_t pe_dispatch_admin_cmd(struct policy_engine *pe, struct ssd *ssd, struct NvmeCommandEvent *event);
void pe_dispatch_backend_event(struct policy_engine *pe, struct FtlBackend *fb, struct bbm *ctx, struct FtlBackendEvent *event);
/* Backend pSWD notify callback: signature matches PswdTransitionNotifyFn; notify_ctx is struct policy_engine * */
void pe_dispatch_pswd_transition(struct FtlBackend *fb, const struct PswdStateTransitionEvent *event, void *notify_ctx);
/* Background event: call from ftl_thread (e.g. after each I/O); first matching hook runs */
void pe_dispatch_background_event(struct policy_engine *pe, struct ssd *ssd);

/* NVMe hooks (opcode-keyed, condition + callback) */
int pe_register_nvme_hook(struct policy_engine *pe, uint8_t opcode,
                          NvmeHookCondition condition,
                          NvmeHookCallback callback,
                          void *context);
int pe_unregister_nvme_hook(struct policy_engine *pe, int hook_handle);
int pe_inactivate_nvme_hook(struct policy_engine *pe, int hook_handle);
int pe_reactivate_nvme_hook(struct policy_engine *pe, int hook_handle);
int pe_register_admin_hook(struct policy_engine *pe, uint8_t opcode,
                           NvmeHookCondition condition,
                           NvmeHookCallback callback,
                           void *context);
int pe_unregister_admin_hook(struct policy_engine *pe, int hook_handle);
int pe_inactivate_admin_hook(struct policy_engine *pe, int hook_handle);
int pe_reactivate_admin_hook(struct policy_engine *pe, int hook_handle);

/* Backend (BBM) hooks */
int pe_register_backend_hook(struct policy_engine *pe, BackendEventHookCondition condition, BackendEventHookCallback callback, void *context);
int pe_unregister_backend_hook(struct policy_engine *pe, int hook_handle);
int pe_inactivate_backend_hook(struct policy_engine *pe, int hook_handle);
int pe_reactivate_backend_hook(struct policy_engine *pe, int hook_handle);

/* pSWD transition hooks */
int pe_register_pswd_transition_hook(struct policy_engine *pe, PswdTransitionHookCondition condition, PswdTransitionHookCallback callback, void *context);
int pe_unregister_pswd_transition_hook(struct policy_engine *pe, int hook_handle);
int pe_inactivate_pswd_transition_hook(struct policy_engine *pe, int hook_handle);
int pe_reactivate_pswd_transition_hook(struct policy_engine *pe, int hook_handle);

/* Background hooks */
int pe_register_background_hook(struct policy_engine *pe, BackgroundHookCondition condition, BackgroundHookCallback callback, void *context);
int pe_unregister_background_hook(struct policy_engine *pe, int hook_handle);
int pe_inactivate_background_hook(struct policy_engine *pe, int hook_handle);
int pe_reactivate_background_hook(struct policy_engine *pe, int hook_handle);

/* Check if any active hooks exist for this opcode (for fast-path filtering in bb_io_cmd) */
bool pe_has_nvme_hook(struct policy_engine *pe, uint8_t opcode);
bool pe_has_admin_hook(struct policy_engine *pe, uint8_t opcode);

/* Create and init */
struct policy_engine *pe_create(void);
void pe_set_bbm(struct policy_engine *pe, struct bbm *ctx);
int pe_read_policy_payload(struct ssd *ssd,
                           const struct policy_storage_desc *desc,
                           uint8_t **payload_out);
int pe_activate_stored_policy(struct policy_engine *pe, struct ssd *ssd,
                              const struct policy_storage_desc *desc);
int pe_deactivate_policy(struct policy_engine *pe, uint32_t policy_id);
bool pe_is_policy_active(struct policy_engine *pe, uint32_t policy_id);

#endif /* POLICY_ENGINE_H */
