#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include "policy-engine-types.h"
#include "ftl.h"
#include "bbm.h"
#include "qemu/thread.h"

#define MAX_RUNTIME_POLICIES 16
#define MAX_PRIVILEGED_ADMIN_HOOKS 16
#define MAX_ORDINARY_SUBSCRIPTIONS                                      \
    (MAX_NVME_HOOKS + MAX_ADMIN_HOOKS + MAX_BACKEND_EVENT_HOOKS +      \
     MAX_PSWD_TRANSITION_HOOKS + MAX_BACKGROUND_HOOKS)
#define MAX_POLICY_OWNED_OOB 16

struct pe_bpf_vm;
struct pe_policy_state_store;

enum pe_runtime_state {
    PE_RUNTIME_INACTIVE = 0,
    PE_RUNTIME_ACTIVATING,
    PE_RUNTIME_ACTIVE,
    PE_RUNTIME_DRAINING,
};

struct policy_storage_desc {
    uint32_t policy_id;
    uint32_t policy_version;
    uint32_t generation;
    uint32_t policy_size_bytes;
    uint32_t block_count;
    const struct pba *blocks;
    const uint8_t *expected_payload;
};

struct pe_owned_oob {
    uint32_t object_id;
    uint32_t bytes_per_page;
    int backend_handle;
};

struct runtime_policy_record {
    uint32_t policy_id;
    uint32_t policy_version;
    uint32_t generation;
    enum pe_runtime_state state;
    struct pe_bpf_vm *vm;
    struct pe_policy_state_store *state_store;
    QemuMutex execution_lock;
    bool gc_active;
    uint64_t fault_count;
    struct pe_owned_oob owned_oob[MAX_POLICY_OWNED_OOB];
    uint32_t owned_oob_count;
};

struct pe_bpf_subscription {
    bool active;
    uint8_t event_kind;
    uint16_t flags;
    uint32_t selector;
    uint32_t pair_id;
    uint32_t owner_policy_id;
    uint32_t owner_generation;
    uint16_t owner_runtime_slot;
    uint64_t registration_sequence;
};

struct policy_engine {
    /* The meta-interface is the only native policy callback table. */
    struct AdminHook privileged_admin_hooks[MAX_PRIVILEGED_ADMIN_HOOKS];
    struct pe_bpf_subscription
        subscriptions[MAX_ORDINARY_SUBSCRIPTIONS];
    struct runtime_policy_record runtime_policies[MAX_RUNTIME_POLICIES];
    struct bbm *bbm_ctx;
    struct ssd *ssd;
    QemuMutex management_lock;
    QemuMutex state_lock;
    uint64_t next_registration_sequence;
    uint64_t state_bytes;

    uint32_t ftl_config_owner_policy_id;
    bool ftl_config_committed;
    struct eswd_config committed_eswd_config;
};

uint64_t pe_dispatch_nvme_cmd(struct policy_engine *pe, struct ssd *ssd,
                              struct NvmeCommandEvent *event);
uint64_t pe_dispatch_admin_cmd(struct policy_engine *pe, struct ssd *ssd,
                               struct NvmeCommandEvent *event);
void pe_dispatch_backend_event(struct policy_engine *pe, struct FtlBackend *fb,
                               struct bbm *ctx,
                               struct FtlBackendEvent *event);
void pe_dispatch_pswd_transition(struct FtlBackend *fb,
                                 const struct PswdStateTransitionEvent *event,
                                 void *notify_ctx);
void pe_dispatch_background_event(struct policy_engine *pe, struct ssd *ssd);

int pe_register_privileged_admin_hook(struct policy_engine *pe, uint8_t opcode,
                                      NvmeHookCondition condition,
                                      NvmeHookCallback callback,
                                      void *context);

bool pe_has_nvme_hook(struct policy_engine *pe, uint8_t opcode);
bool pe_has_admin_hook(struct policy_engine *pe, uint8_t opcode);

struct policy_engine *pe_create(void);
void pe_set_bbm(struct policy_engine *pe, struct bbm *ctx);
int pe_read_policy_payload(struct ssd *ssd,
                           const struct policy_storage_desc *desc,
                           uint8_t **payload_out);
int pe_validate_policy_image(const uint8_t *image, size_t image_size);
int pe_activate_stored_policy(struct policy_engine *pe, struct ssd *ssd,
                              const struct policy_storage_desc *desc);
int pe_deactivate_policy(struct policy_engine *pe, uint32_t policy_id);
int pe_can_remove_policy_state(struct policy_engine *pe, uint32_t policy_id,
                               uint32_t generation);
int pe_remove_policy_state(struct policy_engine *pe, uint32_t policy_id,
                           uint32_t generation);
bool pe_is_policy_active(struct policy_engine *pe, uint32_t policy_id);

#endif /* POLICY_ENGINE_H */
