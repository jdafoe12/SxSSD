#ifndef FEMU_SXSSD_POLICY_ENGINE_H
#define FEMU_SXSSD_POLICY_ENGINE_H

#include "policy-api.h"
#include "bbm.h"
#include "qemu/thread.h"

#define MAX_BACKEND_EVENT_HOOKS 256
#define MAX_NVME_HOOKS 256
#define MAX_PSWD_TRANSITION_HOOKS 64
#define MAX_BACKGROUND_HOOKS 64
#define MAX_ADMIN_HOOKS 256

#define PE_MAX_STAGED_OOB 16U
#define PE_MAX_NAMESPACE_BLOB_BYTES (64U * 1024U)

enum pe_policy_privilege {
    PE_PRIVILEGE_NORMAL = 0,
    PE_PRIVILEGE_PRIVILEGED,
};

enum pe_policy_origin {
    PE_ORIGIN_STORED = 0,
    PE_ORIGIN_FIRMWARE,
};

#define MAX_STORED_RUNTIME_POLICIES 16
#define MAX_FIRMWARE_RUNTIME_POLICIES 4
#define MAX_RUNTIME_POLICIES \
    (MAX_STORED_RUNTIME_POLICIES + MAX_FIRMWARE_RUNTIME_POLICIES)
#define MAX_POLICY_SUBSCRIPTIONS                                        \
    (MAX_NVME_HOOKS + MAX_ADMIN_HOOKS + MAX_BACKEND_EVENT_HOOKS +      \
     MAX_PSWD_TRANSITION_HOOKS + MAX_BACKGROUND_HOOKS)
#define MAX_POLICY_OWNED_OOB 16

struct pe_wamr_vm;

enum pe_runtime_state {
    PE_RUNTIME_INACTIVE = 0,
    PE_RUNTIME_ACTIVATING,
    PE_RUNTIME_ACTIVE,
    PE_RUNTIME_DRAINING,
};

#define PE_FIRMWARE_POLICY_ID_BASE 0xffff0000U

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
    enum pe_policy_privilege privilege;
    enum pe_policy_origin origin;
    enum pe_runtime_state state;
    struct pe_wamr_vm *vm;
    QemuMutex execution_lock;
    uint64_t fault_count;
    struct pe_owned_oob owned_oob[MAX_POLICY_OWNED_OOB];
    uint32_t owned_oob_count;
};

struct pe_policy_subscription {
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
    struct pe_policy_subscription
        subscriptions[MAX_POLICY_SUBSCRIPTIONS];
    struct runtime_policy_record runtime_policies[MAX_RUNTIME_POLICIES];
    struct ssd *ssd;
    QemuMutex management_lock;
    uint64_t next_registration_sequence;

    uint32_t policy_api_config_owner_policy_id;
    bool policy_api_config_committed;
    struct eswd_config committed_eswd_config;
};

struct pe_staged_oob {
    uint32_t object_id;
    uint32_t bytes_per_page;
    int committed_handle;
    bool already_committed;
};

struct pe_activation_transaction {
    struct pe_policy_subscription
        subscriptions[SXS_WASM_MAX_SUBSCRIPTIONS_PER_POLICY];
    uint32_t subscription_count;
    bool eswd_config_staged;
    struct sxs_eswd_config eswd_config;
    bool namespace_config_staged;
    struct sxs_namespace_config namespace_config;
    uint8_t *namespace_blob;
    uint8_t *controller_blob;
    uint8_t *namespace_blob_written;
    uint8_t *controller_blob_written;
    bool eswd_layout_finalize_staged;
    struct pe_staged_oob oob[PE_MAX_STAGED_OOB];
    uint32_t oob_count;
};

struct pe_policy_execution {
    struct policy_engine *engine;
    struct runtime_policy_record *owner;
    enum sxs_phase authoritative_phase;
    enum sxs_event_kind authoritative_event_kind;
    uint32_t pair_id;
    uint32_t flags;
    union {
        struct sxs_nvme_event nvme;
        struct sxs_backend_event backend;
        struct sxs_pswd_event pswd;
    } event_snapshot;
    union {
        struct NvmeCommandEvent *nvme;
        const struct BbmEvent *backend;
        const struct PswdStateTransitionEvent *pswd;
    } native_event;
    struct pe_activation_transaction *activation;
};

int pe_activation_stage_subscription(struct pe_policy_execution *execution,
                                     uint32_t event_kind, uint32_t selector,
                                     uint32_t pair_id, uint32_t flags);
int pe_activation_stage_eswd_config(
    struct pe_policy_execution *execution,
    const struct sxs_eswd_config *source);
int pe_activation_stage_namespace_config(
    struct pe_policy_execution *execution,
    const struct sxs_namespace_config *source);
int pe_activation_stage_eswd_layout_finalize(
    struct pe_policy_execution *execution);
int pe_activation_stage_oob(struct pe_policy_execution *execution,
                            uint32_t object_id, uint32_t bytes_per_page);
int pe_activation_stage_namespace_blob(
    struct pe_policy_execution *execution, uint32_t kind,
    uint32_t destination_offset, const void *source, uint32_t length);
int pe_runtime_owned_oob_handle(const struct runtime_policy_record *owner,
                                uint32_t object_id, uint32_t *bytes_out);

uint64_t pe_dispatch_nvme_cmd(struct policy_engine *pe, struct ssd *ssd,
                              struct NvmeCommandEvent *event);
uint64_t pe_dispatch_admin_cmd(struct policy_engine *pe, struct ssd *ssd,
                               struct NvmeCommandEvent *event);
void pe_dispatch_flash_event(const struct BbmEvent *event, void *context);
void pe_dispatch_pswd_transition(struct RawFlash *fb,
                                 const struct PswdStateTransitionEvent *event,
                                 void *notify_ctx);
void pe_dispatch_background_event(struct policy_engine *pe, struct ssd *ssd);

bool pe_has_nvme_hook(struct policy_engine *pe, uint8_t opcode);
bool pe_has_admin_hook(struct policy_engine *pe, uint8_t opcode);

struct policy_engine *pe_create(struct ssd *ssd);
int pe_validate_policy_image(const uint8_t *image, size_t image_size);
int pe_activate_stored_policy(struct policy_engine *pe, struct ssd *ssd,
                              const struct policy_storage_desc *desc);
int pe_activate_firmware_policy(struct policy_engine *pe, struct ssd *ssd,
                                uint32_t policy_id, uint32_t policy_version,
                                const uint8_t *artifact, size_t artifact_size,
                                enum pe_policy_privilege privilege);
int pe_bootstrap_meta_interface_policy(struct policy_engine *pe,
                                       struct ssd *ssd);
int pe_deactivate_policy(struct policy_engine *pe, uint32_t policy_id);
int pe_can_remove_policy(struct policy_engine *pe, uint32_t policy_id,
                         uint32_t generation);
int pe_remove_policy(struct policy_engine *pe, uint32_t policy_id,
                     uint32_t generation);
bool pe_is_policy_active(struct policy_engine *pe, uint32_t policy_id);

#endif /* FEMU_SXSSD_POLICY_ENGINE_H */
