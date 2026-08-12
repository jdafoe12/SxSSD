#ifndef FEMU_POLICY_WASM_RUNTIME_H
#define FEMU_POLICY_WASM_RUNTIME_H

#include "policy-engine.h"
#include "policy/policy-wasm-abi.h"

#define PE_MAX_STAGED_OOB 16U
#define PE_MAX_NAMESPACE_BLOB_BYTES (64U * 1024U)

struct pe_policy_state_transaction;

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
    struct pe_policy_state_transaction *state_transaction;

    bool eswd_config_staged;
    struct sxs_eswd_config eswd_config;
    bool namespace_config_staged;
    struct sxs_namespace_config namespace_config;
    uint8_t *namespace_blob;
    uint8_t *controller_blob;
    uint8_t *namespace_blob_written;
    uint8_t *controller_blob_written;
    bool finalize_staged;

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
        struct FtlBackendEvent *backend;
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
int pe_activation_stage_ftl_finalize(struct pe_policy_execution *execution);
int pe_activation_stage_oob(struct pe_policy_execution *execution,
                            uint32_t object_id, uint32_t bytes_per_page);
int pe_activation_stage_namespace_blob(
    struct pe_policy_execution *execution, uint32_t kind,
    uint32_t destination_offset, const void *source, uint32_t length);
int pe_runtime_owned_oob_handle(const struct runtime_policy_record *owner,
                                uint32_t object_id, uint32_t *bytes_out);

#endif /* FEMU_POLICY_WASM_RUNTIME_H */
