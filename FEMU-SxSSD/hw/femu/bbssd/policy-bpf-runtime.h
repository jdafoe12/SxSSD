#ifndef FEMU_POLICY_BPF_RUNTIME_H
#define FEMU_POLICY_BPF_RUNTIME_H

#include "policy-engine.h"
#include "policy/policy-bpf-abi.h"

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
    struct pe_bpf_subscription
        subscriptions[SXS_BPF_MAX_SUBSCRIPTIONS_PER_POLICY];
    uint32_t subscription_count;
    struct pe_policy_state_transaction *state_transaction;

    bool eswd_config_staged;
    struct sxs_bpf_eswd_config eswd_config;
    bool namespace_config_staged;
    struct sxs_bpf_namespace_config namespace_config;
    uint8_t *namespace_blob;
    uint8_t *controller_blob;
    uint8_t *namespace_blob_written;
    uint8_t *controller_blob_written;
    bool finalize_staged;

    struct pe_staged_oob oob[PE_MAX_STAGED_OOB];
    uint32_t oob_count;
};

struct pe_bpf_execution {
    struct sxs_bpf_context public_context; /* Must remain first. */
    struct policy_engine *engine;
    struct runtime_policy_record *owner;
    enum sxs_bpf_phase authoritative_phase;
    enum sxs_bpf_event_kind authoritative_event_kind;
    union {
        struct NvmeCommandEvent *nvme;
        struct FtlBackendEvent *backend;
        const struct PswdStateTransitionEvent *pswd;
    } native_event;
    struct pe_activation_transaction *activation;
};

int pe_activation_stage_subscription(struct pe_bpf_execution *execution,
                                     uint32_t event_kind, uint32_t selector,
                                     uint32_t pair_id, uint32_t flags);
int pe_runtime_owned_oob_handle(const struct runtime_policy_record *owner,
                                uint32_t object_id, uint32_t *bytes_out);

#endif /* FEMU_POLICY_BPF_RUNTIME_H */
