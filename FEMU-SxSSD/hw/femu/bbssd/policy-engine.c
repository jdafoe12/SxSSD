#include "qemu/osdep.h"
#include "policy-engine.h"
#include "policy-bpf-runtime.h"
#include "policy-bpf-state.h"
#include "policy-bpf-vm.h"
#include "policy/policy-bpf-abi.h"
#include "qemu/error-report.h"

#include <elf.h>
#include <inttypes.h>
#include <openssl/crypto.h>

static __thread uint16_t pe_executing_slots;

static int runtime_policy_slot_by_id(struct policy_engine *pe,
                                     uint32_t policy_id)
{
    int i;

    for (i = 0; i < MAX_RUNTIME_POLICIES; i++) {
        if (pe->runtime_policies[i].policy_id == policy_id) {
            return i;
        }
    }
    return -1;
}

static int runtime_policy_free_slot(struct policy_engine *pe)
{
    int i;

    for (i = 0; i < MAX_RUNTIME_POLICIES; i++) {
        if (pe->runtime_policies[i].policy_id == 0) {
            return i;
        }
    }
    return -1;
}

static void runtime_policy_clear_identity(struct runtime_policy_record *record)
{
    if (!record) {
        return;
    }
    record->policy_id = 0;
    record->policy_version = 0;
    record->generation = 0;
    record->state = PE_RUNTIME_INACTIVE;
    record->vm = NULL;
    record->state_store = NULL;
    record->gc_active = false;
    record->fault_count = 0;
    record->owned_oob_count = 0;
    memset(record->owned_oob, 0, sizeof(record->owned_oob));
}

static bool privileged_opcode_registered(const struct policy_engine *pe,
                                         uint8_t opcode)
{
    int i;

    for (i = 0; i < MAX_PRIVILEGED_ADMIN_HOOKS; i++) {
        if (pe->privileged_admin_hooks[i].active &&
            pe->privileged_admin_hooks[i].callback &&
            pe->privileged_admin_hooks[i].opcode == opcode) {
            return true;
        }
    }
    return false;
}

int pe_activation_stage_subscription(struct pe_bpf_execution *execution,
                                     uint32_t event_kind, uint32_t selector,
                                     uint32_t pair_id, uint32_t flags)
{
    struct pe_activation_transaction *activation;
    uint32_t i;

    if (!execution || !execution->engine || !execution->owner ||
        execution->authoritative_phase != SXS_BPF_PHASE_INIT ||
        !execution->activation) {
        return -SXS_BPF_EPERM;
    }
    activation = execution->activation;
    if (flags != 0 || pair_id == 0 || pair_id > UINT16_MAX) {
        return -SXS_BPF_EINVAL;
    }
    switch (event_kind) {
    case SXS_BPF_EVENT_NVME_IO:
        if (selector > UINT8_MAX) {
            return -SXS_BPF_EINVAL;
        }
        break;
    case SXS_BPF_EVENT_NVME_ADMIN:
        if (selector > UINT8_MAX) {
            return -SXS_BPF_EINVAL;
        }
        if (privileged_opcode_registered(execution->engine,
                                         (uint8_t)selector)) {
            return -SXS_BPF_EPERM;
        }
        break;
    case SXS_BPF_EVENT_BACKEND:
        if (selector != SXS_BPF_SELECTOR_ANY &&
            selector > FTL_BACKEND_EVENT_ERASE) {
            return -SXS_BPF_EINVAL;
        }
        break;
    case SXS_BPF_EVENT_PSWD_TRANSITION:
        if (selector != SXS_BPF_SELECTOR_ANY && selector > PSWD_BAD) {
            return -SXS_BPF_EINVAL;
        }
        break;
    case SXS_BPF_EVENT_BACKGROUND:
        if (selector != 0) {
            return -SXS_BPF_EINVAL;
        }
        break;
    default:
        return -SXS_BPF_EINVAL;
    }
    if (activation->subscription_count >=
        SXS_BPF_MAX_SUBSCRIPTIONS_PER_POLICY) {
        return -SXS_BPF_ENOSPC;
    }
    for (i = 0; i < activation->subscription_count; i++) {
        struct pe_bpf_subscription *existing =
            &activation->subscriptions[i];

        if (existing->event_kind == event_kind &&
            existing->selector == selector && existing->pair_id == pair_id &&
            existing->flags == flags) {
            return -SXS_BPF_EEXIST;
        }
    }

    activation->subscriptions[activation->subscription_count++] =
        (struct pe_bpf_subscription) {
            .event_kind = event_kind,
            .selector = selector,
            .pair_id = pair_id,
            .flags = flags,
        };
    return 0;
}

int pe_runtime_owned_oob_handle(const struct runtime_policy_record *owner,
                                uint32_t object_id, uint32_t *bytes_out)
{
    uint32_t i;

    if (!owner || object_id == 0) {
        return -1;
    }
    for (i = 0; i < owner->owned_oob_count; i++) {
        if (owner->owned_oob[i].object_id == object_id) {
            if (bytes_out) {
                *bytes_out = owner->owned_oob[i].bytes_per_page;
            }
            return owner->owned_oob[i].backend_handle;
        }
    }
    return -1;
}

int pe_read_policy_payload(struct ssd *ssd,
                           const struct policy_storage_desc *desc,
                           uint8_t **payload_out)
{
    uint32_t page_size;
    uint32_t pages_per_block;
    uint32_t page_count;
    struct ppa *ppa_list = NULL;
    uint8_t *payload = NULL;
    uint32_t i;
    int rc = -1;

    if (!ssd || !desc || !desc->blocks || !payload_out ||
        desc->policy_size_bytes == 0 ||
        desc->policy_size_bytes > SXS_BPF_MAX_ARTIFACT_BYTES) {
        return -1;
    }
    page_size = ssd->fb->sp.secs_per_pg * ssd->fb->sp.secsz;
    pages_per_block = ssd->fb->sp.pgs_per_blk;
    page_count = (desc->policy_size_bytes + page_size - 1) / page_size;
    payload = g_malloc0((size_t)page_count * page_size);
    ppa_list = g_malloc0(sizeof(*ppa_list) * page_count);

    for (i = 0; i < page_count; i++) {
        uint32_t block_index = i / pages_per_block;
        uint32_t page_index = i % pages_per_block;

        if (block_index >= desc->block_count) {
            goto cleanup;
        }
        ppa_list[i].g.ch = desc->blocks[block_index].g.ch;
        ppa_list[i].g.lun = desc->blocks[block_index].g.lun;
        ppa_list[i].g.pl = desc->blocks[block_index].g.pl;
        ppa_list[i].g.blk = desc->blocks[block_index].g.blk;
        ppa_list[i].g.pg = page_index;
        ppa_list[i].g.sec = 0;
    }
    if (ftl_backend_raw_read(ssd->fb, payload, ppa_list, page_count,
                             page_size, NULL, 0, 0, NULL) != 0) {
        goto cleanup;
    }
    if (desc->expected_payload &&
        memcmp(payload, desc->expected_payload,
               desc->policy_size_bytes) != 0) {
        goto cleanup;
    }
    *payload_out = payload;
    payload = NULL;
    rc = 0;

cleanup:
    g_free(ppa_list);
    g_free(payload);
    return rc;
}

static void initialize_public_context(struct pe_bpf_execution *execution,
                                      enum sxs_bpf_phase phase,
                                      uint32_t event_kind, uint32_t pair_id)
{
    struct runtime_policy_record *owner = execution->owner;

    memset(&execution->public_context, 0,
           sizeof(execution->public_context));
    execution->authoritative_phase = phase;
    execution->authoritative_event_kind = event_kind;
    execution->public_context.abi_version = SXS_BPF_ABI_VERSION;
    execution->public_context.context_size =
        sizeof(execution->public_context);
    execution->public_context.phase = phase;
    execution->public_context.event_kind = event_kind;
    execution->public_context.policy_id = owner->policy_id;
    execution->public_context.policy_version = owner->policy_version;
    execution->public_context.generation = owner->generation;
    execution->public_context.pair_id = pair_id;
}

static void copy_nvme_event(struct pe_bpf_execution *execution,
                            struct NvmeCommandEvent *event)
{
    struct sxs_bpf_nvme_event *destination =
        &execution->public_context.event.nvme;
    NvmeCmd *command = event->cmd;

    destination->opcode = event->opcode;
    destination->lba = event->lba;
    destination->nsecs = event->nsecs;
    destination->start_lpn = event->start_lpn;
    destination->end_lpn = event->end_lpn;
    destination->lpn_count = event->lpn_cnt;
    destination->start_time_ns = event->stime;
    destination->initial_status = event->status;
    if (command) {
        destination->nsid = le32_to_cpu(command->nsid);
        destination->cdw10 = le32_to_cpu(command->cdw10);
        destination->cdw11 = le32_to_cpu(command->cdw11);
        destination->cdw12 = le32_to_cpu(command->cdw12);
        destination->cdw13 = le32_to_cpu(command->cdw13);
        destination->cdw14 = le32_to_cpu(command->cdw14);
        destination->cdw15 = le32_to_cpu(command->cdw15);
    }
}

static void copy_backend_event(struct pe_bpf_execution *execution,
                               struct FtlBackendEvent *event)
{
    struct sxs_bpf_backend_event *destination =
        &execution->public_context.event.backend;

    destination->command = event->cmd;
    destination->io_type = event->type;
    destination->status_count = event->count;
    destination->start_time_ns = event->stime;
    destination->latency_ns = event->lat;
}

static void copy_pswd_event(struct pe_bpf_execution *execution,
                            const struct PswdStateTransitionEvent *event)
{
    struct sxs_bpf_pswd_event *destination =
        &execution->public_context.event.pswd;

    destination->old_state = event->old_state;
    destination->new_state = event->new_state;
    destination->pba = event->pba.pba;
    destination->erase_count = event->erase_cnt;
    destination->write_pointer = event->wp;
}

static void build_event_execution(struct pe_bpf_execution *execution,
                                  enum sxs_bpf_phase phase,
                                  const struct pe_bpf_subscription *subscription,
                                  void *native_event)
{
    initialize_public_context(execution, phase, subscription->event_kind,
                              subscription->pair_id);
    switch (subscription->event_kind) {
    case SXS_BPF_EVENT_NVME_IO:
    case SXS_BPF_EVENT_NVME_ADMIN:
        execution->native_event.nvme = native_event;
        copy_nvme_event(execution, native_event);
        break;
    case SXS_BPF_EVENT_BACKEND:
        execution->native_event.backend = native_event;
        copy_backend_event(execution, native_event);
        break;
    case SXS_BPF_EVENT_PSWD_TRANSITION:
        execution->native_event.pswd = native_event;
        copy_pswd_event(execution, native_event);
        break;
    case SXS_BPF_EVENT_BACKGROUND:
        break;
    default:
        g_assert_not_reached();
    }
}

static void record_runtime_fault(struct runtime_policy_record *record,
                                 const char *phase)
{
    record->fault_count++;
    if (record->fault_count == 1 ||
        (record->fault_count & (record->fault_count - 1)) == 0) {
        warn_report("policy id=%u generation=%u %s fault "
                    "(count=%" PRIu64 ")",
                    record->policy_id, record->generation, phase,
                    record->fault_count);
    }
}

static bool execute_subscription(struct policy_engine *pe,
                                 const struct pe_bpf_subscription *subscription,
                                 void *native_event, uint64_t *action_result,
                                 bool *action_fault)
{
    struct runtime_policy_record *record;
    struct pe_bpf_execution execution = {0};
    uint16_t slot = subscription->owner_runtime_slot;
    uint64_t result = 0;
    int rc;

    *action_fault = false;
    if (slot >= MAX_RUNTIME_POLICIES ||
        (pe_executing_slots & (1U << slot)) != 0) {
        return false;
    }
    record = &pe->runtime_policies[slot];
    qemu_mutex_lock(&record->execution_lock);
    qemu_mutex_lock(&pe->management_lock);
    if (record->state != PE_RUNTIME_ACTIVE || !record->vm ||
        record->policy_id != subscription->owner_policy_id ||
        record->generation != subscription->owner_generation) {
        qemu_mutex_unlock(&pe->management_lock);
        qemu_mutex_unlock(&record->execution_lock);
        return false;
    }
    qemu_mutex_unlock(&pe->management_lock);

    pe_executing_slots |= (uint16_t)(1U << slot);
    execution.engine = pe;
    execution.owner = record;
    build_event_execution(&execution, SXS_BPF_PHASE_CONDITION,
                          subscription, native_event);
    rc = pe_bpf_vm_execute(record->vm, &execution.public_context,
                           sizeof(execution.public_context), &result);
    if (rc != 0 || result > 1) {
        record_runtime_fault(record, "condition");
        goto no_match;
    }
    if (result == 0) {
        goto no_match;
    }

    memset(&execution.native_event, 0, sizeof(execution.native_event));
    build_event_execution(&execution, SXS_BPF_PHASE_ACTION,
                          subscription, native_event);
    result = 0;
    rc = pe_bpf_vm_execute(record->vm, &execution.public_context,
                           sizeof(execution.public_context), &result);
    if (rc != 0 || result == SXS_BPF_ACTION_ERROR) {
        record_runtime_fault(record, "action");
        *action_fault = true;
    }
    *action_result = result;
    pe_executing_slots &= (uint16_t)~(1U << slot);
    OPENSSL_cleanse(&execution, sizeof(execution));
    qemu_mutex_unlock(&record->execution_lock);
    return true;

no_match:
    pe_executing_slots &= (uint16_t)~(1U << slot);
    OPENSSL_cleanse(&execution, sizeof(execution));
    qemu_mutex_unlock(&record->execution_lock);
    return false;
}

static bool subscription_matches(const struct pe_bpf_subscription *subscription,
                                 uint32_t event_kind, uint32_t selector)
{
    if (!subscription->active || subscription->event_kind != event_kind) {
        return false;
    }
    if (event_kind == SXS_BPF_EVENT_BACKGROUND) {
        return true;
    }
    return subscription->selector == selector ||
           subscription->selector == SXS_BPF_SELECTOR_ANY;
}

static int subscription_oldest_first(const void *left, const void *right)
{
    const struct pe_bpf_subscription *a = left;
    const struct pe_bpf_subscription *b = right;

    return a->registration_sequence < b->registration_sequence ? -1 :
           a->registration_sequence > b->registration_sequence ? 1 : 0;
}

static int subscription_newest_first(const void *left, const void *right)
{
    return -subscription_oldest_first(left, right);
}

static struct pe_bpf_subscription *
snapshot_subscriptions(struct policy_engine *pe, uint32_t event_kind,
                       uint32_t selector, bool newest_first,
                       size_t *count_out)
{
    struct pe_bpf_subscription *snapshot;
    size_t count = 0;
    int i;

    snapshot = g_new(struct pe_bpf_subscription,
                     MAX_ORDINARY_SUBSCRIPTIONS);
    qemu_mutex_lock(&pe->management_lock);
    for (i = 0; i < MAX_ORDINARY_SUBSCRIPTIONS; i++) {
        if (subscription_matches(&pe->subscriptions[i], event_kind,
                                 selector)) {
            snapshot[count++] = pe->subscriptions[i];
        }
    }
    qemu_mutex_unlock(&pe->management_lock);
    qsort(snapshot, count, sizeof(*snapshot),
          newest_first ? subscription_newest_first :
                         subscription_oldest_first);
    *count_out = count;
    return snapshot;
}

uint64_t pe_dispatch_nvme_cmd(struct policy_engine *pe, struct ssd *ssd,
                              struct NvmeCommandEvent *event)
{
    struct pe_bpf_subscription *subscriptions;
    size_t count;
    size_t i;

    if (!pe || !ssd || !event) {
        return 0;
    }
    subscriptions = snapshot_subscriptions(
        pe, SXS_BPF_EVENT_NVME_IO, event->opcode, true, &count);
    for (i = 0; i < count; i++) {
        uint64_t result = 0;
        bool fault;

        if (!execute_subscription(pe, &subscriptions[i], event, &result,
                                  &fault)) {
            continue;
        }
        if (fault) {
            event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
            result = 0;
        }
        event->lat = result;
        g_free(subscriptions);
        return result;
    }
    g_free(subscriptions);
    event->lat = 0;
    return 0;
}

uint64_t pe_dispatch_admin_cmd(struct policy_engine *pe, struct ssd *ssd,
                               struct NvmeCommandEvent *event)
{
    struct pe_bpf_subscription *subscriptions;
    size_t count;
    size_t i;

    if (!pe || !ssd || !event) {
        return 0;
    }
    for (i = 0; i < MAX_PRIVILEGED_ADMIN_HOOKS; i++) {
        struct AdminHook *hook = &pe->privileged_admin_hooks[i];
        bool should_fire;

        if (!hook->active || !hook->callback ||
            hook->opcode != event->opcode) {
            continue;
        }
        should_fire = !hook->condition ||
            hook->condition(ssd, event, ssd->policy_api, hook->context);
        if (should_fire) {
            event->lat = hook->callback(ssd, event, ssd->policy_api,
                                        hook->context);
            return event->lat;
        }
    }

    subscriptions = snapshot_subscriptions(
        pe, SXS_BPF_EVENT_NVME_ADMIN, event->opcode, true, &count);
    for (i = 0; i < count; i++) {
        uint64_t result = 0;
        bool fault;

        if (!execute_subscription(pe, &subscriptions[i], event, &result,
                                  &fault)) {
            continue;
        }
        if (fault) {
            event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
            result = 0;
        }
        event->lat = result;
        g_free(subscriptions);
        return result;
    }
    g_free(subscriptions);
    event->lat = 0;
    return 0;
}

void pe_dispatch_backend_event(struct policy_engine *pe, struct FtlBackend *fb,
                               struct bbm *ctx,
                               struct FtlBackendEvent *event)
{
    struct pe_bpf_subscription *subscriptions;
    size_t count;
    size_t i;

    if (!pe || !fb || !ctx || !event) {
        return;
    }
    subscriptions = snapshot_subscriptions(
        pe, SXS_BPF_EVENT_BACKEND, event->cmd, false, &count);
    for (i = 0; i < count; i++) {
        uint64_t ignored;
        bool fault;

        execute_subscription(pe, &subscriptions[i], event, &ignored, &fault);
    }
    g_free(subscriptions);
}

void pe_dispatch_pswd_transition(struct FtlBackend *fb,
                                 const struct PswdStateTransitionEvent *event,
                                 void *notify_ctx)
{
    struct policy_engine *pe = notify_ctx;
    struct pe_bpf_subscription *subscriptions;
    size_t count;
    size_t i;

    if (!pe || !fb || !event || !pe->bbm_ctx) {
        return;
    }
    subscriptions = snapshot_subscriptions(
        pe, SXS_BPF_EVENT_PSWD_TRANSITION, event->new_state, false, &count);
    for (i = 0; i < count; i++) {
        uint64_t ignored;
        bool fault;

        execute_subscription(pe, &subscriptions[i], (void *)event,
                             &ignored, &fault);
    }
    g_free(subscriptions);
}

void pe_dispatch_background_event(struct policy_engine *pe, struct ssd *ssd)
{
    struct pe_bpf_subscription *subscriptions;
    size_t count;
    size_t i;

    if (!pe || !ssd) {
        return;
    }
    subscriptions = snapshot_subscriptions(
        pe, SXS_BPF_EVENT_BACKGROUND, 0, false, &count);
    for (i = 0; i < count; i++) {
        uint64_t ignored;
        bool fault;

        if (execute_subscription(pe, &subscriptions[i], NULL,
                                 &ignored, &fault)) {
            break;
        }
    }
    g_free(subscriptions);
}

int pe_register_privileged_admin_hook(struct policy_engine *pe, uint8_t opcode,
                                      NvmeHookCondition condition,
                                      NvmeHookCallback callback,
                                      void *context)
{
    int free_slot = -1;
    int i;

    if (!pe || !callback) {
        return -1;
    }
    qemu_mutex_lock(&pe->management_lock);
    for (i = 0; i < MAX_PRIVILEGED_ADMIN_HOOKS; i++) {
        if (pe->privileged_admin_hooks[i].callback) {
            if (pe->privileged_admin_hooks[i].opcode == opcode) {
                goto fail;
            }
        } else if (free_slot < 0) {
            free_slot = i;
        }
    }
    for (i = 0; i < MAX_ORDINARY_SUBSCRIPTIONS; i++) {
        if (pe->subscriptions[i].active &&
            pe->subscriptions[i].event_kind == SXS_BPF_EVENT_NVME_ADMIN &&
            pe->subscriptions[i].selector == opcode) {
            goto fail;
        }
    }
    if (free_slot < 0) {
        goto fail;
    }
    pe->privileged_admin_hooks[free_slot] = (struct AdminHook) {
        .opcode = opcode,
        .condition = condition,
        .callback = callback,
        .context = context,
        .active = true,
    };
    qemu_mutex_unlock(&pe->management_lock);
    return free_slot;

fail:
    qemu_mutex_unlock(&pe->management_lock);
    return -1;
}

bool pe_has_nvme_hook(struct policy_engine *pe, uint8_t opcode)
{
    bool found = false;
    int i;

    if (!pe) {
        return false;
    }
    qemu_mutex_lock(&pe->management_lock);
    for (i = 0; i < MAX_ORDINARY_SUBSCRIPTIONS; i++) {
        if (pe->subscriptions[i].active &&
            pe->subscriptions[i].event_kind == SXS_BPF_EVENT_NVME_IO &&
            pe->subscriptions[i].selector == opcode) {
            found = true;
            break;
        }
    }
    qemu_mutex_unlock(&pe->management_lock);
    return found;
}

bool pe_has_admin_hook(struct policy_engine *pe, uint8_t opcode)
{
    bool found;
    int i;

    if (!pe) {
        return false;
    }
    qemu_mutex_lock(&pe->management_lock);
    found = privileged_opcode_registered(pe, opcode);
    for (i = 0; !found && i < MAX_ORDINARY_SUBSCRIPTIONS; i++) {
        if (pe->subscriptions[i].active &&
            pe->subscriptions[i].event_kind == SXS_BPF_EVENT_NVME_ADMIN &&
            pe->subscriptions[i].selector == opcode) {
            found = true;
        }
    }
    qemu_mutex_unlock(&pe->management_lock);
    return found;
}

struct policy_engine *pe_create(void)
{
    struct policy_engine *pe = g_new0(struct policy_engine, 1);
    int i;

    qemu_mutex_init(&pe->management_lock);
    qemu_mutex_init(&pe->state_lock);
    for (i = 0; i < MAX_RUNTIME_POLICIES; i++) {
        qemu_mutex_init(&pe->runtime_policies[i].execution_lock);
        pe->runtime_policies[i].state = PE_RUNTIME_INACTIVE;
    }
    pe->next_registration_sequence = 1;
    return pe;
}

void pe_set_bbm(struct policy_engine *pe, struct bbm *ctx)
{
    if (pe) {
        pe->bbm_ctx = ctx;
    }
}

int pe_validate_policy_image(const uint8_t *image, size_t image_size)
{
    char *error = NULL;
    int rc = pe_bpf_vm_validate(image, image_size, &error);

    if (rc != 0) {
        warn_report("invalid ordinary policy: %s",
                    error ? error : "unknown uBPF loader error");
    }
    g_free(error);
    return rc;
}

static uint32_t count_free_subscriptions(const struct policy_engine *pe)
{
    uint32_t count = 0;
    int i;

    for (i = 0; i < MAX_ORDINARY_SUBSCRIPTIONS; i++) {
        if (!pe->subscriptions[i].active) {
            count++;
        }
    }
    return count;
}

static void remove_policy_subscriptions_locked(
    struct policy_engine *pe, uint32_t policy_id, uint32_t generation)
{
    int i;

    for (i = 0; i < MAX_ORDINARY_SUBSCRIPTIONS; i++) {
        struct pe_bpf_subscription *subscription = &pe->subscriptions[i];

        if (subscription->active &&
            subscription->owner_policy_id == policy_id &&
            subscription->owner_generation == generation) {
            memset(subscription, 0, sizeof(*subscription));
        }
    }
}

static void publish_subscriptions_locked(
    struct policy_engine *pe, struct runtime_policy_record *record,
    uint16_t runtime_slot, struct pe_activation_transaction *activation)
{
    uint32_t published = 0;
    int i;

    g_assert(count_free_subscriptions(pe) >= activation->subscription_count);
    for (i = 0; i < MAX_ORDINARY_SUBSCRIPTIONS &&
                published < activation->subscription_count; i++) {
        struct pe_bpf_subscription *destination = &pe->subscriptions[i];

        if (destination->active) {
            continue;
        }
        *destination = activation->subscriptions[published++];
        destination->active = true;
        destination->owner_policy_id = record->policy_id;
        destination->owner_generation = record->generation;
        destination->owner_runtime_slot = runtime_slot;
        destination->registration_sequence =
            pe->next_registration_sequence++;
        if (pe->next_registration_sequence == 0) {
            pe->next_registration_sequence = 1;
        }
    }
    g_assert(published == activation->subscription_count);
}

static bool blob_complete(const uint8_t *written, uint32_t length)
{
    uint32_t i;

    if (length == 0) {
        return true;
    }
    if (!written) {
        return false;
    }
    for (i = 0; i < length; i++) {
        if (!written[i]) {
            return false;
        }
    }
    return true;
}

static int validate_activation_transaction(
    struct policy_engine *pe, struct runtime_policy_record *record,
    const struct pe_activation_transaction *activation)
{
    const struct FemuCtrl *controller = pe->ssd->ctrl;
    const NvmeNamespace *namespace = NULL;
    struct eswd_config candidate_config;
    struct eswd_layout candidate_layout = {0};
    uint64_t page_size;
    uint32_t new_oob_sizes[PE_MAX_STAGED_OOB];
    uint32_t new_oob_count = 0;
    uint32_t i;

    page_size = (uint64_t)pe->ssd->fb->sp.secs_per_pg *
                pe->ssd->fb->sp.secsz;
    if (page_size > SXS_BPF_MAX_PAGE_BYTES ||
        !blob_complete(activation->namespace_blob_written,
                       activation->namespace_config.namespace_blob_length) ||
        !blob_complete(activation->controller_blob_written,
                       activation->namespace_config.controller_blob_length)) {
        return -1;
    }
    if (activation->namespace_config_staged && controller &&
        controller->namespaces && controller->num_namespaces != 0) {
        namespace = &controller->namespaces[0];
    }
    if (activation->namespace_config_staged && !namespace) {
        return -1;
    }
    if (!pe->ftl_config_committed &&
        (activation->eswd_config_staged ||
         activation->namespace_config_staged || activation->finalize_staged) &&
        (!activation->eswd_config_staged ||
         !activation->namespace_config_staged ||
         !activation->finalize_staged)) {
        return -1;
    }
    if (activation->finalize_staged && !activation->eswd_config_staged &&
        !pe->ssd->eswd_config_set) {
        return -1;
    }
    if (pe->ftl_config_committed) {
        if ((activation->eswd_config_staged ||
             activation->namespace_config_staged ||
             activation->finalize_staged) &&
            pe->ftl_config_owner_policy_id != record->policy_id) {
            return -1;
        }
        if (activation->eswd_config_staged &&
            (pe->committed_eswd_config.striping_level !=
                 activation->eswd_config.striping_level ||
             pe->committed_eswd_config.blocks_per_eswd !=
                 activation->eswd_config.blocks_per_eswd)) {
            return -1;
        }
        if (activation->namespace_config_staged &&
            (controller->csi != activation->namespace_config.csi ||
             le64_to_cpu(namespace->id_ns.nsze) !=
                 activation->namespace_config.nsze ||
             le64_to_cpu(namespace->id_ns.ncap) !=
                 activation->namespace_config.ncap ||
             le64_to_cpu(namespace->id_ns.nuse) !=
                 activation->namespace_config.nuse ||
             namespace->id_ns.noiob != activation->namespace_config.noiob ||
             controller->id_ns_csi_len !=
                 activation->namespace_config.namespace_blob_length ||
             controller->id_ctrl_csi_len !=
                 activation->namespace_config.controller_blob_length ||
             (controller->id_ns_csi_len &&
              memcmp(controller->id_ns_csi, activation->namespace_blob,
                     controller->id_ns_csi_len) != 0) ||
             (controller->id_ctrl_csi_len &&
              memcmp(controller->id_ctrl_csi, activation->controller_blob,
                     controller->id_ctrl_csi_len) != 0))) {
            return -1;
        }
    } else if (activation->eswd_config_staged) {
        candidate_config = (struct eswd_config) {
            .striping_level = activation->eswd_config.striping_level,
            .blocks_per_eswd = activation->eswd_config.blocks_per_eswd,
        };
        if (!pe->ssd->bbm || !pe->ssd->bbm->geom ||
            !eswd_config_valid(&candidate_config,
                               pe->ssd->bbm->geom->nchs,
                               pe->ssd->bbm->geom->luns_per_ch,
                               pe->ssd->bbm->geom->pls_per_lun,
                               pe->ssd->bbm->geom->blks_per_lun_log) ||
            eswd_layout_compute(&candidate_layout, &candidate_config,
                                pe->ssd->bbm->geom) != 0) {
            return -1;
        }
        eswd_layout_cleanup(&candidate_layout);
    }
    for (i = 0; i < activation->oob_count; i++) {
        if (!activation->oob[i].already_committed) {
            new_oob_sizes[new_oob_count++] =
                activation->oob[i].bytes_per_page;
        }
    }
    if (new_oob_count > MAX_POLICY_OWNED_OOB - record->owned_oob_count ||
        ftl_backend_can_register_oob_policies(pe->ssd->fb, new_oob_sizes,
                                              new_oob_count) != 0) {
        return -1;
    }
    return 0;
}

static void commit_activation_resources(
    struct policy_engine *pe, struct runtime_policy_record *record,
    struct pe_activation_transaction *activation)
{
    uint32_t i;
    int rc;

    if (activation->eswd_config_staged && !pe->ftl_config_committed) {
        struct eswd_config config = {
            .striping_level = activation->eswd_config.striping_level,
            .blocks_per_eswd = activation->eswd_config.blocks_per_eswd,
        };

        set_eswd_config(pe->ssd, &config);
        g_assert(pe->ssd->eswd_config_set);
        pe->committed_eswd_config = config;
    }
    if (activation->namespace_config_staged && !pe->ftl_config_committed) {
        struct NamespacePersonalityConfig config = {
            .csi = activation->namespace_config.csi,
            .nsze = activation->namespace_config.nsze,
            .ncap = activation->namespace_config.ncap,
            .nuse = activation->namespace_config.nuse,
            .noiob = activation->namespace_config.noiob,
            .ns_csi_data = activation->namespace_blob,
            .ns_csi_data_len =
                activation->namespace_config.namespace_blob_length,
            .ctrl_csi_data = activation->controller_blob,
            .ctrl_csi_data_len =
                activation->namespace_config.controller_blob_length,
        };

        rc = configure_namespace_personality(pe->ssd, &config);
        g_assert(rc == 0);
    }
    for (i = 0; i < activation->oob_count; i++) {
        struct pe_staged_oob *staged = &activation->oob[i];
        char name[48];
        int handle;

        if (staged->already_committed) {
            continue;
        }
        snprintf(name, sizeof(name), "policy-%u-object-%u",
                 record->policy_id, staged->object_id);
        g_assert(record->owned_oob_count < MAX_POLICY_OWNED_OOB);
        rc = ftl_register_oob_region(pe->ssd, name, staged->bytes_per_page,
                                     &handle);
        g_assert(rc == 0);
        record->owned_oob[record->owned_oob_count++] =
            (struct pe_owned_oob) {
                .object_id = staged->object_id,
                .bytes_per_page = staged->bytes_per_page,
                .backend_handle = handle,
            };
    }
    if (activation->finalize_staged && !pe->ssd->eswd_layout_finalized) {
        rc = finalize_ftl_init(pe->ssd);
        g_assert(rc == 0);
        pe->ftl_config_owner_policy_id = record->policy_id;
        pe->ftl_config_committed = true;
    }
}

static void activation_transaction_destroy(
    struct pe_activation_transaction *activation, bool abort_state)
{
    if (!activation) {
        return;
    }
    if (abort_state && activation->state_transaction) {
        pe_policy_state_transaction_abort(activation->state_transaction);
    }
    g_free(activation->namespace_blob);
    g_free(activation->controller_blob);
    g_free(activation->namespace_blob_written);
    g_free(activation->controller_blob_written);
    g_free(activation);
}

int pe_activate_stored_policy(struct policy_engine *pe, struct ssd *ssd,
                              const struct policy_storage_desc *desc)
{
    struct runtime_policy_record *record;
    struct pe_activation_transaction *activation = NULL;
    struct pe_bpf_execution execution = {0};
    struct pe_bpf_vm *candidate_vm = NULL;
    uint8_t *payload = NULL;
    uint64_t result = SXS_BPF_ACTION_ERROR;
    char *error = NULL;
    int slot;
    bool new_record = false;
    bool restored;
    int rc = -1;

    if (!pe || !ssd || !desc || !desc->blocks || desc->policy_id == 0 ||
        desc->policy_version == 0 || desc->generation == 0) {
        return -1;
    }
    pe->ssd = ssd;
    qemu_mutex_lock(&pe->management_lock);
    slot = runtime_policy_slot_by_id(pe, desc->policy_id);
    if (slot >= 0) {
        record = &pe->runtime_policies[slot];
        if (record->state == PE_RUNTIME_ACTIVE &&
            record->generation == desc->generation) {
            qemu_mutex_unlock(&pe->management_lock);
            return 0;
        }
        if (record->state != PE_RUNTIME_INACTIVE ||
            record->generation != desc->generation) {
            qemu_mutex_unlock(&pe->management_lock);
            return -1;
        }
    } else {
        slot = runtime_policy_free_slot(pe);
        if (slot < 0) {
            qemu_mutex_unlock(&pe->management_lock);
            return -1;
        }
        record = &pe->runtime_policies[slot];
        new_record = true;
        record->policy_id = desc->policy_id;
        record->generation = desc->generation;
    }
    record->policy_version = desc->policy_version;
    record->state = PE_RUNTIME_ACTIVATING;
    restored = record->state_store != NULL;
    qemu_mutex_unlock(&pe->management_lock);

    if (pe_read_policy_payload(ssd, desc, &payload) != 0) {
        goto fail;
    }
    candidate_vm = pe_bpf_vm_create(payload, desc->policy_size_bytes, &error);
    g_free(payload);
    payload = NULL;
    if (!candidate_vm) {
        warn_report("failed to load policy id=%u: %s", desc->policy_id,
                    error ? error : "unknown uBPF error");
        goto fail;
    }

    activation = g_new0(struct pe_activation_transaction, 1);
    activation->state_transaction = pe_policy_state_transaction_begin(
        record->state_store, &pe->state_bytes, &pe->state_lock);
    if (!activation->state_transaction) {
        goto fail;
    }
    execution.engine = pe;
    execution.owner = record;
    execution.activation = activation;
    initialize_public_context(&execution, SXS_BPF_PHASE_INIT,
                              SXS_BPF_EVENT_NONE, 0);
    if (restored) {
        execution.public_context.flags |= SXS_BPF_FLAG_STATE_RESTORED;
    }
    if (pe_bpf_vm_execute(candidate_vm, &execution.public_context,
                          sizeof(execution.public_context), &result) != 0 ||
        result != 0) {
        OPENSSL_cleanse(&execution, sizeof(execution));
        warn_report("policy id=%u INIT failed (result=%" PRIu64 ")",
                    desc->policy_id, result);
        goto fail;
    }
    OPENSSL_cleanse(&execution, sizeof(execution));

    qemu_mutex_lock(&pe->management_lock);
    if (record->state != PE_RUNTIME_ACTIVATING ||
        record->policy_id != desc->policy_id ||
        record->generation != desc->generation ||
        count_free_subscriptions(pe) < activation->subscription_count ||
        validate_activation_transaction(pe, record, activation) != 0) {
        qemu_mutex_unlock(&pe->management_lock);
        goto fail;
    }
    if (pe_policy_state_transaction_commit(
            activation->state_transaction, &record->state_store) != 0) {
        qemu_mutex_unlock(&pe->management_lock);
        goto fail;
    }
    activation->state_transaction = NULL;
    /* Everything below is a no-fail publication of prevalidated resources. */
    commit_activation_resources(pe, record, activation);
    publish_subscriptions_locked(pe, record, slot, activation);
    record->vm = candidate_vm;
    candidate_vm = NULL;
    record->state = PE_RUNTIME_ACTIVE;
    qemu_mutex_unlock(&pe->management_lock);
    activation_transaction_destroy(activation, false);
    g_free(error);
    info_report("activated safe uBPF policy id=%u version=%u generation=%u",
                record->policy_id, record->policy_version,
                record->generation);
    return 0;

fail:
    g_free(payload);
    g_free(error);
    pe_bpf_vm_destroy(candidate_vm);
    activation_transaction_destroy(activation, true);
    qemu_mutex_lock(&pe->management_lock);
    record->state = PE_RUNTIME_INACTIVE;
    if (new_record && !record->state_store) {
        runtime_policy_clear_identity(record);
    }
    qemu_mutex_unlock(&pe->management_lock);
    return rc;
}

int pe_deactivate_policy(struct policy_engine *pe, uint32_t policy_id)
{
    struct runtime_policy_record *record;
    struct pe_bpf_vm *vm;
    int slot;

    if (!pe || policy_id == 0) {
        return -1;
    }
    qemu_mutex_lock(&pe->management_lock);
    slot = runtime_policy_slot_by_id(pe, policy_id);
    if (slot < 0) {
        qemu_mutex_unlock(&pe->management_lock);
        return -1;
    }
    record = &pe->runtime_policies[slot];
    if (record->state == PE_RUNTIME_INACTIVE) {
        qemu_mutex_unlock(&pe->management_lock);
        return 0;
    }
    if (record->state != PE_RUNTIME_ACTIVE) {
        qemu_mutex_unlock(&pe->management_lock);
        return -1;
    }
    record->state = PE_RUNTIME_DRAINING;
    remove_policy_subscriptions_locked(pe, record->policy_id,
                                       record->generation);
    qemu_mutex_unlock(&pe->management_lock);

    qemu_mutex_lock(&record->execution_lock);
    vm = record->vm;
    record->vm = NULL;
    record->gc_active = false;
    pe_bpf_vm_destroy(vm);
    qemu_mutex_unlock(&record->execution_lock);

    qemu_mutex_lock(&pe->management_lock);
    record->state = PE_RUNTIME_INACTIVE;
    pe->ssd->stats.gc_active = false;
    for (slot = 0; slot < MAX_RUNTIME_POLICIES; slot++) {
        pe->ssd->stats.gc_active |= pe->runtime_policies[slot].gc_active;
    }
    qemu_mutex_unlock(&pe->management_lock);
    return 0;
}

static int can_remove_policy_state_locked(struct policy_engine *pe,
                                          uint32_t policy_id,
                                          uint32_t generation)
{
    struct runtime_policy_record *record;
    int slot;

    slot = runtime_policy_slot_by_id(pe, policy_id);
    if (slot < 0) {
        return 0;
    }
    record = &pe->runtime_policies[slot];
    if (record->state != PE_RUNTIME_INACTIVE ||
        record->generation != generation) {
        return -1;
    }
    for (uint32_t i = 0; i < record->owned_oob_count; i++) {
        size_t bytes_per_page;

        if (ftl_backend_get_oob_policy_info(
                pe->ssd->fb, record->owned_oob[i].backend_handle,
                NULL, &bytes_per_page) != 0 ||
            bytes_per_page != record->owned_oob[i].bytes_per_page) {
            return -1;
        }
    }
    return 0;
}

int pe_can_remove_policy_state(struct policy_engine *pe, uint32_t policy_id,
                               uint32_t generation)
{
    int rc;

    if (!pe || !pe->ssd || policy_id == 0 || generation == 0) {
        return -1;
    }
    qemu_mutex_lock(&pe->management_lock);
    rc = can_remove_policy_state_locked(pe, policy_id, generation);
    qemu_mutex_unlock(&pe->management_lock);
    return rc;
}

int pe_remove_policy_state(struct policy_engine *pe, uint32_t policy_id,
                           uint32_t generation)
{
    struct runtime_policy_record *record;
    int slot;

    if (!pe || policy_id == 0 || generation == 0) {
        return -1;
    }
    qemu_mutex_lock(&pe->management_lock);
    if (can_remove_policy_state_locked(pe, policy_id, generation) != 0) {
        qemu_mutex_unlock(&pe->management_lock);
        return -1;
    }
    slot = runtime_policy_slot_by_id(pe, policy_id);
    if (slot < 0) {
        qemu_mutex_unlock(&pe->management_lock);
        return 0;
    }
    record = &pe->runtime_policies[slot];
    for (uint32_t i = 0; i < record->owned_oob_count; i++) {
        if (ftl_backend_unregister_oob_policy(
                pe->ssd->fb, record->owned_oob[i].backend_handle) != 0) {
            qemu_mutex_unlock(&pe->management_lock);
            return -1;
        }
    }
    pe_policy_state_store_destroy(record->state_store, &pe->state_bytes,
                                  &pe->state_lock);
    record->state_store = NULL;
    runtime_policy_clear_identity(record);
    qemu_mutex_unlock(&pe->management_lock);
    return 0;
}

bool pe_is_policy_active(struct policy_engine *pe, uint32_t policy_id)
{
    bool active = false;
    int slot;

    if (!pe) {
        return false;
    }
    qemu_mutex_lock(&pe->management_lock);
    slot = runtime_policy_slot_by_id(pe, policy_id);
    if (slot >= 0) {
        active = pe->runtime_policies[slot].state == PE_RUNTIME_ACTIVE;
    }
    qemu_mutex_unlock(&pe->management_lock);
    return active;
}
