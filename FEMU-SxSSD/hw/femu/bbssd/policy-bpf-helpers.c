#include "qemu/osdep.h"
#include "policy-bpf-helpers.h"
#include "policy-bpf-runtime.h"
#include "policy-bpf-state.h"
#include "policy-crypto.h"
#include "device-signing.h"

#include "qemu/timer.h"
#include <openssl/crypto.h>
#include <ubpf.h>

QEMU_BUILD_BUG_ON(offsetof(struct pe_bpf_execution, public_context) != 0);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_nvme_event) != 88);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_backend_event) != 32);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_pswd_event) != 24);
QEMU_BUILD_BUG_ON(offsetof(struct sxs_bpf_context, scratch) != 128);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_context) != 8320);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_geometry) != 80);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_layout) != 32);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_eswd) != 24);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_stats) != 136);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_dsm_range) != 16);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_eswd_location) != 8);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_eswd_config) != 8);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_namespace_config) != 40);
QEMU_BUILD_BUG_ON(offsetof(struct sxs_bpf_namespace_config, nsze) != 8);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_namespace_blob) != 16);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_page_read_request) != 40);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_page_append_request) != 32);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_page_migrate_request) != 16);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_eswd_stage_write_request) != 32);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_eswd_page_read_request) != 24);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_page_result) != 24);
QEMU_BUILD_BUG_ON(offsetof(struct sxs_bpf_page_result, ppa) != 8);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_ed25519_verify_request) != 16);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_hmac_sha256_request) != 20);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bpf_bootstrap_sign_request) != 160);
QEMU_BUILD_BUG_ON(offsetof(struct sxs_bpf_bootstrap_sign_request,
                           signature) != 96);

typedef uint64_t (*pe_helper_fn)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, void *);

#define PE_MAX_COMMAND_TRANSFER_BYTES (1024U * 1024U)

static struct pe_bpf_execution *execution_from_cookie(void *cookie)
{
    struct pe_bpf_execution *execution = cookie;

    if (!execution || !execution->engine || !execution->owner ||
        (execution->authoritative_phase != SXS_BPF_PHASE_INIT &&
         execution->authoritative_phase != SXS_BPF_PHASE_CONDITION &&
         execution->authoritative_phase != SXS_BPF_PHASE_ACTION)) {
        return NULL;
    }
    return execution;
}

static bool phase_is(const struct pe_bpf_execution *execution,
                     enum sxs_bpf_phase phase)
{
    return execution && execution->authoritative_phase == phase;
}

static bool phase_is_condition_or_action(
    const struct pe_bpf_execution *execution)
{
    return phase_is(execution, SXS_BPF_PHASE_CONDITION) ||
           phase_is(execution, SXS_BPF_PHASE_ACTION);
}

static int64_t execution_start_time_ns(
    const struct pe_bpf_execution *execution)
{
    if (!execution) {
        return 0;
    }
    switch (execution->authoritative_event_kind) {
    case SXS_BPF_EVENT_NVME_IO:
    case SXS_BPF_EVENT_NVME_ADMIN:
        return execution->native_event.nvme ?
               execution->native_event.nvme->stime : 0;
    case SXS_BPF_EVENT_BACKEND:
        return execution->native_event.backend ?
               execution->native_event.backend->stime : 0;
    default:
        return 0;
    }
}

static uint8_t *scratch_range(struct pe_bpf_execution *execution,
                              uint64_t offset, uint64_t length)
{
    if (!execution || offset > SXS_BPF_SCRATCH_BYTES ||
        length > SXS_BPF_SCRATCH_BYTES - offset) {
        return NULL;
    }
    return execution->public_context.scratch + offset;
}

static uint64_t helper_subscribe(uint64_t event_kind, uint64_t selector,
                                 uint64_t pair_id, uint64_t flags,
                                 uint64_t unused, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    (void)unused;
    if (!execution) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (event_kind > UINT32_MAX || selector > UINT32_MAX ||
        pair_id > UINT32_MAX || flags > UINT32_MAX) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return pe_activation_stage_subscription(
        execution, event_kind, selector, pair_id, flags);
}

static uint64_t helper_state_create(uint64_t object_id,
                                    uint64_t element_size,
                                    uint64_t element_count, uint64_t flags,
                                    uint64_t initial_u64, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    if (!phase_is(execution, SXS_BPF_PHASE_INIT) ||
        !execution->activation) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (object_id > UINT32_MAX || element_size > UINT32_MAX ||
        flags > UINT32_MAX) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return pe_policy_state_create(execution->activation->state_transaction,
                                  object_id, element_size, element_count,
                                  flags, initial_u64);
}

static uint64_t helper_state_read(uint64_t object_id, uint64_t index,
                                  uint64_t element_offset,
                                  uint64_t scratch_offset, uint64_t length,
                                  void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    uint8_t *destination;

    if (!execution || object_id > UINT32_MAX ||
        element_offset > UINT32_MAX || length > UINT32_MAX) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    destination = scratch_range(execution, scratch_offset, length);
    if (!destination) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return pe_policy_state_read(
        execution->owner->state_store,
        execution->activation ? execution->activation->state_transaction : NULL,
        object_id, index, element_offset, destination, length);
}

static uint64_t helper_state_write(uint64_t object_id, uint64_t index,
                                   uint64_t element_offset,
                                   uint64_t scratch_offset, uint64_t length,
                                   void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    uint8_t *source;
    bool init_phase;

    if (!execution || phase_is(execution, SXS_BPF_PHASE_CONDITION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    init_phase = phase_is(execution, SXS_BPF_PHASE_INIT);
    if (!init_phase && !phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (object_id > UINT32_MAX || element_offset > UINT32_MAX ||
        length > UINT32_MAX ||
        !(source = scratch_range(execution, scratch_offset, length))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return pe_policy_state_write(
        execution->owner->state_store,
        execution->activation ? execution->activation->state_transaction : NULL,
        init_phase, object_id, index, element_offset, source, length);
}

static uint64_t helper_state_fill_u64(uint64_t object_id, uint64_t value,
                                      uint64_t unused2, uint64_t unused3,
                                      uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    bool init_phase;

    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!execution || phase_is(execution, SXS_BPF_PHASE_CONDITION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    init_phase = phase_is(execution, SXS_BPF_PHASE_INIT);
    if (!init_phase && !phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (object_id > UINT32_MAX) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return pe_policy_state_fill_u64(
        execution->owner->state_store,
        execution->activation ? execution->activation->state_transaction : NULL,
        init_phase, object_id, value);
}

static uint64_t helper_backend_status_get(uint64_t index,
                                          uint64_t scratch_offset,
                                          uint64_t unused2,
                                          uint64_t unused3,
                                          uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct FtlBackendEvent *event;
    int32_t *destination;

    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is_condition_or_action(execution) ||
        execution->authoritative_event_kind != SXS_BPF_EVENT_BACKEND) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    event = execution->native_event.backend;
    destination = (int32_t *)scratch_range(execution, scratch_offset,
                                           sizeof(*destination));
    if (!event || !event->status_list || index >= event->count ||
        !destination) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    *destination = event->status_list[index];
    return 0;
}

static uint64_t saturating_add_u64(uint64_t value, uint64_t increment)
{
    return increment > UINT64_MAX - value ? UINT64_MAX : value + increment;
}

static uint64_t helper_stats_add(uint64_t counter, uint64_t value,
                                 uint64_t unused2, uint64_t unused3,
                                 uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct ssd_stats *stats;
    uint64_t *destination;

    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    stats = &execution->engine->ssd->stats;
    switch (counter) {
    case SXS_BPF_STATS_GC_INVOCATIONS:
        destination = &stats->gc_invocations;
        break;
    case SXS_BPF_STATS_GC_PAGES_MIGRATED:
        destination = &stats->gc_pages_migrated;
        break;
    case SXS_BPF_STATS_FOREGROUND_GC:
        destination = &stats->foreground_gc_count;
        break;
    case SXS_BPF_STATS_BACKGROUND_GC:
        destination = &stats->background_gc_count;
        break;
    case SXS_BPF_STATS_GC_TIME_NS:
        destination = &stats->gc_time_ns;
        break;
    case SXS_BPF_STATS_BLOCK_ERASES:
        destination = &stats->block_erases;
        break;
    default:
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    *destination = saturating_add_u64(*destination, value);
    return 0;
}

static uint64_t helper_stats_gc_active_set(uint64_t active,
                                           uint64_t unused1,
                                           uint64_t unused2,
                                           uint64_t unused3,
                                           uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    bool any_active = false;
    int i;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION) || active > 1) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    qemu_mutex_lock(&execution->engine->management_lock);
    execution->owner->gc_active = active;
    for (i = 0; i < MAX_RUNTIME_POLICIES; i++) {
        any_active |= execution->engine->runtime_policies[i].gc_active;
    }
    execution->engine->ssd->stats.gc_active = any_active;
    qemu_mutex_unlock(&execution->engine->management_lock);
    return 0;
}

static uint64_t helper_geometry_get(uint64_t scratch_offset,
                                    uint64_t unused1, uint64_t unused2,
                                    uint64_t unused3, uint64_t unused4,
                                    void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    const struct bbm_geom *source;
    struct sxs_bpf_geometry *destination;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!execution) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    source = get_bbm_geom(execution->engine->ssd);
    destination = (struct sxs_bpf_geometry *)scratch_range(
        execution, scratch_offset, sizeof(*destination));
    if (!source || !destination) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    *destination = (struct sxs_bpf_geometry) {
        .blocks_per_plane_log = source->blks_per_pl_log,
        .blocks_per_lun_log = source->blks_per_lun_log,
        .blocks_per_channel_log = source->blks_per_ch_log,
        .pages_per_block = source->pgs_per_blk,
        .pages_per_plane = source->pgs_per_pl,
        .pages_per_lun = source->pgs_per_lun,
        .pages_per_channel = source->pgs_per_ch,
        .blocks_per_line = source->blks_per_line,
        .pages_per_line = source->pgs_per_line,
        .total_lines = source->tt_lines,
        .planes_per_lun = source->pls_per_lun,
        .luns_per_channel = source->luns_per_ch,
        .channels = source->nchs,
        .total_luns = source->tt_luns,
        .sectors_per_page = source->secs_per_pg,
        .sector_size = source->secsz,
        .total_blocks_log = source->tt_blks_log,
        .total_pages_log = source->tt_pgs_log,
    };
    return 0;
}

static uint64_t helper_layout_get(uint64_t scratch_offset,
                                  uint64_t unused1, uint64_t unused2,
                                  uint64_t unused3, uint64_t unused4,
                                  void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    const struct eswd_layout *source;
    struct sxs_bpf_layout *destination;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!execution) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    source = get_eswd_layout(execution->engine->ssd);
    destination = (struct sxs_bpf_layout *)scratch_range(
        execution, scratch_offset, sizeof(*destination));
    if (!source || !destination || !execution->engine->ssd->eswd_layout_finalized) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    *destination = (struct sxs_bpf_layout) {
        .total_eswds = source->tt_eswds,
        .blocks_per_eswd = source->blks_per_eswd,
        .pages_per_eswd = source->pgs_per_eswd,
        .striping_level = source->striping_level,
        .total_planes = source->tt_pl,
        .blocks_per_plane = source->blks_per_pl,
    };
    return 0;
}

static uint64_t helper_eswd_get(uint64_t eswd_id, uint64_t scratch_offset,
                                uint64_t unused2, uint64_t unused3,
                                uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct eswd *source;
    struct sxs_bpf_eswd *destination;

    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!execution || eswd_id > UINT32_MAX) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    source = get_eswd_by_id(execution->engine->ssd, eswd_id);
    destination = (struct sxs_bpf_eswd *)scratch_range(
        execution, scratch_offset, sizeof(*destination));
    if (!source || !destination) {
        return (uint64_t)-SXS_BPF_ENOENT;
    }
    *destination = (struct sxs_bpf_eswd) {
        .id = source->id,
        .valid_page_count = source->vpc,
        .invalid_page_count = source->ipc,
        .write_page_index = source->wp_page_index,
        .write_lba = source->wp_lba,
    };
    return 0;
}

static uint64_t helper_eswd_from_ppa(uint64_t ppa_value,
                                     uint64_t scratch_offset,
                                     uint64_t unused2, uint64_t unused3,
                                     uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_eswd_location *destination;
    PseudoPpa ppa = { .ppa = ppa_value };

    (void)unused2;
    (void)unused3;
    (void)unused4;
    destination = execution ?
        (struct sxs_bpf_eswd_location *)scratch_range(
            execution, scratch_offset, sizeof(*destination)) : NULL;
    if (!destination || ppa_to_eswd_id_wrapper(execution->engine->ssd, &ppa,
                                                &destination->eswd_id,
                                                &destination->page_index) != 0) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return 0;
}

static uint64_t helper_ppa_validate(uint64_t ppa_value, uint64_t unused1,
                                    uint64_t unused2, uint64_t unused3,
                                    uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    PseudoPpa ppa = { .ppa = ppa_value };

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    return execution && valid_ppa(execution->engine->ssd, &ppa) ? 1 : 0;
}

static uint64_t helper_ppa_to_page_index(uint64_t ppa_value,
                                         uint64_t unused1,
                                         uint64_t unused2,
                                         uint64_t unused3,
                                         uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    PseudoPpa ppa = { .ppa = ppa_value };

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!execution || !valid_ppa(execution->engine->ssd, &ppa)) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return ppa_to_pgidx(execution->engine->ssd, &ppa);
}

static uint64_t helper_page_status_get(uint64_t ppa_value,
                                       uint64_t unused1, uint64_t unused2,
                                       uint64_t unused3, uint64_t unused4,
                                       void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    PseudoPpa ppa = { .ppa = ppa_value };
    int status;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!execution ||
        (status = ftl_get_page_status(execution->engine->ssd, &ppa)) < 0) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return status;
}

static uint64_t helper_stats_get(uint64_t scratch_offset, uint64_t unused1,
                                 uint64_t unused2, uint64_t unused3,
                                 uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_stats *destination;
    const struct ssd_stats *source;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    destination = execution ? (struct sxs_bpf_stats *)scratch_range(
        execution, scratch_offset, sizeof(*destination)) : NULL;
    if (!destination) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    source = &execution->engine->ssd->stats;
    *destination = (struct sxs_bpf_stats) {
        .host_read_commands = source->host_read_cmds,
        .host_write_commands = source->host_write_cmds,
        .host_trim_commands = source->host_trim_cmds,
        .host_read_sectors = source->host_read_sectors,
        .host_write_sectors = source->host_write_sectors,
        .host_trim_sectors = source->host_trim_sectors,
        .physical_page_reads = source->phys_page_reads,
        .physical_page_programs = source->phys_page_programs,
        .block_erases = source->block_erases,
        .gc_invocations = source->gc_invocations,
        .gc_pages_migrated = source->gc_pages_migrated,
        .foreground_gc_count = source->foreground_gc_count,
        .background_gc_count = source->background_gc_count,
        .gc_time_ns = source->gc_time_ns,
        .policy_dispatch_time_ns = source->policy_dispatch_time_ns,
        .bytes_copied = source->bytes_copied,
        .gc_active = source->gc_active,
    };
    return 0;
}

static struct NvmeCommandEvent *nvme_execution_event(
    struct pe_bpf_execution *execution)
{
    if (!execution ||
        (execution->authoritative_event_kind != SXS_BPF_EVENT_NVME_IO &&
         execution->authoritative_event_kind != SXS_BPF_EVENT_NVME_ADMIN)) {
        return NULL;
    }
    return execution->native_event.nvme;
}

static uint64_t helper_request_read(uint64_t request_offset,
                                    uint64_t scratch_offset, uint64_t length,
                                    uint64_t unused3, uint64_t unused4,
                                    void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct NvmeCommandEvent *event = nvme_execution_event(execution);
    uint8_t *destination;
    uint8_t *copy;
    uint64_t copied = 0;

    (void)unused3;
    (void)unused4;
    if (!phase_is_condition_or_action(execution) || !event || !event->req ||
        !(destination = scratch_range(execution, scratch_offset, length))) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    copy = ftl_copy_request_data(event->req, request_offset, length, &copied);
    if (!copy || copied != length) {
        g_free(copy);
        return (uint64_t)-SXS_BPF_EIO;
    }
    memcpy(destination, copy, length);
    if (phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        execution->engine->ssd->stats.bytes_copied += length;
    }
    g_free(copy);
    return 0;
}

static uint64_t helper_request_write(uint64_t request_offset,
                                     uint64_t scratch_offset, uint64_t length,
                                     uint64_t unused3, uint64_t unused4,
                                     void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct NvmeCommandEvent *event = nvme_execution_event(execution);
    uint8_t *source;

    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION) || !event || !event->req) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    source = scratch_range(execution, scratch_offset, length);
    if (!source || ftl_write_request_data(event->req, source, request_offset,
                                          length) != length) {
        return (uint64_t)-SXS_BPF_EIO;
    }
    if (phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        execution->engine->ssd->stats.bytes_copied += length;
    }
    return 0;
}

static uint64_t command_transfer(struct pe_bpf_execution *execution,
                                 bool write_to_host, uint64_t command_offset,
                                 uint64_t scratch_offset, uint64_t length)
{
    struct NvmeCommandEvent *event = nvme_execution_event(execution);
    uint8_t *scratch;
    uint8_t *temporary;
    uint64_t total;
    uint16_t status;

    if (!event || length == 0 || command_offset > UINT32_MAX ||
        length > UINT32_MAX || command_offset > PE_MAX_COMMAND_TRANSFER_BYTES ||
        length > PE_MAX_COMMAND_TRANSFER_BYTES - command_offset ||
        !(scratch = scratch_range(execution, scratch_offset, length))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    total = command_offset + length;
    temporary = g_try_malloc0(total);
    if (!temporary) {
        return (uint64_t)-SXS_BPF_ENOMEM;
    }
    if (write_to_host) {
        if (command_offset != 0) {
            status = ftl_read_cmd_buffer(event, temporary, total);
            if (status != NVME_SUCCESS) {
                goto fail;
            }
        }
        memcpy(temporary + command_offset, scratch, length);
        status = ftl_write_cmd_buffer(event, temporary, total);
    } else {
        status = ftl_read_cmd_buffer(event, temporary, total);
        if (status == NVME_SUCCESS) {
            memcpy(scratch, temporary + command_offset, length);
        }
    }
    OPENSSL_cleanse(temporary, total);
    g_free(temporary);
    if (status != NVME_SUCCESS) {
        return (uint64_t)-SXS_BPF_EIO;
    }
    if (phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        execution->engine->ssd->stats.bytes_copied += length;
    }
    return 0;

fail:
    OPENSSL_cleanse(temporary, total);
    g_free(temporary);
    return (uint64_t)-SXS_BPF_EIO;
}

static uint64_t helper_command_read(uint64_t command_offset,
                                    uint64_t scratch_offset, uint64_t length,
                                    uint64_t unused3, uint64_t unused4,
                                    void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    (void)unused3;
    (void)unused4;
    if (!phase_is_condition_or_action(execution)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    return command_transfer(execution, false, command_offset,
                            scratch_offset, length);
}

static uint64_t helper_command_write(uint64_t command_offset,
                                     uint64_t scratch_offset, uint64_t length,
                                     uint64_t unused3, uint64_t unused4,
                                     void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    return command_transfer(execution, true, command_offset,
                            scratch_offset, length);
}

static uint64_t helper_dsm_range_get(uint64_t index,
                                     uint64_t scratch_offset,
                                     uint64_t unused2, uint64_t unused3,
                                     uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct NvmeCommandEvent *event = nvme_execution_event(execution);
    struct sxs_bpf_dsm_range *destination;
    const NvmeDsmRange *ranges;
    int count;

    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is_condition_or_action(execution) || !event || !event->req ||
        !(destination = (struct sxs_bpf_dsm_range *)scratch_range(
              execution, scratch_offset, sizeof(*destination)))) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    ranges = ftl_get_dsm_ranges(event->req, &count);
    if (!ranges || index >= (uint64_t)count) {
        return (uint64_t)-SXS_BPF_ENOENT;
    }
    *destination = (struct sxs_bpf_dsm_range) {
        .attributes = le32_to_cpu(ranges[index].cattr),
        .lba_count = le32_to_cpu(ranges[index].nlb),
        .start_lba = le64_to_cpu(ranges[index].slba),
    };
    return 0;
}

static uint64_t helper_completion_status_set(uint64_t status,
                                             uint64_t unused1,
                                             uint64_t unused2,
                                             uint64_t unused3,
                                             uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct NvmeCommandEvent *event = nvme_execution_event(execution);

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION) || !event) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (status > UINT16_MAX) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    event->status = status;
    return 0;
}

static uint64_t helper_completion_result_set(uint64_t result,
                                             uint64_t unused1,
                                             uint64_t unused2,
                                             uint64_t unused3,
                                             uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct NvmeCommandEvent *event = nvme_execution_event(execution);

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION) || !event) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    ftl_set_completion_result_u64(event, result);
    return 0;
}

static uint64_t helper_time_now_ns(uint64_t unused0, uint64_t unused1,
                                   uint64_t unused2, uint64_t unused3,
                                   uint64_t unused4, void *cookie)
{
    (void)unused0;
    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    return execution_from_cookie(cookie) ?
        qemu_clock_get_ns(QEMU_CLOCK_REALTIME) :
        (uint64_t)-SXS_BPF_EPERM;
}

static uint64_t helper_eswd_config_stage(uint64_t scratch_offset,
                                         uint64_t unused1,
                                         uint64_t unused2,
                                         uint64_t unused3,
                                         uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_eswd_config *source;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_INIT) || !execution->activation ||
        !(source = (struct sxs_bpf_eswd_config *)scratch_range(
              execution, scratch_offset, sizeof(*source)))) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (execution->activation->eswd_config_staged &&
        memcmp(&execution->activation->eswd_config, source,
               sizeof(*source)) != 0) {
        return (uint64_t)-SXS_BPF_EBUSY;
    }
    execution->activation->eswd_config = *source;
    execution->activation->eswd_config_staged = true;
    return 0;
}

static uint64_t helper_namespace_config_stage(uint64_t scratch_offset,
                                              uint64_t unused1,
                                              uint64_t unused2,
                                              uint64_t unused3,
                                              uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_namespace_config *source;
    struct pe_activation_transaction *activation;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_INIT) || !execution->activation ||
        !(source = (struct sxs_bpf_namespace_config *)scratch_range(
              execution, scratch_offset, sizeof(*source)))) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (source->namespace_blob_length > PE_MAX_NAMESPACE_BLOB_BYTES ||
        source->controller_blob_length > PE_MAX_NAMESPACE_BLOB_BYTES) {
        return (uint64_t)-SXS_BPF_ENOSPC;
    }
    activation = execution->activation;
    if (activation->namespace_config_staged) {
        return memcmp(&activation->namespace_config, source,
                      sizeof(*source)) == 0 ? 0 :
               (uint64_t)-SXS_BPF_EBUSY;
    }
    activation->namespace_blob =
        source->namespace_blob_length ?
            g_try_malloc0(source->namespace_blob_length) : NULL;
    activation->controller_blob =
        source->controller_blob_length ?
            g_try_malloc0(source->controller_blob_length) : NULL;
    activation->namespace_blob_written =
        source->namespace_blob_length ?
            g_try_malloc0(source->namespace_blob_length) : NULL;
    activation->controller_blob_written =
        source->controller_blob_length ?
            g_try_malloc0(source->controller_blob_length) : NULL;
    if ((source->namespace_blob_length &&
         (!activation->namespace_blob ||
          !activation->namespace_blob_written)) ||
        (source->controller_blob_length &&
         (!activation->controller_blob ||
          !activation->controller_blob_written))) {
        g_clear_pointer(&activation->namespace_blob, g_free);
        g_clear_pointer(&activation->controller_blob, g_free);
        g_clear_pointer(&activation->namespace_blob_written, g_free);
        g_clear_pointer(&activation->controller_blob_written, g_free);
        return (uint64_t)-SXS_BPF_ENOMEM;
    }
    activation->namespace_config = *source;
    activation->namespace_config_staged = true;
    return 0;
}

static uint64_t helper_ftl_finalize_stage(uint64_t unused0,
                                          uint64_t unused1,
                                          uint64_t unused2,
                                          uint64_t unused3,
                                          uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    (void)unused0;
    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_INIT) || !execution->activation) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    execution->activation->finalize_staged = true;
    return 0;
}

static uint64_t helper_oob_register_stage(uint64_t object_id,
                                          uint64_t bytes_per_page,
                                          uint64_t unused2,
                                          uint64_t unused3,
                                          uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct pe_activation_transaction *activation;
    uint32_t existing_bytes;
    int existing_handle;
    uint32_t i;

    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_INIT) || !execution->activation) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (object_id == 0 || object_id > UINT32_MAX || bytes_per_page == 0 ||
        bytes_per_page > UINT32_MAX) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    activation = execution->activation;
    for (i = 0; i < activation->oob_count; i++) {
        if (activation->oob[i].object_id == object_id) {
            return activation->oob[i].bytes_per_page == bytes_per_page ? 0 :
                   (uint64_t)-SXS_BPF_EINVAL;
        }
    }
    if (activation->oob_count >= PE_MAX_STAGED_OOB) {
        return (uint64_t)-SXS_BPF_ENOSPC;
    }
    existing_handle = pe_runtime_owned_oob_handle(
        execution->owner, object_id, &existing_bytes);
    if (existing_handle >= 0 && existing_bytes != bytes_per_page) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    activation->oob[activation->oob_count++] = (struct pe_staged_oob) {
        .object_id = object_id,
        .bytes_per_page = bytes_per_page,
        .committed_handle = existing_handle,
        .already_committed = existing_handle >= 0,
    };
    return 0;
}

static uint64_t helper_eswd_wp_get(uint64_t eswd_id, uint64_t unused1,
                                   uint64_t unused2, uint64_t unused3,
                                   uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!execution || eswd_id >= execution->engine->ssd->tt_eswds) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return eswd_get_wp_lba(execution->engine->ssd, eswd_id);
}

static uint64_t helper_eswd_effective_wp_get(uint64_t eswd_id,
                                             uint64_t unused1,
                                             uint64_t unused2,
                                             uint64_t unused3,
                                             uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!execution || eswd_id >= execution->engine->ssd->tt_eswds) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return ftl_eswd_get_effective_wp_lba(execution->engine->ssd, eswd_id);
}

static uint64_t helper_eswd_range_check(uint64_t operation,
                                        uint64_t eswd_id,
                                        uint64_t start_lba,
                                        uint64_t lba_count,
                                        uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    (void)unused4;
    if (!execution || eswd_id > UINT32_MAX || lba_count > UINT32_MAX) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    switch (operation) {
    case SXS_BPF_ESWD_CHECK_SEQUENTIAL_WRITE:
        return eswd_check_seq_write(execution->engine->ssd, eswd_id,
                                    start_lba, lba_count);
    case SXS_BPF_ESWD_CHECK_READ:
        return eswd_check_read_range(execution->engine->ssd, eswd_id,
                                     start_lba, lba_count);
    default:
        return (uint64_t)-SXS_BPF_EINVAL;
    }
}

static uint64_t helper_eswd_to_ppa(uint64_t eswd_id, uint64_t page_index,
                                   uint64_t scratch_offset,
                                   uint64_t unused3, uint64_t unused4,
                                   void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    uint64_t *destination;
    PseudoPpa ppa;

    (void)unused3;
    (void)unused4;
    destination = execution ? (uint64_t *)scratch_range(
        execution, scratch_offset, sizeof(*destination)) : NULL;
    if (!destination || eswd_id > UINT32_MAX || page_index > UINT32_MAX ||
        eswd_id_to_ppa_wrapper(execution->engine->ssd, eswd_id,
                               page_index, &ppa) != 0) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    *destination = ppa.ppa;
    return 0;
}

static uint64_t helper_ppa_to_eswd(uint64_t ppa, uint64_t scratch_offset,
                                   uint64_t unused2, uint64_t unused3,
                                   uint64_t unused4, void *cookie)
{
    return helper_eswd_from_ppa(ppa, scratch_offset, unused2, unused3,
                                unused4, cookie);
}

static int write_page_result(struct pe_bpf_execution *execution,
                             uint32_t result_offset, int32_t status,
                             uint32_t committed_lbas, uint64_t ppa,
                             uint64_t latency)
{
    struct sxs_bpf_page_result *result =
        (struct sxs_bpf_page_result *)scratch_range(
            execution, result_offset, sizeof(*result));

    if (!result) {
        return -SXS_BPF_EINVAL;
    }
    *result = (struct sxs_bpf_page_result) {
        .status = status,
        .committed_lbas = committed_lbas,
        .ppa = ppa,
        .latency_ns = latency,
    };
    return 0;
}

static uint64_t helper_page_read(uint64_t request_offset,
                                 uint64_t unused1, uint64_t unused2,
                                 uint64_t unused3, uint64_t unused4,
                                 void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_page_read_request request;
    uint8_t page[SXS_BPF_MAX_PAGE_BYTES];
    uint8_t *destination;
    uint8_t *oob = NULL;
    uint32_t owned_oob_bytes = 0;
    uint64_t page_size;
    uint64_t latency;
    int oob_handle = -1;
    PseudoPpa ppa;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (!scratch_range(execution, request_offset, sizeof(request))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    memcpy(&request, scratch_range(execution, request_offset, sizeof(request)),
           sizeof(request));
    page_size = (uint64_t)execution->engine->ssd->fb->sp.secs_per_pg *
                execution->engine->ssd->fb->sp.secsz;
    if (page_size > sizeof(page) || request.page_offset > page_size ||
        request.length > page_size - request.page_offset ||
        !(destination = scratch_range(execution, request.data_offset,
                                      request.length)) ||
        !scratch_range(execution, request.result_offset,
                       sizeof(struct sxs_bpf_page_result))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    if (request.oob_length) {
        oob_handle = pe_runtime_owned_oob_handle(execution->owner,
                                                 request.oob_object_id,
                                                 &owned_oob_bytes);
        if (oob_handle < 0 || request.oob_length > owned_oob_bytes ||
            !scratch_range(execution, request.oob_offset,
                           request.oob_length)) {
            return (uint64_t)-SXS_BPF_EPERM;
        }
        oob = g_try_malloc0(owned_oob_bytes);
        if (!oob) {
            return (uint64_t)-SXS_BPF_ENOMEM;
        }
    }
    memset(page, 0, sizeof(page));
    ppa.ppa = request.ppa;
    if (!valid_ppa(execution->engine->ssd, &ppa)) {
        g_free(oob);
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    latency = read_page_buffer(execution->engine->ssd, &ppa, page,
                               oob_handle, oob,
                               execution_start_time_ns(execution));
    memcpy(destination, page + request.page_offset, request.length);
    if (oob) {
        memcpy(scratch_range(execution, request.oob_offset,
                             request.oob_length),
               oob, request.oob_length);
        OPENSSL_cleanse(oob, owned_oob_bytes);
        g_free(oob);
    }
    execution->engine->ssd->stats.phys_page_reads++;
    return write_page_result(execution, request.result_offset, 0, 0,
                             request.ppa, latency);
}

static uint64_t helper_page_append(uint64_t request_offset,
                                   uint64_t unused1, uint64_t unused2,
                                   uint64_t unused3, uint64_t unused4,
                                   void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_page_append_request request;
    uint8_t *data;
    uint8_t *oob = NULL;
    uint32_t owned_oob_bytes = 0;
    uint64_t page_size;
    uint64_t latency = 0;
    int oob_handle = -1;
    PseudoPpa ppa;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (!scratch_range(execution, request_offset, sizeof(request))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    memcpy(&request, scratch_range(execution, request_offset, sizeof(request)),
           sizeof(request));
    page_size = (uint64_t)execution->engine->ssd->fb->sp.secs_per_pg *
                execution->engine->ssd->fb->sp.secsz;
    data = scratch_range(execution, request.data_offset, request.data_length);
    if (!data || request.data_length != page_size ||
        !scratch_range(execution, request.result_offset,
                       sizeof(struct sxs_bpf_page_result))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    if (request.oob_length) {
        oob_handle = pe_runtime_owned_oob_handle(execution->owner,
                                                 request.oob_object_id,
                                                 &owned_oob_bytes);
        oob = scratch_range(execution, request.oob_offset,
                            request.oob_length);
        if (oob_handle < 0 || !oob ||
            request.oob_length != owned_oob_bytes) {
            return (uint64_t)-SXS_BPF_EPERM;
        }
    }
    if (ftl_policy_page_append(execution->engine->ssd, request.eswd_id,
                               data, oob_handle, oob, request.oob_length,
                               &ppa, &latency,
                               execution_start_time_ns(execution)) != 0) {
        return write_page_result(execution, request.result_offset,
                                 -SXS_BPF_EIO, 0, UINT64_MAX, 0);
    }
    return write_page_result(execution, request.result_offset, 0,
                             execution->engine->ssd->fb->sp.secs_per_pg,
                             ppa.ppa, latency);
}

static uint64_t helper_page_invalidate(uint64_t ppa_value,
                                       uint64_t unused1, uint64_t unused2,
                                       uint64_t unused3, uint64_t unused4,
                                       void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    PseudoPpa ppa = { .ppa = ppa_value };

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (ftl_get_page_status(execution->engine->ssd, &ppa) != PG_VALID) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    mark_page_invalid(execution->engine->ssd, &ppa);
    return 0;
}

static uint64_t helper_eswd_reset(uint64_t eswd_id, uint64_t unused1,
                                  uint64_t unused2, uint64_t unused3,
                                  uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (eswd_id >= execution->engine->ssd->tt_eswds) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    eswd_reset(execution->engine->ssd, eswd_id);
    return 0;
}

static uint64_t helper_eswd_advance_wp(uint64_t eswd_id,
                                       uint64_t unused1, uint64_t unused2,
                                       uint64_t unused3, uint64_t unused4,
                                       void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    return ftl_eswd_advance_wp_to_end(execution->engine->ssd, eswd_id) == 0 ?
           0 : (uint64_t)-SXS_BPF_EINVAL;
}

static uint64_t helper_eswd_erase(uint64_t eswd_id, uint64_t unused1,
                                  uint64_t unused2, uint64_t unused3,
                                  uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (eswd_id >= execution->engine->ssd->tt_eswds) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    {
        uint64_t latency = ftl_eswd_erase_physical(
            execution->engine->ssd, eswd_id,
            execution_start_time_ns(execution));

        execution->engine->ssd->stats.block_erases = saturating_add_u64(
            execution->engine->ssd->stats.block_erases,
            execution->engine->ssd->eswd_layout.blks_per_eswd);
        return latency;
    }
}

static uint64_t helper_page_migrate(uint64_t request_offset,
                                    uint64_t unused1, uint64_t unused2,
                                    uint64_t unused3, uint64_t unused4,
                                    void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_page_migrate_request request;
    PseudoPpa source;
    PseudoPpa destination;
    uint64_t latency = 0;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (!scratch_range(execution, request_offset, sizeof(request))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    memcpy(&request, scratch_range(execution, request_offset, sizeof(request)),
           sizeof(request));
    if (!scratch_range(execution, request.result_offset,
                       sizeof(struct sxs_bpf_page_result))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    source.ppa = request.source_ppa;
    if (ftl_policy_page_migrate(execution->engine->ssd, &source,
                                request.destination_eswd_id, &destination,
                                &latency) != 0) {
        return write_page_result(execution, request.result_offset,
                                 -SXS_BPF_EIO, 0, UINT64_MAX, 0);
    }
    return write_page_result(execution, request.result_offset, 0,
                             execution->engine->ssd->fb->sp.secs_per_pg,
                             destination.ppa, latency);
}

static uint64_t helper_eswd_stage_write(uint64_t request_offset,
                                        uint64_t unused1, uint64_t unused2,
                                        uint64_t unused3, uint64_t unused4,
                                        void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_eswd_stage_write_request request;
    struct NvmeCommandEvent *event = nvme_execution_event(execution);
    uint8_t *buffer;
    uint64_t buffer_length;
    uint64_t copied = 0;
    uint64_t latency;
    uint64_t ppa = UINT64_MAX;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION) || !event || !event->req) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (!scratch_range(execution, request_offset, sizeof(request))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    memcpy(&request, scratch_range(execution, request_offset, sizeof(request)),
           sizeof(request));
    if (request.lba_count == 0) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    if (request.lba_count > UINT64_MAX /
            execution->engine->ssd->fb->sp.secsz) {
        return (uint64_t)-SXS_BPF_EOVERFLOW;
    }
    if (!scratch_range(execution, request.result_offset,
                       sizeof(struct sxs_bpf_page_result))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    buffer_length = (uint64_t)request.lba_count *
                    execution->engine->ssd->fb->sp.secsz;
    buffer = ftl_copy_request_data(event->req, request.request_byte_offset,
                                   buffer_length, &copied);
    if (!buffer || copied != buffer_length) {
        g_free(buffer);
        return (uint64_t)-SXS_BPF_EIO;
    }
    {
        PseudoPpa last_ppa = { .ppa = UINT64_MAX };
        latency = ftl_write_seq_lbas(execution->engine->ssd, request.eswd_id,
                                     request.start_lba, buffer,
                                     request.lba_count, &last_ppa,
                                     event->stime);
        ppa = last_ppa.ppa;
    }
    g_free(buffer);
    execution->engine->ssd->stats.bytes_copied = saturating_add_u64(
        execution->engine->ssd->stats.bytes_copied, buffer_length);
    return write_page_result(execution, request.result_offset, 0,
                             ppa == UINT64_MAX ? 0 : request.lba_count,
                             ppa, latency);
}

static uint64_t helper_eswd_page_read(uint64_t request_offset,
                                      uint64_t unused1, uint64_t unused2,
                                      uint64_t unused3, uint64_t unused4,
                                      void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_eswd_page_read_request request;
    uint8_t page[SXS_BPF_MAX_PAGE_BYTES];
    uint8_t *destination;
    uint64_t page_size;
    uint64_t latency;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    if (!scratch_range(execution, request_offset, sizeof(request))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    memcpy(&request, scratch_range(execution, request_offset, sizeof(request)),
           sizeof(request));
    page_size = (uint64_t)execution->engine->ssd->fb->sp.secs_per_pg *
                execution->engine->ssd->fb->sp.secsz;
    destination = scratch_range(execution, request.data_offset,
                                request.data_length);
    if (page_size > sizeof(page) || request.data_length > page_size ||
        !destination ||
        !scratch_range(execution, request.result_offset,
                       sizeof(struct sxs_bpf_page_result))) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    memset(page, 0, sizeof(page));
    latency = ftl_read_eswd_page(
        execution->engine->ssd, request.eswd_id, request.page_lba, page,
        execution_start_time_ns(execution));
    memcpy(destination, page, request.data_length);
    return write_page_result(execution, request.result_offset, 0, 0,
                             UINT64_MAX, latency);
}

static uint64_t helper_namespace_blob_stage(uint64_t descriptor_offset,
                                            uint64_t unused1,
                                            uint64_t unused2,
                                            uint64_t unused3,
                                            uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_namespace_blob descriptor;
    uint8_t *destination;
    uint8_t *written;
    uint8_t *source;
    uint32_t total_length;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_INIT) || !execution->activation ||
        !execution->activation->namespace_config_staged ||
        !scratch_range(execution, descriptor_offset, sizeof(descriptor))) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    memcpy(&descriptor,
           scratch_range(execution, descriptor_offset, sizeof(descriptor)),
           sizeof(descriptor));
    source = scratch_range(execution, descriptor.source_offset,
                           descriptor.length);
    if (!source) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    if (descriptor.kind == SXS_BPF_NAMESPACE_BLOB_NS) {
        destination = execution->activation->namespace_blob;
        written = execution->activation->namespace_blob_written;
        total_length =
            execution->activation->namespace_config.namespace_blob_length;
    } else if (descriptor.kind == SXS_BPF_NAMESPACE_BLOB_CTRL) {
        destination = execution->activation->controller_blob;
        written = execution->activation->controller_blob_written;
        total_length =
            execution->activation->namespace_config.controller_blob_length;
    } else {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    if (descriptor.destination_offset > total_length ||
        descriptor.length > total_length - descriptor.destination_offset ||
        (!destination && descriptor.length)) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    if (descriptor.length == 0) {
        return 0;
    }
    memcpy(destination + descriptor.destination_offset, source,
           descriptor.length);
    memset(written + descriptor.destination_offset, 1, descriptor.length);
    return 0;
}

static uint64_t helper_crypto_random(uint64_t scratch_offset,
                                     uint64_t length, uint64_t unused2,
                                     uint64_t unused3, uint64_t unused4,
                                     void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    uint8_t *output;

    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    output = scratch_range(execution, scratch_offset, length);
    return output && pe_crypto_random(output, length) == 0 ? 0 :
           (uint64_t)-SXS_BPF_EIO;
}

static uint64_t helper_crypto_ed25519_verify(uint64_t request_offset,
                                             uint64_t unused1,
                                             uint64_t unused2,
                                             uint64_t unused3,
                                             uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_ed25519_verify_request request;
    uint8_t *public_key;
    uint8_t *message;
    uint8_t *signature;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is_condition_or_action(execution) ||
        !scratch_range(execution, request_offset, sizeof(request))) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    memcpy(&request, scratch_range(execution, request_offset, sizeof(request)),
           sizeof(request));
    public_key = scratch_range(execution, request.public_key_offset, 32);
    message = scratch_range(execution, request.message_offset,
                            request.message_length);
    signature = scratch_range(execution, request.signature_offset, 64);
    if (!public_key || !message || !signature) {
        return (uint64_t)-SXS_BPF_EINVAL;
    }
    return pe_crypto_ed25519_verify(public_key, message,
                                    request.message_length, signature) == 0 ?
           1 : 0;
}

static uint64_t helper_crypto_x25519_public(uint64_t private_offset,
                                            uint64_t public_offset,
                                            uint64_t unused2,
                                            uint64_t unused3,
                                            uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    uint8_t *private_key;
    uint8_t *public_key;

    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    private_key = scratch_range(execution, private_offset, 32);
    public_key = scratch_range(execution, public_offset, 32);
    return private_key && public_key &&
           pe_crypto_x25519_public(private_key, public_key) == 0 ? 0 :
           (uint64_t)-SXS_BPF_EIO;
}

static uint64_t helper_crypto_x25519_shared(uint64_t private_offset,
                                            uint64_t peer_offset,
                                            uint64_t output_offset,
                                            uint64_t unused3,
                                            uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    uint8_t *private_key;
    uint8_t *peer_key;
    uint8_t *output;

    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    private_key = scratch_range(execution, private_offset, 32);
    peer_key = scratch_range(execution, peer_offset, 32);
    output = scratch_range(execution, output_offset, 32);
    return private_key && peer_key && output &&
           pe_crypto_x25519_shared(private_key, peer_key, output) == 0 ? 0 :
           (uint64_t)-SXS_BPF_EIO;
}

static uint64_t helper_crypto_hmac_sha256(uint64_t request_offset,
                                          uint64_t unused1,
                                          uint64_t unused2,
                                          uint64_t unused3,
                                          uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_hmac_sha256_request request;
    uint8_t *key;
    uint8_t *message;
    uint8_t *output;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is_condition_or_action(execution) ||
        !scratch_range(execution, request_offset, sizeof(request))) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    memcpy(&request, scratch_range(execution, request_offset, sizeof(request)),
           sizeof(request));
    key = scratch_range(execution, request.key_offset, request.key_length);
    message = scratch_range(execution, request.message_offset,
                            request.message_length);
    output = scratch_range(execution, request.output_offset, 32);
    return key && message && output &&
           pe_crypto_hmac_sha256(key, request.key_length, message,
                                 request.message_length, output) == 0 ? 0 :
           (uint64_t)-SXS_BPF_EIO;
}

static uint64_t helper_sign_key_bootstrap(uint64_t request_offset,
                                          uint64_t unused1,
                                          uint64_t unused2,
                                          uint64_t unused3,
                                          uint64_t unused4, void *cookie)
{
    struct pe_bpf_execution *execution = execution_from_cookie(cookie);
    struct sxs_bpf_bootstrap_sign_request *request;

    (void)unused1;
    (void)unused2;
    (void)unused3;
    (void)unused4;
    if (!phase_is(execution, SXS_BPF_PHASE_ACTION)) {
        return (uint64_t)-SXS_BPF_EPERM;
    }
    request = (struct sxs_bpf_bootstrap_sign_request *)scratch_range(
        execution, request_offset, sizeof(*request));
    if (!request || sign_policy_key_bootstrap(
            request->owner_nonce, request->owner_ephemeral_public_key,
            request->policy_ephemeral_public_key,
            request->signature) != 0) {
        return (uint64_t)-SXS_BPF_EIO;
    }
    return 0;
}

struct pe_helper_registration {
    unsigned int id;
    const char *name;
    pe_helper_fn function;
};

#define PE_HELPER(id_name, symbol_name, function_name) \
    { id_name, symbol_name, function_name }

static const struct pe_helper_registration helpers[] = {
    PE_HELPER(SXS_HELPER_SUBSCRIBE, "sxs_subscribe", helper_subscribe),
    PE_HELPER(SXS_HELPER_STATE_CREATE, "sxs_state_create", helper_state_create),
    PE_HELPER(SXS_HELPER_STATE_READ, "sxs_state_read", helper_state_read),
    PE_HELPER(SXS_HELPER_STATE_WRITE, "sxs_state_write", helper_state_write),
    PE_HELPER(SXS_HELPER_STATE_FILL_U64, "sxs_state_fill_u64", helper_state_fill_u64),
    PE_HELPER(SXS_HELPER_BACKEND_STATUS_GET, "sxs_backend_status_get", helper_backend_status_get),
    PE_HELPER(SXS_HELPER_STATS_ADD, "sxs_stats_add", helper_stats_add),
    PE_HELPER(SXS_HELPER_STATS_GC_ACTIVE_SET, "sxs_stats_gc_active_set", helper_stats_gc_active_set),
    PE_HELPER(SXS_HELPER_GEOMETRY_GET, "sxs_geometry_get", helper_geometry_get),
    PE_HELPER(SXS_HELPER_LAYOUT_GET, "sxs_layout_get", helper_layout_get),
    PE_HELPER(SXS_HELPER_ESWD_GET, "sxs_eswd_get", helper_eswd_get),
    PE_HELPER(SXS_HELPER_ESWD_FROM_PPA, "sxs_eswd_from_ppa", helper_eswd_from_ppa),
    PE_HELPER(SXS_HELPER_PPA_VALIDATE, "sxs_ppa_validate", helper_ppa_validate),
    PE_HELPER(SXS_HELPER_PPA_TO_PAGE_INDEX, "sxs_ppa_to_page_index", helper_ppa_to_page_index),
    PE_HELPER(SXS_HELPER_PAGE_STATUS_GET, "sxs_page_status_get", helper_page_status_get),
    PE_HELPER(SXS_HELPER_STATS_GET, "sxs_stats_get", helper_stats_get),
    PE_HELPER(SXS_HELPER_REQUEST_READ, "sxs_request_read", helper_request_read),
    PE_HELPER(SXS_HELPER_REQUEST_WRITE, "sxs_request_write", helper_request_write),
    PE_HELPER(SXS_HELPER_COMMAND_READ, "sxs_command_read", helper_command_read),
    PE_HELPER(SXS_HELPER_COMMAND_WRITE, "sxs_command_write", helper_command_write),
    PE_HELPER(SXS_HELPER_DSM_RANGE_GET, "sxs_dsm_range_get", helper_dsm_range_get),
    PE_HELPER(SXS_HELPER_COMPLETION_STATUS_SET, "sxs_completion_status_set", helper_completion_status_set),
    PE_HELPER(SXS_HELPER_COMPLETION_RESULT_SET, "sxs_completion_result_set", helper_completion_result_set),
    PE_HELPER(SXS_HELPER_TIME_NOW_NS, "sxs_time_now_ns", helper_time_now_ns),
    PE_HELPER(SXS_HELPER_ESWD_CONFIG_STAGE, "sxs_eswd_config_stage", helper_eswd_config_stage),
    PE_HELPER(SXS_HELPER_NAMESPACE_CONFIG_STAGE, "sxs_namespace_config_stage", helper_namespace_config_stage),
    PE_HELPER(SXS_HELPER_FTL_FINALIZE_STAGE, "sxs_ftl_finalize_stage", helper_ftl_finalize_stage),
    PE_HELPER(SXS_HELPER_OOB_REGISTER_STAGE, "sxs_oob_register_stage", helper_oob_register_stage),
    PE_HELPER(SXS_HELPER_ESWD_WP_GET, "sxs_eswd_wp_get", helper_eswd_wp_get),
    PE_HELPER(SXS_HELPER_ESWD_EFFECTIVE_WP_GET, "sxs_eswd_effective_wp_get", helper_eswd_effective_wp_get),
    PE_HELPER(SXS_HELPER_ESWD_RANGE_CHECK, "sxs_eswd_range_check", helper_eswd_range_check),
    PE_HELPER(SXS_HELPER_ESWD_TO_PPA, "sxs_eswd_to_ppa", helper_eswd_to_ppa),
    PE_HELPER(SXS_HELPER_PPA_TO_ESWD, "sxs_ppa_to_eswd", helper_ppa_to_eswd),
    PE_HELPER(SXS_HELPER_PAGE_READ, "sxs_page_read", helper_page_read),
    PE_HELPER(SXS_HELPER_PAGE_APPEND, "sxs_page_append", helper_page_append),
    PE_HELPER(SXS_HELPER_PAGE_INVALIDATE, "sxs_page_invalidate", helper_page_invalidate),
    PE_HELPER(SXS_HELPER_ESWD_RESET, "sxs_eswd_reset", helper_eswd_reset),
    PE_HELPER(SXS_HELPER_ESWD_ADVANCE_WP, "sxs_eswd_advance_wp", helper_eswd_advance_wp),
    PE_HELPER(SXS_HELPER_ESWD_ERASE, "sxs_eswd_erase", helper_eswd_erase),
    PE_HELPER(SXS_HELPER_PAGE_MIGRATE, "sxs_page_migrate", helper_page_migrate),
    PE_HELPER(SXS_HELPER_ESWD_STAGE_WRITE, "sxs_eswd_stage_write", helper_eswd_stage_write),
    PE_HELPER(SXS_HELPER_ESWD_PAGE_READ, "sxs_eswd_page_read", helper_eswd_page_read),
    PE_HELPER(SXS_HELPER_NAMESPACE_BLOB_STAGE, "sxs_namespace_blob_stage", helper_namespace_blob_stage),
    PE_HELPER(SXS_HELPER_CRYPTO_RANDOM, "sxs_crypto_random", helper_crypto_random),
    PE_HELPER(SXS_HELPER_CRYPTO_ED25519_VERIFY, "sxs_crypto_ed25519_verify", helper_crypto_ed25519_verify),
    PE_HELPER(SXS_HELPER_CRYPTO_X25519_PUBLIC, "sxs_crypto_x25519_public", helper_crypto_x25519_public),
    PE_HELPER(SXS_HELPER_CRYPTO_X25519_SHARED, "sxs_crypto_x25519_shared", helper_crypto_x25519_shared),
    PE_HELPER(SXS_HELPER_CRYPTO_HMAC_SHA256, "sxs_crypto_hmac_sha256", helper_crypto_hmac_sha256),
    PE_HELPER(SXS_HELPER_SIGN_KEY_BOOTSTRAP, "sxs_sign_key_bootstrap", helper_sign_key_bootstrap),
};

int pe_bpf_helpers_register(struct ubpf_vm *vm)
{
    size_t i;

    if (!vm) {
        return -1;
    }
    for (i = 0; i < G_N_ELEMENTS(helpers); i++) {
        struct ubpf_safe_helper_descriptor descriptor = {
            .index = helpers[i].id,
            .name = helpers[i].name,
            .fn = as_external_function_t((void *)helpers[i].function),
            .result_kind = UBPF_SAFE_HELPER_RESULT_SCALAR,
        };

        if (ubpf_register_safe_helper(vm, &descriptor) != 0) {
            return -1;
        }
    }
    return 0;
}
