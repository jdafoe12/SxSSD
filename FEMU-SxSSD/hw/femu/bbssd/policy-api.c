#include "qemu/osdep.h"
#include "policy-api.h"
#include "device-signing.h"
#include "policy-crypto.h"
#include "policy-runtime.h"
#include "policy-state.h"

#include "qemu/timer.h"
#include <errno.h>
#include <openssl/crypto.h>

QEMU_BUILD_BUG_ON(sizeof(struct sxs_nvme_event) != 88);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_backend_event) != 32);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_pswd_event) != 24);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_policy_context) != 128);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_geometry) != 80);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_layout) != 32);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_eswd) != 24);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_dsm_range) != 16);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_eswd_location) != 8);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_eswd_config) != 8);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_namespace_config) != 40);
QEMU_BUILD_BUG_ON(offsetof(struct sxs_namespace_config, nsze) != 8);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_page_result) != 24);
QEMU_BUILD_BUG_ON(offsetof(struct sxs_page_result, ppa) != 8);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_bootstrap_sign_request) != 160);
QEMU_BUILD_BUG_ON(offsetof(struct sxs_bootstrap_sign_request, signature) != 96);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_physical_block) != 16);
QEMU_BUILD_BUG_ON(sizeof(struct sxs_policy_storage_geometry) != 32);

static struct pe_policy_execution *
validated_execution(struct pe_policy_execution *execution)
{
    if (!execution || !execution->engine || !execution->owner ||
        (execution->authoritative_phase != SXS_PHASE_INIT &&
         execution->authoritative_phase != SXS_PHASE_CONDITION &&
         execution->authoritative_phase != SXS_PHASE_ACTION)) {
        return NULL;
    }
    return execution;
}

static bool phase_is(const struct pe_policy_execution *execution,
                     enum sxs_phase phase)
{
    return execution && execution->authoritative_phase == phase;
}

static bool
phase_is_condition_or_action(const struct pe_policy_execution *execution)
{
    return phase_is(execution, SXS_PHASE_CONDITION) ||
           phase_is(execution, SXS_PHASE_ACTION);
}

static int64_t
execution_start_time_ns(const struct pe_policy_execution *execution)
{
    if (!execution) {
        return 0;
    }
    switch (execution->authoritative_event_kind) {
    case SXS_EVENT_NVME_IO:
    case SXS_EVENT_NVME_ADMIN:
        return execution->native_event.nvme
                   ? execution->native_event.nvme->stime
                   : 0;
    case SXS_EVENT_BACKEND:
        return execution->native_event.backend
                   ? execution->native_event.backend->stime
                   : 0;
    default:
        return 0;
    }
}

int32_t pe_api_subscribe(struct pe_policy_execution *execution,
                         uint32_t event_kind, uint32_t selector,
                         uint32_t pair_id, uint32_t flags)
{
    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EPERM;
    }
    return pe_activation_stage_subscription(execution, event_kind, selector,
                                            pair_id, flags);
}

int32_t pe_api_state_create(struct pe_policy_execution *execution,
                            uint32_t object_id, uint32_t element_size,
                            uint64_t element_count, uint32_t flags,
                            uint64_t initial_u64)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_INIT) || !execution->activation) {
        return -SXS_WASM_EPERM;
    }
    return pe_policy_state_create(execution->activation->state_transaction,
                                  object_id, element_size, element_count, flags,
                                  initial_u64);
}

int32_t pe_api_state_read(struct pe_policy_execution *execution,
                          uint32_t object_id, uint64_t index,
                          uint32_t element_offset, void *destination,
                          uint32_t length)
{
    execution = validated_execution(execution);
    if (!execution || (!destination && length)) {
        return -SXS_WASM_EINVAL;
    }
    return pe_policy_state_read(
        execution->owner->state_store,
        execution->activation ? execution->activation->state_transaction : NULL,
        object_id, index, element_offset, destination, length);
}

int32_t pe_api_state_write(struct pe_policy_execution *execution,
                           uint32_t object_id, uint64_t index,
                           uint32_t element_offset, const void *source,
                           uint32_t length)
{
    bool init_phase;

    execution = validated_execution(execution);
    if (!execution || phase_is(execution, SXS_PHASE_CONDITION)) {
        return -SXS_WASM_EPERM;
    }
    init_phase = phase_is(execution, SXS_PHASE_INIT);
    if (!init_phase && !phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    if (!source && length) {
        return -SXS_WASM_EINVAL;
    }
    return pe_policy_state_write(
        execution->owner->state_store,
        execution->activation ? execution->activation->state_transaction : NULL,
        init_phase, object_id, index, element_offset, source, length);
}

int32_t pe_api_state_fill_u64(struct pe_policy_execution *execution,
                              uint32_t object_id, uint64_t value)
{
    bool init_phase;

    execution = validated_execution(execution);
    if (!execution || phase_is(execution, SXS_PHASE_CONDITION)) {
        return -SXS_WASM_EPERM;
    }
    init_phase = phase_is(execution, SXS_PHASE_INIT);
    if (!init_phase && !phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    return pe_policy_state_fill_u64(
        execution->owner->state_store,
        execution->activation ? execution->activation->state_transaction : NULL,
        init_phase, object_id, value);
}

int32_t pe_api_backend_status_get(struct pe_policy_execution *execution,
                                  uint64_t index, int32_t *destination)
{
    struct FtlBackendEvent *event;

    execution = validated_execution(execution);
    if (!phase_is_condition_or_action(execution) ||
        execution->authoritative_event_kind != SXS_EVENT_BACKEND) {
        return -SXS_WASM_EPERM;
    }
    event = execution->native_event.backend;
    if (!event || !event->status_list || index >= event->count ||
        !destination) {
        return -SXS_WASM_EINVAL;
    }
    *destination = event->status_list[index];
    return 0;
}

int32_t pe_api_geometry_get(struct pe_policy_execution *execution,
                            struct sxs_geometry *destination)
{
    const struct bbm_geom *source;

    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EPERM;
    }
    source = get_bbm_geom(execution->engine->ssd);
    if (!source || !destination) {
        return -SXS_WASM_EINVAL;
    }
    *destination = (struct sxs_geometry){
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

int32_t pe_api_layout_get(struct pe_policy_execution *execution,
                          struct sxs_layout *destination)
{
    const struct eswd_layout *source;

    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EPERM;
    }
    source = get_eswd_layout(execution->engine->ssd);
    if (!source || !destination ||
        !execution->engine->ssd->eswd_layout_finalized) {
        return -SXS_WASM_EINVAL;
    }
    *destination = (struct sxs_layout){
        .total_eswds = source->tt_eswds,
        .blocks_per_eswd = source->blks_per_eswd,
        .pages_per_eswd = source->pgs_per_eswd,
        .striping_level = source->striping_level,
        .total_planes = source->tt_pl,
        .blocks_per_plane = source->blks_per_pl,
    };
    return 0;
}

int32_t pe_api_eswd_get(struct pe_policy_execution *execution, uint32_t eswd_id,
                        struct sxs_eswd *destination)
{
    struct eswd *source;

    execution = validated_execution(execution);
    if (!execution || !destination) {
        return -SXS_WASM_EINVAL;
    }
    source = get_eswd_by_id(execution->engine->ssd, eswd_id);
    if (!source) {
        return -SXS_WASM_ENOENT;
    }
    *destination = (struct sxs_eswd){
        .id = source->id,
        .valid_page_count = source->vpc,
        .invalid_page_count = source->ipc,
        .write_page_index = source->wp_page_index,
        .write_lba = source->wp_lba,
    };
    return 0;
}

int32_t pe_api_eswd_from_ppa(struct pe_policy_execution *execution,
                             uint64_t ppa_value,
                             struct sxs_eswd_location *destination)
{
    PseudoPpa ppa = {.ppa = ppa_value};

    execution = validated_execution(execution);
    if (!execution || !destination ||
        ppa_to_eswd_id_wrapper(execution->engine->ssd, &ppa,
                               &destination->eswd_id,
                               &destination->page_index) != 0) {
        return -SXS_WASM_EINVAL;
    }
    return 0;
}

int32_t pe_api_ppa_validate(struct pe_policy_execution *execution,
                            uint64_t ppa_value)
{
    PseudoPpa ppa = {.ppa = ppa_value};

    execution = validated_execution(execution);
    return execution && valid_ppa(execution->engine->ssd, &ppa) ? 1 : 0;
}

int64_t pe_api_ppa_to_page_index(struct pe_policy_execution *execution,
                                 uint64_t ppa_value)
{
    PseudoPpa ppa = {.ppa = ppa_value};

    execution = validated_execution(execution);
    if (!execution || !valid_ppa(execution->engine->ssd, &ppa)) {
        return -SXS_WASM_EINVAL;
    }
    return ppa_to_pgidx(execution->engine->ssd, &ppa);
}

int32_t pe_api_page_status_get(struct pe_policy_execution *execution,
                               uint64_t ppa_value)
{
    PseudoPpa ppa = {.ppa = ppa_value};
    int status;

    execution = validated_execution(execution);
    if (!execution ||
        (status = ftl_get_page_status(execution->engine->ssd, &ppa)) < 0) {
        return -SXS_WASM_EINVAL;
    }
    return status;
}

static struct NvmeCommandEvent *
nvme_execution_event(struct pe_policy_execution *execution)
{
    if (!execution ||
        (execution->authoritative_event_kind != SXS_EVENT_NVME_IO &&
         execution->authoritative_event_kind != SXS_EVENT_NVME_ADMIN)) {
        return NULL;
    }
    return execution->native_event.nvme;
}

int32_t pe_api_request_read(struct pe_policy_execution *execution,
                            uint64_t request_offset, void *destination,
                            uint32_t length)
{
    struct NvmeCommandEvent *event;
    uint8_t *copy;
    uint64_t copied = 0;

    execution = validated_execution(execution);
    event = nvme_execution_event(execution);
    if (!phase_is_condition_or_action(execution) || !event || !event->req ||
        (!destination && length)) {
        return -SXS_WASM_EPERM;
    }
    copy = ftl_copy_request_data(event->req, request_offset, length, &copied);
    if (!copy || copied != length) {
        g_free(copy);
        return -SXS_WASM_EIO;
    }
    if (length) {
        memcpy(destination, copy, length);
    }
    g_free(copy);
    return 0;
}

int32_t pe_api_request_write(struct pe_policy_execution *execution,
                             uint64_t request_offset, const void *source,
                             uint32_t length)
{
    struct NvmeCommandEvent *event;

    execution = validated_execution(execution);
    event = nvme_execution_event(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION) || !event || !event->req) {
        return -SXS_WASM_EPERM;
    }
    if ((!source && length) ||
        ftl_write_request_data(event->req, source, request_offset, length) !=
            length) {
        return -SXS_WASM_EIO;
    }
    return 0;
}

static int32_t command_transfer_result(int result)
{
    switch (result) {
    case 0:
        return 0;
    case -EINVAL:
        return -SXS_WASM_EINVAL;
    case -ENOMEM:
        return -SXS_WASM_ENOMEM;
    default:
        return -SXS_WASM_EIO;
    }
}

int32_t pe_api_command_read(struct pe_policy_execution *execution,
                            uint32_t command_offset, void *destination,
                            uint32_t length)
{
    struct NvmeCommandEvent *event;
    int32_t result;

    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EPERM;
    }
    event = nvme_execution_event(execution);
    result = command_transfer_result(
        ftl_command_data_read(event, command_offset, destination, length));
    return result;
}

int32_t pe_api_command_write(struct pe_policy_execution *execution,
                             uint32_t command_offset, const void *source,
                             uint32_t length)
{
    struct NvmeCommandEvent *event;
    int32_t result;

    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    event = nvme_execution_event(execution);
    result = command_transfer_result(
        ftl_command_data_write(event, command_offset, source, length));
    return result;
}

int32_t pe_api_dsm_range_get(struct pe_policy_execution *execution,
                             uint32_t index, struct sxs_dsm_range *destination)
{
    struct NvmeCommandEvent *event;
    const NvmeDsmRange *ranges;
    int count;

    execution = validated_execution(execution);
    event = nvme_execution_event(execution);
    if (!phase_is_condition_or_action(execution) || !event || !event->req ||
        !destination) {
        return -SXS_WASM_EPERM;
    }
    ranges = ftl_get_dsm_ranges(event->req, &count);
    if (!ranges || index >= (uint64_t)count) {
        return -SXS_WASM_ENOENT;
    }
    *destination = (struct sxs_dsm_range){
        .attributes = le32_to_cpu(ranges[index].cattr),
        .lba_count = le32_to_cpu(ranges[index].nlb),
        .start_lba = le64_to_cpu(ranges[index].slba),
    };
    return 0;
}

int32_t pe_api_completion_status_set(struct pe_policy_execution *execution,
                                     uint32_t status)
{
    struct NvmeCommandEvent *event;

    execution = validated_execution(execution);
    event = nvme_execution_event(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION) || !event) {
        return -SXS_WASM_EPERM;
    }
    if (status > UINT16_MAX) {
        return -SXS_WASM_EINVAL;
    }
    event->status = status;
    return 0;
}

int32_t pe_api_completion_result_set(struct pe_policy_execution *execution,
                                     uint64_t result)
{
    struct NvmeCommandEvent *event;

    execution = validated_execution(execution);
    event = nvme_execution_event(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION) || !event) {
        return -SXS_WASM_EPERM;
    }
    ftl_set_completion_result_u64(event, result);
    return 0;
}

uint64_t pe_api_time_now_ns(struct pe_policy_execution *execution)
{
    return validated_execution(execution)
               ? qemu_clock_get_ns(QEMU_CLOCK_REALTIME)
               : (uint64_t)-SXS_WASM_EPERM;
}

int32_t pe_api_eswd_config_stage(struct pe_policy_execution *execution,
                                 const struct sxs_eswd_config *source)
{
    execution = validated_execution(execution);
    return pe_activation_stage_eswd_config(execution, source);
}

int32_t pe_api_namespace_config_stage(struct pe_policy_execution *execution,
                                      const struct sxs_namespace_config *source)
{
    execution = validated_execution(execution);
    return pe_activation_stage_namespace_config(execution, source);
}

int32_t pe_api_ftl_finalize_stage(struct pe_policy_execution *execution)
{
    execution = validated_execution(execution);
    return pe_activation_stage_ftl_finalize(execution);
}

int32_t pe_api_oob_register_stage(struct pe_policy_execution *execution,
                                  uint32_t object_id, uint32_t bytes_per_page)
{
    execution = validated_execution(execution);
    return pe_activation_stage_oob(execution, object_id, bytes_per_page);
}

int64_t pe_api_eswd_wp_get(struct pe_policy_execution *execution,
                           uint32_t eswd_id)
{
    execution = validated_execution(execution);
    if (!execution || eswd_id >= execution->engine->ssd->tt_eswds) {
        return -SXS_WASM_EINVAL;
    }
    return eswd_get_wp_lba(execution->engine->ssd, eswd_id);
}

int64_t pe_api_eswd_effective_wp_get(struct pe_policy_execution *execution,
                                     uint32_t eswd_id)
{
    execution = validated_execution(execution);
    if (!execution || eswd_id >= execution->engine->ssd->tt_eswds) {
        return -SXS_WASM_EINVAL;
    }
    return ftl_eswd_get_effective_wp_lba(execution->engine->ssd, eswd_id);
}

int32_t pe_api_eswd_range_check(struct pe_policy_execution *execution,
                                uint32_t operation, uint32_t eswd_id,
                                uint64_t start_lba, uint32_t lba_count)
{
    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EINVAL;
    }
    switch (operation) {
    case SXS_ESWD_CHECK_SEQUENTIAL_WRITE:
        return eswd_check_seq_write(execution->engine->ssd, eswd_id, start_lba,
                                    lba_count);
    case SXS_ESWD_CHECK_READ:
        return eswd_check_read_range(execution->engine->ssd, eswd_id, start_lba,
                                     lba_count);
    default:
        return -SXS_WASM_EINVAL;
    }
}

int64_t pe_api_eswd_to_ppa(struct pe_policy_execution *execution,
                           uint32_t eswd_id, uint32_t page_index)
{
    PseudoPpa ppa;

    execution = validated_execution(execution);
    if (!execution || eswd_id_to_ppa_wrapper(execution->engine->ssd, eswd_id,
                                             page_index, &ppa) != 0) {
        return -SXS_WASM_EINVAL;
    }
    return ppa.ppa;
}

int32_t pe_api_ppa_to_eswd(struct pe_policy_execution *execution, uint64_t ppa,
                           struct sxs_eswd_location *destination)
{
    return pe_api_eswd_from_ppa(execution, ppa, destination);
}

static int write_page_result(struct sxs_page_result *result, int32_t status,
                             uint32_t committed_lbas, uint64_t ppa,
                             uint64_t latency)
{
    if (!result) {
        return -SXS_WASM_EINVAL;
    }
    *result = (struct sxs_page_result){
        .status = status,
        .committed_lbas = committed_lbas,
        .ppa = ppa,
        .latency_ns = latency,
    };
    return 0;
}

int32_t pe_api_page_read(struct pe_policy_execution *execution,
                         const struct sxs_page_read_request *request,
                         void *data, uint32_t data_length, void *oob_output,
                         uint32_t oob_length, struct sxs_page_result *result)
{
    uint8_t page[SXS_WASM_MAX_PAGE_BYTES];
    uint8_t *native_oob = NULL;
    uint32_t owned_oob_bytes = 0;
    uint64_t page_size;
    uint64_t latency;
    int oob_handle = -1;
    PseudoPpa ppa;

    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    page_size = (uint64_t)execution->engine->ssd->fb->sp.secs_per_pg *
                execution->engine->ssd->fb->sp.secsz;
    if (!request || !result || (!data && data_length) ||
        (!oob_output && oob_length) || page_size > sizeof(page) ||
        request->length != data_length || request->page_offset > page_size ||
        data_length > page_size - request->page_offset) {
        return -SXS_WASM_EINVAL;
    }
    if (oob_length) {
        oob_handle = pe_runtime_owned_oob_handle(
            execution->owner, request->oob_object_id, &owned_oob_bytes);
        if (oob_handle < 0 || oob_length > owned_oob_bytes) {
            return -SXS_WASM_EPERM;
        }
        native_oob = g_try_malloc0(owned_oob_bytes);
        if (!native_oob) {
            return -SXS_WASM_ENOMEM;
        }
    }
    memset(page, 0, sizeof(page));
    ppa.ppa = request->ppa;
    if (!valid_ppa(execution->engine->ssd, &ppa)) {
        g_free(native_oob);
        return -SXS_WASM_EINVAL;
    }
    if (ftl_policy_page_read(execution->engine->ssd, &ppa, page, oob_handle,
                             native_oob, execution_start_time_ns(execution),
                             &latency) != 0) {
        g_free(native_oob);
        return -SXS_WASM_EIO;
    }
    if (data_length) {
        memcpy(data, page + request->page_offset, data_length);
    }
    if (native_oob) {
        memcpy(oob_output, native_oob, oob_length);
        OPENSSL_cleanse(native_oob, owned_oob_bytes);
        g_free(native_oob);
    }
    return write_page_result(result, 0, 0, request->ppa, latency);
}

int32_t pe_api_page_append(struct pe_policy_execution *execution,
                           const struct sxs_page_append_request *request,
                           const void *data, uint32_t data_length,
                           const void *oob, uint32_t oob_length,
                           struct sxs_page_result *result)
{
    uint32_t owned_oob_bytes = 0;
    uint64_t page_size;
    uint64_t latency = 0;
    int oob_handle = -1;
    PseudoPpa ppa;

    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    page_size = (uint64_t)execution->engine->ssd->fb->sp.secs_per_pg *
                execution->engine->ssd->fb->sp.secsz;
    if (!request || !data || !result || data_length != page_size ||
        (!oob && oob_length)) {
        return -SXS_WASM_EINVAL;
    }
    if (oob_length) {
        oob_handle = pe_runtime_owned_oob_handle(
            execution->owner, request->oob_object_id, &owned_oob_bytes);
        if (oob_handle < 0 || oob_length != owned_oob_bytes) {
            return -SXS_WASM_EPERM;
        }
    }
    if (ftl_policy_page_append(execution->engine->ssd, request->eswd_id, data,
                               oob_handle, oob, oob_length, &ppa, &latency,
                               execution_start_time_ns(execution)) != 0) {
        return write_page_result(result, -SXS_WASM_EIO, 0, UINT64_MAX, 0);
    }
    return write_page_result(result, 0,
                             execution->engine->ssd->fb->sp.secs_per_pg,
                             ppa.ppa, latency);
}

int32_t pe_api_page_invalidate(struct pe_policy_execution *execution,
                               uint64_t ppa_value)
{
    PseudoPpa ppa = {.ppa = ppa_value};

    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    if (ftl_get_page_status(execution->engine->ssd, &ppa) != PG_VALID) {
        return -SXS_WASM_EINVAL;
    }
    mark_page_invalid(execution->engine->ssd, &ppa);
    return 0;
}

int32_t pe_api_eswd_reset(struct pe_policy_execution *execution,
                          uint32_t eswd_id)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    if (eswd_id >= execution->engine->ssd->tt_eswds) {
        return -SXS_WASM_EINVAL;
    }
    eswd_reset(execution->engine->ssd, eswd_id);
    return 0;
}

int32_t pe_api_eswd_advance_wp(struct pe_policy_execution *execution,
                               uint32_t eswd_id)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    return ftl_eswd_advance_wp_to_end(execution->engine->ssd, eswd_id) == 0
               ? 0
               : -SXS_WASM_EINVAL;
}

uint64_t pe_api_eswd_erase(struct pe_policy_execution *execution,
                           uint32_t eswd_id)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return (uint64_t)-SXS_WASM_EPERM;
    }
    if (eswd_id >= execution->engine->ssd->tt_eswds) {
        return (uint64_t)-SXS_WASM_EINVAL;
    }
    return ftl_eswd_erase_physical(execution->engine->ssd, eswd_id,
                                   execution_start_time_ns(execution));
}

int32_t pe_api_page_migrate(struct pe_policy_execution *execution,
                            uint64_t source_ppa, uint32_t destination_eswd_id,
                            struct sxs_page_result *result)
{
    PseudoPpa source;
    PseudoPpa destination;
    uint64_t latency = 0;

    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    if (!result) {
        return -SXS_WASM_EINVAL;
    }
    source.ppa = source_ppa;
    if (ftl_policy_page_migrate(execution->engine->ssd, &source,
                                destination_eswd_id, &destination,
                                &latency) != 0) {
        return write_page_result(result, -SXS_WASM_EIO, 0, UINT64_MAX, 0);
    }
    return write_page_result(result, 0,
                             execution->engine->ssd->fb->sp.secs_per_pg,
                             destination.ppa, latency);
}

int32_t
pe_api_eswd_stage_write(struct pe_policy_execution *execution,
                        const struct sxs_eswd_stage_write_request *request,
                        struct sxs_page_result *result)
{
    struct NvmeCommandEvent *event;
    uint8_t *buffer;
    uint64_t buffer_length;
    uint64_t copied = 0;
    uint64_t latency;
    uint64_t ppa = UINT64_MAX;

    execution = validated_execution(execution);
    event = nvme_execution_event(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION) || !event || !event->req) {
        return -SXS_WASM_EPERM;
    }
    if (!request || !result || request->lba_count == 0) {
        return -SXS_WASM_EINVAL;
    }
    if (request->lba_count >
        UINT64_MAX / execution->engine->ssd->fb->sp.secsz) {
        return -SXS_WASM_EOVERFLOW;
    }
    buffer_length =
        (uint64_t)request->lba_count * execution->engine->ssd->fb->sp.secsz;
    buffer = ftl_copy_request_data(event->req, request->request_byte_offset,
                                   buffer_length, &copied);
    if (!buffer || copied != buffer_length) {
        g_free(buffer);
        return -SXS_WASM_EIO;
    }
    {
        PseudoPpa last_ppa = {.ppa = UINT64_MAX};
        latency = ftl_write_seq_lbas(
            execution->engine->ssd, request->eswd_id, request->start_lba,
            buffer, request->lba_count, &last_ppa, event->stime);
        ppa = last_ppa.ppa;
    }
    g_free(buffer);
    return write_page_result(
        result, 0, ppa == UINT64_MAX ? 0 : request->lba_count, ppa, latency);
}

int32_t pe_api_eswd_page_read(struct pe_policy_execution *execution,
                              const struct sxs_eswd_page_read_request *request,
                              void *data, uint32_t data_length,
                              struct sxs_page_result *result)
{
    uint8_t page[SXS_WASM_MAX_PAGE_BYTES];
    uint64_t page_size;
    uint64_t latency;

    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    page_size = (uint64_t)execution->engine->ssd->fb->sp.secs_per_pg *
                execution->engine->ssd->fb->sp.secsz;
    if (!request || !result || (!data && data_length) ||
        page_size > sizeof(page) || data_length > page_size) {
        return -SXS_WASM_EINVAL;
    }
    memset(page, 0, sizeof(page));
    latency = ftl_read_eswd_page(execution->engine->ssd, request->eswd_id,
                                 request->page_lba, page,
                                 execution_start_time_ns(execution));
    if (data_length) {
        memcpy(data, page, data_length);
    }
    return write_page_result(result, 0, 0, UINT64_MAX, latency);
}

int32_t pe_api_namespace_blob_stage(struct pe_policy_execution *execution,
                                    uint32_t kind, uint32_t destination_offset,
                                    const void *source, uint32_t length)
{
    execution = validated_execution(execution);
    return pe_activation_stage_namespace_blob(
        execution, kind, destination_offset, source, length);
}

int32_t pe_api_crypto_random(struct pe_policy_execution *execution,
                             void *output, uint32_t length)
{
    execution = validated_execution(execution);
    if (!execution || phase_is(execution, SXS_PHASE_CONDITION)) {
        return -SXS_WASM_EPERM;
    }
    if (!output) {
        return -SXS_WASM_EINVAL;
    }
    return pe_crypto_random(output, length) == 0 ? 0 : -SXS_WASM_EIO;
}

int32_t
pe_api_crypto_ed25519_verify(struct pe_policy_execution *execution,
                             const void *public_key, uint32_t public_key_length,
                             const void *message, uint32_t message_length,
                             const void *signature, uint32_t signature_length)
{
    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EPERM;
    }
    if (!public_key || public_key_length != 32 || !message || !signature ||
        signature_length != 64) {
        return -SXS_WASM_EINVAL;
    }
    return pe_crypto_ed25519_verify(public_key, message, message_length,
                                    signature) == 0
               ? 1
               : 0;
}

int32_t pe_api_crypto_x25519_public(struct pe_policy_execution *execution,
                                    const void *private_key,
                                    uint32_t private_key_length,
                                    void *public_key,
                                    uint32_t public_key_length)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    if (!private_key || private_key_length != 32 || !public_key ||
        public_key_length != 32) {
        return -SXS_WASM_EINVAL;
    }
    return pe_crypto_x25519_public(private_key, public_key) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_crypto_x25519_shared(struct pe_policy_execution *execution,
                                    const void *private_key,
                                    uint32_t private_key_length,
                                    const void *peer_key,
                                    uint32_t peer_key_length, void *output,
                                    uint32_t output_length)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    if (!private_key || private_key_length != 32 || !peer_key ||
        peer_key_length != 32 || !output || output_length != 32) {
        return -SXS_WASM_EINVAL;
    }
    return pe_crypto_x25519_shared(private_key, peer_key, output) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_crypto_hmac_sha256(struct pe_policy_execution *execution,
                                  const void *key, uint32_t key_length,
                                  const void *message, uint32_t message_length,
                                  void *output, uint32_t output_length)
{
    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EPERM;
    }
    if (!key || !message || !output || output_length != 32) {
        return -SXS_WASM_EINVAL;
    }
    return pe_crypto_hmac_sha256(key, key_length, message, message_length,
                                 output) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_crypto_sha256(struct pe_policy_execution *execution,
                             const void *message, uint32_t message_length,
                             void *output, uint32_t output_length)
{
    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EPERM;
    }
    if ((!message && message_length) || !output || output_length != 32) {
        return -SXS_WASM_EINVAL;
    }
    return pe_crypto_sha256(message, message_length, output) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_crypto_hkdf_sha256(struct pe_policy_execution *execution,
                                  const void *key, uint32_t key_length,
                                  const void *info, uint32_t info_length,
                                  void *output, uint32_t output_length)
{
    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EPERM;
    }
    if ((!key && key_length) || (!info && info_length) ||
        !output || output_length == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_crypto_hkdf_sha256(key, key_length, info, info_length,
                                 output, output_length) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_crypto_aes256_gcm_decrypt(
    struct pe_policy_execution *execution,
    const void *key, uint32_t key_length,
    const void *nonce, uint32_t nonce_length,
    const void *aad, uint32_t aad_length,
    const void *ciphertext, uint32_t ciphertext_length,
    const void *tag, uint32_t tag_length,
    void *plaintext, uint32_t plaintext_length)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    if (!key || key_length != 32 || !nonce || nonce_length != 12 ||
        (!aad && aad_length) || (!ciphertext && ciphertext_length) ||
        !tag || tag_length != 16 || (!plaintext && plaintext_length) ||
        plaintext_length != ciphertext_length) {
        return -SXS_WASM_EINVAL;
    }
    return pe_crypto_aes256_gcm_decrypt(
               key, nonce, aad, aad_length, ciphertext, ciphertext_length,
               tag, plaintext) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_sign_key_bootstrap(struct pe_policy_execution *execution,
                                  const uint8_t owner_nonce[32],
                                  const uint8_t owner_public[32],
                                  const uint8_t policy_public[32],
                                  uint8_t signature[64])
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    if (!owner_nonce || !owner_public || !policy_public || !signature) {
        return -SXS_WASM_EINVAL;
    }
    if (sign_policy_key_bootstrap(owner_nonce, owner_public, policy_public,
                                  signature) != 0) {
        return -SXS_WASM_EIO;
    }
    return 0;
}

static struct pe_policy_execution *
validated_privileged_action(struct pe_policy_execution *execution)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION) ||
        execution->owner->privilege != PE_PRIVILEGE_PRIVILEGED) {
        return NULL;
    }
    return execution;
}

static int physical_block_from_abi(
    const struct pe_policy_execution *execution,
    const struct sxs_physical_block *source, struct pba *destination)
{
    const struct ssd *ssd;

    if (!execution || !source || !destination) {
        return -1;
    }
    ssd = execution->engine->ssd;
    if (!ssd || !ssd->bbm || !ssd->fb) {
        return -1;
    }
    *destination = (struct pba){0};
    destination->g.ch = source->channel;
    destination->g.lun = source->lun;
    destination->g.pl = source->plane;
    destination->g.blk = source->block;
    return bbm_policy_storage_block_valid(ssd->bbm, destination) ? 0 : -1;
}

static int physical_blocks_from_abi(
    const struct pe_policy_execution *execution,
    const struct sxs_physical_block *sources, uint32_t count,
    struct pba *destinations)
{
    if (!sources || !destinations || count == 0 ||
        count > SXS_PRIVILEGED_MAX_POLICY_BLOCKS) {
        return -1;
    }
    for (uint32_t i = 0; i < count; i++) {
        if (physical_block_from_abi(execution, &sources[i],
                                    &destinations[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

int32_t pe_api_privileged_storage_geometry_get(
    struct pe_policy_execution *execution,
    struct sxs_policy_storage_geometry *geometry)
{
    struct bbm_policy_storage_geometry native;
    struct ssd *ssd;

    execution = validated_privileged_action(execution);
    if (!execution || !geometry) {
        return -SXS_WASM_EPERM;
    }
    ssd = execution->engine->ssd;
    if (bbm_policy_storage_geometry(ssd->fb, ssd->bbm, &native) != 0) {
        return -SXS_WASM_EIO;
    }
    *geometry = (struct sxs_policy_storage_geometry){
        .channels = native.channels,
        .luns_per_channel = native.luns_per_channel,
        .planes_per_lun = native.planes_per_lun,
        .logical_blocks_per_plane = native.logical_blocks_per_plane,
        .physical_blocks_per_plane = native.physical_blocks_per_plane,
        .reserved_blocks_per_lun = native.reserved_blocks_per_lun,
        .pages_per_block = native.pages_per_block,
        .page_size = native.page_size,
    };
    return 0;
}

int32_t pe_api_privileged_block_is_claimed(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *block)
{
    struct pba native;
    bool claimed;

    execution = validated_privileged_action(execution);
    if (!execution ||
        physical_block_from_abi(execution, block, &native) != 0) {
        return -SXS_WASM_EINVAL;
    }
    qemu_mutex_lock(&execution->engine->management_lock);
    claimed = bbm_is_excluded_phys_blk(execution->engine->ssd->bbm, &native);
    qemu_mutex_unlock(&execution->engine->management_lock);
    return claimed ? 1 : 0;
}

int32_t pe_api_privileged_block_claim(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *block)
{
    struct pba native;
    int rc;

    execution = validated_privileged_action(execution);
    if (!execution ||
        physical_block_from_abi(execution, block, &native) != 0) {
        return -SXS_WASM_EINVAL;
    }
    qemu_mutex_lock(&execution->engine->management_lock);
    rc = bbm_policy_storage_claim(execution->engine->ssd->bbm, &native);
    qemu_mutex_unlock(&execution->engine->management_lock);
    return rc == 0 ? 0 : -SXS_WASM_EBUSY;
}

int32_t pe_api_privileged_block_release(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *block)
{
    struct pba native;
    int rc;

    execution = validated_privileged_action(execution);
    if (!execution ||
        physical_block_from_abi(execution, block, &native) != 0) {
        return -SXS_WASM_EINVAL;
    }
    qemu_mutex_lock(&execution->engine->management_lock);
    rc = bbm_policy_storage_release(execution->engine->ssd->bbm, &native);
    qemu_mutex_unlock(&execution->engine->management_lock);
    return rc == 0 ? 0 : -SXS_WASM_EIO;
}

int32_t pe_api_privileged_storage_read(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *blocks, uint32_t block_count,
    void *data, uint32_t length)
{
    struct pba native_blocks[SXS_PRIVILEGED_MAX_POLICY_BLOCKS];

    execution = validated_privileged_action(execution);
    if (!execution || !data || length == 0 ||
        physical_blocks_from_abi(execution, blocks, block_count,
                                 native_blocks) != 0) {
        return -SXS_WASM_EINVAL;
    }
    return bbm_policy_storage_read(
               execution->engine->ssd->fb, execution->engine->ssd->bbm,
               native_blocks, block_count, data, length) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_privileged_storage_write(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *blocks, uint32_t block_count,
    const void *data, uint32_t length)
{
    struct pba native_blocks[SXS_PRIVILEGED_MAX_POLICY_BLOCKS];

    execution = validated_privileged_action(execution);
    if (!execution || !data || length == 0 ||
        physical_blocks_from_abi(execution, blocks, block_count,
                                 native_blocks) != 0) {
        return -SXS_WASM_EINVAL;
    }
    return bbm_policy_storage_write(
               execution->engine->ssd->fb, execution->engine->ssd->bbm,
               native_blocks, block_count, data, length) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_privileged_storage_erase(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *blocks, uint32_t block_count)
{
    struct pba native_blocks[SXS_PRIVILEGED_MAX_POLICY_BLOCKS];

    execution = validated_privileged_action(execution);
    if (!execution ||
        physical_blocks_from_abi(execution, blocks, block_count,
                                 native_blocks) != 0) {
        return -SXS_WASM_EINVAL;
    }
    return bbm_policy_storage_erase(
               execution->engine->ssd->fb, execution->engine->ssd->bbm,
               native_blocks, block_count) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_privileged_policy_validate_image(
    struct pe_policy_execution *execution,
    const void *image, uint32_t image_size)
{
    execution = validated_privileged_action(execution);
    if (!execution || !image || image_size == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_validate_policy_image(image, image_size) == 0
               ? 0
               : -SXS_WASM_EINVAL;
}

int32_t pe_api_privileged_policy_activate_stored(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t policy_version, uint32_t generation,
    uint32_t policy_size,
    const struct sxs_physical_block *blocks, uint32_t block_count)
{
    struct pba native_blocks[SXS_PRIVILEGED_MAX_POLICY_BLOCKS];
    struct policy_storage_desc description;

    execution = validated_privileged_action(execution);
    if (!execution ||
        physical_blocks_from_abi(execution, blocks, block_count,
                                 native_blocks) != 0) {
        return -SXS_WASM_EINVAL;
    }
    description = (struct policy_storage_desc){
        .policy_id = policy_id,
        .policy_version = policy_version,
        .generation = generation,
        .policy_size_bytes = policy_size,
        .block_count = block_count,
        .blocks = native_blocks,
    };
    return pe_activate_stored_policy(
               execution->engine, execution->engine->ssd, &description) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_privileged_policy_deactivate(
    struct pe_policy_execution *execution, uint32_t policy_id)
{
    execution = validated_privileged_action(execution);
    if (!execution || policy_id == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_deactivate_policy(execution->engine, policy_id) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_privileged_policy_state_can_remove(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t generation)
{
    execution = validated_privileged_action(execution);
    if (!execution || policy_id == 0 || generation == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_can_remove_policy_state(execution->engine, policy_id,
                                      generation) == 0
               ? 0
               : -SXS_WASM_EBUSY;
}

int32_t pe_api_privileged_policy_state_remove(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t generation)
{
    execution = validated_privileged_action(execution);
    if (!execution || policy_id == 0 || generation == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_remove_policy_state(execution->engine, policy_id,
                                  generation) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t pe_api_privileged_device_attestation_sign(
    struct pe_policy_execution *execution,
    const void *message, uint32_t message_length,
    void *signature, uint32_t signature_length)
{
    execution = validated_privileged_action(execution);
    if (!execution || (!message && message_length) ||
        !signature || signature_length != 64) {
        return -SXS_WASM_EINVAL;
    }
    return sign_with_attestation_key(message, message_length, signature) == 0
               ? 0
               : -SXS_WASM_EIO;
}
