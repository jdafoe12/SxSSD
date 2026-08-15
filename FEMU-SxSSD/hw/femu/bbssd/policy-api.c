#include "qemu/osdep.h"
#include "policy-api.h"
#include "device-trust.h"
#include "policy-crypto.h"
#include "policy-engine.h"

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

/*
 * Private native mechanisms used to implement the semantic Policy API below.
 * These functions operate on FEMU pointers and structures. They are not WASM
 * imports and must not be called across the WAMR boundary.
 */

/* Geometry, layout, and address translation. */
static int native_layout_ppa_to_eswd(const struct eswd_layout *layout,
                                     const struct bbm_geom *geometry,
                                     const PseudoPpa *ppa);
static int native_layout_page_to_ppa(const struct eswd_layout *layout,
                                     const struct bbm_geom *geometry,
                                     uint32_t eswd_id, uint32_t page_index,
                                     PseudoPpa *ppa);
static int native_layout_ppa_to_page(const struct eswd_layout *layout,
                                     const struct bbm_geom *geometry,
                                     const PseudoPpa *ppa,
                                     uint32_t *eswd_id,
                                     uint32_t *page_index);
static int native_layout_block_to_ppa(const struct eswd_layout *layout,
                                      const struct bbm_geom *geometry,
                                      uint32_t eswd_id, uint32_t block_index,
                                      PseudoPpa *ppa);
static const struct bbm_geom *native_geometry(struct ssd *ssd);
static const struct eswd_layout *native_layout(struct ssd *ssd);
static uint64_t native_ppa_to_page_index(struct ssd *ssd, PseudoPpa *ppa);
static bool native_ppa_valid(struct ssd *ssd, PseudoPpa *ppa);

/* eSWD lookup, state, and physical-page operations. */
static struct eswd *native_find_eswd(struct ssd *ssd, PseudoPpa *ppa);
static struct eswd *native_find_eswd_by_id(struct ssd *ssd, uint32_t eswd_id);
static void native_eswd_increment_wp(struct ssd *ssd, uint32_t eswd_id);
static void native_eswd_reset_state(struct ssd *ssd, uint32_t eswd_id);
static uint64_t native_eswd_wp_lba(struct ssd *ssd, uint32_t eswd_id);
static int native_eswd_page_to_ppa(struct ssd *ssd, uint32_t eswd_id,
                                   uint32_t page_index, PseudoPpa *ppa);
static int native_ppa_to_eswd_page(struct ssd *ssd, const PseudoPpa *ppa,
                                   uint32_t *eswd_id, uint32_t *page_index);
static int native_eswd_block_to_ppa(struct ssd *ssd, uint32_t eswd_id,
                                    uint32_t block_index, PseudoPpa *ppa);
static int native_eswd_advance_wp_to_end(struct ssd *ssd, uint32_t eswd_id);
static uint64_t native_eswd_erase_physical(struct ssd *ssd, uint32_t eswd_id,
                                           int64_t start_time_ns);
static int native_append_page(struct ssd *ssd, uint32_t eswd_id,
                              const uint8_t *page_data, int oob_handle,
                              const uint8_t *oob_data, uint32_t oob_length,
                              PseudoPpa *ppa, uint64_t *latency_ns,
                              int64_t start_time_ns);
static int native_read_physical_page(struct ssd *ssd, const PseudoPpa *ppa,
                                     uint8_t *page_data, int oob_handle,
                                     void *oob_data, int64_t start_time_ns,
                                     uint64_t *latency_ns);
static uint64_t native_read_page_buffer(struct ssd *ssd, const PseudoPpa *ppa,
                                        uint8_t *buffer, int oob_handle,
                                        void *oob_data, int64_t start_time_ns);
static int native_migrate_page(struct ssd *ssd, const PseudoPpa *source,
                               uint32_t destination_eswd_id,
                               PseudoPpa *destination,
                               uint64_t *latency_ns);
static int native_get_page_status(struct ssd *ssd, const PseudoPpa *ppa);
static void native_mark_page_valid(struct ssd *ssd, PseudoPpa *ppa);
static void native_mark_page_invalid(struct ssd *ssd, PseudoPpa *ppa);
static void native_mark_block_free(struct ssd *ssd, PseudoPpa *ppa);

/* NVMe request, command, completion, and event access. */
static uint64_t native_get_request_buffer_size(NvmeRequest *request);
static uint8_t *native_copy_request_data(NvmeRequest *request, uint64_t offset,
                                         uint64_t length,
                                         uint64_t *copied_length);
static uint64_t native_write_request_data(NvmeRequest *request,
                                          const uint8_t *buffer,
                                          uint64_t offset, uint64_t length);
static const NvmeDsmRange *native_get_dsm_ranges(NvmeRequest *request,
                                                  int *range_count);
static uint16_t native_read_cmd_buffer(struct NvmeCommandEvent *event,
                                       void *destination, uint32_t length);
static uint16_t native_write_cmd_buffer(struct NvmeCommandEvent *event,
                                        const void *source, uint32_t length);
static int native_command_data_read(struct NvmeCommandEvent *event,
                                    uint32_t command_offset,
                                    void *destination, uint32_t length);
static int native_command_data_write(struct NvmeCommandEvent *event,
                                     uint32_t command_offset,
                                     const void *source, uint32_t length);
static void native_set_completion_result_u64(struct NvmeCommandEvent *event,
                                             uint64_t value);

/* ========================================================================== */
/* WASM-facing Policy API semantics                                           */
/* ========================================================================== */

/* Establish and inspect the authoritative context for the current call. */
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

/* Initialization subscriptions. */
int32_t policy_api_subscribe(struct pe_policy_execution *execution,
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

/* Read-only backend, geometry, layout, eSWD, and address information. */
int32_t policy_api_backend_status_get(struct pe_policy_execution *execution,
                                  uint64_t index, int32_t *destination)
{
    const struct BbmEvent *event;

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

int32_t policy_api_geometry_get(struct pe_policy_execution *execution,
                            struct sxs_geometry *destination)
{
    const struct bbm_geom *source;

    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EPERM;
    }
    source = native_geometry(execution->engine->ssd);
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

int32_t policy_api_layout_get(struct pe_policy_execution *execution,
                          struct sxs_layout *destination)
{
    const struct eswd_layout *source;

    execution = validated_execution(execution);
    if (!execution) {
        return -SXS_WASM_EPERM;
    }
    source = native_layout(execution->engine->ssd);
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

int32_t policy_api_eswd_get(struct pe_policy_execution *execution, uint32_t eswd_id,
                        struct sxs_eswd *destination)
{
    struct eswd *source;

    execution = validated_execution(execution);
    if (!execution || !destination) {
        return -SXS_WASM_EINVAL;
    }
    source = native_find_eswd_by_id(execution->engine->ssd, eswd_id);
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

int32_t policy_api_eswd_from_ppa(struct pe_policy_execution *execution,
                             uint64_t ppa_value,
                             struct sxs_eswd_location *destination)
{
    PseudoPpa ppa = {.ppa = ppa_value};

    execution = validated_execution(execution);
    if (!execution || !destination ||
        native_ppa_to_eswd_page(execution->engine->ssd, &ppa,
                               &destination->eswd_id,
                               &destination->page_index) != 0) {
        return -SXS_WASM_EINVAL;
    }
    return 0;
}

int32_t policy_api_ppa_validate(struct pe_policy_execution *execution,
                            uint64_t ppa_value)
{
    PseudoPpa ppa = {.ppa = ppa_value};

    execution = validated_execution(execution);
    return execution && native_ppa_valid(execution->engine->ssd, &ppa) ? 1 : 0;
}

int64_t policy_api_ppa_to_page_index(struct pe_policy_execution *execution,
                                 uint64_t ppa_value)
{
    PseudoPpa ppa = {.ppa = ppa_value};

    execution = validated_execution(execution);
    if (!execution || !native_ppa_valid(execution->engine->ssd, &ppa)) {
        return -SXS_WASM_EINVAL;
    }
    return native_ppa_to_page_index(execution->engine->ssd, &ppa);
}

int32_t policy_api_page_status_get(struct pe_policy_execution *execution,
                               uint64_t ppa_value)
{
    PseudoPpa ppa = {.ppa = ppa_value};
    int status;

    execution = validated_execution(execution);
    if (!execution ||
        (status = native_get_page_status(execution->engine->ssd, &ppa)) < 0) {
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

/* Access to the NVMe operation that caused the current event. */
int32_t policy_api_request_read(struct pe_policy_execution *execution,
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
    copy = native_copy_request_data(event->req, request_offset, length, &copied);
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

int32_t policy_api_request_write(struct pe_policy_execution *execution,
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
        native_write_request_data(event->req, source, request_offset, length) !=
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

int32_t policy_api_command_read(struct pe_policy_execution *execution,
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
        native_command_data_read(event, command_offset, destination, length));
    return result;
}

int32_t policy_api_command_write(struct pe_policy_execution *execution,
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
        native_command_data_write(event, command_offset, source, length));
    return result;
}

int32_t policy_api_dsm_range_get(struct pe_policy_execution *execution,
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
    ranges = native_get_dsm_ranges(event->req, &count);
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

int32_t policy_api_completion_status_set(struct pe_policy_execution *execution,
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

int32_t policy_api_completion_result_set(struct pe_policy_execution *execution,
                                     uint64_t result)
{
    struct NvmeCommandEvent *event;

    execution = validated_execution(execution);
    event = nvme_execution_event(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION) || !event) {
        return -SXS_WASM_EPERM;
    }
    native_set_completion_result_u64(event, result);
    return 0;
}

/* Host clock access. */
uint64_t policy_api_time_now_ns(struct pe_policy_execution *execution)
{
    return validated_execution(execution)
               ? qemu_clock_get_ns(QEMU_CLOCK_REALTIME)
               : (uint64_t)-SXS_WASM_EPERM;
}

/* Transactional configuration recorded during policy initialization. */
int32_t policy_api_eswd_config_stage(struct pe_policy_execution *execution,
                                 const struct sxs_eswd_config *source)
{
    execution = validated_execution(execution);
    return pe_activation_stage_eswd_config(execution, source);
}

int32_t policy_api_namespace_config_stage(struct pe_policy_execution *execution,
                                      const struct sxs_namespace_config *source)
{
    execution = validated_execution(execution);
    return pe_activation_stage_namespace_config(execution, source);
}

int32_t policy_api_eswd_layout_finalize_stage(
    struct pe_policy_execution *execution)
{
    execution = validated_execution(execution);
    return pe_activation_stage_eswd_layout_finalize(execution);
}

int32_t policy_api_oob_register_stage(struct pe_policy_execution *execution,
                                  uint32_t object_id, uint32_t bytes_per_page)
{
    execution = validated_execution(execution);
    return pe_activation_stage_oob(execution, object_id, bytes_per_page);
}

/* eSWD state queries and address conversion. */
int64_t policy_api_eswd_wp_get(struct pe_policy_execution *execution,
                           uint32_t eswd_id)
{
    execution = validated_execution(execution);
    if (!execution || eswd_id >= execution->engine->ssd->tt_eswds) {
        return -SXS_WASM_EINVAL;
    }
    return native_eswd_wp_lba(execution->engine->ssd, eswd_id);
}

int64_t policy_api_eswd_to_ppa(struct pe_policy_execution *execution,
                           uint32_t eswd_id, uint32_t page_index)
{
    PseudoPpa ppa;

    execution = validated_execution(execution);
    if (!execution || native_eswd_page_to_ppa(execution->engine->ssd, eswd_id,
                                             page_index, &ppa) != 0) {
        return -SXS_WASM_EINVAL;
    }
    return ppa.ppa;
}

int32_t policy_api_ppa_to_eswd(struct pe_policy_execution *execution, uint64_t ppa,
                           struct sxs_eswd_location *destination)
{
    return policy_api_eswd_from_ppa(execution, ppa, destination);
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

/* Physical-page and eSWD lifecycle operations. */
int32_t policy_api_page_read(struct pe_policy_execution *execution,
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
    page_size = (uint64_t)execution->engine->ssd->raw_flash->sp.secs_per_pg *
                execution->engine->ssd->raw_flash->sp.secsz;
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
    if (!native_ppa_valid(execution->engine->ssd, &ppa)) {
        g_free(native_oob);
        return -SXS_WASM_EINVAL;
    }
    if (native_read_physical_page(execution->engine->ssd, &ppa, page, oob_handle,
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

// TODO: Look at this? what is the purpose of it?
// I think this is a complete page write?
int32_t policy_api_page_append(struct pe_policy_execution *execution,
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
    page_size = (uint64_t)execution->engine->ssd->raw_flash->sp.secs_per_pg *
                execution->engine->ssd->raw_flash->sp.secsz;
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
    if (native_append_page(execution->engine->ssd, request->eswd_id, data,
                               oob_handle, oob, oob_length, &ppa, &latency,
                               execution_start_time_ns(execution)) != 0) {
        return write_page_result(result, -SXS_WASM_EIO, 0, UINT64_MAX, 0);
    }
    return write_page_result(result, 0,
                             execution->engine->ssd->raw_flash->sp.secs_per_pg,
                             ppa.ppa, latency);
}

int32_t policy_api_page_invalidate(struct pe_policy_execution *execution,
                               uint64_t ppa_value)
{
    PseudoPpa ppa = {.ppa = ppa_value};

    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    if (native_get_page_status(execution->engine->ssd, &ppa) != PG_VALID) {
        return -SXS_WASM_EINVAL;
    }
    native_mark_page_invalid(execution->engine->ssd, &ppa);
    return 0;
}

int32_t policy_api_eswd_reset(struct pe_policy_execution *execution,
                          uint32_t eswd_id)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    if (eswd_id >= execution->engine->ssd->tt_eswds) {
        return -SXS_WASM_EINVAL;
    }
    native_eswd_reset_state(execution->engine->ssd, eswd_id);
    return 0;
}

int32_t policy_api_eswd_advance_wp(struct pe_policy_execution *execution,
                               uint32_t eswd_id)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return -SXS_WASM_EPERM;
    }
    return native_eswd_advance_wp_to_end(execution->engine->ssd, eswd_id) == 0
               ? 0
               : -SXS_WASM_EINVAL;
}

uint64_t policy_api_eswd_erase(struct pe_policy_execution *execution,
                           uint32_t eswd_id)
{
    execution = validated_execution(execution);
    if (!phase_is(execution, SXS_PHASE_ACTION)) {
        return (uint64_t)-SXS_WASM_EPERM;
    }
    if (eswd_id >= execution->engine->ssd->tt_eswds) {
        return (uint64_t)-SXS_WASM_EINVAL;
    }
    return native_eswd_erase_physical(execution->engine->ssd, eswd_id,
                                   execution_start_time_ns(execution));
}

int32_t policy_api_page_migrate(struct pe_policy_execution *execution,
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
    if (native_migrate_page(execution->engine->ssd, &source,
                                destination_eswd_id, &destination,
                                &latency) != 0) {
        return write_page_result(result, -SXS_WASM_EIO, 0, UINT64_MAX, 0);
    }
    return write_page_result(result, 0,
                             execution->engine->ssd->raw_flash->sp.secs_per_pg,
                             destination.ppa, latency);
}

/* Variable-sized namespace/controller data recorded during initialization. */
int32_t policy_api_namespace_blob_stage(struct pe_policy_execution *execution,
                                    uint32_t kind, uint32_t destination_offset,
                                    const void *source, uint32_t length)
{
    execution = validated_execution(execution);
    return pe_activation_stage_namespace_blob(
        execution, kind, destination_offset, source, length);
}

/* Cryptographic services provided by the trusted host environment. */
int32_t policy_api_crypto_random(struct pe_policy_execution *execution,
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
policy_api_crypto_ed25519_verify(struct pe_policy_execution *execution,
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

int32_t policy_api_crypto_x25519_public(struct pe_policy_execution *execution,
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

int32_t policy_api_crypto_x25519_shared(struct pe_policy_execution *execution,
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

int32_t policy_api_crypto_hmac_sha256(struct pe_policy_execution *execution,
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

int32_t policy_api_crypto_sha256(struct pe_policy_execution *execution,
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

int32_t policy_api_crypto_hkdf_sha256(struct pe_policy_execution *execution,
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

int32_t policy_api_crypto_aes256_gcm_decrypt(
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

int32_t policy_api_sign_key_bootstrap(struct pe_policy_execution *execution,
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
    if (device_trust_sign_policy_key_bootstrap(owner_nonce, owner_public, policy_public,
                                  signature) != 0) {
        return -SXS_WASM_EIO;
    }
    return 0;
}

/* Protected storage, policy lifecycle, state removal, and attestation. */
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
    if (!ssd || !ssd->bbm || !ssd->raw_flash) {
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

int32_t policy_api_privileged_storage_geometry_get(
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
    if (bbm_policy_storage_geometry(ssd->raw_flash, ssd->bbm, &native) != 0) {
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

int32_t policy_api_privileged_block_is_claimed(
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

int32_t policy_api_privileged_block_claim(
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

int32_t policy_api_privileged_block_release(
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

int32_t policy_api_privileged_storage_read(
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
               execution->engine->ssd->raw_flash, execution->engine->ssd->bbm,
               native_blocks, block_count, data, length) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t policy_api_privileged_storage_write(
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
               execution->engine->ssd->raw_flash, execution->engine->ssd->bbm,
               native_blocks, block_count, data, length) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t policy_api_privileged_storage_erase(
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
               execution->engine->ssd->raw_flash, execution->engine->ssd->bbm,
               native_blocks, block_count) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t policy_api_privileged_policy_validate_image(
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

int32_t policy_api_privileged_policy_activate_stored(
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

int32_t policy_api_privileged_policy_deactivate(
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

int32_t policy_api_privileged_policy_can_remove(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t generation)
{
    execution = validated_privileged_action(execution);
    if (!execution || policy_id == 0 || generation == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_can_remove_policy(execution->engine, policy_id, generation) == 0
               ? 0
               : -SXS_WASM_EBUSY;
}

int32_t policy_api_privileged_policy_remove(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t generation)
{
    execution = validated_privileged_action(execution);
    if (!execution || policy_id == 0 || generation == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_remove_policy(execution->engine, policy_id, generation) == 0
               ? 0
               : -SXS_WASM_EIO;
}

int32_t policy_api_privileged_device_attestation_sign(
    struct pe_policy_execution *execution,
    const void *message, uint32_t message_length,
    void *signature, uint32_t signature_length)
{
    execution = validated_privileged_action(execution);
    if (!execution || (!message && message_length) ||
        !signature || signature_length != 64) {
        return -SXS_WASM_EINVAL;
    }
    return device_trust_sign_attestation(message, message_length, signature) == 0
               ? 0
               : -SXS_WASM_EIO;
}


/* ========================================================================== */
/* Native flash-subsystem mechanisms                                          */
/* ========================================================================== */

/* Validate and construct the native eSWD layout committed during init. */
bool flash_subsystem_eswd_config_valid(const struct eswd_config *config,
                       uint32_t nchs, uint32_t luns_per_ch, uint32_t pls_per_lun,
                       uint32_t blks_per_lun_log)
{
    if (!config || nchs == 0 || luns_per_ch == 0) {
        return false;
    }
    uint32_t tt_luns = nchs * luns_per_ch;
    uint32_t blocks_per_eswd = config->blocks_per_eswd;
    if (blocks_per_eswd == 0) {
        blocks_per_eswd = tt_luns;  /* default */
    }
    /* blocks_per_eswd must be a positive multiple of tt_luns for simple mapping */
    if (blocks_per_eswd % tt_luns != 0) {
        return false;
    }
    uint64_t total_blocks = (uint64_t)blks_per_lun_log * tt_luns;
    if (total_blocks % (uint64_t)blocks_per_eswd != 0) {
        return false;
    }
    switch (config->striping_level) {
    case ESWD_STRIPE_CHANNEL:
    case ESWD_STRIPE_LUN:
        break;
    case ESWD_STRIPE_PLANE:
        if (pls_per_lun == 0) {
            return false;
        }
        break;
    case ESWD_STRIPE_BLOCK:
        return false;  /* not yet supported */
    default:
        return false;
    }
    return true;
}


int flash_subsystem_eswd_layout_compute(struct eswd_layout *layout,
                        const struct eswd_config *config,
                        const struct bbm_geom *geom)
{
    if (!layout || !config || !geom) {
        return -1;
    }
    uint32_t tt_luns = geom->nchs * geom->luns_per_ch;
    uint32_t blocks_per_eswd = config->blocks_per_eswd;
    if (blocks_per_eswd == 0) {
        blocks_per_eswd = tt_luns;
    }
    uint64_t total_blocks = (uint64_t)geom->blks_per_lun_log * tt_luns;
    if (total_blocks % (uint64_t)blocks_per_eswd != 0) {
        return -1;
    }
    layout->blks_per_eswd = blocks_per_eswd;
    layout->tt_eswds = (uint32_t)(total_blocks / (uint64_t)blocks_per_eswd);
    layout->pgs_per_eswd = layout->blks_per_eswd * geom->pgs_per_blk;
    layout->striping_level = config->striping_level;

    /* Initialize eSWD → starting block mapping (identity by default) */
    layout->tt_pl = tt_luns * geom->pls_per_lun;
    layout->blks_per_pl = layout->blks_per_eswd / layout->tt_pl;
    layout->eswd_to_starting_block = g_malloc0(sizeof(uint32_t) * layout->tt_eswds);

    for (uint32_t i = 0; i < layout->tt_eswds; i++) {
        layout->eswd_to_starting_block[i] = i * layout->blks_per_pl;
    }

    return 0;
}

static int native_layout_ppa_to_eswd(const struct eswd_layout *layout,
                        const struct bbm_geom *geom,
                        const PseudoPpa *ppa)
{
    if (!layout || !geom || !ppa) {
        return -1;
    }
    uint32_t tt_luns = geom->nchs * geom->luns_per_ch;
    uint32_t blk = ppa->g.blk;
    uint32_t eswd_id = blk * tt_luns / layout->blks_per_eswd;
    if (eswd_id >= layout->tt_eswds) {
        return -1;
    }
    return (int)eswd_id;
}

/* PLANE striping: pl first, then ch, lun, block_slot. */
static void blkoff_plane(uint32_t block_offset, uint32_t tt_luns, uint32_t nchs,
    uint32_t pls_per_lun, uint32_t *ch, uint32_t *lun, uint32_t *pl, uint32_t *block_slot)
{
    uint32_t tt_pl = tt_luns * pls_per_lun;
    *block_slot = block_offset / tt_pl;
    uint32_t rem = block_offset % tt_pl;
    *pl = rem / tt_luns;
    rem %= tt_luns;
    *ch = rem % nchs;
    *lun = rem / nchs;
}

static int native_layout_page_to_ppa(const struct eswd_layout *layout,
                     const struct bbm_geom *geom,
                     uint32_t eswd_id,
                     uint32_t page_index,
                     PseudoPpa *ppa)
{
    if (!layout || !geom || !ppa || eswd_id >= layout->tt_eswds) {
        return -1;
    }
    if (page_index >= layout->pgs_per_eswd) {
        return -1;
    }
    uint32_t tt_luns = geom->nchs * geom->luns_per_ch;
    uint32_t nchs = geom->nchs;
    uint32_t luns_per_ch = geom->luns_per_ch;
    uint32_t pls_per_lun = geom->pls_per_lun;
    uint32_t pgs_per_blk = geom->pgs_per_blk;

    uint32_t ch, lun, pl, block_slot, pg;

    /* Order: striping dimension fastest (ch or lun), then pg, then block_slot for parallelism. */
    switch (layout->striping_level) {
    case ESWD_STRIPE_CHANNEL: {
        /* Striping order: ch, pl, lun, block_slot, pg */
        ch = page_index % nchs;
        pl = (page_index / nchs) % pls_per_lun;
        lun = (page_index / (nchs * pls_per_lun)) % luns_per_ch;
        uint32_t rem = page_index / (tt_luns * pls_per_lun);
        block_slot = rem / pgs_per_blk;
        pg = rem % pgs_per_blk; // This should match the pSWD write pointer.
        break;
    }
    case ESWD_STRIPE_LUN: {
        /* Striping order: lun, pl, ch, block_slot, pg */
        lun = page_index % luns_per_ch;
        pl = (page_index / luns_per_ch) % pls_per_lun;
        ch = (page_index / (luns_per_ch * pls_per_lun)) % nchs;
        uint32_t rem = page_index / (tt_luns * pls_per_lun);
        block_slot = rem / pgs_per_blk;
        pg = rem % pgs_per_blk; // This should match the pSWD write pointer.
        break;
    }
    case ESWD_STRIPE_PLANE: {
        if (pls_per_lun == 0) {
            return -1;
        }
        uint32_t block_offset = page_index / pgs_per_blk;
        pg = page_index % pgs_per_blk; // This should match the pSWD write pointer.
        blkoff_plane(block_offset, tt_luns, nchs, pls_per_lun, &ch, &lun, &pl, &block_slot);
        break;
    }
    case ESWD_STRIPE_BLOCK:
    default:
        return -1;
    }

    /* Look up starting block from mapping table */
    uint32_t starting_block = layout->eswd_to_starting_block[eswd_id];

    /* Add block_slot offset within this eSWD */
    uint32_t blk = starting_block + block_slot;

    memset(ppa, 0, sizeof(PseudoPpa));
    ppa->g.ch = ch;
    ppa->g.lun = lun;
    ppa->g.pl = pl;
    ppa->g.blk = blk;
    ppa->g.pg = pg;
    return 0;
}

static int native_layout_ppa_to_page(const struct eswd_layout *layout,
                     const struct bbm_geom *geom,
                     const PseudoPpa *ppa,
                     uint32_t *out_eswd_id,
                     uint32_t *out_page_index)
{
    if (!layout || !geom || !ppa || !out_eswd_id || !out_page_index) {
        return -1;
    }
    int eswd_id_ret = native_layout_ppa_to_eswd(layout, geom, ppa);
    if (eswd_id_ret < 0) {
        return -1;
    }
    *out_eswd_id = (uint32_t)eswd_id_ret;

    uint32_t tt_luns = geom->nchs * geom->luns_per_ch;
    uint32_t nchs = geom->nchs;
    uint32_t luns_per_ch = geom->luns_per_ch;
    uint32_t pls_per_lun = geom->pls_per_lun;
    uint32_t pgs_per_blk = geom->pgs_per_blk;
    uint32_t blk = ppa->g.blk;
    uint32_t ch = ppa->g.ch;
    uint32_t lun = ppa->g.lun;
    uint32_t pl = ppa->g.pl;
    uint32_t pg = ppa->g.pg;

    uint32_t eswd_id = (uint32_t)eswd_id_ret;

    /* Extract block_slot using mapping table */
    uint32_t starting_block = layout->eswd_to_starting_block[eswd_id];
    uint32_t block_slot = blk - starting_block;

    /* Validate block is within this eSWD */
    if (block_slot >= layout->blks_per_pl) {
        return -1;
    }

    /* Inverse of page_to_ppa: page_index = rem*(tt_luns*pls_per_lun) + (ch,lun,pl)_ordinal, rem = block_slot*pgs_per_blk+pg */
    uint32_t rem = block_slot * pgs_per_blk + pg;
    uint32_t ord;
    switch (layout->striping_level) {
    case ESWD_STRIPE_CHANNEL:
        /* Inverse: page_index has ch fastest, then pl, then lun */
        ord = ch + pl * nchs + lun * (nchs * pls_per_lun);
        break;
    case ESWD_STRIPE_LUN:
        /* Inverse: page_index has lun fastest, then pl, then ch */
        ord = lun + pl * luns_per_ch + ch * (luns_per_ch * pls_per_lun);
        break;
    case ESWD_STRIPE_PLANE: {
        uint32_t tt_pl = tt_luns * pls_per_lun;
        ord = block_slot * tt_pl + pl * tt_luns + ch + lun * nchs;
        *out_page_index = ord * pgs_per_blk + pg;
        goto check;
    }
    case ESWD_STRIPE_BLOCK:
    default:
        return -1;
    }
    *out_page_index = rem * (tt_luns * pls_per_lun) + ord;
check:
    if (*out_page_index >= layout->pgs_per_eswd) {
        return -1;
    }
    return 0;
}

static int native_layout_block_to_ppa(const struct eswd_layout *layout,
                      const struct bbm_geom *geom,
                      uint32_t eswd_id,
                      uint32_t block_index,
                      PseudoPpa *ppa)
{
    if (!layout || !geom || !ppa || eswd_id >= layout->tt_eswds || block_index >= layout->blks_per_eswd) {
        return -1;
    }

    uint32_t tt_luns = geom->nchs * geom->luns_per_ch;
    uint32_t nchs = geom->nchs;
    uint32_t luns_per_ch = geom->luns_per_ch;
    uint32_t pls_per_lun = geom->pls_per_lun;

    /* With page-level striping, block_index maps to a (ch, lun, pl) tuple.
     * Each "eSWD block" represents all pages on one (ch, lun, pl) within this eSWD. */
    uint32_t ch, lun, pl, blk;

    switch (layout->striping_level) {
    case ESWD_STRIPE_CHANNEL:
        /* block_index maps: ch, then pl, then lun */
        ch = block_index % nchs;
        pl = (block_index / nchs) % pls_per_lun;
        lun = block_index / (nchs * pls_per_lun);
        break;
    case ESWD_STRIPE_LUN:
        /* block_index maps: lun, then pl, then ch */
        lun = block_index % luns_per_ch;
        pl = (block_index / luns_per_ch) % pls_per_lun;
        ch = block_index / (luns_per_ch * pls_per_lun);
        break;
    case ESWD_STRIPE_PLANE:
        if (pls_per_lun == 0) {
            return -1;
        }
        /* block_index maps: pl, then ch, then lun */
        pl = block_index / tt_luns;
        {
            uint32_t rem = block_index % tt_luns;
            ch = rem % nchs;
            lun = rem / nchs;
        }
        break;
    case ESWD_STRIPE_BLOCK:
    default:
        return -1;
    }

    /* Look up starting block from mapping table */
    uint32_t starting_block = layout->eswd_to_starting_block[eswd_id];
    uint32_t tt_pl = layout->tt_pl;

    /* Each block_index maps to a (ch, lun, pl) tuple.
     * Multiple tuples may share the same physical block when blks_per_eswd > tt_pl. */
    uint32_t block_offset_within_eswd = block_index / tt_pl;
    blk = starting_block + block_offset_within_eswd;

    memset(ppa, 0, sizeof(PseudoPpa));
    ppa->g.ch = ch;
    ppa->g.lun = lun;
    ppa->g.pl = pl;
    ppa->g.blk = blk;
    ppa->g.pg = 0;  /* First page of the block */
    return 0;
}

void flash_subsystem_eswd_layout_cleanup(struct eswd_layout *layout)
{
    if (layout && layout->eswd_to_starting_block) {
        g_free(layout->eswd_to_starting_block);
        layout->eswd_to_starting_block = NULL;
    }
}

//#include "raw-flash.h"

//#define FEMU_DEBUG_FTL

typedef void (*FtlInternalPpaCommit)(void *context, struct ssd *ssd,
                                     uint64_t lpn,
                                     const PseudoPpa *new_ppa);
typedef void (*FtlInternalOobFill)(void *context, struct ssd *ssd,
                                   uint64_t lpn, void *oob_buffer,
                                   uint32_t oob_length);


// LBA is the OS/NVMe view of the logical address space. Each LBA is a "sector"
// PBA is the physical address space.
// LPN is the logical page number.
// PPN is the physical page number.

static inline uint32_t eswd_lbas_per_page(struct ssd *ssd)
{
    return ssd->bbm->geom->secs_per_pg;
}

static inline uint32_t eswd_lba_size(struct ssd *ssd)
{
    return ssd->bbm->geom->secsz; // Sector size in bytes.
}

static inline uint64_t eswd_page_size_bytes(struct ssd *ssd)
{
    return (uint64_t)eswd_lbas_per_page(ssd) * eswd_lba_size(ssd);
}

static inline uint64_t eswd_capacity_lbas(struct ssd *ssd)
{
    return (uint64_t)ssd->eswd_layout.pgs_per_eswd * eswd_lbas_per_page(ssd);
}

static inline uint64_t eswd_start_lba(struct ssd *ssd, uint32_t eswd_id)
{
    return (uint64_t)eswd_id * eswd_capacity_lbas(ssd);
}

static inline uint64_t eswd_end_lba(struct ssd *ssd, uint32_t eswd_id)
{
    return eswd_start_lba(ssd, eswd_id) + eswd_capacity_lbas(ssd);
}

static bool native_get_oob_range(struct ssd *ssd, int oob_handle,
                              size_t *offset_out, size_t *len_out)
{
    if (!ssd || !ssd->raw_flash || oob_handle < 0) {
        return false;
    }
    return raw_flash_get_oob_policy_info(ssd->raw_flash, oob_handle,
                                           offset_out, len_out) == 0;
}

/*
 * Private physical-write primitive: program one or more page-sized buffers to the
 * given PseudoPpas via bbm_write, then mark the pages valid.
 */

 // TODO: look over this in details. Is this what we want? is it general enouph?
 // Also, what is the purpose of each write function? even, of each function in this file?
static uint64_t native_write_pages_raw(struct ssd *ssd, const uint8_t *buffer,
                                    PseudoPpa *ppas, uint32_t page_count,
                                    int oob_handle,
                                    FtlInternalOobFill fill_oob,
                                    void *oob_ctx,
                                    uint64_t start_lpn,
                                    int64_t stime_ns)
{
    struct BbmEvent event = {0};
    uint64_t page_size = eswd_page_size_bytes(ssd);
    uint8_t *oob_pages = NULL;
    size_t oob_offset = 0;
    size_t oob_len = 0;
    if (!ssd || !buffer || !ppas || page_count == 0) {
        return 0;
    }

    if (fill_oob && native_get_oob_range(ssd, oob_handle, &oob_offset, &oob_len) &&
        oob_len > 0) {
        oob_pages = g_malloc0((size_t)page_count * oob_len);
        if (!oob_pages) {
            return 0;
        }
        for (uint32_t i = 0; i < page_count; i++) {
            fill_oob(oob_ctx, ssd, start_lpn + i, oob_pages + ((size_t)i * oob_len),
                     (uint32_t)oob_len);
        }
    }

    event.cmd = BBM_EVENT_WRITE;
    event.type = BBM_EVENT_POLICY_IO;
    event.count = page_count;
    event.stime = stime_ns;
    bbm_write(ssd->raw_flash, ssd->bbm, (uint8_t *)buffer, ppas, page_count,
                  page_size, oob_pages, oob_offset, oob_len, &event);
    g_free(oob_pages);
    for (uint32_t i = 0; i < page_count; i++) {
        native_mark_page_valid(ssd, &ppas[i]);
    }
    return (uint64_t)event.lat;
}

static uint64_t native_write_direct_pages(struct ssd *ssd, uint32_t eswd_id,
                                       const uint8_t *buffer, uint32_t page_count,
                                       uint64_t start_lpn,
                                       int oob_handle,
                                       FtlInternalOobFill fill_oob,
                                       void *oob_ctx,
                                       FtlInternalPpaCommit on_page_commit,
                                       void *commit_ctx,
                                       PseudoPpa *ppa_out,
                                       int64_t stime_ns)
{
    struct eswd *e;
    PseudoPpa *ppas;
    uint32_t pages_until_end;
    uint64_t lat;
    if (!ssd || eswd_id >= ssd->tt_eswds || !buffer || !page_count) {
        return 0;
    }
    e = &ssd->eswds[eswd_id];
    pages_until_end = ssd->eswd_layout.pgs_per_eswd - e->wp_page_index;
    if (page_count > pages_until_end) {
        page_count = pages_until_end;
    }
    if (!page_count) {
        return 0;
    }

    ppas = g_malloc0(sizeof(*ppas) * page_count);
    if (!ppas) {
        return 0;
    }
    for (uint32_t i = 0; i < page_count; i++) {
        if (native_eswd_page_to_ppa(ssd, eswd_id, e->wp_page_index + i, &ppas[i]) != 0) {
            page_count = i;
            break;
        }
    }
    if (!page_count) {
        g_free(ppas);
        return 0;
    }

    lat = native_write_pages_raw(ssd, buffer, ppas, page_count, oob_handle,
                              fill_oob, oob_ctx, start_lpn, stime_ns);
    for (uint32_t i = 0; i < page_count; i++) {
        uint64_t lpn = start_lpn + i;

        if (ppa_out) {
            *ppa_out = ppas[i];
        }
        if (on_page_commit) {
            on_page_commit(commit_ctx, ssd, lpn, &ppas[i]);
        }
        native_eswd_increment_wp(ssd, eswd_id);
    }
    g_free(ppas);
    return lat;
}

struct native_fixed_oob_context {
    const uint8_t *data;
    uint32_t length;
};

static void native_copy_fixed_oob(void *opaque, struct ssd *ssd, uint64_t lpn,
                               void *oob_buffer, uint32_t oob_length)
{
    const struct native_fixed_oob_context *context = opaque;

    (void)ssd;
    (void)lpn;
    if (context && context->data && context->length == oob_length) {
        memcpy(oob_buffer, context->data, oob_length);
    }
}

static int native_append_page(struct ssd *ssd, uint32_t eswd_id,
                           const uint8_t *page_data, int oob_handle,
                           const uint8_t *oob_data, uint32_t oob_length,
                           PseudoPpa *ppa_out, uint64_t *latency_out,
                           int64_t stime_ns)
{
    struct native_fixed_oob_context oob_context = {
        .data = oob_data,
        .length = oob_length,
    };
    struct eswd *eswd;
    uint64_t latency;

    if (!ssd || !page_data || !ppa_out || !latency_out ||
        eswd_id >= ssd->tt_eswds ||
        (oob_length != 0 && (!oob_data || oob_handle < 0))) {
        return -1;
    }
    eswd = &ssd->eswds[eswd_id];
    if (eswd->wp_page_index >= ssd->eswd_layout.pgs_per_eswd) {
        return -1;
    }
    ppa_out->ppa = INVALID_PPA;
    latency = native_write_direct_pages(
        ssd, eswd_id, page_data, 1,
        eswd->wp_lba / eswd_lbas_per_page(ssd), oob_handle,
        oob_length ? native_copy_fixed_oob : NULL,
        oob_length ? &oob_context : NULL, NULL, NULL, ppa_out, stime_ns);
    if (ppa_out->ppa == INVALID_PPA) {
        return -1;
    }
    *latency_out = latency;
    return 0;
}

static int native_read_physical_page(struct ssd *ssd, const PseudoPpa *ppa,
                         uint8_t *page_data, int oob_handle, void *oob_data,
                         int64_t stime_ns, uint64_t *latency_out)
{
    if (!ssd || !ppa || !page_data || !latency_out ||
        !native_ppa_valid(ssd, (PseudoPpa *)ppa)) {
        return -1;
    }
    *latency_out = native_read_page_buffer(ssd, ppa, page_data, oob_handle, oob_data,
                                    stime_ns);
    return 0;
}

/* Copy between native NVMe scatter-gather buffers and contiguous memory. */

static uint64_t native_get_request_buffer_size(NvmeRequest *req)
{
    if (!req) {
        return 0;
    }

    uint64_t total_size = 0;
    QEMUSGList *qsg = &req->qsg;

    for (int i = 0; i < qsg->nsg; i++) {
        total_size += qsg->sg[i].len;
    }

    return total_size;
}

static uint8_t *native_copy_request_data(NvmeRequest *req, uint64_t offset,
                                uint64_t length, uint64_t *out_size)
{
    if (!req || !out_size) {
        return NULL;
    }

    QEMUSGList *qsg = &req->qsg;
    if (qsg->nsg == 0) {
        *out_size = 0;
        return NULL;
    }

    /* Calculate total available data */
    uint64_t total_size = native_get_request_buffer_size(req);

    if (offset >= total_size) {
        *out_size = 0;
        return NULL;
    }

    /* Determine how much to copy */
    uint64_t available = total_size - offset;
    uint64_t to_copy = (length == 0 || length > available) ? available : length;

    /* Allocate destination buffer */
    uint8_t *buffer = g_malloc(to_copy);
    if (!buffer) {
        *out_size = 0;
        return NULL;
    }

    /* Copy data from scatter-gather list */
    uint64_t copied = 0;
    uint64_t sg_offset = 0;
    int sg_index = 0;

    /* Skip to the starting offset */
    uint64_t skip_remaining = offset;
    while (sg_index < qsg->nsg && skip_remaining > 0) {
        if (skip_remaining >= qsg->sg[sg_index].len) {
            skip_remaining -= qsg->sg[sg_index].len;
            sg_index++;
        } else {
            sg_offset = skip_remaining;
            skip_remaining = 0;
        }
    }

    /* Copy the data */
    while (sg_index < qsg->nsg && copied < to_copy) {
        dma_addr_t cur_addr = qsg->sg[sg_index].base + sg_offset;
        uint64_t sg_remaining = qsg->sg[sg_index].len - sg_offset;
        uint64_t chunk = (to_copy - copied < sg_remaining) ?
                         (to_copy - copied) : sg_remaining;

        /* Use DMA memory read to copy from guest memory */
        if (dma_memory_read(qsg->as, cur_addr, buffer + copied, chunk,
                           MEMTXATTRS_UNSPECIFIED)) {
            fprintf(stderr, "[PolicyAPI] DMA read failed\n");
            g_free(buffer);
            *out_size = 0;
            return NULL;
        }

        copied += chunk;
        sg_offset = 0;  /* After first chunk, start from beginning of next SG entry */
        sg_index++;
    }

    *out_size = copied;
    return buffer;
}

static uint64_t native_write_request_data(NvmeRequest *req, const uint8_t *buffer,
                                 uint64_t offset, uint64_t length)
{
    if (!req || !buffer || length == 0) {
        return 0;
    }

    QEMUSGList *qsg = &req->qsg;
    if (qsg->nsg == 0) {
        return 0;
    }

    /* Calculate total available space */
    uint64_t total_size = native_get_request_buffer_size(req);

    if (offset >= total_size) {
        return 0;
    }

    /* Determine how much to write */
    uint64_t available = total_size - offset;
    uint64_t to_write = (length > available) ? available : length;

    /* Write data to scatter-gather list */
    uint64_t written = 0;
    uint64_t sg_offset = 0;
    int sg_index = 0;

    /* Skip to the starting offset */
    uint64_t skip_remaining = offset;
    while (sg_index < qsg->nsg && skip_remaining > 0) {
        if (skip_remaining >= qsg->sg[sg_index].len) {
            skip_remaining -= qsg->sg[sg_index].len;
            sg_index++;
        } else {
            sg_offset = skip_remaining;
            skip_remaining = 0;
        }
    }

    /* Write the data */
    while (sg_index < qsg->nsg && written < to_write) {
        dma_addr_t cur_addr = qsg->sg[sg_index].base + sg_offset;
        uint64_t sg_remaining = qsg->sg[sg_index].len - sg_offset;
        uint64_t chunk = (to_write - written < sg_remaining) ?
                         (to_write - written) : sg_remaining;

        /* Use DMA memory write to copy to guest memory */
        if (dma_memory_write(qsg->as, cur_addr, buffer + written, chunk,
                            MEMTXATTRS_UNSPECIFIED)) {
            fprintf(stderr, "[PolicyAPI] DMA write failed\n");
            return written;  /* Return partial write count */
        }

        written += chunk;
        sg_offset = 0;  /* After first chunk, start from beginning of next SG entry */
        sg_index++;
    }

    return written;
}

static const NvmeDsmRange *native_get_dsm_ranges(NvmeRequest *req, int *nr_ranges)
{
    if (nr_ranges) {
        *nr_ranges = req ? req->dsm_nr_ranges : 0;
    }
    return req ? req->dsm_ranges : NULL;
}

static uint16_t native_read_cmd_buffer(struct NvmeCommandEvent *event, void *dst,
                             uint32_t length)
{
    FemuCtrl *n;
    NvmeCmd *cmd;

    if (!event || !dst || length == 0) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    n = event->ctrl;
    cmd = event->cmd;
    if (!n || !cmd) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (dma_write_prp(n, dst, length,
                      le64_to_cpu(cmd->dptr.prp1),
                      le64_to_cpu(cmd->dptr.prp2)) != NVME_SUCCESS) {
        return NVME_DATA_TRAS_ERROR | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t native_write_cmd_buffer(struct NvmeCommandEvent *event, const void *src,
                              uint32_t length)
{
    FemuCtrl *n;
    NvmeCmd *cmd;

    if (!event || !src || length == 0) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    n = event->ctrl;
    cmd = event->cmd;
    if (!n || !cmd) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (dma_read_prp(n, (uint8_t *)src, length,
                     le64_to_cpu(cmd->dptr.prp1),
                     le64_to_cpu(cmd->dptr.prp2)) != NVME_SUCCESS) {
        return NVME_DATA_TRAS_ERROR | NVME_DNR;
    }

    return NVME_SUCCESS;
}

#define FTL_MAX_COMMAND_TRANSFER_BYTES (1024U * 1024U)

static int native_command_data_transfer(struct NvmeCommandEvent *event,
                                     bool write_to_host,
                                     uint32_t command_offset, void *buffer,
                                     uint32_t length)
{
    uint8_t *temporary;
    uint64_t total;
    uint16_t status;
    int rc = -EIO;

    if (!event || !buffer || length == 0 ||
        command_offset > FTL_MAX_COMMAND_TRANSFER_BYTES ||
        length > FTL_MAX_COMMAND_TRANSFER_BYTES - command_offset) {
        return -EINVAL;
    }
    total = command_offset + length;
    temporary = g_try_malloc0(total);
    if (!temporary) {
        return -ENOMEM;
    }
    if (write_to_host) {
        if (command_offset != 0) {
            status = native_read_cmd_buffer(event, temporary, total);
            if (status != NVME_SUCCESS) {
                goto cleanup;
            }
        }
        memcpy(temporary + command_offset, buffer, length);
        status = native_write_cmd_buffer(event, temporary, total);
    } else {
        status = native_read_cmd_buffer(event, temporary, total);
        if (status == NVME_SUCCESS) {
            memcpy(buffer, temporary + command_offset, length);
        }
    }
    if (status == NVME_SUCCESS) {
        rc = 0;
    }

cleanup:
    OPENSSL_cleanse(temporary, total);
    g_free(temporary);
    return rc;
}

static int native_command_data_read(struct NvmeCommandEvent *event,
                          uint32_t command_offset, void *destination,
                          uint32_t length)
{
    return native_command_data_transfer(event, false, command_offset, destination,
                                     length);
}

static int native_command_data_write(struct NvmeCommandEvent *event,
                           uint32_t command_offset, const void *source,
                           uint32_t length)
{
    return native_command_data_transfer(event, true, command_offset,
                                     (void *)source, length);
}

static void native_set_completion_result_u64(struct NvmeCommandEvent *event,
                                   uint64_t value)
{
    NvmeRequest *req;

    if (!event) {
        return;
    }

    req = event->req;
    if (req) {
        req->cqe.res64 = cpu_to_le64(value);
    } else if (event->cqe) {
        event->cqe->res64 = cpu_to_le64(value);
    }
}

static int native_get_page_status(struct ssd *ssd, const PseudoPpa *ppa)
{
    if (!ssd || !ssd->bbm || !ppa) {
        return -1;
    }
    return bbm_get_page_status(ssd->raw_flash, ssd->bbm, ppa);
}

int flash_subsystem_register_oob_region(struct ssd *ssd, const char *name,
                            uint32_t size, int *handle_out)
{
    if (!ssd || !ssd->raw_flash || !name || !handle_out || size == 0) {
        return -1;
    }
    return raw_flash_register_oob_policy(ssd->raw_flash, name, size, handle_out);
}

void policy_event_from_nvme_request(struct ssd *ssd, NvmeRequest *req, struct NvmeCommandEvent *event)
{
    if (!ssd || !req || !event) {
        return;
    }
    const struct bbm_geom *geom = ssd->bbm->geom;

    event->opcode = req->cmd.opcode;
    event->is_admin = false;
    event->lba = req->slba;
    event->nsecs = req->nlb;
    event->start_lpn = req->slba / geom->secs_per_pg;
    event->end_lpn = (req->slba + req->nlb - 1) / geom->secs_per_pg;
    event->lpn_cnt = event->end_lpn - event->start_lpn + 1;
    event->req = req;
    event->cmd = &req->cmd;
    event->cqe = &req->cqe;
    event->ctrl = req->sq ? req->sq->ctrl : NULL;
    event->stime = req->stime;
    event->lat = 0;
    event->status = NVME_SUCCESS;
}

static const struct bbm_geom *native_geometry(struct ssd *ssd)
{
    return (ssd && ssd->bbm) ? ssd->bbm->geom : NULL;
}

static const struct eswd_layout *native_layout(struct ssd *ssd)
{
    return ssd ? &ssd->eswd_layout : NULL;
}


static uint64_t native_ppa_to_page_index(struct ssd *ssd, PseudoPpa *ppa)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    uint64_t pgidx;

    pgidx = ppa->g.ch  * geom->pgs_per_ch  + \
            ppa->g.lun * geom->pgs_per_lun + \
            ppa->g.pl  * geom->pgs_per_pl  + \
            ppa->g.blk * geom->pgs_per_blk + \
            ppa->g.pg;

    assert(pgidx < geom->tt_pgs_log);

    return pgidx;
}

/* Commit the eSWD configuration selected during policy initialization. */
void flash_subsystem_set_eswd_config(struct ssd *ssd, const struct eswd_config *config)
{
    if (!ssd || !config || !ssd->bbm || !ssd->bbm->geom) {
        return;
    }
    if (ssd->eswd_layout_finalized) {
        fprintf(stderr, "[PolicyAPI] eSWD layout is already finalized\n");
        return;
    }
    const struct bbm_geom *geom = ssd->bbm->geom;
    if (!flash_subsystem_eswd_config_valid(config, geom->nchs, geom->luns_per_ch,
                           geom->pls_per_lun, geom->blks_per_lun_log)) {
        fprintf(stderr, "[PolicyAPI] invalid eSWD configuration\n");
        return;
    }
    ssd->eswd_config = *config;
    ssd->eswd_config_set = true;
}

static void ssd_init_eswds(struct ssd *ssd)
{
    const struct eswd_layout *layout = &ssd->eswd_layout;
    uint32_t tt = layout->tt_eswds;

    ssd->tt_eswds = tt;
    ssd->eswds = g_malloc0(sizeof(struct eswd) * tt);
    for (uint32_t i = 0; i < tt; i++) {
        ssd->eswds[i].id = i;
        ssd->eswds[i].ipc = 0;
        ssd->eswds[i].vpc = 0;
        ssd->eswds[i].wp_page_index = 0;
        ssd->eswds[i].wp_lba = eswd_start_lba(ssd, i);
    }
}

int flash_subsystem_finalize(struct ssd *ssd)
{
    const struct bbm_geom *geom;

    if (!ssd || !ssd->bbm || !ssd->bbm->geom) {
        return -1;
    }
    if (ssd->eswd_layout_finalized) {
        return 0;
    }
    if (!ssd->eswd_config_set) {
        fprintf(stderr, "[PolicyAPI] eSWD configuration has not been set\n");
        return -1;
    }

    geom = ssd->bbm->geom;
    if (flash_subsystem_eswd_layout_compute(&ssd->eswd_layout, &ssd->eswd_config, geom) != 0) {
        fprintf(stderr, "[PolicyAPI] failed to compute eSWD layout\n");
        return -1;
    }

    ssd->eswd_layout_finalized = true;
    ssd_init_eswds(ssd);
    return 0;
}

/* Resolve a physical page to the eSWD containing it. */
static struct eswd *native_find_eswd(struct ssd *ssd, PseudoPpa *ppa)
{
    uint32_t eswd_id;
    uint32_t page_index;
    if (native_layout_ppa_to_page(&ssd->eswd_layout, ssd->bbm->geom, ppa, &eswd_id, &page_index) != 0) {
        return NULL;
    }
    if (eswd_id >= ssd->tt_eswds) {
        return NULL;
    }
    return &ssd->eswds[eswd_id];
}

/* Keep BBM page validity and the containing eSWD counters synchronized. */
static void native_mark_page_invalid(struct ssd *ssd, PseudoPpa *ppa)
{
    struct eswd *e = native_find_eswd(ssd, ppa);

    bbm_mark_page_invalid(ssd->raw_flash, ssd->bbm, ppa);
    if (!e) {
        fprintf(stderr,
                "[PolicyAPI] no eSWD contains PPA (%d,%d,%d,%d,%d)\n",
                ppa->g.ch, ppa->g.lun, ppa->g.pl, ppa->g.blk,
                ppa->g.pg);
        return;
    }

    assert(e->ipc >= 0 && e->ipc < (int)ssd->eswd_layout.pgs_per_eswd);
    assert(e->vpc > 0 && e->vpc <= (int)ssd->eswd_layout.pgs_per_eswd);
    e->ipc++;
    e->vpc--;
}

static void native_mark_page_valid(struct ssd *ssd, PseudoPpa *ppa)
{
    struct eswd *e = native_find_eswd(ssd, ppa);

    bbm_mark_page_valid(ssd->raw_flash, ssd->bbm, ppa);
    if (!e) {
        fprintf(stderr,
                "[PolicyAPI] no eSWD contains PPA (%d,%d,%d,%d,%d)\n",
                ppa->g.ch, ppa->g.lun, ppa->g.pl, ppa->g.blk,
                ppa->g.pg);
        return;
    }
    assert(e->vpc >= 0 && e->vpc < (int)ssd->eswd_layout.pgs_per_eswd);
    e->vpc++;
}

/* Native eSWD state operations used by the semantic wrappers. */

static struct eswd *native_find_eswd_by_id(struct ssd *ssd, uint32_t eswd_id)
{
    if (eswd_id >= ssd->tt_eswds) {
        return NULL;
    }
    return &ssd->eswds[eswd_id];
}

static void native_eswd_increment_wp(struct ssd *ssd, uint32_t eswd_id)
{
    if (eswd_id >= ssd->tt_eswds) {
        return;
    }
    ssd->eswds[eswd_id].wp_page_index++;
    ssd->eswds[eswd_id].wp_lba += eswd_lbas_per_page(ssd);
}

static void native_eswd_reset_state(struct ssd *ssd, uint32_t eswd_id)
{
    if (eswd_id >= ssd->tt_eswds) {
        return;
    }
    struct eswd *e = &ssd->eswds[eswd_id];
    e->ipc = 0;
    e->vpc = 0;
    e->wp_page_index = 0;
    e->wp_lba = eswd_start_lba(ssd, eswd_id);
}

static uint64_t native_eswd_wp_lba(struct ssd *ssd, uint32_t eswd_id)
{
    if (eswd_id >= ssd->tt_eswds) {
        return 0;
    }
    return ssd->eswds[eswd_id].wp_lba;
}


static uint64_t native_read_page_buffer(struct ssd *ssd, const PseudoPpa *ppa,
                          uint8_t *buffer,
                          int oob_handle, void *oob_buf,
                          int64_t stime_ns)
{
    struct BbmEvent event = {0};
    uint64_t page_size;
    PseudoPpa local;
    size_t oob_offset = 0;
    size_t oob_len = 0;

    if (!ssd || !ppa || !buffer) {
        return 0;
    }
    local = *ppa;
    if (!native_ppa_valid(ssd, &local)) {
        return 0;
    }

    page_size = eswd_page_size_bytes(ssd);
    event.cmd = BBM_EVENT_READ;
    event.type = BBM_EVENT_POLICY_IO;
    event.count = 1;
    event.stime = stime_ns;
    if (!oob_buf || !native_get_oob_range(ssd, oob_handle, &oob_offset, &oob_len)) {
        oob_buf = NULL;
        oob_offset = 0;
        oob_len = 0;
    }
    bbm_read(ssd->raw_flash, ssd->bbm, buffer, &local, 1, page_size,
                 oob_buf, oob_offset, oob_len, &event);
    return (uint64_t)event.lat;
}

/* eSWD layout query wrappers */
static int native_eswd_page_to_ppa(struct ssd *ssd, uint32_t eswd_id, uint32_t page_index, PseudoPpa *ppa)
{
    return native_layout_page_to_ppa(&ssd->eswd_layout, ssd->bbm->geom, eswd_id, page_index, ppa);
}

static int native_ppa_to_eswd_page(struct ssd *ssd, const PseudoPpa *ppa, uint32_t *eswd_id, uint32_t *page_index)
{
    return native_layout_ppa_to_page(&ssd->eswd_layout, ssd->bbm->geom, ppa, eswd_id, page_index);
}

static int native_eswd_block_to_ppa(struct ssd *ssd, uint32_t eswd_id, uint32_t block_index, PseudoPpa *ppa)
{
    return native_layout_block_to_ppa(&ssd->eswd_layout, ssd->bbm->geom, eswd_id, block_index, ppa);
}

static int native_eswd_advance_wp_to_end(struct ssd *ssd, uint32_t eswd_id)
{
    if (!ssd || eswd_id >= ssd->tt_eswds) {
        return -1;
    }
    ssd->eswds[eswd_id].wp_page_index = ssd->eswd_layout.pgs_per_eswd;
    ssd->eswds[eswd_id].wp_lba = eswd_end_lba(ssd, eswd_id);
    return 0;
}

static uint64_t native_eswd_erase_physical(struct ssd *ssd, uint32_t eswd_id, int64_t stime_ns)
{
    const struct eswd_layout *layout;
    uint64_t maxlat = 0;
    struct BbmEvent bbm_ev = {0};

    if (!ssd || !ssd->raw_flash || !ssd->bbm || eswd_id >= ssd->tt_eswds) {
        return 0;
    }
    layout = &ssd->eswd_layout;
    bbm_ev.cmd = BBM_EVENT_ERASE;
    bbm_ev.type = BBM_EVENT_POLICY_IO;
    bbm_ev.stime = stime_ns;
    if (layout->blks_per_eswd > 0) {
        bbm_ev.status_list = g_malloc0(sizeof(int) * (size_t)layout->blks_per_eswd);
    }

    for (uint32_t blk = 0; blk < layout->blks_per_eswd; blk++) {
        PseudoPpa ppa;
        PseudoPba pba;

        if (native_eswd_block_to_ppa(ssd, eswd_id, blk, &ppa) != 0) {
            continue;
        }
        native_mark_block_free(ssd, &ppa);
        pba.g.ch = ppa.g.ch;
        pba.g.lun = ppa.g.lun;
        pba.g.pl = ppa.g.pl;
        pba.g.blk = ppa.g.blk;
        bbm_erase(ssd->raw_flash, ssd->bbm, &pba, 1, &bbm_ev);
        if ((uint64_t)bbm_ev.lat > maxlat) {
            maxlat = (uint64_t)bbm_ev.lat;
        }
    }

    g_free(bbm_ev.status_list);
    return maxlat;
}

/* Copy one valid page to the current write position of another eSWD. */

static int native_migrate_page(struct ssd *ssd, const PseudoPpa *source,
                            uint32_t destination_eswd_id,
                            PseudoPpa *destination_out,
                            uint64_t *latency_out)
{
    struct eswd *source_eswd;
    struct eswd *destination_eswd;
    struct BbmEvent read_event = {0};
    struct BbmEvent write_event = {0};
    PseudoPpa source_copy;
    uint8_t *page_buffer;
    uint8_t *oob_buffer;
    uint64_t page_size;
    size_t oob_size;
    int rc = -1;

    if (!ssd || !source || !destination_out || !latency_out ||
        destination_eswd_id >= ssd->tt_eswds) {
        return -1;
    }
    source_copy = *source;
    if (!native_ppa_valid(ssd, &source_copy) ||
        native_get_page_status(ssd, &source_copy) != PG_VALID) {
        return -1;
    }
    source_eswd = native_find_eswd(ssd, &source_copy);
    destination_eswd = native_find_eswd_by_id(ssd, destination_eswd_id);
    if (!source_eswd || !destination_eswd ||
        source_eswd == destination_eswd ||
        destination_eswd->wp_page_index >=
            ssd->eswd_layout.pgs_per_eswd ||
        native_eswd_page_to_ppa(ssd, destination_eswd_id,
                               destination_eswd->wp_page_index,
                               destination_out) != 0) {
        return -1;
    }

    page_size = eswd_page_size_bytes(ssd);
    oob_size = ssd->raw_flash->oob_size_per_page;
    if (page_size > ssd->raw_flash->migration_page_buf_size ||
        oob_size > ssd->raw_flash->migration_oob_buf_size) {
        return -1;
    }
    page_buffer = ssd->raw_flash->migration_page_buf;
    oob_buffer = oob_size ? ssd->raw_flash->migration_oob_buf : NULL;

    read_event.cmd = BBM_EVENT_READ;
    read_event.type = BBM_EVENT_POLICY_IO;
    read_event.count = 1;
    bbm_read(ssd->raw_flash, ssd->bbm, page_buffer, &source_copy, 1,
                 page_size, oob_buffer, 0, oob_size, &read_event);

    write_event.cmd = BBM_EVENT_WRITE;
    write_event.type = BBM_EVENT_POLICY_IO;
    write_event.count = 1;
    bbm_write(ssd->raw_flash, ssd->bbm, page_buffer, destination_out, 1,
                  page_size, oob_buffer, 0, oob_size, &write_event);

    bbm_mark_page_invalid(ssd->raw_flash, ssd->bbm, &source_copy);
    bbm_mark_page_valid(ssd->raw_flash, ssd->bbm, destination_out);
    source_eswd->vpc--;
    source_eswd->ipc++;
    destination_eswd->vpc++;
    native_eswd_increment_wp(ssd, destination_eswd_id);
    *latency_out = MAX((uint64_t)read_event.lat,
                       (uint64_t)write_event.lat);
    rc = 0;
    return rc;
}

/* Namespace configuration committed by the policy engine after init. */

static void *native_dup_payload(const void *src, size_t len)
{
    void *dst;

    if (!src || len == 0) {
        return NULL;
    }

    dst = g_malloc0(len);
    memcpy(dst, src, len);
    return dst;
}

static uint32_t native_count_published_namespaces(FemuCtrl *n)
{
    uint32_t i;
    uint32_t count = 0;

    if (!n || !n->namespaces) {
        return 0;
    }

    for (i = 0; i < n->num_namespaces; i++) {
        if (n->namespaces[i].published) {
            count++;
        }
    }

    return count;
}

int flash_subsystem_configure_namespace(struct ssd *ssd,
                                    const struct NamespacePersonalityConfig *config)
{
    FemuCtrl *n;
    NvmeNamespace *ns;
    unsigned long *new_util;
    unsigned long *new_uncorrectable;
    void *ns_csi_copy = NULL;
    void *ctrl_csi_copy = NULL;
    uint64_t old_lba_count;
    uint64_t preserved_lba_count;
    uint64_t namespace_size;
    uint8_t lba_index;
    uint8_t lba_shift;

    if (!ssd || !ssd->ctrl || !config) {
        return -1;
    }

    n = ssd->ctrl;
    if (!n->namespaces || n->num_namespaces == 0) {
        return -1;
    }
    ns = &n->namespaces[0];
    if (!ns) {
        return -1;
    }

    if (config->ns_csi_data_len && !config->ns_csi_data) {
        return -1;
    }
    if (config->ctrl_csi_data_len && !config->ctrl_csi_data) {
        return -1;
    }
    if (config->nsze == 0 || config->ncap > config->nsze ||
        config->nuse > config->ncap) {
        return -1;
    }

    lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    lba_shift = ns->id_ns.lbaf[lba_index].lbads;
    if (lba_shift >= 64 || config->nsze > (UINT64_MAX >> lba_shift)) {
        return -1;
    }
    namespace_size = config->nsze << lba_shift;

    new_util = bitmap_new(config->nsze);
    new_uncorrectable = bitmap_new(config->nsze);
    old_lba_count = ns->ns_blks;
    preserved_lba_count = MIN(old_lba_count, config->nsze);
    if (preserved_lba_count != 0) {
        bitmap_copy(new_util, ns->util, preserved_lba_count);
        bitmap_copy(new_uncorrectable, ns->uncorrectable,
                    preserved_lba_count);
    }

    ns_csi_copy = native_dup_payload(config->ns_csi_data, config->ns_csi_data_len);
    ctrl_csi_copy = native_dup_payload(config->ctrl_csi_data, config->ctrl_csi_data_len);

    g_free(n->id_ns_csi);
    g_free(n->id_ctrl_csi);

    n->csi = config->csi;
    n->id_ns_csi = ns_csi_copy;
    n->id_ns_csi_len = config->ns_csi_data_len;
    n->id_ctrl_csi = ctrl_csi_copy;
    n->id_ctrl_csi_len = config->ctrl_csi_data_len;

    /* Preserve the legacy zoned pointer for existing identify paths that still
     * special-case CSI_ZONED while keeping the installed payload generic. */
    n->id_ns_zoned = (config->csi == NVME_CSI_ZONED) ? (NvmeIdNsZoned *)n->id_ns_csi : NULL;

    g_free(ns->util);
    g_free(ns->uncorrectable);
    ns->util = new_util;
    ns->uncorrectable = new_uncorrectable;
    ns->ns_blks = config->nsze;
    ns->size = namespace_size;
    n->ns_size = namespace_size;
    ns->id_ns.nsze = cpu_to_le64(config->nsze);
    ns->id_ns.ncap = cpu_to_le64(config->ncap);
    ns->id_ns.nuse = cpu_to_le64(config->nuse);
    ns->id_ns.noiob = config->noiob;
    ns->published = true;
    n->id_ctrl.nn = cpu_to_le32(native_count_published_namespaces(n));

    return 0;
}


/* Validate addresses before passing them to BBM. */
static bool native_ppa_valid(struct ssd *ssd, PseudoPpa *ppa)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    int ch = ppa->g.ch;
    int lun = ppa->g.lun;
    int pl = ppa->g.pl;
    int blk = ppa->g.blk;
    int pg = ppa->g.pg;
    int sec = ppa->g.sec;

    if (ch >= 0 && ch < (int)geom->nchs && lun >= 0 && lun < (int)geom->luns_per_ch &&
        pl >= 0 && pl < (int)geom->pls_per_lun && blk >= 0 && blk < (int)geom->blks_per_lun_log &&
        pg >= 0 && pg < (int)geom->pgs_per_blk && sec >= 0 && sec < (int)geom->secs_per_pg)
        return true;

    return false;
}

/* Reset BBM validity for a block after the eSWD has been cleaned. */
static void native_mark_block_free(struct ssd *ssd, PseudoPpa *ppa)
{
    bbm_mark_block_free(ssd->raw_flash, ssd->bbm, ppa);
}
