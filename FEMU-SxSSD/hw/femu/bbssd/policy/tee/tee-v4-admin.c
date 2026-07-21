#include "tee-v4-admin.h"

#include "tee-v2-hmac-group.h"

#include <stdlib.h>
#include <string.h>

static int status_from_query(enum tee_v3_query_result result)
{
    if (result == TEE_V3_QUERY_OK) {
        return TEE_V4_ADMIN_STATUS_OK;
    }
    if (result == TEE_V3_QUERY_NOT_FOUND) {
        return TEE_V4_ADMIN_STATUS_NOT_FOUND;
    }
    return TEE_V4_ADMIN_STATUS_BAD_REQUEST;
}

static uint32_t items_per_admin_page(uint32_t admin_buffer_bytes,
                                     uint32_t item_size)
{
    uint32_t payload_bytes;

    if (item_size == 0 ||
        admin_buffer_bytes <= TEE_V4_ADMIN_RESPONSE_HEADER_SIZE) {
        return 1;
    }
    payload_bytes = admin_buffer_bytes - TEE_V4_ADMIN_RESPONSE_HEADER_SIZE;
    return payload_bytes / item_size ? payload_bytes / item_size : 1U;
}

static uint32_t requested_items_per_page(uint32_t admin_buffer_bytes,
                                         uint32_t item_size,
                                         uint32_t requested)
{
    uint32_t maximum = items_per_admin_page(admin_buffer_bytes, item_size);
    return requested && requested < maximum ? requested : maximum;
}

static int compute_request_mac(const void *request_buffer,
                               size_t request_bytes,
                               uint8_t out[TEE_V2_HMAC_SIZE])
{
    const struct tee_v4_admin_request_header *header = request_buffer;
    const uint8_t *payload = (const uint8_t *)request_buffer + sizeof(*header);
    uint8_t *covered;
    size_t span;

    if (!tee_v4_admin_request_valid(header, request_bytes) ||
        !tee_v4_admin_mac_span(header, request_bytes, &span)) {
        return -1;
    }
    covered = malloc(span);
    if (!covered) {
        return -1;
    }
    memcpy(covered, request_buffer, TEE_V4_ADMIN_REQUEST_MAC_OFFSET);
    if (header->payload_len > 0) {
        memcpy(covered + TEE_V4_ADMIN_REQUEST_MAC_OFFSET, payload,
               header->payload_len);
    }
    /* V4 authenticates the operation domain through header.flags. Production
     * key provisioning and a dedicated derived admin key are deferred to V6.
     */
    tee_v2_hmac_sha256(tee_v2_prototype_key, TEE_V2_PROTOTYPE_KEY_SIZE,
                       covered, span, out);
    free(covered);
    return 0;
}

static int verify_request_mac(const void *request_buffer, size_t request_bytes)
{
    const struct tee_v4_admin_request_header *header = request_buffer;
    uint8_t actual[TEE_V2_HMAC_SIZE];

    if (compute_request_mac(request_buffer, request_bytes, actual) != 0) {
        return -1;
    }
    return memcmp(actual, header->request_mac, sizeof(actual)) == 0 ? 0 : -1;
}

int tee_v4_admin_verify_request(const void *request_buffer,
                                size_t request_bytes)
{
    const struct tee_v4_admin_request_header *header = request_buffer;

    if (!request_buffer ||
        !tee_v4_admin_request_valid(header, request_bytes) ||
        request_bytes != sizeof(*header) + header->payload_len) {
        return -1;
    }
    return verify_request_mac(request_buffer, request_bytes);
}

int tee_v4_admin_init(struct tee_v4_admin *admin,
                      struct tee_v3_policy_context *policy,
                      uint32_t admin_buffer_bytes,
                      size_t response_item_bytes)
{
    if (!admin || !policy) {
        return -1;
    }
    memset(admin, 0, sizeof(*admin));
    admin->policy = policy;
    admin->admin_buffer_bytes = admin_buffer_bytes ?
        admin_buffer_bytes : TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES;
    return tee_v4_admin_response_init(&admin->pending, response_item_bytes);
}

void tee_v4_admin_destroy(struct tee_v4_admin *admin)
{
    if (!admin) {
        return;
    }
    tee_v4_admin_response_destroy(&admin->pending);
    memset(admin, 0, sizeof(*admin));
}

void tee_v4_admin_set_writeback(struct tee_v4_admin *admin,
                                struct tee_v4_writeback *writeback)
{
    if (admin) {
        admin->writeback = writeback;
    }
}

void tee_v4_admin_set_metadata_intake(
    struct tee_v4_admin *admin,
    int (*intake)(void *,
                  const struct tee_v4_admin_active_metadata_payload *,
                  const struct tee_v4_admin_hmac_group_wire *),
    void *opaque)
{
    if (!admin) return;
    admin->metadata_intake = intake;
    admin->metadata_intake_opaque = opaque;
}

int tee_v4_admin_sign_request(void *request_buffer, size_t request_bytes)
{
    struct tee_v4_admin_request_header *header = request_buffer;
    uint8_t mac[TEE_V2_HMAC_SIZE];

    if (!header) {
        return -1;
    }
    memset(header->request_mac, 0, sizeof(header->request_mac));
    if (compute_request_mac(request_buffer, request_bytes, mac) != 0) {
        return -1;
    }
    memcpy(header->request_mac, mac, sizeof(mac));
    return 0;
}

static int prepare_status(struct tee_v4_admin *admin,
                          const struct tee_v4_admin_request_header *header,
                          int status)
{
    return tee_v4_admin_response_prepare_items(
        &admin->pending, header->command_type, header->request_id, status,
        NULL, 0, 0, 1);
}

static int handle_summary(struct tee_v4_admin *admin,
                          const struct tee_v4_admin_request_header *header,
                          const struct tee_v4_admin_chunk_query_payload *query)
{
    struct tee_v3_read_summary summary;
    enum tee_v3_query_result result;
    uint32_t page_size = query->page_size ?
        query->page_size : admin->admin_buffer_bytes;

    result = tee_v3_policy_read_summary(admin->policy, query->file_id,
                                        query->chunk_id, page_size, &summary);
    if (result != TEE_V3_QUERY_OK) {
        return prepare_status(admin, header, status_from_query(result));
    }
    return tee_v4_admin_response_prepare_items(
        &admin->pending, header->command_type, header->request_id,
        TEE_V4_ADMIN_STATUS_OK, &summary, 1, sizeof(summary), 1);
}

static int handle_locations(struct tee_v4_admin *admin,
                            const struct tee_v4_admin_request_header *header,
                            const struct tee_v4_admin_chunk_query_payload *query)
{
    struct tee_v3_read_summary summary;
    uint64_t *locations;
    size_t written = 0;
    enum tee_v3_query_result result;

    result = tee_v3_policy_read_summary(admin->policy, query->file_id,
                                        query->chunk_id,
                                        admin->admin_buffer_bytes, &summary);
    if (result != TEE_V3_QUERY_OK) {
        return prepare_status(admin, header, status_from_query(result));
    }
    locations = calloc(summary.location_item_count, sizeof(*locations));
    if (!locations && summary.location_item_count > 0) {
        return prepare_status(admin, header,
                              TEE_V4_ADMIN_STATUS_INTERNAL_ERROR);
    }
    result = tee_v3_policy_read_locations(
        admin->policy, query->file_id, query->chunk_id, 0, locations,
        summary.location_item_count, &written);
    if (result != TEE_V3_QUERY_OK || written != summary.location_item_count) {
        free(locations);
        return prepare_status(admin, header, status_from_query(result));
    }
    result = tee_v4_admin_response_prepare_items(
        &admin->pending, header->command_type, header->request_id,
        TEE_V4_ADMIN_STATUS_OK, locations, summary.location_item_count,
        sizeof(*locations),
        requested_items_per_page(admin->admin_buffer_bytes,
                                 sizeof(*locations), query->page_size));
    free(locations);
    return result;
}

static int handle_hmac_groups(
    struct tee_v4_admin *admin,
    const struct tee_v4_admin_request_header *header,
    const struct tee_v4_admin_chunk_query_payload *query)
{
    struct tee_v3_read_summary summary;
    struct tee_v3_hmac_group_item *groups;
    size_t written = 0;
    enum tee_v3_query_result result;

    result = tee_v3_policy_read_summary(admin->policy, query->file_id,
                                        query->chunk_id,
                                        admin->admin_buffer_bytes, &summary);
    if (result != TEE_V3_QUERY_OK) {
        return prepare_status(admin, header, status_from_query(result));
    }
    groups = calloc(summary.hmac_group_count, sizeof(*groups));
    if (!groups && summary.hmac_group_count > 0) {
        return prepare_status(admin, header,
                              TEE_V4_ADMIN_STATUS_INTERNAL_ERROR);
    }
    result = tee_v3_policy_read_hmac_groups(
        admin->policy, query->file_id, query->chunk_id, 0, groups,
        summary.hmac_group_count, &written);
    if (result != TEE_V3_QUERY_OK || written != summary.hmac_group_count) {
        free(groups);
        return prepare_status(admin, header, status_from_query(result));
    }
    result = tee_v4_admin_response_prepare_items(
        &admin->pending, header->command_type, header->request_id,
        TEE_V4_ADMIN_STATUS_OK, groups, summary.hmac_group_count,
        sizeof(*groups),
        requested_items_per_page(admin->admin_buffer_bytes,
                                 sizeof(*groups), query->page_size));
    free(groups);
    return result;
}

static int handle_one_bit_proof(
    struct tee_v4_admin *admin,
    const struct tee_v4_admin_request_header *header,
    const struct tee_v4_admin_chunk_query_payload *query)
{
    struct tee_v3_one_bit_proof proof;
    uint32_t *missing;
    size_t capacity;
    size_t written = 0;
    enum tee_v3_query_result result;

    capacity = admin->pending.item_bytes_capacity / sizeof(*missing);
    missing = capacity ? calloc(capacity, sizeof(*missing)) : NULL;
    result = tee_v3_policy_one_bit_proof(admin->policy, query->file_id,
                                         query->chunk_id, 0, missing,
                                         capacity, &written, &proof);
    if (result != TEE_V3_QUERY_OK) {
        free(missing);
        return prepare_status(admin, header, status_from_query(result));
    }
    if (proof.state == TEE_V3_PROOF_MISSING && written > 0) {
        result = tee_v4_admin_response_prepare_items(
            &admin->pending, header->command_type, header->request_id,
            TEE_V4_ADMIN_STATUS_OK, missing, (uint32_t)written,
            sizeof(*missing),
            requested_items_per_page(admin->admin_buffer_bytes,
                                     sizeof(*missing), query->page_size));
    } else {
        result = tee_v4_admin_response_prepare_items(
            &admin->pending, header->command_type, header->request_id,
            TEE_V4_ADMIN_STATUS_OK, &proof, 1, sizeof(proof), 1);
    }
    free(missing);
    return result;
}

int tee_v4_admin_submit(struct tee_v4_admin *admin, const void *request_buffer,
                        size_t request_bytes)
{
    const struct tee_v4_admin_request_header *header = request_buffer;
    const struct tee_v4_admin_chunk_query_payload *query;
    int result;

    if (!admin || !request_buffer ||
        !tee_v4_admin_request_valid(header, request_bytes) ||
        request_bytes != sizeof(*header) + header->payload_len ||
        header->flags != TEE_V4_ADMIN_FLAG_SUBMIT ||
        (admin->has_last_submit_request_id &&
         header->request_id <= admin->last_submit_request_id) ||
        verify_request_mac(request_buffer, request_bytes) != 0) {
        return -1;
    }
    query = (const struct tee_v4_admin_chunk_query_payload *)
        ((const uint8_t *)request_buffer + sizeof(*header));
    if (header->command_type != TEE_V4_ADMIN_CMD_SYNC_METADATA &&
        header->command_type != TEE_V4_ADMIN_CMD_SET_ACTIVE_METADATA &&
        header->payload_len != sizeof(*query)) {
        return -1;
    }
    switch (header->command_type) {
    case TEE_V4_ADMIN_CMD_READ_SUMMARY:
        if (query->reserved[0] || query->reserved[1] || query->reserved[2] ||
            query->page_size > admin->admin_buffer_bytes) return -1;
        result = handle_summary(admin, header, query);
        break;
    case TEE_V4_ADMIN_CMD_READ_LOCATIONS:
        if (query->reserved[0] || query->reserved[1] || query->reserved[2] ||
            query->page_size > admin->admin_buffer_bytes) return -1;
        result = handle_locations(admin, header, query);
        break;
    case TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS:
        if (query->reserved[0] || query->reserved[1] || query->reserved[2] ||
            query->page_size > admin->admin_buffer_bytes) return -1;
        result = handle_hmac_groups(admin, header, query);
        break;
    case TEE_V4_ADMIN_CMD_ONE_BIT_PROOF:
        if (query->reserved[0] || query->reserved[1] || query->reserved[2] ||
            query->page_size > admin->admin_buffer_bytes) return -1;
        result = handle_one_bit_proof(admin, header, query);
        break;
    case TEE_V4_ADMIN_CMD_SYNC_METADATA:
        if (header->payload_len != 0 || !admin->writeback ||
            tee_v4_writeback_sync(admin->writeback) != 0) {
            (void)prepare_status(admin, header,
                                 TEE_V4_ADMIN_STATUS_INTERNAL_ERROR);
            return -2;
        }
        result = prepare_status(admin, header, TEE_V4_ADMIN_STATUS_OK);
        break;
    case TEE_V4_ADMIN_CMD_SET_ACTIVE_METADATA:
        {
            const struct tee_v4_admin_active_metadata_payload *metadata;
            const struct tee_v4_admin_hmac_group_wire *groups;
            size_t groups_bytes;
            size_t expected;
            uint32_t i;
            uint64_t expected_start = 1;

            if (header->payload_len < sizeof(*metadata) ||
                !admin->metadata_intake) return -1;
            metadata = (const void *)((const uint8_t *)request_buffer +
                                      sizeof(*header));
            if (metadata->reserved[0] || metadata->reserved[1] ||
                metadata->reserved[2] || !metadata->chunk_size_bytes ||
                metadata->chunk_id > 0xFFFFFFU ||
                !metadata->segment_count || !metadata->number_coefficient ||
                metadata->number_coefficient > metadata->segment_count ||
                !metadata->group_count ||
                metadata->group_count >
                    (UINT32_MAX - sizeof(*metadata)) / sizeof(*groups)) {
                return -1;
            }
            groups_bytes = (size_t)metadata->group_count * sizeof(*groups);
            expected = sizeof(*metadata) + groups_bytes;
            if (expected != header->payload_len) return -1;
            groups = (const void *)(metadata + 1);
            for (i = 0; i < metadata->group_count; i++) {
                if (!groups[i].start_segment_index ||
                    !groups[i].group_segment_count ||
                    groups[i].start_segment_index != expected_start ||
                    groups[i].start_segment_index > metadata->segment_count ||
                    groups[i].group_segment_count >
                        metadata->segment_count -
                            groups[i].start_segment_index + 1U) {
                    return -1;
                }
                expected_start += groups[i].group_segment_count;
            }
            if (expected_start != (uint64_t)metadata->segment_count + 1U)
                return -1;
            if (admin->metadata_intake(admin->metadata_intake_opaque,
                                       metadata, groups) != 0) return -1;
            result = prepare_status(admin, header, TEE_V4_ADMIN_STATUS_OK);
            break;
        }
    default:
        return -1;
    }
    if (result == 0) {
        admin->last_submit_request_id = header->request_id;
        admin->has_last_submit_request_id = true;
    }
    return result;
}

int tee_v4_admin_fetch(struct tee_v4_admin *admin, const void *request_buffer,
                       size_t request_bytes, void *response_buffer,
                       size_t response_capacity, size_t *written)
{
    const struct tee_v4_admin_request_header *header = request_buffer;

    if (!admin || !request_buffer ||
        !tee_v4_admin_request_valid(header, request_bytes) ||
        request_bytes != sizeof(*header) || header->payload_len != 0 ||
        header->flags != TEE_V4_ADMIN_FLAG_FETCH ||
        verify_request_mac(request_buffer, request_bytes) != 0 ||
        !admin->pending.valid ||
        admin->pending.command_type != header->command_type ||
        admin->pending.request_id != header->request_id) {
        if (written) *written = 0;
        return -1;
    }
    return tee_v4_admin_response_materialize_page(
        &admin->pending, 0, response_buffer, response_capacity, written);
}

int tee_v4_admin_continue(struct tee_v4_admin *admin,
                          const void *request_buffer, size_t request_bytes,
                          void *response_buffer,
                          size_t response_capacity, size_t *written)
{
    const struct tee_v4_admin_request_header *header = request_buffer;
    const struct tee_v4_admin_continue_payload *payload;

    if (!admin || !request_buffer ||
        !tee_v4_admin_request_valid(header, request_bytes) ||
        request_bytes != sizeof(*header) + sizeof(*payload) ||
        header->payload_len != sizeof(*payload) ||
        header->flags != TEE_V4_ADMIN_FLAG_CONTINUE ||
        verify_request_mac(request_buffer, request_bytes) != 0) {
        if (written) {
            *written = 0;
        }
        return -1;
    }
    payload = (const struct tee_v4_admin_continue_payload *)
        ((const uint8_t *)request_buffer + sizeof(*header));
    if (!admin->pending.valid ||
        admin->pending.command_type != header->command_type ||
        admin->pending.request_id != header->request_id ||
        payload->request_id != header->request_id) {
        if (written) *written = 0;
        return -1;
    }
    return tee_v4_admin_response_materialize_page(
        &admin->pending, payload->page_index, response_buffer, response_capacity,
        written);
}
