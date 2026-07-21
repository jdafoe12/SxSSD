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
        items_per_admin_page(admin->admin_buffer_bytes, sizeof(*locations)));
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
        items_per_admin_page(admin->admin_buffer_bytes, sizeof(*groups)));
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
            items_per_admin_page(admin->admin_buffer_bytes,
                                 sizeof(*missing)));
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

    if (!admin || !request_buffer ||
        !tee_v4_admin_request_valid(header, request_bytes) ||
        verify_request_mac(request_buffer, request_bytes) != 0) {
        return -1;
    }
    query = (const struct tee_v4_admin_chunk_query_payload *)
        ((const uint8_t *)request_buffer + sizeof(*header));
    if (header->payload_len != sizeof(*query) &&
        header->command_type != TEE_V4_ADMIN_CMD_SYNC_METADATA) {
        return -1;
    }
    switch (header->command_type) {
    case TEE_V4_ADMIN_CMD_READ_SUMMARY:
        return handle_summary(admin, header, query);
    case TEE_V4_ADMIN_CMD_READ_LOCATIONS:
        return handle_locations(admin, header, query);
    case TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS:
        return handle_hmac_groups(admin, header, query);
    case TEE_V4_ADMIN_CMD_ONE_BIT_PROOF:
        return handle_one_bit_proof(admin, header, query);
    case TEE_V4_ADMIN_CMD_SYNC_METADATA:
        return prepare_status(admin, header, TEE_V4_ADMIN_STATUS_OK);
    default:
        return -1;
    }
}

int tee_v4_admin_fetch(struct tee_v4_admin *admin, void *response_buffer,
                       size_t response_capacity, size_t *written)
{
    if (!admin) {
        return -1;
    }
    return tee_v4_admin_response_materialize_page(
        &admin->pending, 0, response_buffer, response_capacity, written);
}

int tee_v4_admin_continue(struct tee_v4_admin *admin, uint64_t request_id,
                          uint32_t page_index, void *response_buffer,
                          size_t response_capacity, size_t *written)
{
    if (!admin || !admin->pending.valid ||
        admin->pending.request_id != request_id) {
        if (written) {
            *written = 0;
        }
        return -1;
    }
    return tee_v4_admin_response_materialize_page(
        &admin->pending, page_index, response_buffer, response_capacity,
        written);
}
