#ifndef TEE_V4_ADMIN_FORMAT_H
#define TEE_V4_ADMIN_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tee-v2-format.h"

#define TEE_V4_ADMIN_MAGIC 0x34544c54U
#define TEE_V4_ADMIN_VERSION 4U
#define TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES 4096U

#define TEE_V4_ADMIN_SUBMIT_OPCODE   0xe4U
#define TEE_V4_ADMIN_FETCH_OPCODE    0xe5U
#define TEE_V4_ADMIN_CONTINUE_OPCODE 0xe6U

enum tee_v4_admin_command_type {
    TEE_V4_ADMIN_CMD_READ_SUMMARY = 1,
    TEE_V4_ADMIN_CMD_READ_LOCATIONS = 2,
    TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS = 3,
    TEE_V4_ADMIN_CMD_ONE_BIT_PROOF = 4,
    TEE_V4_ADMIN_CMD_SYNC_METADATA = 5
};

enum tee_v4_admin_status {
    TEE_V4_ADMIN_STATUS_OK = 0,
    TEE_V4_ADMIN_STATUS_NOT_FOUND = 1,
    TEE_V4_ADMIN_STATUS_BAD_REQUEST = 2,
    TEE_V4_ADMIN_STATUS_NO_PENDING_RESPONSE = 3,
    TEE_V4_ADMIN_STATUS_INTERNAL_ERROR = 4
};

#pragma pack(push, 1)
struct tee_v4_admin_request_header {
    uint32_t magic;
    uint16_t version;
    uint16_t command_type;
    uint64_t request_id;
    uint32_t payload_len;
    uint32_t flags;
    uint8_t request_mac[TEE_V2_HMAC_SIZE];
};

struct tee_v4_admin_response_header {
    uint32_t magic;
    uint16_t version;
    uint16_t command_type;
    uint64_t request_id;
    int32_t status;
    uint32_t total_items;
    uint32_t start_item;
    uint32_t returned_items;
    uint32_t item_size;
    uint32_t total_pages;
    uint32_t page_index;
};

struct tee_v4_admin_chunk_query_payload {
    uint8_t file_id;
    uint8_t reserved[3];
    uint32_t chunk_id;
    uint32_t page_size;
};

struct tee_v4_admin_continue_payload {
    uint64_t request_id;
    uint32_t page_index;
};
#pragma pack(pop)

#define TEE_V4_ADMIN_REQUEST_HEADER_SIZE \
    ((uint32_t)sizeof(struct tee_v4_admin_request_header))
#define TEE_V4_ADMIN_REQUEST_MAC_OFFSET \
    ((uint32_t)offsetof(struct tee_v4_admin_request_header, request_mac))
#define TEE_V4_ADMIN_RESPONSE_HEADER_SIZE \
    ((uint32_t)sizeof(struct tee_v4_admin_response_header))
#define TEE_V4_ADMIN_CHUNK_QUERY_PAYLOAD_SIZE \
    ((uint32_t)sizeof(struct tee_v4_admin_chunk_query_payload))
#define TEE_V4_ADMIN_CONTINUE_PAYLOAD_SIZE \
    ((uint32_t)sizeof(struct tee_v4_admin_continue_payload))

bool tee_v4_admin_request_valid(
    const struct tee_v4_admin_request_header *header, size_t buffer_bytes);
bool tee_v4_admin_mac_span(const struct tee_v4_admin_request_header *header,
                           size_t buffer_bytes, size_t *span_out);
uint32_t tee_v4_admin_total_pages(uint32_t total_items,
                                  uint32_t items_per_page);
uint32_t tee_v4_admin_start_item(uint32_t page_index,
                                 uint32_t items_per_page);
uint32_t tee_v4_admin_returned_items(uint32_t total_items,
                                     uint32_t page_index,
                                     uint32_t items_per_page);
void tee_v4_admin_response_header_init(
    struct tee_v4_admin_response_header *header, uint16_t command_type,
    uint64_t request_id, int32_t status, uint32_t total_items,
    uint32_t item_size, uint32_t items_per_page, uint32_t page_index);

#endif
