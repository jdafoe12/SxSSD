#define TEE_V2_POLICY 1
#define TEE_V3_POLICY 1
#define init_policy tee_v3_base_init_policy
#include "tee-ftl-v1-policy.c"
#undef init_policy
#include "tee-ftl-v3-policy.h"

static struct tee_v3_storage g_v3_storage;
static struct tee_v3_memory_backend g_v3_backend;
static struct tee_v3_policy_context g_v3_policy;

static int tee_v3_write_hidden_image(void *opaque, const uint8_t *data,
                                     size_t size)
{
    struct tee_v3_memory_backend *backend = opaque;
    if (!backend || size > backend->capacity) return -1;
    memcpy(backend->bytes, data, size);
    backend->size = size;
    return 0;
}

int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    if (tee_v3_base_init_policy(ssd, api) != 0) return -1;
    g_v3_backend.capacity = (size_t)(g_v1_layout.hidden_lba_count *
                                     g_v1_layout.lba_size);
    g_v3_backend.bytes = calloc(g_v3_backend.capacity, 1);
    if (!g_v3_backend.bytes ||
        tee_v3_storage_init(&g_v3_storage, &g_v1_layout,
                            tee_v3_write_hidden_image, &g_v3_backend) != 0)
        return -1;
    tee_v3_policy_context_init(&g_v3_policy, &g_v2_write, &g_v3_storage);
    tee_v2_write_set_promotion_hook(&g_v2_write,
                                    tee_v3_policy_persist_promotion,
                                    &g_v3_policy);
    return 0;
}

enum tee_v3_query_result tee_v3_policy_query_summary(
    uint8_t file_id, uint32_t chunk_id, uint32_t page_size,
    struct tee_v3_read_summary *out)
{
    return tee_v3_policy_read_summary(&g_v3_policy, file_id, chunk_id,
                                      page_size, out);
}

enum tee_v3_query_result tee_v3_policy_query_locations(
    uint8_t file_id, uint32_t chunk_id, uint32_t offset,
    uint64_t *items, size_t capacity, size_t *written)
{
    return tee_v3_policy_read_locations(&g_v3_policy, file_id, chunk_id,
                                        offset, items, capacity, written);
}

enum tee_v3_query_result tee_v3_policy_query_hmac_groups(
    uint8_t file_id, uint32_t chunk_id, uint32_t offset,
    struct tee_v3_hmac_group_item *items, size_t capacity, size_t *written)
{
    return tee_v3_policy_read_hmac_groups(&g_v3_policy, file_id, chunk_id,
                                          offset, items, capacity, written);
}

enum tee_v3_query_result tee_v3_policy_query_one_bit_proof(
    uint8_t file_id, uint32_t chunk_id, uint32_t offset,
    uint32_t *items, size_t capacity, size_t *written,
    struct tee_v3_one_bit_proof *proof)
{
    return tee_v3_policy_one_bit_proof(&g_v3_policy, file_id, chunk_id,
                                       offset, items, capacity, written,
                                       proof);
}
