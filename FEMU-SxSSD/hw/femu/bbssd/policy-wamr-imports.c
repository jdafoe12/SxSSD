#include "qemu/osdep.h"
#include "policy-wamr-imports.h"
#include "policy-api.h"
#include "policy-runtime.h"

#define WASM_ENABLE_INSTRUCTION_METERING 1
#include <wasm_export.h>

QEMU_BUILD_BUG_ON(sizeof(struct sxs_execution_info) != 32);

static struct pe_policy_execution *execution_from_env(wasm_exec_env_t env)
{
    struct pe_policy_execution *execution;

    if (!env) {
        return NULL;
    }
    execution = wasm_runtime_get_user_data(env);
    if (!execution || !execution->engine || !execution->owner ||
        (execution->authoritative_phase != SXS_PHASE_INIT &&
         execution->authoritative_phase != SXS_PHASE_CONDITION &&
         execution->authoritative_phase != SXS_PHASE_ACTION)) {
        return NULL;
    }
    return execution;
}

static int32_t import_execution_get(wasm_exec_env_t env, void *output,
                                    uint32_t output_size)
{
    struct pe_policy_execution *execution = execution_from_env(env);
    struct sxs_execution_info info;

    if (!execution || !output || output_size != sizeof(info)) {
        return -SXS_WASM_EINVAL;
    }
    info = (struct sxs_execution_info){
        .abi_version = SXS_WASM_ABI_VERSION,
        .phase = execution->authoritative_phase,
        .event_kind = execution->authoritative_event_kind,
        .pair_id = execution->pair_id,
        .policy_id = execution->owner->policy_id,
        .policy_version = execution->owner->policy_version,
        .generation = execution->owner->generation,
        .flags = execution->flags,
    };
    memcpy(output, &info, sizeof(info));
    return 0;
}

static int32_t import_nvme_event_get(wasm_exec_env_t env, void *output,
                                     uint32_t output_size)
{
    struct pe_policy_execution *execution = execution_from_env(env);

    if (!execution || !output ||
        output_size != sizeof(execution->event_snapshot.nvme) ||
        (execution->authoritative_event_kind != SXS_EVENT_NVME_IO &&
         execution->authoritative_event_kind != SXS_EVENT_NVME_ADMIN)) {
        return -SXS_WASM_EPERM;
    }
    memcpy(output, &execution->event_snapshot.nvme, output_size);
    return 0;
}

static int32_t import_backend_event_get(wasm_exec_env_t env, void *output,
                                        uint32_t output_size)
{
    struct pe_policy_execution *execution = execution_from_env(env);

    if (!execution || !output ||
        output_size != sizeof(execution->event_snapshot.backend) ||
        execution->authoritative_event_kind != SXS_EVENT_BACKEND) {
        return -SXS_WASM_EPERM;
    }
    memcpy(output, &execution->event_snapshot.backend, output_size);
    return 0;
}

static int32_t import_pswd_event_get(wasm_exec_env_t env, void *output,
                                     uint32_t output_size)
{
    struct pe_policy_execution *execution = execution_from_env(env);

    if (!execution || !output ||
        output_size != sizeof(execution->event_snapshot.pswd) ||
        execution->authoritative_event_kind != SXS_EVENT_PSWD_TRANSITION) {
        return -SXS_WASM_EPERM;
    }
    memcpy(output, &execution->event_snapshot.pswd, output_size);
    return 0;
}

static int32_t import_subscribe(wasm_exec_env_t env, uint32_t kind,
                                uint32_t selector, uint32_t pair,
                                uint32_t flags)
{
    return pe_api_subscribe(execution_from_env(env), kind, selector, pair,
                            flags);
}

static int32_t import_state_create(wasm_exec_env_t env, uint32_t object_id,
                                   uint32_t element_size,
                                   uint64_t element_count, uint32_t flags,
                                   uint64_t initial)
{
    return pe_api_state_create(execution_from_env(env), object_id, element_size,
                               element_count, flags, initial);
}

static int32_t import_state_read(wasm_exec_env_t env, uint32_t object_id,
                                 uint64_t index, uint32_t element_offset,
                                 void *output, uint32_t length)
{
    return pe_api_state_read(execution_from_env(env), object_id, index,
                             element_offset, output, length);
}

static int32_t import_state_write(wasm_exec_env_t env, uint32_t object_id,
                                  uint64_t index, uint32_t element_offset,
                                  const void *input, uint32_t length)
{
    return pe_api_state_write(execution_from_env(env), object_id, index,
                              element_offset, input, length);
}

static int32_t import_state_fill_u64(wasm_exec_env_t env, uint32_t object_id,
                                     uint64_t value)
{
    return pe_api_state_fill_u64(execution_from_env(env), object_id, value);
}

static int32_t import_backend_status_get(wasm_exec_env_t env, uint64_t index,
                                         int32_t *output, uint32_t output_size)
{
    int32_t native_output;
    int32_t result;

    if (!output || output_size != sizeof(*output)) {
        return -SXS_WASM_EINVAL;
    }
    result = pe_api_backend_status_get(execution_from_env(env), index,
                                       &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_stats_add(wasm_exec_env_t env, uint32_t counter,
                                uint64_t value)
{
    return pe_api_stats_add(execution_from_env(env), counter, value);
}

static int32_t import_stats_gc_active_set(wasm_exec_env_t env, uint32_t active)
{
    return pe_api_stats_gc_active_set(execution_from_env(env), active);
}

#define DEFINE_OUTPUT_IMPORT(name, type)                                       \
    static int32_t import_##name(wasm_exec_env_t env, void *output,            \
                                 uint32_t output_size)                         \
    {                                                                          \
        type native_output;                                                    \
        int32_t result;                                                        \
        if (!output || output_size != sizeof(native_output)) {                 \
            return -SXS_WASM_EINVAL;                                           \
        }                                                                      \
        result = pe_api_##name(execution_from_env(env), &native_output);       \
        if (result == 0) {                                                     \
            memcpy(output, &native_output, sizeof(native_output));             \
        }                                                                      \
        return result;                                                         \
    }

DEFINE_OUTPUT_IMPORT(geometry_get, struct sxs_geometry)
DEFINE_OUTPUT_IMPORT(layout_get, struct sxs_layout)
DEFINE_OUTPUT_IMPORT(stats_get, struct sxs_stats)
#undef DEFINE_OUTPUT_IMPORT

#define DEFINE_KEYED_OUTPUT_IMPORT(name, key_type, type)                       \
    static int32_t import_##name(wasm_exec_env_t env, key_type key,            \
                                 void *output, uint32_t output_size)           \
    {                                                                          \
        type native_output;                                                    \
        int32_t result;                                                        \
        if (!output || output_size != sizeof(native_output)) {                 \
            return -SXS_WASM_EINVAL;                                           \
        }                                                                      \
        result = pe_api_##name(execution_from_env(env), key, &native_output);  \
        if (result == 0) {                                                     \
            memcpy(output, &native_output, sizeof(native_output));             \
        }                                                                      \
        return result;                                                         \
    }

DEFINE_KEYED_OUTPUT_IMPORT(eswd_get, uint32_t, struct sxs_eswd)
DEFINE_KEYED_OUTPUT_IMPORT(eswd_from_ppa, uint64_t, struct sxs_eswd_location)
DEFINE_KEYED_OUTPUT_IMPORT(dsm_range_get, uint32_t, struct sxs_dsm_range)
DEFINE_KEYED_OUTPUT_IMPORT(ppa_to_eswd, uint64_t, struct sxs_eswd_location)
#undef DEFINE_KEYED_OUTPUT_IMPORT

#define DEFINE_UNARY_IMPORT(result_type, name, argument_type)                  \
    static result_type import_##name(wasm_exec_env_t env, argument_type value) \
    {                                                                          \
        return pe_api_##name(execution_from_env(env), value);                  \
    }

DEFINE_UNARY_IMPORT(int32_t, ppa_validate, uint64_t)
DEFINE_UNARY_IMPORT(int64_t, ppa_to_page_index, uint64_t)
DEFINE_UNARY_IMPORT(int32_t, page_status_get, uint64_t)
DEFINE_UNARY_IMPORT(int64_t, eswd_wp_get, uint32_t)
DEFINE_UNARY_IMPORT(int64_t, eswd_effective_wp_get, uint32_t)
DEFINE_UNARY_IMPORT(int32_t, page_invalidate, uint64_t)
DEFINE_UNARY_IMPORT(int32_t, eswd_reset, uint32_t)
DEFINE_UNARY_IMPORT(int32_t, eswd_advance_wp, uint32_t)
DEFINE_UNARY_IMPORT(uint64_t, eswd_erase, uint32_t)
#undef DEFINE_UNARY_IMPORT

static int32_t import_request_read(wasm_exec_env_t env, uint64_t offset,
                                   void *output, uint32_t length)
{
    return pe_api_request_read(execution_from_env(env), offset, output, length);
}

static int32_t import_request_write(wasm_exec_env_t env, uint64_t offset,
                                    const void *input, uint32_t length)
{
    return pe_api_request_write(execution_from_env(env), offset, input, length);
}

static int32_t import_command_read(wasm_exec_env_t env, uint32_t offset,
                                   void *output, uint32_t length)
{
    return pe_api_command_read(execution_from_env(env), offset, output, length);
}

static int32_t import_command_write(wasm_exec_env_t env, uint32_t offset,
                                    const void *input, uint32_t length)
{
    return pe_api_command_write(execution_from_env(env), offset, input, length);
}

static int32_t import_completion_status_set(wasm_exec_env_t env,
                                            uint32_t status)
{
    return pe_api_completion_status_set(execution_from_env(env), status);
}

static int32_t import_completion_result_set(wasm_exec_env_t env,
                                            uint64_t result)
{
    return pe_api_completion_result_set(execution_from_env(env), result);
}

static uint64_t import_time_now_ns(wasm_exec_env_t env)
{
    return pe_api_time_now_ns(execution_from_env(env));
}

static int32_t import_eswd_config_stage(wasm_exec_env_t env, const void *input,
                                        uint32_t size)
{
    struct sxs_eswd_config native_input;

    if (!input || size != sizeof(native_input)) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    return pe_api_eswd_config_stage(execution_from_env(env), &native_input);
}

static int32_t import_namespace_config_stage(wasm_exec_env_t env,
                                             const void *input, uint32_t size)
{
    struct sxs_namespace_config native_input;

    if (!input || size != sizeof(native_input)) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    return pe_api_namespace_config_stage(execution_from_env(env),
                                         &native_input);
}

static int32_t import_ftl_finalize_stage(wasm_exec_env_t env)
{
    return pe_api_ftl_finalize_stage(execution_from_env(env));
}

static int32_t import_oob_register_stage(wasm_exec_env_t env,
                                         uint32_t object_id, uint32_t bytes)
{
    return pe_api_oob_register_stage(execution_from_env(env), object_id, bytes);
}

static int32_t import_eswd_range_check(wasm_exec_env_t env, uint32_t operation,
                                       uint32_t eswd, uint64_t lba,
                                       uint32_t count)
{
    return pe_api_eswd_range_check(execution_from_env(env), operation, eswd,
                                   lba, count);
}

static int64_t import_eswd_to_ppa(wasm_exec_env_t env, uint32_t eswd,
                                  uint32_t page)
{
    return pe_api_eswd_to_ppa(execution_from_env(env), eswd, page);
}

static int32_t
import_page_read(wasm_exec_env_t env, const struct sxs_page_read_request *input,
                 uint32_t input_size, void *data, uint32_t data_size, void *oob,
                 uint32_t oob_size, struct sxs_page_result *output,
                 uint32_t output_size)
{
    struct sxs_page_read_request native_input;
    struct sxs_page_result native_output;
    int32_t result;

    if (!input || input_size != sizeof(native_input) || !output ||
        output_size != sizeof(native_output) || (!data && data_size) ||
        (!oob && oob_size) || data_size > SXS_WASM_MAX_PAGE_BYTES) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    result = pe_api_page_read(execution_from_env(env), &native_input, data,
                              data_size, oob, oob_size, &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_page_append(
    wasm_exec_env_t env, const struct sxs_page_append_request *input,
    uint32_t input_size, const void *data, uint32_t data_size, const void *oob,
    uint32_t oob_size, struct sxs_page_result *output, uint32_t output_size)
{
    struct sxs_page_append_request native_input;
    struct sxs_page_result native_output;
    int32_t result;

    if (!input || input_size != sizeof(native_input) || !output ||
        output_size != sizeof(native_output) || (!data && data_size) ||
        (!oob && oob_size) || data_size > SXS_WASM_MAX_PAGE_BYTES) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    result = pe_api_page_append(execution_from_env(env), &native_input, data,
                                data_size, oob, oob_size, &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_page_migrate(wasm_exec_env_t env, uint64_t source,
                                   uint32_t destination,
                                   struct sxs_page_result *output,
                                   uint32_t output_size)
{
    struct sxs_page_result native_output;
    int32_t result;

    if (!output || output_size != sizeof(native_output)) {
        return -SXS_WASM_EINVAL;
    }
    result = pe_api_page_migrate(execution_from_env(env), source, destination,
                                 &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_eswd_stage_write(
    wasm_exec_env_t env, const struct sxs_eswd_stage_write_request *input,
    uint32_t input_size, struct sxs_page_result *output, uint32_t output_size)
{
    struct sxs_eswd_stage_write_request native_input;
    struct sxs_page_result native_output;
    int32_t result;

    if (!input || input_size != sizeof(native_input) || !output ||
        output_size != sizeof(native_output)) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    result = pe_api_eswd_stage_write(execution_from_env(env), &native_input,
                                     &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t
import_eswd_page_read(wasm_exec_env_t env,
                      const struct sxs_eswd_page_read_request *input,
                      uint32_t input_size, void *data, uint32_t data_size,
                      struct sxs_page_result *output, uint32_t output_size)
{
    struct sxs_eswd_page_read_request native_input;
    struct sxs_page_result native_output;
    int32_t result;

    if (!input || input_size != sizeof(native_input) || !output ||
        output_size != sizeof(native_output) || (!data && data_size) ||
        data_size > SXS_WASM_MAX_PAGE_BYTES) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    result = pe_api_eswd_page_read(execution_from_env(env), &native_input, data,
                                   data_size, &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_namespace_blob_stage(wasm_exec_env_t env, uint32_t kind,
                                           uint32_t destination,
                                           const void *source, uint32_t length)
{
    return pe_api_namespace_blob_stage(execution_from_env(env), kind,
                                       destination, source, length);
}

static int32_t import_crypto_random(wasm_exec_env_t env, void *output,
                                    uint32_t length)
{
    return pe_api_crypto_random(execution_from_env(env), output, length);
}

static int32_t
import_crypto_ed25519_verify(wasm_exec_env_t env, const void *public_key,
                             uint32_t public_length, const void *message,
                             uint32_t message_length, const void *signature,
                             uint32_t signature_length)
{
    return pe_api_crypto_ed25519_verify(execution_from_env(env), public_key,
                                        public_length, message, message_length,
                                        signature, signature_length);
}

static int32_t import_crypto_x25519_public(wasm_exec_env_t env,
                                           const void *private_key,
                                           uint32_t private_length,
                                           void *public_key,
                                           uint32_t public_length)
{
    return pe_api_crypto_x25519_public(execution_from_env(env), private_key,
                                       private_length, public_key,
                                       public_length);
}

static int32_t import_crypto_x25519_shared(wasm_exec_env_t env,
                                           const void *private_key,
                                           uint32_t private_length,
                                           const void *peer_key,
                                           uint32_t peer_length, void *output,
                                           uint32_t output_length)
{
    return pe_api_crypto_x25519_shared(execution_from_env(env), private_key,
                                       private_length, peer_key, peer_length,
                                       output, output_length);
}

static int32_t import_crypto_hmac_sha256(wasm_exec_env_t env, const void *key,
                                         uint32_t key_length,
                                         const void *message,
                                         uint32_t message_length, void *output,
                                         uint32_t output_length)
{
    return pe_api_crypto_hmac_sha256(execution_from_env(env), key, key_length,
                                     message, message_length, output,
                                     output_length);
}

static int32_t import_crypto_sha256(wasm_exec_env_t env, const void *message,
                                    uint32_t message_length, void *output,
                                    uint32_t output_length)
{
    return pe_api_crypto_sha256(execution_from_env(env), message,
                                message_length, output, output_length);
}

static int32_t import_crypto_hkdf_sha256(
    wasm_exec_env_t env, const void *key, uint32_t key_length,
    const void *info, uint32_t info_length, void *output,
    uint32_t output_length)
{
    return pe_api_crypto_hkdf_sha256(
        execution_from_env(env), key, key_length, info, info_length,
        output, output_length);
}

static int32_t import_crypto_aes256_gcm_decrypt(
    wasm_exec_env_t env,
    const void *key, uint32_t key_length,
    const void *nonce, uint32_t nonce_length,
    const void *aad, uint32_t aad_length,
    const void *ciphertext, uint32_t ciphertext_length,
    const void *tag, uint32_t tag_length,
    void *plaintext, uint32_t plaintext_length)
{
    return pe_api_crypto_aes256_gcm_decrypt(
        execution_from_env(env), key, key_length, nonce, nonce_length,
        aad, aad_length, ciphertext, ciphertext_length, tag, tag_length,
        plaintext, plaintext_length);
}

static int32_t
import_sign_key_bootstrap(wasm_exec_env_t env, const uint8_t *owner_nonce,
                          uint32_t nonce_length, const uint8_t *owner_public,
                          uint32_t owner_length, const uint8_t *policy_public,
                          uint32_t policy_length, uint8_t *signature,
                          uint32_t signature_length)
{
    if (!owner_nonce || nonce_length != 32 || !owner_public ||
        owner_length != 32 || !policy_public || policy_length != 32 ||
        !signature || signature_length != 64) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_sign_key_bootstrap(execution_from_env(env), owner_nonce,
                                     owner_public, policy_public, signature);
}

static int32_t import_privileged_storage_geometry_get(
    wasm_exec_env_t env, void *geometry, uint32_t geometry_size)
{
    if (!geometry ||
        geometry_size != sizeof(struct sxs_policy_storage_geometry)) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_storage_geometry_get(
        execution_from_env(env), geometry);
}

static int32_t import_privileged_block_is_claimed(
    wasm_exec_env_t env, const void *block, uint32_t block_size)
{
    if (!block || block_size != sizeof(struct sxs_physical_block)) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_block_is_claimed(
        execution_from_env(env), block);
}

static int32_t import_privileged_block_claim(
    wasm_exec_env_t env, const void *block, uint32_t block_size)
{
    if (!block || block_size != sizeof(struct sxs_physical_block)) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_block_claim(execution_from_env(env), block);
}

static int32_t import_privileged_block_release(
    wasm_exec_env_t env, const void *block, uint32_t block_size)
{
    if (!block || block_size != sizeof(struct sxs_physical_block)) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_block_release(execution_from_env(env), block);
}

static bool valid_block_array(const void *blocks, uint32_t blocks_size,
                              uint32_t block_count)
{
    return blocks && block_count != 0 &&
           block_count <= SXS_PRIVILEGED_MAX_POLICY_BLOCKS &&
           blocks_size == block_count * sizeof(struct sxs_physical_block);
}

static int32_t import_privileged_storage_read(
    wasm_exec_env_t env, const void *blocks, uint32_t blocks_size,
    uint32_t block_count, void *data, uint32_t data_length)
{
    if (!valid_block_array(blocks, blocks_size, block_count) ||
        !data || data_length == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_storage_read(
        execution_from_env(env), blocks, block_count, data, data_length);
}

static int32_t import_privileged_storage_write(
    wasm_exec_env_t env, const void *blocks, uint32_t blocks_size,
    uint32_t block_count, const void *data, uint32_t data_length)
{
    if (!valid_block_array(blocks, blocks_size, block_count) ||
        !data || data_length == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_storage_write(
        execution_from_env(env), blocks, block_count, data, data_length);
}

static int32_t import_privileged_storage_erase(
    wasm_exec_env_t env, const void *blocks, uint32_t blocks_size,
    uint32_t block_count)
{
    if (!valid_block_array(blocks, blocks_size, block_count)) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_storage_erase(
        execution_from_env(env), blocks, block_count);
}

static int32_t import_privileged_policy_validate_image(
    wasm_exec_env_t env, const void *image, uint32_t image_size)
{
    return pe_api_privileged_policy_validate_image(
        execution_from_env(env), image, image_size);
}

static int32_t import_privileged_policy_activate_stored(
    wasm_exec_env_t env, uint32_t policy_id, uint32_t policy_version,
    uint32_t generation, uint32_t policy_size,
    const void *blocks, uint32_t blocks_size, uint32_t block_count)
{
    if (!valid_block_array(blocks, blocks_size, block_count)) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_policy_activate_stored(
        execution_from_env(env), policy_id, policy_version, generation,
        policy_size, blocks, block_count);
}

static int32_t import_privileged_policy_deactivate(
    wasm_exec_env_t env, uint32_t policy_id)
{
    return pe_api_privileged_policy_deactivate(
        execution_from_env(env), policy_id);
}

static int32_t import_privileged_policy_state_can_remove(
    wasm_exec_env_t env, uint32_t policy_id, uint32_t generation)
{
    return pe_api_privileged_policy_state_can_remove(
        execution_from_env(env), policy_id, generation);
}

static int32_t import_privileged_policy_state_remove(
    wasm_exec_env_t env, uint32_t policy_id, uint32_t generation)
{
    return pe_api_privileged_policy_state_remove(
        execution_from_env(env), policy_id, generation);
}

static int32_t import_privileged_device_attestation_sign(
    wasm_exec_env_t env, const void *message, uint32_t message_length,
    void *signature, uint32_t signature_length)
{
    return pe_api_privileged_device_attestation_sign(
        execution_from_env(env), message, message_length,
        signature, signature_length);
}

static NativeSymbol native_symbols[] = {
#define SXS_COMMON_IMPORT(api_name, linker_symbol, native_wrapper,             \
                          wamr_signature, meta_access)                          \
    {"sxs_" #api_name, (void *)native_wrapper, wamr_signature, NULL},
#define SXS_PRIVILEGED_IMPORT(api_name, linker_symbol, native_wrapper,          \
                              wamr_signature)
#include "policy/policy-imports.def"
#undef SXS_PRIVILEGED_IMPORT
#undef SXS_COMMON_IMPORT
};

static NativeSymbol privileged_native_symbols[] = {
#define SXS_COMMON_IMPORT(api_name, linker_symbol, native_wrapper,             \
                          wamr_signature, meta_access)
#define SXS_PRIVILEGED_IMPORT(api_name, linker_symbol, native_wrapper,          \
                              wamr_signature)                                   \
    {"sxs_privileged_" #api_name, (void *)native_wrapper, wamr_signature, NULL},
#include "policy/policy-imports.def"
#undef SXS_PRIVILEGED_IMPORT
#undef SXS_COMMON_IMPORT
};

int pe_wamr_imports_register(void)
{
    if (!wasm_runtime_register_natives("sxs_v1", native_symbols,
                                       G_N_ELEMENTS(native_symbols)) ||
        !wasm_runtime_register_natives(
            "sxs_privileged_v1", privileged_native_symbols,
            G_N_ELEMENTS(privileged_native_symbols))) {
        return -1;
    }
    return 0;
}
