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

static bool fixed_buffer_is_valid(wasm_exec_env_t env, const void *buffer,
                                  uint64_t size)
{
    wasm_module_inst_t instance;

    if (!env || !buffer) {
        return false;
    }
    instance = wasm_runtime_get_module_inst(env);
    return instance && wasm_runtime_validate_native_addr(
                           instance, (void *)(uintptr_t)buffer, size);
}

static int32_t import_execution_get(wasm_exec_env_t env,
                                    struct sxs_execution_info *output)
{
    struct pe_policy_execution *execution = execution_from_env(env);
    struct sxs_execution_info info;

    if (!execution || !fixed_buffer_is_valid(env, output, sizeof(*output))) {
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

static int32_t import_nvme_event_get(wasm_exec_env_t env,
                                     struct sxs_nvme_event *output)
{
    struct pe_policy_execution *execution = execution_from_env(env);

    if (!execution ||
        (execution->authoritative_event_kind != SXS_EVENT_NVME_IO &&
         execution->authoritative_event_kind != SXS_EVENT_NVME_ADMIN)) {
        return -SXS_WASM_EPERM;
    }
    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(output, &execution->event_snapshot.nvme, sizeof(*output));
    return 0;
}

static int32_t import_backend_event_get(wasm_exec_env_t env,
                                        struct sxs_backend_event *output)
{
    struct pe_policy_execution *execution = execution_from_env(env);

    if (!execution ||
        execution->authoritative_event_kind != SXS_EVENT_BACKEND) {
        return -SXS_WASM_EPERM;
    }
    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(output, &execution->event_snapshot.backend, sizeof(*output));
    return 0;
}

static int32_t import_pswd_event_get(wasm_exec_env_t env,
                                     struct sxs_pswd_event *output)
{
    struct pe_policy_execution *execution = execution_from_env(env);

    if (!execution ||
        execution->authoritative_event_kind != SXS_EVENT_PSWD_TRANSITION) {
        return -SXS_WASM_EPERM;
    }
    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(output, &execution->event_snapshot.pswd, sizeof(*output));
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
                                         int32_t *output)
{
    int32_t native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = pe_api_backend_status_get(execution_from_env(env), index,
                                       &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_geometry_get(wasm_exec_env_t env,
                                   struct sxs_geometry *output)
{
    struct sxs_geometry native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = pe_api_geometry_get(execution_from_env(env), &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_layout_get(wasm_exec_env_t env, struct sxs_layout *output)
{
    struct sxs_layout native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = pe_api_layout_get(execution_from_env(env), &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_eswd_get(wasm_exec_env_t env, uint32_t eswd_id,
                               struct sxs_eswd *output)
{
    struct sxs_eswd native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = pe_api_eswd_get(execution_from_env(env), eswd_id, &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_eswd_from_ppa(wasm_exec_env_t env, uint64_t ppa,
                                    struct sxs_eswd_location *output)
{
    struct sxs_eswd_location native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = pe_api_eswd_from_ppa(execution_from_env(env), ppa,
                                  &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_dsm_range_get(wasm_exec_env_t env, uint32_t range_index,
                                    struct sxs_dsm_range *output)
{
    struct sxs_dsm_range native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = pe_api_dsm_range_get(execution_from_env(env), range_index,
                                  &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_ppa_to_eswd(wasm_exec_env_t env, uint64_t ppa,
                                  struct sxs_eswd_location *output)
{
    struct sxs_eswd_location native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = pe_api_ppa_to_eswd(execution_from_env(env), ppa, &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_ppa_validate(wasm_exec_env_t env, uint64_t ppa)
{
    return pe_api_ppa_validate(execution_from_env(env), ppa);
}

static int64_t import_ppa_to_page_index(wasm_exec_env_t env, uint64_t ppa)
{
    return pe_api_ppa_to_page_index(execution_from_env(env), ppa);
}

static int32_t import_page_status_get(wasm_exec_env_t env, uint64_t ppa)
{
    return pe_api_page_status_get(execution_from_env(env), ppa);
}

static int64_t import_eswd_wp_get(wasm_exec_env_t env, uint32_t eswd_id)
{
    return pe_api_eswd_wp_get(execution_from_env(env), eswd_id);
}

static int64_t import_eswd_effective_wp_get(wasm_exec_env_t env,
                                            uint32_t eswd_id)
{
    return pe_api_eswd_effective_wp_get(execution_from_env(env), eswd_id);
}

static int32_t import_page_invalidate(wasm_exec_env_t env, uint64_t ppa)
{
    return pe_api_page_invalidate(execution_from_env(env), ppa);
}

static int32_t import_eswd_reset(wasm_exec_env_t env, uint32_t eswd_id)
{
    return pe_api_eswd_reset(execution_from_env(env), eswd_id);
}

static int32_t import_eswd_advance_wp(wasm_exec_env_t env, uint32_t eswd_id)
{
    return pe_api_eswd_advance_wp(execution_from_env(env), eswd_id);
}

static uint64_t import_eswd_erase(wasm_exec_env_t env, uint32_t eswd_id)
{
    return pe_api_eswd_erase(execution_from_env(env), eswd_id);
}

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

static int32_t import_eswd_config_stage(
    wasm_exec_env_t env, const struct sxs_eswd_config *input)
{
    struct sxs_eswd_config native_input;

    if (!fixed_buffer_is_valid(env, input, sizeof(*input))) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    return pe_api_eswd_config_stage(execution_from_env(env), &native_input);
}

static int32_t import_namespace_config_stage(
    wasm_exec_env_t env, const struct sxs_namespace_config *input)
{
    struct sxs_namespace_config native_input;

    if (!fixed_buffer_is_valid(env, input, sizeof(*input))) {
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
                 void *data, uint32_t data_size, void *oob, uint32_t oob_size,
                 struct sxs_page_result *output)
{
    struct sxs_page_read_request native_input;
    struct sxs_page_result native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, input, sizeof(*input)) ||
        !fixed_buffer_is_valid(env, output, sizeof(*output)) ||
        (!data && data_size) ||
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
    const void *data, uint32_t data_size, const void *oob,
    uint32_t oob_size, struct sxs_page_result *output)
{
    struct sxs_page_append_request native_input;
    struct sxs_page_result native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, input, sizeof(*input)) ||
        !fixed_buffer_is_valid(env, output, sizeof(*output)) ||
        (!data && data_size) ||
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
                                   struct sxs_page_result *output)
{
    struct sxs_page_result native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
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
    struct sxs_page_result *output)
{
    struct sxs_eswd_stage_write_request native_input;
    struct sxs_page_result native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, input, sizeof(*input)) ||
        !fixed_buffer_is_valid(env, output, sizeof(*output))) {
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
                      void *data, uint32_t data_size,
                      struct sxs_page_result *output)
{
    struct sxs_eswd_page_read_request native_input;
    struct sxs_page_result native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, input, sizeof(*input)) ||
        !fixed_buffer_is_valid(env, output, sizeof(*output)) ||
        (!data && data_size) ||
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
                          const uint8_t *owner_public,
                          const uint8_t *policy_public, uint8_t *signature)
{
    if (!fixed_buffer_is_valid(env, owner_nonce, 32) ||
        !fixed_buffer_is_valid(env, owner_public, 32) ||
        !fixed_buffer_is_valid(env, policy_public, 32) ||
        !fixed_buffer_is_valid(env, signature, 64)) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_sign_key_bootstrap(execution_from_env(env), owner_nonce,
                                     owner_public, policy_public, signature);
}

static int32_t import_privileged_storage_geometry_get(
    wasm_exec_env_t env, struct sxs_policy_storage_geometry *geometry)
{
    if (!fixed_buffer_is_valid(env, geometry, sizeof(*geometry))) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_storage_geometry_get(
        execution_from_env(env), geometry);
}

static int32_t import_privileged_block_is_claimed(
    wasm_exec_env_t env, const struct sxs_physical_block *block)
{
    if (!fixed_buffer_is_valid(env, block, sizeof(*block))) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_block_is_claimed(
        execution_from_env(env), block);
}

static int32_t import_privileged_block_claim(
    wasm_exec_env_t env, const struct sxs_physical_block *block)
{
    if (!fixed_buffer_is_valid(env, block, sizeof(*block))) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_block_claim(execution_from_env(env), block);
}

static int32_t import_privileged_block_release(
    wasm_exec_env_t env, const struct sxs_physical_block *block)
{
    if (!fixed_buffer_is_valid(env, block, sizeof(*block))) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_block_release(execution_from_env(env), block);
}

static bool valid_block_array(wasm_exec_env_t env,
                              const struct sxs_physical_block *blocks,
                              uint32_t block_count)
{
    return block_count != 0 &&
           block_count <= SXS_PRIVILEGED_MAX_POLICY_BLOCKS &&
           fixed_buffer_is_valid(env, blocks, block_count * sizeof(*blocks));
}

static int32_t import_privileged_storage_read(
    wasm_exec_env_t env, const struct sxs_physical_block *blocks,
    uint32_t block_count, void *data, uint32_t data_length)
{
    if (!valid_block_array(env, blocks, block_count) ||
        !data || data_length == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_storage_read(
        execution_from_env(env), blocks, block_count, data, data_length);
}

static int32_t import_privileged_storage_write(
    wasm_exec_env_t env, const struct sxs_physical_block *blocks,
    uint32_t block_count, const void *data, uint32_t data_length)
{
    if (!valid_block_array(env, blocks, block_count) ||
        !data || data_length == 0) {
        return -SXS_WASM_EINVAL;
    }
    return pe_api_privileged_storage_write(
        execution_from_env(env), blocks, block_count, data, data_length);
}

static int32_t import_privileged_storage_erase(
    wasm_exec_env_t env, const struct sxs_physical_block *blocks,
    uint32_t block_count)
{
    if (!valid_block_array(env, blocks, block_count)) {
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
    const struct sxs_physical_block *blocks, uint32_t block_count)
{
    if (!valid_block_array(env, blocks, block_count)) {
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

/*
 * Keep the WAMR host-call boundary explicit.  policy-imports.def describes the
 * same ABI for policy declarations and linker allowlists, but it does not
 * generate these runtime tables.  ABI changes must update both places.
 */
static NativeSymbol native_symbols[] = {
    {"sxs_execution_get", (void *)import_execution_get, "(*)i", NULL},
    {"sxs_nvme_event_get", (void *)import_nvme_event_get, "(*)i", NULL},
    {"sxs_backend_event_get", (void *)import_backend_event_get, "(*)i", NULL},
    {"sxs_pswd_event_get", (void *)import_pswd_event_get, "(*)i", NULL},
    {"sxs_subscribe", (void *)import_subscribe, "(iiii)i", NULL},
    {"sxs_state_create", (void *)import_state_create, "(iiIiI)i", NULL},
    {"sxs_state_read", (void *)import_state_read, "(iIi*~)i", NULL},
    {"sxs_state_write", (void *)import_state_write, "(iIi*~)i", NULL},
    {"sxs_state_fill_u64", (void *)import_state_fill_u64, "(iI)i", NULL},
    {"sxs_backend_status_get", (void *)import_backend_status_get,
     "(I*)i", NULL},
    {"sxs_geometry_get", (void *)import_geometry_get, "(*)i", NULL},
    {"sxs_layout_get", (void *)import_layout_get, "(*)i", NULL},
    {"sxs_eswd_get", (void *)import_eswd_get, "(i*)i", NULL},
    {"sxs_eswd_from_ppa", (void *)import_eswd_from_ppa, "(I*)i", NULL},
    {"sxs_ppa_validate", (void *)import_ppa_validate, "(I)i", NULL},
    {"sxs_ppa_to_page_index", (void *)import_ppa_to_page_index, "(I)I", NULL},
    {"sxs_page_status_get", (void *)import_page_status_get, "(I)i", NULL},
    {"sxs_request_read", (void *)import_request_read, "(I*~)i", NULL},
    {"sxs_request_write", (void *)import_request_write, "(I*~)i", NULL},
    {"sxs_command_read", (void *)import_command_read, "(i*~)i", NULL},
    {"sxs_command_write", (void *)import_command_write, "(i*~)i", NULL},
    {"sxs_dsm_range_get", (void *)import_dsm_range_get, "(i*)i", NULL},
    {"sxs_completion_status_set", (void *)import_completion_status_set,
     "(i)i", NULL},
    {"sxs_completion_result_set", (void *)import_completion_result_set,
     "(I)i", NULL},
    {"sxs_time_now_ns", (void *)import_time_now_ns, "()I", NULL},
    {"sxs_eswd_config_stage", (void *)import_eswd_config_stage, "(*)i", NULL},
    {"sxs_namespace_config_stage", (void *)import_namespace_config_stage,
     "(*)i", NULL},
    {"sxs_ftl_finalize_stage", (void *)import_ftl_finalize_stage, "()i", NULL},
    {"sxs_oob_register_stage", (void *)import_oob_register_stage,
     "(ii)i", NULL},
    {"sxs_eswd_wp_get", (void *)import_eswd_wp_get, "(i)I", NULL},
    {"sxs_eswd_effective_wp_get", (void *)import_eswd_effective_wp_get,
     "(i)I", NULL},
    {"sxs_eswd_range_check", (void *)import_eswd_range_check, "(iiIi)i", NULL},
    {"sxs_eswd_to_ppa", (void *)import_eswd_to_ppa, "(ii)I", NULL},
    {"sxs_ppa_to_eswd", (void *)import_ppa_to_eswd, "(I*)i", NULL},
    {"sxs_page_read", (void *)import_page_read, "(**~*~*)i", NULL},
    {"sxs_page_append", (void *)import_page_append, "(**~*~*)i", NULL},
    {"sxs_page_invalidate", (void *)import_page_invalidate, "(I)i", NULL},
    {"sxs_eswd_reset", (void *)import_eswd_reset, "(i)i", NULL},
    {"sxs_eswd_advance_wp", (void *)import_eswd_advance_wp, "(i)i", NULL},
    {"sxs_eswd_erase", (void *)import_eswd_erase, "(i)I", NULL},
    {"sxs_page_migrate", (void *)import_page_migrate, "(Ii*)i", NULL},
    {"sxs_eswd_stage_write", (void *)import_eswd_stage_write, "(**)i", NULL},
    {"sxs_eswd_page_read", (void *)import_eswd_page_read, "(**~*)i", NULL},
    {"sxs_namespace_blob_stage", (void *)import_namespace_blob_stage,
     "(ii*~)i", NULL},
    {"sxs_crypto_random", (void *)import_crypto_random, "(*~)i", NULL},
    {"sxs_crypto_ed25519_verify", (void *)import_crypto_ed25519_verify,
     "(*~*~*~)i", NULL},
    {"sxs_crypto_x25519_public", (void *)import_crypto_x25519_public,
     "(*~*~)i", NULL},
    {"sxs_crypto_x25519_shared", (void *)import_crypto_x25519_shared,
     "(*~*~*~)i", NULL},
    {"sxs_crypto_hmac_sha256", (void *)import_crypto_hmac_sha256,
     "(*~*~*~)i", NULL},
    {"sxs_crypto_sha256", (void *)import_crypto_sha256, "(*~*~)i", NULL},
    {"sxs_crypto_hkdf_sha256", (void *)import_crypto_hkdf_sha256,
     "(*~*~*~)i", NULL},
    {"sxs_crypto_aes256_gcm_decrypt",
     (void *)import_crypto_aes256_gcm_decrypt, "(*~*~*~*~*~*~)i", NULL},
    {"sxs_sign_key_bootstrap", (void *)import_sign_key_bootstrap,
     "(****)i", NULL},
};

static NativeSymbol privileged_native_symbols[] = {
    {"sxs_privileged_storage_geometry_get",
     (void *)import_privileged_storage_geometry_get, "(*)i", NULL},
    {"sxs_privileged_block_is_claimed",
     (void *)import_privileged_block_is_claimed, "(*)i", NULL},
    {"sxs_privileged_block_claim", (void *)import_privileged_block_claim,
     "(*)i", NULL},
    {"sxs_privileged_block_release", (void *)import_privileged_block_release,
     "(*)i", NULL},
    {"sxs_privileged_storage_read", (void *)import_privileged_storage_read,
     "(*i*~)i", NULL},
    {"sxs_privileged_storage_write", (void *)import_privileged_storage_write,
     "(*i*~)i", NULL},
    {"sxs_privileged_storage_erase", (void *)import_privileged_storage_erase,
     "(*i)i", NULL},
    {"sxs_privileged_policy_validate_image",
     (void *)import_privileged_policy_validate_image, "(*~)i", NULL},
    {"sxs_privileged_policy_activate_stored",
     (void *)import_privileged_policy_activate_stored, "(iiii*i)i", NULL},
    {"sxs_privileged_policy_deactivate",
     (void *)import_privileged_policy_deactivate, "(i)i", NULL},
    {"sxs_privileged_policy_state_can_remove",
     (void *)import_privileged_policy_state_can_remove, "(ii)i", NULL},
    {"sxs_privileged_policy_state_remove",
     (void *)import_privileged_policy_state_remove, "(ii)i", NULL},
    {"sxs_privileged_device_attestation_sign",
     (void *)import_privileged_device_attestation_sign, "(*~*~)i", NULL},
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
