#ifndef FEMU_POLICY_API_H
#define FEMU_POLICY_API_H

#include <stdint.h>

#include "policy/policy-wasm-abi.h"
#include "policy/policy-privileged-wasm-abi.h"

struct pe_policy_execution;

int32_t pe_api_subscribe(struct pe_policy_execution *execution,
                         uint32_t event_kind, uint32_t selector,
                         uint32_t pair_id, uint32_t flags);
int32_t pe_api_state_create(struct pe_policy_execution *execution,
                            uint32_t object_id, uint32_t element_size,
                            uint64_t element_count, uint32_t flags,
                            uint64_t initial_u64);
int32_t pe_api_state_read(struct pe_policy_execution *execution,
                          uint32_t object_id, uint64_t index,
                          uint32_t element_offset, void *destination,
                          uint32_t length);
int32_t pe_api_state_write(struct pe_policy_execution *execution,
                           uint32_t object_id, uint64_t index,
                           uint32_t element_offset, const void *source,
                           uint32_t length);
int32_t pe_api_state_fill_u64(struct pe_policy_execution *execution,
                              uint32_t object_id, uint64_t value);
int32_t pe_api_backend_status_get(struct pe_policy_execution *execution,
                                  uint64_t index, int32_t *destination);
int32_t pe_api_stats_add(struct pe_policy_execution *execution,
                         uint32_t counter, uint64_t value);
int32_t pe_api_stats_gc_active_set(struct pe_policy_execution *execution,
                                   uint32_t active);
int32_t pe_api_geometry_get(struct pe_policy_execution *execution,
                            struct sxs_geometry *destination);
int32_t pe_api_layout_get(struct pe_policy_execution *execution,
                          struct sxs_layout *destination);
int32_t pe_api_eswd_get(struct pe_policy_execution *execution, uint32_t eswd_id,
                        struct sxs_eswd *destination);
int32_t pe_api_eswd_from_ppa(struct pe_policy_execution *execution,
                             uint64_t ppa,
                             struct sxs_eswd_location *destination);
int32_t pe_api_ppa_validate(struct pe_policy_execution *execution,
                            uint64_t ppa);
int64_t pe_api_ppa_to_page_index(struct pe_policy_execution *execution,
                                 uint64_t ppa);
int32_t pe_api_page_status_get(struct pe_policy_execution *execution,
                               uint64_t ppa);
int32_t pe_api_stats_get(struct pe_policy_execution *execution,
                         struct sxs_stats *destination);
int32_t pe_api_request_read(struct pe_policy_execution *execution,
                            uint64_t request_offset, void *destination,
                            uint32_t length);
int32_t pe_api_request_write(struct pe_policy_execution *execution,
                             uint64_t request_offset, const void *source,
                             uint32_t length);
int32_t pe_api_command_read(struct pe_policy_execution *execution,
                            uint32_t command_offset, void *destination,
                            uint32_t length);
int32_t pe_api_command_write(struct pe_policy_execution *execution,
                             uint32_t command_offset, const void *source,
                             uint32_t length);
int32_t pe_api_dsm_range_get(struct pe_policy_execution *execution,
                             uint32_t index, struct sxs_dsm_range *destination);
int32_t pe_api_completion_status_set(struct pe_policy_execution *execution,
                                     uint32_t status);
int32_t pe_api_completion_result_set(struct pe_policy_execution *execution,
                                     uint64_t result);
uint64_t pe_api_time_now_ns(struct pe_policy_execution *execution);
int32_t pe_api_eswd_config_stage(struct pe_policy_execution *execution,
                                 const struct sxs_eswd_config *source);
int32_t
pe_api_namespace_config_stage(struct pe_policy_execution *execution,
                              const struct sxs_namespace_config *source);
int32_t pe_api_ftl_finalize_stage(struct pe_policy_execution *execution);
int32_t pe_api_oob_register_stage(struct pe_policy_execution *execution,
                                  uint32_t object_id, uint32_t bytes_per_page);
int64_t pe_api_eswd_wp_get(struct pe_policy_execution *execution,
                           uint32_t eswd_id);
int64_t pe_api_eswd_effective_wp_get(struct pe_policy_execution *execution,
                                     uint32_t eswd_id);
int32_t pe_api_eswd_range_check(struct pe_policy_execution *execution,
                                uint32_t operation, uint32_t eswd_id,
                                uint64_t start_lba, uint32_t lba_count);
int64_t pe_api_eswd_to_ppa(struct pe_policy_execution *execution,
                           uint32_t eswd_id, uint32_t page_index);
int32_t pe_api_ppa_to_eswd(struct pe_policy_execution *execution, uint64_t ppa,
                           struct sxs_eswd_location *destination);
int32_t pe_api_page_read(struct pe_policy_execution *execution,
                         const struct sxs_page_read_request *request,
                         void *data, uint32_t data_length, void *oob,
                         uint32_t oob_length, struct sxs_page_result *result);
int32_t pe_api_page_append(struct pe_policy_execution *execution,
                           const struct sxs_page_append_request *request,
                           const void *data, uint32_t data_length,
                           const void *oob, uint32_t oob_length,
                           struct sxs_page_result *result);
int32_t pe_api_page_invalidate(struct pe_policy_execution *execution,
                               uint64_t ppa);
int32_t pe_api_eswd_reset(struct pe_policy_execution *execution,
                          uint32_t eswd_id);
int32_t pe_api_eswd_advance_wp(struct pe_policy_execution *execution,
                               uint32_t eswd_id);
uint64_t pe_api_eswd_erase(struct pe_policy_execution *execution,
                           uint32_t eswd_id);
int32_t pe_api_page_migrate(struct pe_policy_execution *execution,
                            uint64_t source_ppa, uint32_t destination_eswd_id,
                            struct sxs_page_result *result);
int32_t
pe_api_eswd_stage_write(struct pe_policy_execution *execution,
                        const struct sxs_eswd_stage_write_request *request,
                        struct sxs_page_result *result);
int32_t pe_api_eswd_page_read(struct pe_policy_execution *execution,
                              const struct sxs_eswd_page_read_request *request,
                              void *data, uint32_t data_length,
                              struct sxs_page_result *result);
int32_t pe_api_namespace_blob_stage(struct pe_policy_execution *execution,
                                    uint32_t kind, uint32_t destination_offset,
                                    const void *source, uint32_t length);
int32_t pe_api_crypto_random(struct pe_policy_execution *execution,
                             void *output, uint32_t length);
int32_t
pe_api_crypto_ed25519_verify(struct pe_policy_execution *execution,
                             const void *public_key, uint32_t public_key_length,
                             const void *message, uint32_t message_length,
                             const void *signature, uint32_t signature_length);
int32_t pe_api_crypto_x25519_public(struct pe_policy_execution *execution,
                                    const void *private_key,
                                    uint32_t private_key_length,
                                    void *public_key,
                                    uint32_t public_key_length);
int32_t pe_api_crypto_x25519_shared(struct pe_policy_execution *execution,
                                    const void *private_key,
                                    uint32_t private_key_length,
                                    const void *peer_key,
                                    uint32_t peer_key_length, void *output,
                                    uint32_t output_length);
int32_t pe_api_crypto_hmac_sha256(struct pe_policy_execution *execution,
                                  const void *key, uint32_t key_length,
                                  const void *message, uint32_t message_length,
                                  void *output, uint32_t output_length);
int32_t pe_api_crypto_sha256(struct pe_policy_execution *execution,
                             const void *message, uint32_t message_length,
                             void *output, uint32_t output_length);
int32_t pe_api_crypto_hkdf_sha256(struct pe_policy_execution *execution,
                                  const void *key, uint32_t key_length,
                                  const void *info, uint32_t info_length,
                                  void *output, uint32_t output_length);
int32_t pe_api_crypto_aes256_gcm_decrypt(
    struct pe_policy_execution *execution,
    const void *key, uint32_t key_length,
    const void *nonce, uint32_t nonce_length,
    const void *aad, uint32_t aad_length,
    const void *ciphertext, uint32_t ciphertext_length,
    const void *tag, uint32_t tag_length,
    void *plaintext, uint32_t plaintext_length);
int32_t pe_api_sign_key_bootstrap(struct pe_policy_execution *execution,
                                  const uint8_t owner_nonce[32],
                                  const uint8_t owner_public[32],
                                  const uint8_t policy_public[32],
                                  uint8_t signature[64]);

int32_t pe_api_privileged_storage_geometry_get(
    struct pe_policy_execution *execution,
    struct sxs_policy_storage_geometry *geometry);
int32_t pe_api_privileged_block_is_claimed(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *block);
int32_t pe_api_privileged_block_claim(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *block);
int32_t pe_api_privileged_block_release(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *block);
int32_t pe_api_privileged_storage_read(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *blocks, uint32_t block_count,
    void *data, uint32_t length);
int32_t pe_api_privileged_storage_write(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *blocks, uint32_t block_count,
    const void *data, uint32_t length);
int32_t pe_api_privileged_storage_erase(
    struct pe_policy_execution *execution,
    const struct sxs_physical_block *blocks, uint32_t block_count);
int32_t pe_api_privileged_policy_validate_image(
    struct pe_policy_execution *execution,
    const void *image, uint32_t image_size);
int32_t pe_api_privileged_policy_activate_stored(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t policy_version, uint32_t generation,
    uint32_t policy_size,
    const struct sxs_physical_block *blocks, uint32_t block_count);
int32_t pe_api_privileged_policy_deactivate(
    struct pe_policy_execution *execution, uint32_t policy_id);
int32_t pe_api_privileged_policy_state_can_remove(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t generation);
int32_t pe_api_privileged_policy_state_remove(
    struct pe_policy_execution *execution,
    uint32_t policy_id, uint32_t generation);
int32_t pe_api_privileged_device_attestation_sign(
    struct pe_policy_execution *execution,
    const void *message, uint32_t message_length,
    void *signature, uint32_t signature_length);

#endif /* FEMU_POLICY_API_H */
