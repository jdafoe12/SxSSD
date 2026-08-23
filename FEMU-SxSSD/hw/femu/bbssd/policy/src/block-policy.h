/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef SXS_BLOCK_POLICY_H
#define SXS_BLOCK_POLICY_H

#include "policy-wasm-abi.h"

#define BLOCK_NVME_SUCCESS 0x0000U
#define BLOCK_NVME_INVALID_FIELD 0x4002U
#define BLOCK_NVME_INTERNAL_ERROR 0x4006U

struct block_wasm_metadata {
    sxs_u64 total_logical_pages;
    sxs_u32 total_eswds;
    sxs_u32 pages_per_eswd;
    sxs_u32 sectors_per_page;
    sxs_u32 sector_size;
    sxs_u32 page_size;
    sxs_u32 current_eswd;
    sxs_u32 free_eswds;
    sxs_u32 gc_low_watermark;
    sxs_u32 gc_urgent_watermark;
};

sxs_s64 block_read_metadata(struct sxs_policy_context *context,
                             struct block_wasm_metadata *metadata_out);

/* One variant implementation is linked with the shared block policy. */
sxs_s64 block_variant_init(struct sxs_policy_context *context,
                           const struct sxs_geometry *geometry,
                           const struct block_wasm_metadata *metadata);
sxs_u64 block_variant_condition(struct sxs_policy_context *context);
sxs_u64 block_variant_action(struct sxs_policy_context *context);
sxs_s64 block_variant_prepare_append(
    struct sxs_policy_context *context, sxs_u64 lpn, sxs_u64 old_ppa,
    struct sxs_page_append_request *request, sxs_u8 *oob,
    sxs_u32 *oob_length);
sxs_s64 block_variant_handle_old_page(struct sxs_policy_context *context,
                                      sxs_u64 lpn, sxs_u64 old_ppa);
sxs_s64 block_variant_after_new_page(struct sxs_policy_context *context,
                                     sxs_u64 lpn, sxs_u64 old_ppa,
                                     sxs_u64 new_ppa);
sxs_s64 block_variant_on_page_read(struct sxs_policy_context *context,
                                   sxs_u64 lpn, sxs_u64 ppa);
sxs_u32 block_variant_gc_should_migrate(struct sxs_policy_context *context,
                                        sxs_u64 ppa);
sxs_s64 block_variant_gc_after_migrate(struct sxs_policy_context *context,
                                       sxs_u64 old_ppa, sxs_u64 new_ppa,
                                       sxs_u64 lpn);
sxs_s64 block_variant_gc_before_erase(
    struct sxs_policy_context *context, sxs_u32 victim,
    const struct block_wasm_metadata *metadata);

#endif /* SXS_BLOCK_POLICY_H */
