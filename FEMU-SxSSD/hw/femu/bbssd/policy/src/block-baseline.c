/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "block-policy.h"

sxs_s64 block_variant_init(struct sxs_policy_context *context,
                           const struct sxs_geometry *geometry,
                           const struct block_wasm_metadata *metadata)
{
    (void)context;
    (void)geometry;
    (void)metadata;
    return 0;
}

sxs_u64 block_variant_condition(struct sxs_policy_context *context)
{
    (void)context;
    return 0;
}

sxs_u64 block_variant_action(struct sxs_policy_context *context)
{
    (void)context;
    return SXS_WASM_ACTION_ERROR;
}

sxs_s64 block_variant_prepare_append(
    struct sxs_policy_context *context, sxs_u64 lpn, sxs_u64 old_ppa,
    struct sxs_page_append_request *request, sxs_u8 *oob,
    sxs_u32 *oob_length)
{
    (void)context;
    (void)lpn;
    (void)old_ppa;
    (void)request;
    (void)oob;
    (void)oob_length;
    return 0;
}

sxs_s64 block_variant_handle_old_page(struct sxs_policy_context *context,
                                      sxs_u64 lpn, sxs_u64 old_ppa)
{
    (void)context;
    (void)lpn;
    return sxs_page_invalidate(old_ppa);
}

sxs_s64 block_variant_after_new_page(struct sxs_policy_context *context,
                                     sxs_u64 lpn, sxs_u64 old_ppa,
                                     sxs_u64 new_ppa)
{
    (void)context;
    (void)lpn;
    (void)old_ppa;
    (void)new_ppa;
    return 0;
}

sxs_s64 block_variant_on_page_read(struct sxs_policy_context *context,
                                   sxs_u64 lpn, sxs_u64 ppa)
{
    (void)context;
    (void)lpn;
    (void)ppa;
    return 0;
}

sxs_u32 block_variant_gc_should_migrate(struct sxs_policy_context *context,
                                        sxs_u64 ppa)
{
    (void)context;
    (void)ppa;
    return 1;
}

sxs_s64 block_variant_gc_after_migrate(struct sxs_policy_context *context,
                                       sxs_u64 old_ppa, sxs_u64 new_ppa,
                                       sxs_u64 lpn)
{
    (void)context;
    (void)old_ppa;
    (void)new_ppa;
    (void)lpn;
    return 0;
}

sxs_s64 block_variant_gc_before_erase(
    struct sxs_policy_context *context, sxs_u32 victim,
    const struct block_wasm_metadata *metadata)
{
    (void)context;
    (void)victim;
    (void)metadata;
    return 0;
}
