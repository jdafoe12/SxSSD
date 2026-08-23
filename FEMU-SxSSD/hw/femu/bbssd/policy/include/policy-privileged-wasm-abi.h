/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef FEMU_POLICY_PRIVILEGED_WASM_ABI_H
#define FEMU_POLICY_PRIVILEGED_WASM_ABI_H

#include "policy-wasm-abi.h"

/*
 * This is the only ABI difference between normal and privileged policies.
 * The loader rejects this namespace for normal policies, and every native
 * implementation checks the host-assigned binary privilege again at call time.
 *
 * These are mechanism primitives.  They deliberately know nothing about the
 * meta-interface protocol, sessions, installation commands, or attestation
 * formats.
 */
#define SXS_PRIVILEGED_MAX_POLICY_BLOCKS 256U

struct sxs_physical_block {
    sxs_u32 channel;
    sxs_u32 lun;
    sxs_u32 plane;
    sxs_u32 block;
};

struct sxs_policy_storage_geometry {
    sxs_u32 channels;
    sxs_u32 luns_per_channel;
    sxs_u32 planes_per_lun;
    sxs_u32 logical_blocks_per_plane;
    sxs_u32 physical_blocks_per_plane;
    sxs_u32 reserved_blocks_per_lun;
    sxs_u32 pages_per_block;
    sxs_u32 page_size;
};

_Static_assert(sizeof(struct sxs_physical_block) == 16,
               "sxs_physical_block ABI");
_Static_assert(sizeof(struct sxs_policy_storage_geometry) == 32,
               "sxs_policy_storage_geometry ABI");

#if defined(__wasm__)
#define SXS_PRIVILEGED_IMPORT(symbol) \
    __attribute__((import_module("sxs_privileged_v1"), import_name(symbol)))

SXS_PRIVILEGED_IMPORT("sxs_privileged_storage_geometry_get")
extern sxs_s32 sxs_privileged_storage_geometry_get(
    struct sxs_policy_storage_geometry *geometry);

SXS_PRIVILEGED_IMPORT("sxs_privileged_block_is_claimed")
extern sxs_s32 sxs_privileged_block_is_claimed(
    const struct sxs_physical_block *block);
SXS_PRIVILEGED_IMPORT("sxs_privileged_block_claim")
extern sxs_s32 sxs_privileged_block_claim(
    const struct sxs_physical_block *block);
SXS_PRIVILEGED_IMPORT("sxs_privileged_block_release")
extern sxs_s32 sxs_privileged_block_release(
    const struct sxs_physical_block *block);

SXS_PRIVILEGED_IMPORT("sxs_privileged_storage_read")
extern sxs_s32 sxs_privileged_storage_read(
    const struct sxs_physical_block *blocks, sxs_u32 block_count,
    void *data, sxs_u32 data_length);
SXS_PRIVILEGED_IMPORT("sxs_privileged_storage_write")
extern sxs_s32 sxs_privileged_storage_write(
    const struct sxs_physical_block *blocks, sxs_u32 block_count,
    const void *data, sxs_u32 data_length);
SXS_PRIVILEGED_IMPORT("sxs_privileged_storage_erase")
extern sxs_s32 sxs_privileged_storage_erase(
    const struct sxs_physical_block *blocks, sxs_u32 block_count);

SXS_PRIVILEGED_IMPORT("sxs_privileged_policy_validate_image")
extern sxs_s32 sxs_privileged_policy_validate_image(const void *, sxs_u32);
SXS_PRIVILEGED_IMPORT("sxs_privileged_policy_activate_stored")
extern sxs_s32 sxs_privileged_policy_activate_stored(
    sxs_u32 policy_id, sxs_u32 policy_version, sxs_u32 generation,
    sxs_u32 policy_size, const struct sxs_physical_block *blocks,
    sxs_u32 block_count);
SXS_PRIVILEGED_IMPORT("sxs_privileged_policy_deactivate")
extern sxs_s32 sxs_privileged_policy_deactivate(sxs_u32);
SXS_PRIVILEGED_IMPORT("sxs_privileged_policy_can_remove")
extern sxs_s32 sxs_privileged_policy_can_remove(sxs_u32, sxs_u32);
SXS_PRIVILEGED_IMPORT("sxs_privileged_policy_remove")
extern sxs_s32 sxs_privileged_policy_remove(sxs_u32, sxs_u32);

SXS_PRIVILEGED_IMPORT("sxs_privileged_device_attestation_sign")
extern sxs_s32 sxs_privileged_device_attestation_sign(
    const void *, sxs_u32, void *, sxs_u32);

/* See the matching common-import declaration check in policy-wasm-abi.h. */
#undef SXS_PRIVILEGED_IMPORT
#define SXS_COMMON_IMPORT(api_name, linker_symbol, native_wrapper,           \
                          wamr_signature, meta_interface_access)
#define SXS_PRIVILEGED_IMPORT(api_name, linker_symbol, native_wrapper,       \
                              wamr_signature)                                \
    _Static_assert(sizeof(&(linker_symbol)) > 0,                             \
                   "missing privileged import declaration: " #linker_symbol);
#include "policy-imports.def"
#undef SXS_PRIVILEGED_IMPORT
#undef SXS_COMMON_IMPORT
#endif

#endif /* FEMU_POLICY_PRIVILEGED_WASM_ABI_H */
