#ifndef FEMU_POLICY_WASM_ABI_H
#define FEMU_POLICY_WASM_ABI_H

/* Freestanding fixed-width types shared by the host and wasm32 policies. */
typedef __UINT8_TYPE__ sxs_u8;
typedef __UINT16_TYPE__ sxs_u16;
typedef __UINT32_TYPE__ sxs_u32;
typedef __UINT64_TYPE__ sxs_u64;
typedef __INT32_TYPE__ sxs_s32;
typedef __INT64_TYPE__ sxs_s64;

#define SXS_WASM_ABI_VERSION 2U
#define SXS_WASM_MAX_PAGE_BYTES 4096U
#define SXS_WASM_MAX_ARTIFACT_BYTES (1024U * 1024U)
#define SXS_WASM_MAX_SUBSCRIPTIONS_PER_POLICY 64U
#define SXS_WASM_MAX_STATE_OBJECTS 32U
#define SXS_WASM_MAX_STATE_ELEMENT_BYTES 256U
#define SXS_WASM_MAX_STATE_BYTES_PER_POLICY (256ULL * 1024ULL * 1024ULL)
#define SXS_WASM_MAX_STATE_BYTES_GLOBAL (512ULL * 1024ULL * 1024ULL)
#define SXS_WASM_SELECTOR_ANY 0xffffffffU
#define SXS_WASM_ACTION_ERROR (~0ULL)

#define SXS_WASM_EPERM 1
#define SXS_WASM_ENOENT 2
#define SXS_WASM_EIO 5
#define SXS_WASM_ENOMEM 12
#define SXS_WASM_EBUSY 16
#define SXS_WASM_EEXIST 17
#define SXS_WASM_EINVAL 22
#define SXS_WASM_ENOSPC 28
#define SXS_WASM_ENOSYS 38
#define SXS_WASM_EOVERFLOW 75

enum sxs_phase {
    SXS_PHASE_INIT = 1,
    SXS_PHASE_CONDITION = 2,
    SXS_PHASE_ACTION = 3,
};

enum sxs_event_kind {
    SXS_EVENT_NONE = 0,
    SXS_EVENT_NVME_IO = 1,
    SXS_EVENT_NVME_ADMIN = 2,
    SXS_EVENT_BACKEND = 3,
    SXS_EVENT_PSWD_TRANSITION = 4,
    SXS_EVENT_BACKGROUND = 5,
};

enum sxs_policy_context_flags {
    SXS_FLAG_STATE_RESTORED = 1U << 0,
};

enum sxs_state_flags {
    SXS_STATE_INIT_U64 = 1U << 0,
    SXS_STATE_SECRET = 1U << 1,
};

enum sxs_eswd_range_operation {
    SXS_ESWD_CHECK_SEQUENTIAL_WRITE = 1,
    SXS_ESWD_CHECK_READ = 2,
};

enum sxs_namespace_blob_kind {
    SXS_NAMESPACE_BLOB_NS = 1,
    SXS_NAMESPACE_BLOB_CTRL = 2,
};

struct sxs_execution_info {
    sxs_u32 abi_version;
    sxs_u32 phase;
    sxs_u32 event_kind;
    sxs_u32 pair_id;
    sxs_u32 policy_id;
    sxs_u32 policy_version;
    sxs_u32 generation;
    sxs_u32 flags;
};

struct sxs_nvme_event {
    sxs_u32 opcode, nsid;
    sxs_u32 cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
    sxs_u64 lba, nsecs, start_lpn, end_lpn, lpn_count, start_time_ns;
    sxs_u32 initial_status, reserved;
};

struct sxs_backend_event {
    sxs_u32 command, io_type, status_count, reserved;
    sxs_s64 start_time_ns, latency_ns;
};

struct sxs_pswd_event {
    sxs_u32 old_state, new_state;
    sxs_u64 pba;
    sxs_s32 erase_count, write_pointer;
};

/* Temporary source-level context; it contains snapshots, never host pointers. */
struct sxs_policy_context {
    sxs_u32 abi_version, context_size, phase, event_kind;
    sxs_u32 policy_id, policy_version, generation, pair_id;
    sxs_u32 flags, reserved;
    union {
        struct sxs_nvme_event nvme;
        struct sxs_backend_event backend;
        struct sxs_pswd_event pswd;
    } event;
};

struct sxs_geometry {
    sxs_u32 blocks_per_plane_log, blocks_per_lun_log;
    sxs_u32 blocks_per_channel_log, pages_per_block;
    sxs_u32 pages_per_plane, pages_per_lun, pages_per_channel;
    sxs_u32 blocks_per_line, pages_per_line, total_lines;
    sxs_u32 planes_per_lun, luns_per_channel, channels, total_luns;
    sxs_u32 sectors_per_page, sector_size;
    sxs_u64 total_blocks_log, total_pages_log;
};

struct sxs_layout {
    sxs_u32 total_eswds, blocks_per_eswd, pages_per_eswd, striping_level;
    sxs_u32 total_planes, blocks_per_plane, reserved0, reserved1;
};

struct sxs_eswd {
    sxs_u32 id;
    sxs_s32 valid_page_count, invalid_page_count;
    sxs_u32 write_page_index;
    sxs_u64 write_lba;
};

struct sxs_dsm_range {
    sxs_u32 attributes, lba_count;
    sxs_u64 start_lba;
};

struct sxs_eswd_location { sxs_u32 eswd_id, page_index; };
struct sxs_eswd_config { sxs_u32 striping_level, blocks_per_eswd; };

struct sxs_namespace_config {
    sxs_u32 csi, noiob;
    sxs_u64 nsze, ncap, nuse;
    sxs_u32 namespace_blob_length, controller_blob_length;
};

struct sxs_page_read_request {
    sxs_u64 ppa;
    sxs_u32 page_offset, length;
    sxs_u32 oob_object_id, reserved;
};
struct sxs_page_append_request {
    sxs_u32 eswd_id, oob_object_id;
};
struct sxs_eswd_stage_write_request {
    sxs_u32 eswd_id, lba_count;
    sxs_u64 start_lba, request_byte_offset;
};
struct sxs_eswd_page_read_request {
    sxs_u32 eswd_id, reserved;
    sxs_u64 page_lba;
};
struct sxs_page_result {
    sxs_s32 status;
    sxs_u32 committed_lbas;
    sxs_u64 ppa, latency_ns;
};
struct sxs_bootstrap_sign_request {
    sxs_u8 owner_nonce[32];
    sxs_u8 owner_ephemeral_public_key[32];
    sxs_u8 policy_ephemeral_public_key[32];
    sxs_u8 signature[64];
};

_Static_assert(sizeof(struct sxs_execution_info) == 32,
               "sxs_execution_info ABI");
_Static_assert(sizeof(struct sxs_nvme_event) == 88, "sxs_nvme_event ABI");
_Static_assert(sizeof(struct sxs_backend_event) == 32,
               "sxs_backend_event ABI");
_Static_assert(sizeof(struct sxs_pswd_event) == 24, "sxs_pswd_event ABI");
_Static_assert(sizeof(struct sxs_geometry) == 80, "sxs_geometry ABI");
_Static_assert(sizeof(struct sxs_layout) == 32, "sxs_layout ABI");
_Static_assert(sizeof(struct sxs_eswd) == 24, "sxs_eswd ABI");
_Static_assert(sizeof(struct sxs_dsm_range) == 16, "sxs_dsm_range ABI");
_Static_assert(sizeof(struct sxs_namespace_config) == 40,
               "sxs_namespace_config ABI");
_Static_assert(__builtin_offsetof(struct sxs_namespace_config, nsze) == 8,
               "sxs_namespace_config layout");
_Static_assert(sizeof(struct sxs_page_result) == 24,
               "sxs_page_result ABI");
_Static_assert(__builtin_offsetof(struct sxs_page_result, ppa) == 8,
               "sxs_page_result layout");
_Static_assert(sizeof(struct sxs_bootstrap_sign_request) == 160,
               "sxs_bootstrap_sign_request ABI");
_Static_assert(__builtin_offsetof(struct sxs_bootstrap_sign_request,
                                  signature) == 96,
               "sxs_bootstrap_sign_request layout");

#if defined(__wasm__)

#define SXS_IMPORT(symbol) \
    __attribute__((import_module("sxs_v1"), import_name(symbol)))
#define SXS_EXPORT(symbol) __attribute__((export_name(symbol)))

SXS_IMPORT("sxs_execution_get")
extern sxs_s32 __sxs_execution_get(void *, sxs_u32);
SXS_IMPORT("sxs_nvme_event_get")
extern sxs_s32 __sxs_nvme_event_get(void *, sxs_u32);
SXS_IMPORT("sxs_backend_event_get")
extern sxs_s32 __sxs_backend_event_get(void *, sxs_u32);
SXS_IMPORT("sxs_pswd_event_get")
extern sxs_s32 __sxs_pswd_event_get(void *, sxs_u32);

SXS_IMPORT("sxs_subscribe")
extern sxs_s32 sxs_subscribe(sxs_u32, sxs_u32, sxs_u32, sxs_u32);
SXS_IMPORT("sxs_state_create")
extern sxs_s32 sxs_state_create(sxs_u32, sxs_u32, sxs_u64, sxs_u32, sxs_u64);
SXS_IMPORT("sxs_state_read")
extern sxs_s32 sxs_state_read(sxs_u32, sxs_u64, sxs_u32, void *, sxs_u32);
SXS_IMPORT("sxs_state_write")
extern sxs_s32 sxs_state_write(sxs_u32, sxs_u64, sxs_u32, const void *, sxs_u32);
SXS_IMPORT("sxs_state_fill_u64")
extern sxs_s32 sxs_state_fill_u64(sxs_u32, sxs_u64);
SXS_IMPORT("sxs_backend_status_get")
extern sxs_s32 sxs_backend_status_get(sxs_u64, sxs_s32 *, sxs_u32);
#define SXS_DECLARE_OUTPUT_IMPORT(name, type)                              \
    SXS_IMPORT(#name) extern sxs_s32 __##name(void *, sxs_u32);           \
    static inline sxs_s32 name(type *output)                              \
    { return __##name(output, sizeof(*output)); }

SXS_DECLARE_OUTPUT_IMPORT(sxs_geometry_get, struct sxs_geometry)
SXS_DECLARE_OUTPUT_IMPORT(sxs_layout_get, struct sxs_layout)
#undef SXS_DECLARE_OUTPUT_IMPORT

#define SXS_DECLARE_KEYED_OUTPUT_IMPORT(name, key_type, type)              \
    SXS_IMPORT(#name) extern sxs_s32 __##name(key_type, void *, sxs_u32);  \
    static inline sxs_s32 name(key_type key, type *output)                 \
    { return __##name(key, output, sizeof(*output)); }

SXS_DECLARE_KEYED_OUTPUT_IMPORT(sxs_eswd_get, sxs_u32, struct sxs_eswd)
SXS_DECLARE_KEYED_OUTPUT_IMPORT(sxs_eswd_from_ppa, sxs_u64,
                                struct sxs_eswd_location)
SXS_DECLARE_KEYED_OUTPUT_IMPORT(sxs_dsm_range_get, sxs_u32,
                                struct sxs_dsm_range)
#undef SXS_DECLARE_KEYED_OUTPUT_IMPORT

SXS_IMPORT("sxs_ppa_validate") extern sxs_s32 sxs_ppa_validate(sxs_u64);
SXS_IMPORT("sxs_ppa_to_page_index")
extern sxs_s64 sxs_ppa_to_page_index(sxs_u64);
SXS_IMPORT("sxs_page_status_get")
extern sxs_s32 sxs_page_status_get(sxs_u64);
SXS_IMPORT("sxs_request_read")
extern sxs_s32 sxs_request_read(sxs_u64, void *, sxs_u32);
SXS_IMPORT("sxs_request_write")
extern sxs_s32 sxs_request_write(sxs_u64, const void *, sxs_u32);
SXS_IMPORT("sxs_command_read")
extern sxs_s32 sxs_command_read(sxs_u32, void *, sxs_u32);
SXS_IMPORT("sxs_command_write")
extern sxs_s32 sxs_command_write(sxs_u32, const void *, sxs_u32);
SXS_IMPORT("sxs_completion_status_set")
extern sxs_s32 sxs_completion_status_set(sxs_u32);
SXS_IMPORT("sxs_completion_result_set")
extern sxs_s32 sxs_completion_result_set(sxs_u64);
SXS_IMPORT("sxs_time_now_ns") extern sxs_u64 sxs_time_now_ns(void);
SXS_IMPORT("sxs_eswd_config_stage")
extern sxs_s32 __sxs_eswd_config_stage(const void *, sxs_u32);
SXS_IMPORT("sxs_namespace_config_stage")
extern sxs_s32 __sxs_namespace_config_stage(const void *, sxs_u32);
static inline sxs_s32 sxs_eswd_config_stage(const struct sxs_eswd_config *value)
{ return __sxs_eswd_config_stage(value, sizeof(*value)); }
static inline sxs_s32 sxs_namespace_config_stage(
    const struct sxs_namespace_config *value)
{ return __sxs_namespace_config_stage(value, sizeof(*value)); }
SXS_IMPORT("sxs_ftl_finalize_stage")
extern sxs_s32 sxs_ftl_finalize_stage(void);
SXS_IMPORT("sxs_oob_register_stage")
extern sxs_s32 sxs_oob_register_stage(sxs_u32, sxs_u32);
SXS_IMPORT("sxs_eswd_wp_get") extern sxs_s64 sxs_eswd_wp_get(sxs_u32);
SXS_IMPORT("sxs_eswd_effective_wp_get")
extern sxs_s64 sxs_eswd_effective_wp_get(sxs_u32);
SXS_IMPORT("sxs_eswd_range_check")
extern sxs_s32 sxs_eswd_range_check(sxs_u32, sxs_u32, sxs_u64, sxs_u32);
SXS_IMPORT("sxs_eswd_to_ppa")
extern sxs_s64 sxs_eswd_to_ppa(sxs_u32, sxs_u32);
SXS_IMPORT("sxs_ppa_to_eswd")
extern sxs_s32 __sxs_ppa_to_eswd(sxs_u64, void *, sxs_u32);
static inline sxs_s32 sxs_ppa_to_eswd(sxs_u64 ppa,
                                      struct sxs_eswd_location *output)
{ return __sxs_ppa_to_eswd(ppa, output, sizeof(*output)); }
SXS_IMPORT("sxs_page_invalidate")
extern sxs_s32 sxs_page_invalidate(sxs_u64);
SXS_IMPORT("sxs_eswd_reset") extern sxs_s32 sxs_eswd_reset(sxs_u32);
SXS_IMPORT("sxs_eswd_advance_wp")
extern sxs_s32 sxs_eswd_advance_wp(sxs_u32);
SXS_IMPORT("sxs_eswd_erase") extern sxs_u64 sxs_eswd_erase(sxs_u32);

SXS_IMPORT("sxs_page_read")
extern sxs_s32 __sxs_page_read(const void *, sxs_u32, void *, sxs_u32,
                               void *, sxs_u32, void *, sxs_u32);
static inline sxs_s32 sxs_page_read(const struct sxs_page_read_request *request,
                                    void *data, sxs_u32 data_length,
                                    void *oob, sxs_u32 oob_length,
                                    struct sxs_page_result *result)
{
    return __sxs_page_read(request, sizeof(*request), data, data_length,
                           oob, oob_length, result, sizeof(*result));
}
SXS_IMPORT("sxs_page_append")
extern sxs_s32 __sxs_page_append(const void *, sxs_u32, const void *, sxs_u32,
                                 const void *, sxs_u32, void *, sxs_u32);
static inline sxs_s32 sxs_page_append(
    const struct sxs_page_append_request *request, const void *data,
    sxs_u32 data_length, const void *oob, sxs_u32 oob_length,
    struct sxs_page_result *result)
{
    return __sxs_page_append(request, sizeof(*request), data, data_length,
                             oob, oob_length, result, sizeof(*result));
}
SXS_IMPORT("sxs_page_migrate")
extern sxs_s32 __sxs_page_migrate(sxs_u64, sxs_u32, void *, sxs_u32);
static inline sxs_s32 sxs_page_migrate(sxs_u64 source, sxs_u32 destination,
                                       struct sxs_page_result *result)
{ return __sxs_page_migrate(source, destination, result, sizeof(*result)); }
SXS_IMPORT("sxs_eswd_stage_write")
extern sxs_s32 __sxs_eswd_stage_write(const void *, sxs_u32, void *, sxs_u32);
static inline sxs_s32 sxs_eswd_stage_write(
    const struct sxs_eswd_stage_write_request *request,
    struct sxs_page_result *result)
{ return __sxs_eswd_stage_write(request, sizeof(*request), result,
                                sizeof(*result)); }
SXS_IMPORT("sxs_eswd_page_read")
extern sxs_s32 __sxs_eswd_page_read(const void *, sxs_u32, void *, sxs_u32,
                                    void *, sxs_u32);
static inline sxs_s32 sxs_eswd_page_read(
    const struct sxs_eswd_page_read_request *request, void *data,
    sxs_u32 data_length, struct sxs_page_result *result)
{ return __sxs_eswd_page_read(request, sizeof(*request), data, data_length,
                              result, sizeof(*result)); }
SXS_IMPORT("sxs_namespace_blob_stage")
extern sxs_s32 sxs_namespace_blob_stage(sxs_u32, sxs_u32,
                                        const void *, sxs_u32);
SXS_IMPORT("sxs_crypto_random")
extern sxs_s32 sxs_crypto_random(void *, sxs_u32);
SXS_IMPORT("sxs_crypto_ed25519_verify")
extern sxs_s32 sxs_crypto_ed25519_verify(const void *, sxs_u32,
                                         const void *, sxs_u32,
                                         const void *, sxs_u32);
SXS_IMPORT("sxs_crypto_x25519_public")
extern sxs_s32 sxs_crypto_x25519_public(const void *, sxs_u32,
                                        void *, sxs_u32);
SXS_IMPORT("sxs_crypto_x25519_shared")
extern sxs_s32 sxs_crypto_x25519_shared(const void *, sxs_u32,
                                        const void *, sxs_u32,
                                        void *, sxs_u32);
SXS_IMPORT("sxs_crypto_hmac_sha256")
extern sxs_s32 sxs_crypto_hmac_sha256(const void *, sxs_u32,
                                      const void *, sxs_u32,
                                      void *, sxs_u32);
SXS_IMPORT("sxs_crypto_sha256")
extern sxs_s32 sxs_crypto_sha256(const void *, sxs_u32, void *, sxs_u32);
SXS_IMPORT("sxs_crypto_hkdf_sha256")
extern sxs_s32 sxs_crypto_hkdf_sha256(const void *, sxs_u32,
                                      const void *, sxs_u32,
                                      void *, sxs_u32);
SXS_IMPORT("sxs_crypto_aes256_gcm_decrypt")
extern sxs_s32 sxs_crypto_aes256_gcm_decrypt(
    const void *, sxs_u32, const void *, sxs_u32,
    const void *, sxs_u32, const void *, sxs_u32,
    const void *, sxs_u32, void *, sxs_u32);
SXS_IMPORT("sxs_sign_key_bootstrap")
extern sxs_s32 __sxs_sign_key_bootstrap(const sxs_u8 *, sxs_u32,
                                        const sxs_u8 *, sxs_u32,
                                        const sxs_u8 *, sxs_u32,
                                        sxs_u8 *, sxs_u32);
static inline sxs_s32 sxs_sign_key_bootstrap(
    const sxs_u8 owner_nonce[32], const sxs_u8 owner_public[32],
    const sxs_u8 policy_public[32], sxs_u8 signature[64])
{
    return __sxs_sign_key_bootstrap(owner_nonce, 32, owner_public, 32,
                                    policy_public, 32, signature, 64);
}

/*
 * Keep the typed declarations above tied to the canonical import registry.
 * A catalog entry whose linker symbol has no declaration makes every policy
 * compilation fail here, rather than becoming a loader-only ABI mismatch.
 */
#define SXS_COMMON_IMPORT(api_name, linker_symbol, native_wrapper,           \
                          wamr_signature, meta_interface_access)             \
    _Static_assert(sizeof(&(linker_symbol)) > 0,                             \
                   "missing common import declaration: " #linker_symbol);
#define SXS_PRIVILEGED_IMPORT(api_name, linker_symbol, native_wrapper,       \
                              wamr_signature)
#include "policy-imports.def"
#undef SXS_PRIVILEGED_IMPORT
#undef SXS_COMMON_IMPORT

static inline void sxs_zero_context(struct sxs_policy_context *context)
{
    sxs_u8 *bytes = (sxs_u8 *)context;
    for (sxs_u32 i = 0; i < sizeof(*context); i++) {
        bytes[i] = 0;
    }
}

static inline sxs_s32 sxs_context_get(struct sxs_policy_context *context)
{
    struct sxs_execution_info info;
    sxs_s32 status;

    if (!context) {
        return -SXS_WASM_EINVAL;
    }
    sxs_zero_context(context);
    status = __sxs_execution_get(&info, sizeof(info));
    if (status != 0 || info.abi_version != SXS_WASM_ABI_VERSION) {
        return status ? status : -SXS_WASM_EINVAL;
    }
    context->abi_version = info.abi_version;
    context->context_size = sizeof(*context);
    context->phase = info.phase;
    context->event_kind = info.event_kind;
    context->policy_id = info.policy_id;
    context->policy_version = info.policy_version;
    context->generation = info.generation;
    context->pair_id = info.pair_id;
    context->flags = info.flags;
    switch (info.event_kind) {
    case SXS_EVENT_NONE:
    case SXS_EVENT_BACKGROUND:
        return 0;
    case SXS_EVENT_NVME_IO:
    case SXS_EVENT_NVME_ADMIN:
        return __sxs_nvme_event_get(&context->event.nvme,
                                    sizeof(context->event.nvme));
    case SXS_EVENT_BACKEND:
        return __sxs_backend_event_get(&context->event.backend,
                                       sizeof(context->event.backend));
    case SXS_EVENT_PSWD_TRANSITION:
        return __sxs_pswd_event_get(&context->event.pswd,
                                    sizeof(context->event.pswd));
    default:
        return -SXS_WASM_EINVAL;
    }
}

#define SXS_EXPORT_INIT SXS_EXPORT("sxs_policy_init")
#define SXS_EXPORT_CONDITION SXS_EXPORT("sxs_policy_condition")
#define SXS_EXPORT_ACTION SXS_EXPORT("sxs_policy_action")

#endif /* __wasm__ */

#endif /* FEMU_POLICY_WASM_ABI_H */
