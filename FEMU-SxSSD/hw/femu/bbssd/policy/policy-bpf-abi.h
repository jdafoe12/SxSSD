#ifndef FEMU_POLICY_BPF_ABI_H
#define FEMU_POLICY_BPF_ABI_H

/* Freestanding fixed-width types usable by both the host and clang -target bpf. */
typedef __UINT8_TYPE__ sxs_u8;
typedef __UINT16_TYPE__ sxs_u16;
typedef __UINT32_TYPE__ sxs_u32;
typedef __UINT64_TYPE__ sxs_u64;
typedef __INT32_TYPE__ sxs_s32;
typedef __INT64_TYPE__ sxs_s64;

#define SXS_BPF_ABI_VERSION 1U
#define SXS_BPF_SCRATCH_BYTES 8192U
#define SXS_BPF_MAX_PAGE_BYTES 4096U
#define SXS_BPF_MAX_ARTIFACT_BYTES (1024U * 1024U)
#define SXS_BPF_MAX_SUBSCRIPTIONS_PER_POLICY 64U
#define SXS_BPF_MAX_STATE_OBJECTS 32U
#define SXS_BPF_MAX_STATE_ELEMENT_BYTES 256U
#define SXS_BPF_MAX_STATE_BYTES_PER_POLICY (256ULL * 1024ULL * 1024ULL)
#define SXS_BPF_MAX_STATE_BYTES_GLOBAL (512ULL * 1024ULL * 1024ULL)
#define SXS_BPF_SELECTOR_ANY 0xffffffffU
#define SXS_BPF_ACTION_ERROR (~0ULL)

/* Helper return values use negative errno values without depending on libc. */
#define SXS_BPF_EPERM 1
#define SXS_BPF_ENOENT 2
#define SXS_BPF_EIO 5
#define SXS_BPF_ENOMEM 12
#define SXS_BPF_EBUSY 16
#define SXS_BPF_EEXIST 17
#define SXS_BPF_EINVAL 22
#define SXS_BPF_ENOSPC 28
#define SXS_BPF_ENOSYS 38
#define SXS_BPF_EOVERFLOW 75

enum sxs_bpf_phase {
    SXS_BPF_PHASE_INIT = 1,
    SXS_BPF_PHASE_CONDITION = 2,
    SXS_BPF_PHASE_ACTION = 3,
};

enum sxs_bpf_event_kind {
    SXS_BPF_EVENT_NONE = 0,
    SXS_BPF_EVENT_NVME_IO = 1,
    SXS_BPF_EVENT_NVME_ADMIN = 2,
    SXS_BPF_EVENT_BACKEND = 3,
    SXS_BPF_EVENT_PSWD_TRANSITION = 4,
    SXS_BPF_EVENT_BACKGROUND = 5,
};

enum sxs_bpf_context_flags {
    SXS_BPF_FLAG_STATE_RESTORED = 1U << 0,
};

enum sxs_bpf_state_flags {
    SXS_BPF_STATE_INIT_U64 = 1U << 0,
    SXS_BPF_STATE_SECRET = 1U << 1,
};

enum sxs_bpf_helper_id {
    SXS_HELPER_SUBSCRIBE = 0,
    SXS_HELPER_STATE_CREATE = 1,
    SXS_HELPER_STATE_READ = 2,
    SXS_HELPER_STATE_WRITE = 3,
    SXS_HELPER_STATE_FILL_U64 = 4,
    SXS_HELPER_BACKEND_STATUS_GET = 5,
    SXS_HELPER_STATS_ADD = 6,
    SXS_HELPER_STATS_GC_ACTIVE_SET = 7,
    SXS_HELPER_GEOMETRY_GET = 8,
    SXS_HELPER_LAYOUT_GET = 9,
    SXS_HELPER_ESWD_GET = 10,
    SXS_HELPER_ESWD_FROM_PPA = 11,
    SXS_HELPER_PPA_VALIDATE = 12,
    SXS_HELPER_PPA_TO_PAGE_INDEX = 13,
    SXS_HELPER_PAGE_STATUS_GET = 14,
    SXS_HELPER_STATS_GET = 15,
    SXS_HELPER_REQUEST_READ = 16,
    SXS_HELPER_REQUEST_WRITE = 17,
    SXS_HELPER_COMMAND_READ = 18,
    SXS_HELPER_COMMAND_WRITE = 19,
    SXS_HELPER_DSM_RANGE_GET = 20,
    SXS_HELPER_COMPLETION_STATUS_SET = 21,
    SXS_HELPER_COMPLETION_RESULT_SET = 22,
    SXS_HELPER_TIME_NOW_NS = 23,
    SXS_HELPER_ESWD_CONFIG_STAGE = 24,
    SXS_HELPER_NAMESPACE_CONFIG_STAGE = 25,
    SXS_HELPER_FTL_FINALIZE_STAGE = 26,
    SXS_HELPER_OOB_REGISTER_STAGE = 27,
    SXS_HELPER_ESWD_WP_GET = 28,
    SXS_HELPER_ESWD_EFFECTIVE_WP_GET = 29,
    SXS_HELPER_ESWD_RANGE_CHECK = 30,
    SXS_HELPER_ESWD_TO_PPA = 31,
    SXS_HELPER_PPA_TO_ESWD = 32,
    SXS_HELPER_PAGE_READ = 33,
    SXS_HELPER_PAGE_APPEND = 34,
    SXS_HELPER_PAGE_INVALIDATE = 35,
    SXS_HELPER_ESWD_RESET = 36,
    SXS_HELPER_ESWD_ADVANCE_WP = 37,
    SXS_HELPER_ESWD_ERASE = 38,
    SXS_HELPER_PAGE_MIGRATE = 39,
    SXS_HELPER_ESWD_STAGE_WRITE = 40,
    SXS_HELPER_ESWD_PAGE_READ = 41,
    SXS_HELPER_NAMESPACE_BLOB_STAGE = 42,
    SXS_HELPER_CRYPTO_RANDOM = 48,
    SXS_HELPER_CRYPTO_ED25519_VERIFY = 49,
    SXS_HELPER_CRYPTO_X25519_PUBLIC = 50,
    SXS_HELPER_CRYPTO_X25519_SHARED = 51,
    SXS_HELPER_CRYPTO_HMAC_SHA256 = 52,
    SXS_HELPER_SIGN_KEY_BOOTSTRAP = 53,
};

enum sxs_bpf_stats_counter {
    SXS_BPF_STATS_GC_INVOCATIONS = 1,
    SXS_BPF_STATS_GC_PAGES_MIGRATED = 2,
    SXS_BPF_STATS_FOREGROUND_GC = 3,
    SXS_BPF_STATS_BACKGROUND_GC = 4,
    SXS_BPF_STATS_GC_TIME_NS = 5,
    SXS_BPF_STATS_BLOCK_ERASES = 6,
};

enum sxs_bpf_eswd_range_operation {
    SXS_BPF_ESWD_CHECK_SEQUENTIAL_WRITE = 1,
    SXS_BPF_ESWD_CHECK_READ = 2,
};

enum sxs_bpf_namespace_blob_kind {
    SXS_BPF_NAMESPACE_BLOB_NS = 1,
    SXS_BPF_NAMESPACE_BLOB_CTRL = 2,
};

struct sxs_bpf_nvme_event {
    sxs_u32 opcode;
    sxs_u32 nsid;
    sxs_u32 cdw10;
    sxs_u32 cdw11;
    sxs_u32 cdw12;
    sxs_u32 cdw13;
    sxs_u32 cdw14;
    sxs_u32 cdw15;
    sxs_u64 lba;
    sxs_u64 nsecs;
    sxs_u64 start_lpn;
    sxs_u64 end_lpn;
    sxs_u64 lpn_count;
    sxs_u64 start_time_ns;
    sxs_u32 initial_status;
    sxs_u32 reserved;
};

struct sxs_bpf_backend_event {
    sxs_u32 command;
    sxs_u32 io_type;
    sxs_u32 status_count;
    sxs_u32 reserved;
    sxs_s64 start_time_ns;
    sxs_s64 latency_ns;
};

struct sxs_bpf_pswd_event {
    sxs_u32 old_state;
    sxs_u32 new_state;
    sxs_u64 pba;
    sxs_s32 erase_count;
    sxs_s32 write_pointer;
};

struct sxs_bpf_context {
    sxs_u32 abi_version;
    sxs_u32 context_size;
    sxs_u32 phase;
    sxs_u32 event_kind;
    sxs_u32 policy_id;
    sxs_u32 policy_version;
    sxs_u32 generation;
    sxs_u32 pair_id;
    sxs_u32 flags;
    sxs_u32 reserved;
    union {
        struct sxs_bpf_nvme_event nvme;
        struct sxs_bpf_backend_event backend;
        struct sxs_bpf_pswd_event pswd;
    } event;
    sxs_u8 scratch[SXS_BPF_SCRATCH_BYTES];
};

struct sxs_bpf_geometry {
    sxs_u32 blocks_per_plane_log;
    sxs_u32 blocks_per_lun_log;
    sxs_u32 blocks_per_channel_log;
    sxs_u32 pages_per_block;
    sxs_u32 pages_per_plane;
    sxs_u32 pages_per_lun;
    sxs_u32 pages_per_channel;
    sxs_u32 blocks_per_line;
    sxs_u32 pages_per_line;
    sxs_u32 total_lines;
    sxs_u32 planes_per_lun;
    sxs_u32 luns_per_channel;
    sxs_u32 channels;
    sxs_u32 total_luns;
    sxs_u32 sectors_per_page;
    sxs_u32 sector_size;
    sxs_u64 total_blocks_log;
    sxs_u64 total_pages_log;
};

struct sxs_bpf_layout {
    sxs_u32 total_eswds;
    sxs_u32 blocks_per_eswd;
    sxs_u32 pages_per_eswd;
    sxs_u32 striping_level;
    sxs_u32 total_planes;
    sxs_u32 blocks_per_plane;
    sxs_u32 reserved0;
    sxs_u32 reserved1;
};

struct sxs_bpf_eswd {
    sxs_u32 id;
    sxs_s32 valid_page_count;
    sxs_s32 invalid_page_count;
    sxs_u32 write_page_index;
    sxs_u64 write_lba;
};

struct sxs_bpf_stats {
    sxs_u64 host_read_commands;
    sxs_u64 host_write_commands;
    sxs_u64 host_trim_commands;
    sxs_u64 host_read_sectors;
    sxs_u64 host_write_sectors;
    sxs_u64 host_trim_sectors;
    sxs_u64 physical_page_reads;
    sxs_u64 physical_page_programs;
    sxs_u64 block_erases;
    sxs_u64 gc_invocations;
    sxs_u64 gc_pages_migrated;
    sxs_u64 foreground_gc_count;
    sxs_u64 background_gc_count;
    sxs_u64 gc_time_ns;
    sxs_u64 policy_dispatch_time_ns;
    sxs_u64 bytes_copied;
    sxs_u32 gc_active;
    sxs_u32 reserved;
};

struct sxs_bpf_dsm_range {
    sxs_u32 attributes;
    sxs_u32 lba_count;
    sxs_u64 start_lba;
};

struct sxs_bpf_eswd_location {
    sxs_u32 eswd_id;
    sxs_u32 page_index;
};

struct sxs_bpf_eswd_config {
    sxs_u32 striping_level;
    sxs_u32 blocks_per_eswd;
};

struct sxs_bpf_namespace_config {
    sxs_u32 csi;
    sxs_u32 noiob;
    sxs_u64 nsze;
    sxs_u64 ncap;
    sxs_u64 nuse;
    sxs_u32 namespace_blob_length;
    sxs_u32 controller_blob_length;
};

struct sxs_bpf_namespace_blob {
    sxs_u32 kind;
    sxs_u32 destination_offset;
    sxs_u32 source_offset;
    sxs_u32 length;
};

struct sxs_bpf_page_read_request {
    sxs_u64 ppa;
    sxs_u32 page_offset;
    sxs_u32 length;
    sxs_u32 data_offset;
    sxs_u32 result_offset;
    sxs_u32 oob_object_id;
    sxs_u32 oob_offset;
    sxs_u32 oob_length;
};

struct sxs_bpf_page_append_request {
    sxs_u32 eswd_id;
    sxs_u32 data_offset;
    sxs_u32 data_length;
    sxs_u32 result_offset;
    sxs_u32 oob_object_id;
    sxs_u32 oob_offset;
    sxs_u32 oob_length;
    sxs_u32 reserved;
};

struct sxs_bpf_page_migrate_request {
    sxs_u64 source_ppa;
    sxs_u32 destination_eswd_id;
    sxs_u32 result_offset;
};

struct sxs_bpf_eswd_stage_write_request {
    sxs_u32 eswd_id;
    sxs_u32 lba_count;
    sxs_u64 start_lba;
    sxs_u64 request_byte_offset;
    sxs_u32 result_offset;
    sxs_u32 reserved;
};

struct sxs_bpf_eswd_page_read_request {
    sxs_u32 eswd_id;
    sxs_u32 data_offset;
    sxs_u64 page_lba;
    sxs_u32 data_length;
    sxs_u32 result_offset;
};

struct sxs_bpf_page_result {
    sxs_s32 status;
    sxs_u32 committed_lbas;
    sxs_u64 ppa;
    sxs_u64 latency_ns;
};

struct sxs_bpf_ed25519_verify_request {
    sxs_u32 public_key_offset;
    sxs_u32 message_offset;
    sxs_u32 message_length;
    sxs_u32 signature_offset;
};

struct sxs_bpf_hmac_sha256_request {
    sxs_u32 key_offset;
    sxs_u32 key_length;
    sxs_u32 message_offset;
    sxs_u32 message_length;
    sxs_u32 output_offset;
};

struct sxs_bpf_bootstrap_sign_request {
    sxs_u8 owner_nonce[32];
    sxs_u8 owner_ephemeral_public_key[32];
    sxs_u8 policy_ephemeral_public_key[32];
    sxs_u8 signature[64];
};

/* Policy-visible helper declarations. Each symbol is resolved by uBPF. */
extern sxs_s64 sxs_subscribe(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_state_create(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_state_read(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_state_write(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_state_fill_u64(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_backend_status_get(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_stats_add(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_stats_gc_active_set(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_geometry_get(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_layout_get(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_get(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_from_ppa(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_ppa_validate(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_ppa_to_page_index(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_page_status_get(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_stats_get(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_request_read(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_request_write(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_command_read(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_command_write(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_dsm_range_get(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_completion_status_set(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_completion_result_set(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_time_now_ns(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_config_stage(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_namespace_config_stage(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_ftl_finalize_stage(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_oob_register_stage(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_wp_get(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_effective_wp_get(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_range_check(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_to_ppa(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_ppa_to_eswd(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_page_read(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_page_append(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_page_invalidate(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_reset(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_advance_wp(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_erase(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_page_migrate(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_stage_write(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_eswd_page_read(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_namespace_blob_stage(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_crypto_random(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_crypto_ed25519_verify(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_crypto_x25519_public(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_crypto_x25519_shared(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_crypto_hmac_sha256(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);
extern sxs_s64 sxs_sign_key_bootstrap(sxs_u64, sxs_u64, sxs_u64, sxs_u64, sxs_u64);

#endif /* FEMU_POLICY_BPF_ABI_H */
