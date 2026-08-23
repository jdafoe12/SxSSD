/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "meta-interface-protocol.h"
#include "policy/include/policy-privileged-wasm-abi.h"

#define NVME_SUCCESS 0x0000U
#define NVME_INVALID_OPCODE 0x0001U
#define NVME_INVALID_FIELD 0x0002U
#define NVME_DATA_TRANSFER_ERROR 0x0004U
#define NVME_INTERNAL_DEVICE_ERROR 0x0006U
#define NVME_DNR 0x4000U

#define META_AUTH_SIZE 32U
#define META_GCM_TAG_SIZE 16U
#define META_ENVELOPE_HEADER_SIZE (8U + META_AUTH_SIZE)
#define META_MAX_HISTORY_RECORDS 4096U
#define META_MAX_GENERATION_RECORDS META_MAX_HISTORY_RECORDS
#define META_WORK_BYTES (SXS_WASM_MAX_ARTIFACT_BYTES + 64U)
#define META_ATTESTATION_BYTES                                           \
    (POLICY_ATTESTATION_RESPONSE_HEADER_SIZE +                           \
     POLICY_ATTESTATION_MAX_POLICIES *                                  \
         POLICY_ATTESTATION_CONSISTENCY_ENTRY_SIZE +                    \
     META_MAX_HISTORY_RECORDS * POLICY_ATTESTATION_HISTORY_RECORD_SIZE +\
     POLICY_ATTESTATION_SIGNATURE_SIZE)
#define META_POLICY_ID_LIMIT 0xffff0000U

static const sxs_u8 admin_public_key[32] = {
    0xb8, 0xde, 0xd4, 0x25, 0xfe, 0xf9, 0x63, 0x1f,
    0x3f, 0xa1, 0x1c, 0x1c, 0xf2, 0xe1, 0x57, 0x94,
    0xab, 0xae, 0xf9, 0xd5, 0xe0, 0x83, 0x75, 0xcb,
    0x65, 0x71, 0xd9, 0x4e, 0xc4, 0xc3, 0x7e, 0xbc,
};

static const sxs_u8 meta_interface_opcodes[] = {
    SXS_NVME_ADMIN_INIT_SESSION_SUBMIT,
    SXS_NVME_ADMIN_INIT_SESSION_FETCH,
    SXS_NVME_ADMIN_INSTALL_POLICY,
    SXS_NVME_ADMIN_ACTIVATE_POLICY,
    SXS_NVME_ADMIN_DEACTIVATE_POLICY,
    SXS_NVME_ADMIN_UPDATE_POLICY,
    SXS_NVME_ADMIN_REMOVE_POLICY,
    SXS_NVME_ADMIN_ATTESTATION_SUBMIT,
    SXS_NVME_ADMIN_ATTESTATION_FETCH,
};

struct meta_history_record {
    sxs_u8 operation;
    sxs_u32 policy_id;
    sxs_u32 generation;
};

struct meta_generation_record {
    sxs_u32 policy_id;
    sxs_u32 last_generation;
};

struct meta_installed_policy {
    sxs_u32 policy_id;
    sxs_u32 policy_version;
    sxs_u32 generation;
    sxs_u32 policy_size;
    sxs_u32 block_count;
    struct sxs_physical_block
        blocks[SXS_PRIVILEGED_MAX_POLICY_BLOCKS];
    sxs_u8 active;
    sxs_u8 in_use;
};

struct meta_state {
    sxs_u8 session_key[32];
    sxs_u8 pending_session_response[SXS_INIT_SESSION_RESPONSE_SIZE];
    sxs_u8 boot_epoch[POLICY_ATTESTATION_BOOT_EPOCH_SIZE];
    sxs_u8 history_head[POLICY_ATTESTATION_HASH_SIZE];
    sxs_u64 session_counter;
    sxs_u64 active_session_counter;
    sxs_u64 next_policy_alloc_index;
    sxs_u32 history_count;
    sxs_u32 generation_count;
    sxs_u32 pending_attestation_length;
    sxs_u32 pending_attestation_offset;
    sxs_u8 session_mode;
    sxs_u8 session_established;
    sxs_u8 pending_session_response_valid;
    sxs_u8 pending_attestation_valid;
    struct meta_history_record history[META_MAX_HISTORY_RECORDS];
    struct meta_generation_record
        generations[META_MAX_GENERATION_RECORDS];
    struct meta_installed_policy
        installed[POLICY_ATTESTATION_MAX_POLICIES];
};

static struct meta_state state;
static sxs_u8 work_buffer[META_WORK_BYTES];
static sxs_u8 attestation_buffer[META_ATTESTATION_BYTES];

static void bytes_zero(void *destination, sxs_u32 length)
{
    sxs_u8 *bytes = destination;

    for (sxs_u32 i = 0; i < length; i++) {
        bytes[i] = 0;
    }
}

static void bytes_copy(void *destination, const void *source, sxs_u32 length)
{
    sxs_u8 *output = destination;
    const sxs_u8 *input = source;

    for (sxs_u32 i = 0; i < length; i++) {
        output[i] = input[i];
    }
}

static sxs_s32 bytes_equal(const void *left, const void *right,
                           sxs_u32 length)
{
    const sxs_u8 *a = left;
    const sxs_u8 *b = right;
    sxs_u8 difference = 0;

    for (sxs_u32 i = 0; i < length; i++) {
        difference |= a[i] ^ b[i];
    }
    return difference == 0;
}

static sxs_u32 string_length(const char *value)
{
    sxs_u32 length = 0;

    while (value[length]) {
        length++;
    }
    return length;
}

static void encode_u32_le(sxs_u32 value, sxs_u8 output[4])
{
    for (sxs_u32 i = 0; i < 4; i++) {
        output[i] = (sxs_u8)(value >> (8U * i));
    }
}

static sxs_u32 decode_u32_le(const sxs_u8 input[4])
{
    sxs_u32 value = 0;

    for (sxs_u32 i = 0; i < 4; i++) {
        value |= (sxs_u32)input[i] << (8U * i);
    }
    return value;
}

static void encode_u64_le(sxs_u64 value, sxs_u8 output[8])
{
    for (sxs_u32 i = 0; i < 8; i++) {
        output[i] = (sxs_u8)(value >> (8U * i));
    }
}

static sxs_u64 decode_u64_le(const sxs_u8 input[8])
{
    sxs_u64 value = 0;

    for (sxs_u32 i = 0; i < 8; i++) {
        value |= (sxs_u64)input[i] << (8U * i);
    }
    return value;
}

static sxs_u64 complete(sxs_u32 status)
{
    return sxs_completion_status_set(status) == 0
               ? 0
               : SXS_WASM_ACTION_ERROR;
}

static sxs_s32 sha256_parts(const sxs_u8 *first, sxs_u32 first_length,
                            const sxs_u8 *second, sxs_u32 second_length,
                            const sxs_u8 *third, sxs_u32 third_length,
                            sxs_u8 output[32])
{
    sxs_u8 input[160];
    sxs_u32 total = first_length + second_length + third_length;
    sxs_u32 offset = 0;

    if (total > sizeof(input)) {
        return -SXS_WASM_EOVERFLOW;
    }
    if (first_length) {
        bytes_copy(input + offset, first, first_length);
        offset += first_length;
    }
    if (second_length) {
        bytes_copy(input + offset, second, second_length);
        offset += second_length;
    }
    if (third_length) {
        bytes_copy(input + offset, third, third_length);
    }
    return sxs_crypto_sha256(input, total, output, 32);
}

static sxs_s32 initialize_history(void)
{
    static const sxs_u8 domain[] = "SxSSD-History-Root-v1";

    return sha256_parts(domain, sizeof(domain) - 1,
                        state.boot_epoch, sizeof(state.boot_epoch),
                        0, 0, state.history_head);
}

static sxs_s32 prepare_history_record(
    sxs_u8 operation, sxs_u32 policy_id, sxs_u32 generation,
    struct meta_history_record *record, sxs_u8 next_head[32])
{
    static const sxs_u8 domain[] = "SxSSD-History-Event-v1";
    sxs_u8 encoded[8 + POLICY_ATTESTATION_HISTORY_RECORD_SIZE];

    if (!record || !next_head || policy_id == 0 || generation == 0 ||
        operation < POLICY_HISTORY_OP_INSTALL ||
        operation > POLICY_HISTORY_OP_REMOVE ||
        state.history_count >= META_MAX_HISTORY_RECORDS) {
        return -SXS_WASM_ENOSPC;
    }
    record->operation = operation;
    record->policy_id = policy_id;
    record->generation = generation;
    encode_u64_le((sxs_u64)state.history_count + 1, encoded);
    encoded[8] = operation;
    encode_u32_le(policy_id, encoded + 9);
    encode_u32_le(generation, encoded + 13);
    return sha256_parts(domain, sizeof(domain) - 1,
                        state.history_head, sizeof(state.history_head),
                        encoded, sizeof(encoded), next_head);
}

static void commit_history_record(const struct meta_history_record *record,
                                  const sxs_u8 next_head[32])
{
    bytes_copy(&state.history[state.history_count++], record,
               sizeof(*record));
    bytes_copy(state.history_head, next_head, 32);
}

static sxs_s32 find_generation(sxs_u32 policy_id)
{
    for (sxs_u32 i = 0; i < state.generation_count; i++) {
        if (state.generations[i].policy_id == policy_id) {
            return (sxs_s32)i;
        }
    }
    return -1;
}

static sxs_s32 next_generation(sxs_u32 policy_id, sxs_u32 *index,
                               sxs_u32 *generation, sxs_u8 *is_new)
{
    sxs_s32 found = find_generation(policy_id);
    sxs_u32 previous = 0;

    if (!index || !generation || !is_new) {
        return -SXS_WASM_EINVAL;
    }
    if (found >= 0) {
        *index = (sxs_u32)found;
        *is_new = 0;
        previous = state.generations[*index].last_generation;
    } else {
        if (state.generation_count >= META_MAX_GENERATION_RECORDS) {
            return -SXS_WASM_ENOSPC;
        }
        *index = state.generation_count;
        *is_new = 1;
    }
    if (previous == 0xffffffffU) {
        return -SXS_WASM_EOVERFLOW;
    }
    *generation = previous + 1;
    return 0;
}

static void commit_generation(sxs_u32 index, sxs_u8 is_new,
                              sxs_u32 policy_id, sxs_u32 generation)
{
    state.generations[index].policy_id = policy_id;
    state.generations[index].last_generation = generation;
    if (is_new) {
        state.generation_count++;
    }
}

static sxs_s32 find_policy(sxs_u32 policy_id)
{
    for (sxs_u32 i = 0; i < POLICY_ATTESTATION_MAX_POLICIES; i++) {
        if (state.installed[i].in_use &&
            state.installed[i].policy_id == policy_id) {
            return (sxs_s32)i;
        }
    }
    return -1;
}

static sxs_s32 find_free_policy(void)
{
    for (sxs_u32 i = 0; i < POLICY_ATTESTATION_MAX_POLICIES; i++) {
        if (!state.installed[i].in_use) {
            return (sxs_s32)i;
        }
    }
    return -1;
}

static sxs_s32 derive_labeled_key(const sxs_u8 base_key[32],
                                  const char *label, sxs_u8 output[32])
{
    return sxs_crypto_hkdf_sha256(base_key, 32, label,
                                  string_length(label), output, 32);
}

static void build_nonce(sxs_u64 counter, sxs_u8 nonce[12])
{
    bytes_zero(nonce, 12);
    encode_u64_le(counter, nonce + 4);
}

static sxs_s32 authenticate_request(const struct sxs_nvme_event *event,
                                    sxs_u8 **plaintext,
                                    sxs_u32 *plaintext_length)
{
    sxs_u8 header[META_ENVELOPE_HEADER_SIZE];
    sxs_u8 computed_auth[32];
    sxs_u8 key[32];
    sxs_u8 nonce[12];
    sxs_u64 counter;
    sxs_u32 length;
    sxs_s32 rc = -SXS_WASM_EINVAL;

    if (!event || !plaintext || !plaintext_length ||
        !state.session_established ||
        event->cdw12 < META_ENVELOPE_HEADER_SIZE) {
        return -SXS_WASM_EINVAL;
    }
    length = event->cdw12 - META_ENVELOPE_HEADER_SIZE;
    if (length > SXS_WASM_MAX_ARTIFACT_BYTES + 12U ||
        sxs_command_read(0, header, sizeof(header)) != 0) {
        return -SXS_WASM_EINVAL;
    }
    counter = decode_u64_le(header);
    if (counter <= state.active_session_counter) {
        return -SXS_WASM_EPERM;
    }

    if (state.session_mode == SXS_SESSION_MODE_NORMAL) {
        if (length + 9U > sizeof(work_buffer) ||
            sxs_command_read(META_ENVELOPE_HEADER_SIZE,
                             work_buffer + 9, length) != 0 ||
            derive_labeled_key(state.session_key, "meta-normal-mac",
                               key) != 0) {
            goto cleanup;
        }
        work_buffer[0] = (sxs_u8)event->opcode;
        encode_u64_le(counter, work_buffer + 1);
        if (sxs_crypto_hmac_sha256(key, 32, work_buffer, length + 9,
                                   computed_auth, 32) != 0 ||
            !bytes_equal(computed_auth, header + 8, 32)) {
            goto cleanup;
        }
        *plaintext = work_buffer + 9;
    } else if (state.session_mode == SXS_SESSION_MODE_CONFIDENTIAL) {
        if (length > sizeof(work_buffer) ||
            sxs_command_read(META_ENVELOPE_HEADER_SIZE,
                             work_buffer, length) != 0 ||
            derive_labeled_key(state.session_key, "meta-conf-aead",
                               key) != 0) {
            goto cleanup;
        }
        build_nonce(counter, nonce);
        if (sxs_crypto_aes256_gcm_decrypt(
                key, 32, nonce, sizeof(nonce), &event->opcode, 1,
                work_buffer, length, header + 8, META_GCM_TAG_SIZE,
                work_buffer, length) != 0) {
            goto cleanup;
        }
        *plaintext = work_buffer;
    } else {
        goto cleanup;
    }

    state.active_session_counter = counter;
    *plaintext_length = length;
    rc = 0;

cleanup:
    bytes_zero(key, sizeof(key));
    bytes_zero(computed_auth, sizeof(computed_auth));
    bytes_zero(nonce, sizeof(nonce));
    bytes_zero(header, sizeof(header));
    return rc;
}

static sxs_s32 storage_geometry(
    struct sxs_policy_storage_geometry *geometry)
{
    if (!geometry ||
        sxs_privileged_storage_geometry_get(geometry) != 0 ||
        geometry->channels == 0 || geometry->luns_per_channel == 0 ||
        geometry->planes_per_lun == 0 ||
        geometry->reserved_blocks_per_lun == 0 ||
        geometry->pages_per_block == 0 || geometry->page_size == 0 ||
        geometry->physical_blocks_per_plane <=
            geometry->logical_blocks_per_plane) {
        return -SXS_WASM_EIO;
    }
    return 0;
}

static sxs_s32 select_policy_blocks(
    const struct sxs_policy_storage_geometry *geometry, sxs_u32 count,
    struct sxs_physical_block *blocks)
{
    sxs_u64 per_reserved_offset;
    sxs_u64 candidates;
    sxs_u32 found = 0;

    if (!geometry || !blocks || count == 0 ||
        count > SXS_PRIVILEGED_MAX_POLICY_BLOCKS) {
        return -SXS_WASM_EINVAL;
    }
    per_reserved_offset = (sxs_u64)geometry->channels *
                          geometry->luns_per_channel *
                          geometry->planes_per_lun;
    candidates = (sxs_u64)geometry->reserved_blocks_per_lun *
                 per_reserved_offset;
    if (candidates == 0 || count > candidates) {
        return -SXS_WASM_ENOSPC;
    }

    for (sxs_u64 scan = 0; scan < candidates; scan++) {
        sxs_u64 linear =
            (state.next_policy_alloc_index + scan) % candidates;
        sxs_u32 block_offset = (sxs_u32)(linear / per_reserved_offset);
        sxs_u64 remainder = linear % per_reserved_offset;
        struct sxs_physical_block candidate;
        sxs_s32 claimed;

        candidate.channel =
            (sxs_u32)(remainder /
                      (geometry->luns_per_channel *
                       geometry->planes_per_lun));
        remainder %= (sxs_u64)geometry->luns_per_channel *
                     geometry->planes_per_lun;
        candidate.lun =
            (sxs_u32)(remainder / geometry->planes_per_lun);
        candidate.plane =
            (sxs_u32)(remainder % geometry->planes_per_lun);
        candidate.block =
            geometry->logical_blocks_per_plane + block_offset;
        if (candidate.block >= geometry->physical_blocks_per_plane) {
            continue;
        }
        claimed = sxs_privileged_block_is_claimed(&candidate);
        if (claimed < 0) {
            return claimed;
        }
        if (claimed) {
            continue;
        }
        bytes_copy(&blocks[found++], &candidate, sizeof(candidate));
        if (found == count) {
            state.next_policy_alloc_index = (linear + 1) % candidates;
            return 0;
        }
    }
    return -SXS_WASM_ENOSPC;
}

static sxs_s32 claim_blocks(const struct sxs_physical_block *blocks,
                            sxs_u32 count)
{
    sxs_u32 claimed = 0;

    while (claimed < count &&
           sxs_privileged_block_claim(&blocks[claimed]) == 0) {
        claimed++;
    }
    if (claimed == count) {
        return 0;
    }
    while (claimed) {
        claimed--;
        sxs_privileged_block_release(&blocks[claimed]);
    }
    return -SXS_WASM_EBUSY;
}

static void release_blocks(const struct sxs_physical_block *blocks,
                           sxs_u32 count)
{
    for (sxs_u32 i = 0; i < count; i++) {
        sxs_privileged_block_release(&blocks[i]);
    }
}

static sxs_s32 reclaim_storage(const struct sxs_physical_block *blocks,
                               sxs_u32 count)
{
    if (sxs_privileged_storage_erase(blocks, count) != 0) {
        return -SXS_WASM_EIO;
    }
    release_blocks(blocks, count);
    return 0;
}

static sxs_u64 install_policy(const struct sxs_nvme_event *event)
{
    struct sxs_policy_storage_geometry geometry;
    struct meta_history_record history;
    struct meta_installed_policy *record;
    sxs_u8 next_head[32];
    sxs_u8 *plaintext;
    sxs_u32 plaintext_length;
    sxs_u32 policy_id;
    sxs_u32 policy_version;
    sxs_u32 policy_size;
    sxs_u32 page_count;
    sxs_u32 block_count;
    sxs_u32 generation_index;
    sxs_u32 generation;
    sxs_u8 new_generation;
    sxs_s32 slot;

    if (authenticate_request(event, &plaintext, &plaintext_length) != 0 ||
        plaintext_length < 12) {
        return complete(NVME_INVALID_FIELD | NVME_DNR);
    }
    policy_id = decode_u32_le(plaintext);
    policy_version = decode_u32_le(plaintext + 4);
    policy_size = decode_u32_le(plaintext + 8);
    if (policy_id == 0 || policy_id >= META_POLICY_ID_LIMIT ||
        policy_version == 0 || policy_size == 0 ||
        policy_size > SXS_WASM_MAX_ARTIFACT_BYTES ||
        plaintext_length != policy_size + 12 ||
        find_policy(policy_id) >= 0 ||
        (slot = find_free_policy()) < 0 ||
        sxs_privileged_policy_validate_image(plaintext + 12,
                                              policy_size) != 0 ||
        storage_geometry(&geometry) != 0 ||
        next_generation(policy_id, &generation_index, &generation,
                        &new_generation) != 0 ||
        prepare_history_record(POLICY_HISTORY_OP_INSTALL, policy_id,
                               generation, &history, next_head) != 0) {
        return complete(NVME_INVALID_FIELD | NVME_DNR);
    }
    page_count = (policy_size + geometry.page_size - 1) /
                 geometry.page_size;
    block_count = (page_count + geometry.pages_per_block - 1) /
                  geometry.pages_per_block;
    record = &state.installed[slot];
    if (select_policy_blocks(&geometry, block_count, record->blocks) != 0 ||
        claim_blocks(record->blocks, block_count) != 0) {
        return complete(NVME_INTERNAL_DEVICE_ERROR | NVME_DNR);
    }
    if (sxs_privileged_storage_erase(record->blocks, block_count) != 0 ||
        sxs_privileged_storage_write(record->blocks, block_count,
                                     plaintext + 12, policy_size) != 0) {
        sxs_privileged_storage_erase(record->blocks, block_count);
        release_blocks(record->blocks, block_count);
        bytes_zero(record, sizeof(*record));
        return complete(NVME_DATA_TRANSFER_ERROR | NVME_DNR);
    }

    record->policy_id = policy_id;
    record->policy_version = policy_version;
    record->generation = generation;
    record->policy_size = policy_size;
    record->block_count = block_count;
    record->active = 0;
    record->in_use = 1;
    commit_generation(generation_index, new_generation, policy_id,
                      generation);
    commit_history_record(&history, next_head);
    return complete(NVME_SUCCESS);
}

static sxs_s32 authenticated_inactive_policy(
    const struct sxs_nvme_event *event, sxs_u8 **plaintext,
    sxs_u32 *plaintext_length, sxs_u32 *policy_id, sxs_u32 *slot)
{
    sxs_s32 found;

    if (authenticate_request(event, plaintext, plaintext_length) != 0 ||
        *plaintext_length < 4) {
        return -SXS_WASM_EINVAL;
    }
    *policy_id = decode_u32_le(*plaintext);
    found = find_policy(*policy_id);
    if (*policy_id == 0 || found < 0 || state.installed[found].active) {
        return -SXS_WASM_EINVAL;
    }
    *slot = (sxs_u32)found;
    return 0;
}

static sxs_u64 update_policy(const struct sxs_nvme_event *event)
{
    struct sxs_policy_storage_geometry geometry;
    struct meta_history_record history;
    struct meta_installed_policy replacement;
    struct meta_installed_policy *current;
    sxs_u8 next_head[32];
    sxs_u8 *plaintext;
    sxs_u32 plaintext_length;
    sxs_u32 policy_id;
    sxs_u32 policy_version;
    sxs_u32 policy_size;
    sxs_u32 page_count;
    sxs_u32 generation_index;
    sxs_u32 generation;
    sxs_u32 slot;
    sxs_u8 new_generation;

    bytes_zero(&replacement, sizeof(replacement));
    if (authenticated_inactive_policy(event, &plaintext, &plaintext_length,
                                      &policy_id, &slot) != 0 ||
        plaintext_length < 12) {
        return complete(NVME_INVALID_FIELD | NVME_DNR);
    }
    current = &state.installed[slot];
    policy_version = decode_u32_le(plaintext + 4);
    policy_size = decode_u32_le(plaintext + 8);
    if (policy_version == 0 || policy_size == 0 ||
        policy_size > SXS_WASM_MAX_ARTIFACT_BYTES ||
        plaintext_length != policy_size + 12 ||
        sxs_privileged_policy_validate_image(plaintext + 12,
                                              policy_size) != 0 ||
        storage_geometry(&geometry) != 0 ||
        next_generation(policy_id, &generation_index, &generation,
                        &new_generation) != 0 ||
        new_generation || generation != current->generation + 1 ||
        prepare_history_record(POLICY_HISTORY_OP_UPDATE, policy_id,
                               generation, &history, next_head) != 0) {
        return complete(NVME_INVALID_FIELD | NVME_DNR);
    }

    page_count = (policy_size + geometry.page_size - 1) /
                 geometry.page_size;
    replacement.block_count =
        (page_count + geometry.pages_per_block - 1) /
        geometry.pages_per_block;
    if (select_policy_blocks(&geometry, replacement.block_count,
                             replacement.blocks) != 0 ||
        claim_blocks(replacement.blocks, replacement.block_count) != 0) {
        return complete(NVME_INTERNAL_DEVICE_ERROR | NVME_DNR);
    }
    if (sxs_privileged_storage_erase(
            replacement.blocks, replacement.block_count) != 0 ||
        sxs_privileged_storage_write(
            replacement.blocks, replacement.block_count,
            plaintext + 12, policy_size) != 0) {
        sxs_privileged_storage_erase(replacement.blocks,
                                     replacement.block_count);
        release_blocks(replacement.blocks, replacement.block_count);
        return complete(NVME_DATA_TRANSFER_ERROR | NVME_DNR);
    }
    if (sxs_privileged_policy_can_remove(
            policy_id, current->generation) != 0 ||
        reclaim_storage(current->blocks, current->block_count) != 0) {
        reclaim_storage(replacement.blocks, replacement.block_count);
        return complete(NVME_INTERNAL_DEVICE_ERROR | NVME_DNR);
    }

    replacement.policy_id = policy_id;
    replacement.policy_version = policy_version;
    replacement.generation = generation;
    replacement.policy_size = policy_size;
    replacement.active = 0;
    replacement.in_use = 1;
    bytes_copy(current, &replacement, sizeof(replacement));
    commit_generation(generation_index, 0, policy_id, generation);
    commit_history_record(&history, next_head);
    /* The new generation is committed; old runtime resources are cleanup. */
    sxs_privileged_policy_remove(policy_id, generation - 1);
    return complete(NVME_SUCCESS);
}

static sxs_u64 remove_policy(const struct sxs_nvme_event *event)
{
    struct meta_history_record history;
    sxs_u8 next_head[32];
    sxs_u8 *plaintext;
    sxs_u32 plaintext_length;
    sxs_u32 policy_id;
    sxs_u32 slot;
    struct meta_installed_policy *record;

    if (authenticated_inactive_policy(event, &plaintext, &plaintext_length,
                                      &policy_id, &slot) != 0 ||
        plaintext_length != 4) {
        return complete(NVME_INVALID_FIELD | NVME_DNR);
    }
    record = &state.installed[slot];
    if (prepare_history_record(POLICY_HISTORY_OP_REMOVE, policy_id,
                               record->generation, &history,
                               next_head) != 0 ||
        sxs_privileged_policy_can_remove(
            policy_id, record->generation) != 0) {
        return complete(NVME_INTERNAL_DEVICE_ERROR | NVME_DNR);
    }
    if (reclaim_storage(record->blocks, record->block_count) != 0) {
        return complete(NVME_DATA_TRANSFER_ERROR | NVME_DNR);
    }
    if (sxs_privileged_policy_remove(policy_id, record->generation) != 0) {
        return complete(NVME_INTERNAL_DEVICE_ERROR | NVME_DNR);
    }
    commit_history_record(&history, next_head);
    bytes_zero(record, sizeof(*record));
    return complete(NVME_SUCCESS);
}

static sxs_u64 change_policy_activation(const struct sxs_nvme_event *event)
{
    struct meta_history_record history;
    struct meta_installed_policy *record;
    sxs_u8 next_head[32];
    sxs_u8 *plaintext;
    sxs_u32 plaintext_length;
    sxs_u32 policy_id;
    sxs_s32 slot;
    sxs_u8 operation;

    if (authenticate_request(event, &plaintext, &plaintext_length) != 0 ||
        plaintext_length != 4 ||
        (policy_id = decode_u32_le(plaintext)) == 0 ||
        (slot = find_policy(policy_id)) < 0) {
        return complete(NVME_INVALID_FIELD | NVME_DNR);
    }
    record = &state.installed[slot];
    if (event->opcode == SXS_NVME_ADMIN_ACTIVATE_POLICY) {
        if (record->active) {
            return complete(NVME_SUCCESS);
        }
        operation = POLICY_HISTORY_OP_ACTIVATE;
    } else {
        if (!record->active) {
            return complete(NVME_SUCCESS);
        }
        operation = POLICY_HISTORY_OP_DEACTIVATE;
    }
    if (prepare_history_record(operation, policy_id, record->generation,
                               &history, next_head) != 0) {
        return complete(NVME_INTERNAL_DEVICE_ERROR | NVME_DNR);
    }
    if (operation == POLICY_HISTORY_OP_ACTIVATE) {
        if (sxs_privileged_policy_activate_stored(
                record->policy_id, record->policy_version,
                record->generation, record->policy_size,
                record->blocks, record->block_count) != 0) {
            return complete(NVME_INVALID_FIELD | NVME_DNR);
        }
        record->active = 1;
    } else {
        if (sxs_privileged_policy_deactivate(policy_id) != 0) {
            return complete(NVME_INVALID_FIELD | NVME_DNR);
        }
        record->active = 0;
    }
    commit_history_record(&history, next_head);
    return complete(NVME_SUCCESS);
}

static void sort_policy_slots(sxs_u32 *slots, sxs_u32 count)
{
    for (sxs_u32 i = 1; i < count; i++) {
        sxs_u32 value = slots[i];
        sxs_u32 position = i;

        while (position &&
               state.installed[slots[position - 1]].policy_id >
                   state.installed[value].policy_id) {
            slots[position] = slots[position - 1];
            position--;
        }
        slots[position] = value;
    }
}

static sxs_s32 build_attestation(sxs_u8 report_type, sxs_u8 history_mode,
                                 sxs_u64 base_sequence,
                                 const sxs_u8 nonce[16])
{
    sxs_u32 slots[POLICY_ATTESTATION_MAX_POLICIES];
    sxs_u32 policy_count = 0;
    sxs_u32 history_start;
    sxs_u32 history_count;
    sxs_u32 entry_size;
    sxs_u32 response_length;
    sxs_u32 offset;

    for (sxs_u32 i = 0; i < POLICY_ATTESTATION_MAX_POLICIES; i++) {
        if (state.installed[i].in_use) {
            slots[policy_count++] = i;
        }
    }
    sort_policy_slots(slots, policy_count);
    if (history_mode == POLICY_ATTESTATION_HISTORY_CHECKPOINT) {
        history_start = state.history_count;
    } else if (history_mode == POLICY_ATTESTATION_HISTORY_FULL) {
        history_start = 0;
    } else if (history_mode == POLICY_ATTESTATION_HISTORY_DELTA &&
               base_sequence <= state.history_count) {
        history_start = (sxs_u32)base_sequence;
    } else {
        return -SXS_WASM_EINVAL;
    }
    history_count = state.history_count - history_start;
    entry_size =
        report_type == POLICY_ATTESTATION_REPORT_SECURITY
            ? POLICY_ATTESTATION_SECURITY_ENTRY_SIZE
            : POLICY_ATTESTATION_CONSISTENCY_ENTRY_SIZE;
    response_length = POLICY_ATTESTATION_RESPONSE_HEADER_SIZE +
                      policy_count * entry_size +
                      history_count *
                          POLICY_ATTESTATION_HISTORY_RECORD_SIZE +
                      POLICY_ATTESTATION_SIGNATURE_SIZE;
    if (response_length > sizeof(attestation_buffer)) {
        return -SXS_WASM_ENOSPC;
    }
    bytes_zero(attestation_buffer, response_length);
    attestation_buffer[0] = POLICY_ATTESTATION_FORMAT_VERSION;
    attestation_buffer[1] = report_type;
    attestation_buffer[2] = history_mode;
    attestation_buffer[3] = (sxs_u8)policy_count;
    encode_u64_le(state.history_count, attestation_buffer + 4);
    bytes_copy(attestation_buffer + 12, state.boot_epoch, 16);
    bytes_copy(attestation_buffer + 28, nonce, 16);
    bytes_copy(attestation_buffer + 44, state.history_head, 32);
    offset = POLICY_ATTESTATION_RESPONSE_HEADER_SIZE;

    for (sxs_u32 i = 0; i < policy_count; i++) {
        const struct meta_installed_policy *record =
            &state.installed[slots[i]];

        encode_u32_le(record->policy_id, attestation_buffer + offset);
        encode_u32_le(record->generation, attestation_buffer + offset + 4);
        attestation_buffer[offset + 8] = record->active;
        if (report_type == POLICY_ATTESTATION_REPORT_CONSISTENCY) {
            if (record->policy_size > sizeof(work_buffer) ||
                sxs_privileged_storage_read(
                    record->blocks, record->block_count,
                    work_buffer, record->policy_size) != 0 ||
                sxs_crypto_sha256(work_buffer, record->policy_size,
                                  attestation_buffer + offset + 9, 32) != 0) {
                return -SXS_WASM_EIO;
            }
        }
        offset += entry_size;
    }
    for (sxs_u32 i = history_start; i < state.history_count; i++) {
        attestation_buffer[offset] = state.history[i].operation;
        encode_u32_le(state.history[i].policy_id,
                      attestation_buffer + offset + 1);
        encode_u32_le(state.history[i].generation,
                      attestation_buffer + offset + 5);
        offset += POLICY_ATTESTATION_HISTORY_RECORD_SIZE;
    }
    if (sxs_privileged_device_attestation_sign(
            attestation_buffer, offset, attestation_buffer + offset,
            POLICY_ATTESTATION_SIGNATURE_SIZE) != 0) {
        return -SXS_WASM_EIO;
    }
    state.pending_attestation_length = response_length;
    state.pending_attestation_offset = 0;
    state.pending_attestation_valid = 1;
    return 0;
}

static sxs_u64 attestation_command(const struct sxs_nvme_event *event)
{
    if (event->opcode == SXS_NVME_ADMIN_ATTESTATION_FETCH) {
        sxs_u64 offset = (sxs_u64)event->cdw13 |
                         ((sxs_u64)event->cdw14 << 32);

        if (!state.pending_attestation_valid || event->cdw12 == 0 ||
            offset != state.pending_attestation_offset ||
            offset > state.pending_attestation_length ||
            event->cdw12 > state.pending_attestation_length - offset ||
            sxs_command_write(0, attestation_buffer + offset,
                              event->cdw12) != 0) {
            return complete(NVME_INVALID_FIELD | NVME_DNR);
        }
        state.pending_attestation_offset += event->cdw12;
        if (state.pending_attestation_offset ==
            state.pending_attestation_length) {
            state.pending_attestation_valid = 0;
            state.pending_attestation_length = 0;
            state.pending_attestation_offset = 0;
        }
        return complete(NVME_SUCCESS);
    }

    {
        sxs_u8 request[POLICY_ATTESTATION_DELTA_REQUEST_SIZE];
        sxs_u8 report_type;
        sxs_u8 history_mode;
        sxs_u64 base_sequence = 0;

        if ((event->cdw12 != POLICY_ATTESTATION_REQUEST_SIZE &&
             event->cdw12 != POLICY_ATTESTATION_DELTA_REQUEST_SIZE) ||
            sxs_command_read(0, request, event->cdw12) != 0) {
            return complete(NVME_INVALID_FIELD | NVME_DNR);
        }
        report_type = request[1];
        history_mode = request[2];
        if (request[0] != POLICY_ATTESTATION_FORMAT_VERSION ||
            (report_type != POLICY_ATTESTATION_REPORT_SECURITY &&
             report_type != POLICY_ATTESTATION_REPORT_CONSISTENCY) ||
            (history_mode != POLICY_ATTESTATION_HISTORY_CHECKPOINT &&
             history_mode != POLICY_ATTESTATION_HISTORY_FULL &&
             history_mode != POLICY_ATTESTATION_HISTORY_DELTA) ||
            (history_mode == POLICY_ATTESTATION_HISTORY_DELTA &&
             event->cdw12 != POLICY_ATTESTATION_DELTA_REQUEST_SIZE) ||
            (history_mode != POLICY_ATTESTATION_HISTORY_DELTA &&
             event->cdw12 != POLICY_ATTESTATION_REQUEST_SIZE)) {
            return complete(NVME_INVALID_FIELD | NVME_DNR);
        }
        if (history_mode == POLICY_ATTESTATION_HISTORY_DELTA) {
            base_sequence =
                decode_u64_le(request + POLICY_ATTESTATION_REQUEST_SIZE);
        }
        if (build_attestation(report_type, history_mode, base_sequence,
                              request + 3) != 0) {
            return complete(NVME_INTERNAL_DEVICE_ERROR | NVME_DNR);
        }
    }
    return complete(NVME_SUCCESS);
}

static void build_admin_init_message(const sxs_u8 admin_public[32],
                                     sxs_u8 mode, sxs_u64 counter,
                                     sxs_u8 output[42])
{
    output[0] = SXS_NVME_ADMIN_INIT_SESSION_SUBMIT;
    bytes_copy(output + 1, admin_public, 32);
    output[33] = mode;
    encode_u64_le(counter, output + 34);
}

static void build_device_response_message(
    const sxs_u8 admin_public[32], const sxs_u8 device_public[32],
    sxs_u8 mode, sxs_u64 counter, sxs_u8 output[74])
{
    output[0] = SXS_NVME_ADMIN_INIT_SESSION_SUBMIT;
    bytes_copy(output + 1, admin_public, 32);
    bytes_copy(output + 33, device_public, 32);
    output[65] = mode;
    encode_u64_le(counter, output + 66);
}

static sxs_u64 session_command(const struct sxs_nvme_event *event)
{
    if (event->opcode == SXS_NVME_ADMIN_INIT_SESSION_FETCH) {
        if (!state.pending_session_response_valid ||
            sxs_command_write(0, state.pending_session_response,
                              sizeof(state.pending_session_response)) != 0) {
            return complete(NVME_INVALID_FIELD | NVME_DNR);
        }
        state.pending_session_response_valid = 0;
        return complete(NVME_SUCCESS);
    }

    {
        sxs_u8 request[SXS_INIT_SESSION_REQUEST_SIZE];
        sxs_u8 admin_message[42];
        sxs_u8 response_message[74];
        sxs_u8 device_private[32];
        sxs_u8 shared_secret[32];
        sxs_u8 kdf_info[74];
        sxs_u8 mode;
        sxs_u64 counter;

        if (event->cdw12 != SXS_INIT_SESSION_REQUEST_SIZE ||
            sxs_command_read(0, request, sizeof(request)) != 0) {
            return complete(NVME_INVALID_FIELD | NVME_DNR);
        }
        mode = request[32];
        counter = decode_u64_le(request + 33);
        if ((mode != SXS_SESSION_MODE_NORMAL &&
             mode != SXS_SESSION_MODE_CONFIDENTIAL) ||
            counter <= state.session_counter) {
            return complete(NVME_INVALID_FIELD | NVME_DNR);
        }
        build_admin_init_message(request, mode, counter, admin_message);
        if (sxs_crypto_ed25519_verify(
                admin_public_key, sizeof(admin_public_key),
                admin_message, sizeof(admin_message),
                request + 41, 64) != 1 ||
            sxs_crypto_random(device_private, sizeof(device_private)) != 0 ||
            sxs_crypto_x25519_public(
                device_private, sizeof(device_private),
                state.pending_session_response, 32) != 0) {
            bytes_zero(device_private, sizeof(device_private));
            return complete(NVME_INVALID_OPCODE | NVME_DNR);
        }
        encode_u64_le(counter, state.pending_session_response + 32);
        build_device_response_message(
            request, state.pending_session_response, mode, counter,
            response_message);
        if (sxs_privileged_device_attestation_sign(
                response_message, sizeof(response_message),
                state.pending_session_response + 40, 64) != 0 ||
            sxs_crypto_x25519_shared(
                device_private, 32, request, 32,
                shared_secret, 32) != 0) {
            bytes_zero(device_private, sizeof(device_private));
            bytes_zero(shared_secret, sizeof(shared_secret));
            return complete(NVME_INTERNAL_DEVICE_ERROR | NVME_DNR);
        }
        kdf_info[0] = SXS_NVME_ADMIN_INIT_SESSION_SUBMIT;
        bytes_copy(kdf_info + 1, request, 32);
        bytes_copy(kdf_info + 33, state.pending_session_response, 32);
        kdf_info[65] = mode;
        encode_u64_le(counter, kdf_info + 66);
        if (sxs_crypto_hkdf_sha256(
                shared_secret, 32, kdf_info, sizeof(kdf_info),
                state.session_key, sizeof(state.session_key)) != 0) {
            bytes_zero(device_private, sizeof(device_private));
            bytes_zero(shared_secret, sizeof(shared_secret));
            return complete(NVME_INTERNAL_DEVICE_ERROR | NVME_DNR);
        }
        bytes_zero(device_private, sizeof(device_private));
        bytes_zero(shared_secret, sizeof(shared_secret));
        bytes_zero(kdf_info, sizeof(kdf_info));
        state.session_counter = counter;
        state.active_session_counter = 0;
        state.session_mode = mode;
        state.session_established = 1;
        state.pending_session_response_valid = 1;
        state.pending_attestation_valid = 0;
    }
    return complete(NVME_SUCCESS);
}

static sxs_s32 opcode_is_meta_interface(sxs_u32 opcode)
{
    for (sxs_u32 i = 0; i < sizeof(meta_interface_opcodes); i++) {
        if (meta_interface_opcodes[i] == opcode) {
            return 1;
        }
    }
    return 0;
}

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    bytes_zero(&state, sizeof(state));
    if (sxs_crypto_random(state.boot_epoch,
                          sizeof(state.boot_epoch)) != 0 ||
        initialize_history() != 0) {
        return -SXS_WASM_EIO;
    }
    for (sxs_u32 i = 0; i < sizeof(meta_interface_opcodes); i++) {
        sxs_u32 opcode = meta_interface_opcodes[i];

        if (sxs_subscribe(SXS_EVENT_NVME_ADMIN, opcode, opcode, 0) != 0) {
            return -SXS_WASM_EIO;
        }
    }
    return 0;
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (!opcode_is_meta_interface(pair_id) ||
        sxs_context_get(&context) != 0 ||
        context.event_kind != SXS_EVENT_NVME_ADMIN ||
        context.event.nvme.opcode != pair_id) {
        return 0;
    }
    return 1;
}

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 ||
        context.event_kind != SXS_EVENT_NVME_ADMIN ||
        context.event.nvme.opcode != pair_id) {
        return SXS_WASM_ACTION_ERROR;
    }
    switch (pair_id) {
    case SXS_NVME_ADMIN_INIT_SESSION_SUBMIT:
    case SXS_NVME_ADMIN_INIT_SESSION_FETCH:
        return session_command(&context.event.nvme);
    case SXS_NVME_ADMIN_INSTALL_POLICY:
        return install_policy(&context.event.nvme);
    case SXS_NVME_ADMIN_UPDATE_POLICY:
        return update_policy(&context.event.nvme);
    case SXS_NVME_ADMIN_REMOVE_POLICY:
        return remove_policy(&context.event.nvme);
    case SXS_NVME_ADMIN_ACTIVATE_POLICY:
    case SXS_NVME_ADMIN_DEACTIVATE_POLICY:
        return change_policy_activation(&context.event.nvme);
    case SXS_NVME_ADMIN_ATTESTATION_SUBMIT:
    case SXS_NVME_ADMIN_ATTESTATION_FETCH:
        return attestation_command(&context.event.nvme);
    default:
        return SXS_WASM_ACTION_ERROR;
    }
}
