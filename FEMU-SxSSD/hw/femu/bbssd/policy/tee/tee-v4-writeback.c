#include "tee-v4-writeback.h"

#include <stdlib.h>
#include <string.h>

static int flush_pending(struct tee_v4_writeback *writeback)
{
    int rc;
    uint32_t total_count;
    struct tee_v4_transaction_record *combined = NULL;

    if (!writeback ||
        (writeback->pending_count == 0 && !writeback->pending_commit_valid)) {
        return 0;
    }
    if (!writeback->flush) {
        return -1;
    }
    if (writeback->pending_commit_valid) {
        if (writeback->pending_count == UINT32_MAX ||
            (size_t)writeback->pending_count + 1U >
                SIZE_MAX / sizeof(*combined)) {
            return -1;
        }
        total_count = writeback->pending_count + 1U;
        combined = malloc((size_t)total_count * sizeof(*combined));
        if (!combined) return -1;
        if (writeback->pending_count) {
            memcpy(combined, writeback->pending,
                   (size_t)writeback->pending_count * sizeof(*combined));
        }
        combined[writeback->pending_count] = writeback->pending_commit;
        rc = writeback->flush(writeback->flush_opaque, combined, total_count);
        free(combined);
    } else {
        rc = writeback->flush(writeback->flush_opaque, writeback->pending,
                              writeback->pending_count);
    }
    if (rc != 0) {
        return rc;
    }
    writeback->pending_count = 0;
    writeback->pending_commit_valid = false;
    memset(&writeback->pending_commit, 0, sizeof(writeback->pending_commit));
    writeback->first_pending_op = 0;
    return 0;
}

int tee_v4_writeback_init(struct tee_v4_writeback *writeback,
                          struct tee_v4_transaction_record *records,
                          uint32_t capacity, uint64_t timeout_ops,
                          tee_v4_writeback_flush_fn flush,
                          void *flush_opaque)
{
    if (!writeback || !records || capacity == 0 || !flush) {
        return -1;
    }
    memset(writeback, 0, sizeof(*writeback));
    writeback->pending = records;
    writeback->pending_capacity = capacity;
    writeback->timeout_ops =
        timeout_ops ? timeout_ops : TEE_V4_DEFAULT_RELOCATION_TIMEOUT_OPS;
    writeback->next_transaction_id = 1;
    writeback->flush = flush;
    writeback->flush_opaque = flush_opaque;
    return 0;
}

int tee_v4_writeback_reserve_relocation(struct tee_v4_writeback *writeback,
                                        uint8_t file_id, uint32_t chunk_id,
                                        uint32_t segment_index,
                                        uint64_t old_location,
                                        uint64_t new_location)
{
    struct tee_v4_transaction_record *record;

    if (!writeback || writeback->pending_commit_valid ||
        writeback->pending_count >= writeback->pending_capacity) {
        return -1;
    }
    if (writeback->pending_count == 0) {
        writeback->first_pending_op = writeback->current_op;
    }
    record = &writeback->pending[writeback->pending_count++];
    memset(record, 0, sizeof(*record));
    record->type = TEE_V4_TRANSACTION_RELOCATION;
    record->transaction_id = writeback->next_transaction_id++;
    record->state = TEE_V4_TRANSACTION_PREPARED;
    record->file_id = file_id;
    record->chunk_id = chunk_id;
    record->segment_index = segment_index;
    record->old_location = old_location;
    record->new_location = new_location;

    return 0;
}

int tee_v4_writeback_record_relocation(struct tee_v4_writeback *writeback,
                                       uint8_t file_id, uint32_t chunk_id,
                                       uint32_t segment_index,
                                       uint64_t old_location,
                                       uint64_t new_location)
{
    int result = tee_v4_writeback_reserve_relocation(
        writeback, file_id, chunk_id, segment_index, old_location,
        new_location);
    if (result != 0) return result;
    return writeback->pending_count == writeback->pending_capacity ?
           flush_pending(writeback) : 0;
}

int tee_v4_writeback_cancel_reserved(struct tee_v4_writeback *writeback,
                                     uint32_t count)
{
    if (!writeback || count > writeback->pending_count) return -1;
    writeback->pending_count -= count;
    if (writeback->pending_count == 0 && !writeback->pending_commit_valid) {
        writeback->first_pending_op = 0;
    }
    return 0;
}

int tee_v4_writeback_commit_chunk(struct tee_v4_writeback *writeback,
                                  uint8_t file_id, uint32_t chunk_id)
{
    struct tee_v4_transaction_record *record;

    if (!writeback || !writeback->flush || writeback->pending_commit_valid) {
        return -1;
    }
    if (writeback->pending_count == 0) {
        writeback->first_pending_op = writeback->current_op;
    }
    record = &writeback->pending_commit;
    memset(record, 0, sizeof(*record));
    record->type = TEE_V4_TRANSACTION_CHUNK_COMMIT;
    record->transaction_id = writeback->next_transaction_id++;
    record->state = TEE_V4_TRANSACTION_PREPARED;
    record->file_id = file_id;
    record->chunk_id = chunk_id;
    writeback->pending_commit_valid = true;
    return flush_pending(writeback);
}

int tee_v4_writeback_advance(struct tee_v4_writeback *writeback,
                             uint64_t ops)
{
    if (!writeback) {
        return -1;
    }
    writeback->current_op += ops;
    if (writeback->pending_count == writeback->pending_capacity ||
        ((writeback->pending_count > 0 || writeback->pending_commit_valid) &&
         writeback->current_op - writeback->first_pending_op >=
            writeback->timeout_ops)) {
        return flush_pending(writeback);
    }
    return 0;
}

int tee_v4_writeback_sync(struct tee_v4_writeback *writeback)
{
    return flush_pending(writeback);
}
