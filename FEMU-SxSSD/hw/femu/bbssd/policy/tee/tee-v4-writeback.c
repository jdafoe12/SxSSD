#include "tee-v4-writeback.h"

#include <string.h>

static int flush_pending(struct tee_v4_writeback *writeback)
{
    int rc;

    if (!writeback || writeback->pending_count == 0) {
        return 0;
    }
    if (!writeback->flush) {
        return -1;
    }
    rc = writeback->flush(writeback->flush_opaque, writeback->pending,
                          writeback->pending_count);
    if (rc != 0) {
        return rc;
    }
    writeback->pending_count = 0;
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

int tee_v4_writeback_record_relocation(struct tee_v4_writeback *writeback,
                                       uint8_t file_id, uint32_t chunk_id,
                                       uint32_t segment_index,
                                       uint64_t old_location,
                                       uint64_t new_location)
{
    struct tee_v4_transaction_record *record;

    if (!writeback || writeback->pending_count >= writeback->pending_capacity) {
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

    if (writeback->pending_count == writeback->pending_capacity) {
        return flush_pending(writeback);
    }
    return 0;
}

int tee_v4_writeback_commit_chunk(struct tee_v4_writeback *writeback,
                                  uint8_t file_id, uint32_t chunk_id)
{
    struct tee_v4_transaction_record record;

    if (!writeback || !writeback->flush) {
        return -1;
    }
    memset(&record, 0, sizeof(record));
    record.type = TEE_V4_TRANSACTION_CHUNK_COMMIT;
    record.transaction_id = writeback->next_transaction_id++;
    record.state = TEE_V4_TRANSACTION_PREPARED;
    record.file_id = file_id;
    record.chunk_id = chunk_id;
    return writeback->flush(writeback->flush_opaque, &record, 1);
}

void tee_v4_writeback_advance(struct tee_v4_writeback *writeback,
                              uint64_t ops)
{
    if (!writeback) {
        return;
    }
    writeback->current_op += ops;
    if (writeback->pending_count > 0 &&
        writeback->current_op - writeback->first_pending_op >=
            writeback->timeout_ops) {
        (void)flush_pending(writeback);
    }
}

int tee_v4_writeback_sync(struct tee_v4_writeback *writeback)
{
    return flush_pending(writeback);
}
