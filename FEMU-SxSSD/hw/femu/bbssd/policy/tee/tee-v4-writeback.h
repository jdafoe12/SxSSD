#ifndef TEE_V4_WRITEBACK_H
#define TEE_V4_WRITEBACK_H

#include <stdbool.h>
#include <stdint.h>

#define TEE_V4_DEFAULT_RELOCATION_BATCH_MAX 64U
#define TEE_V4_DEFAULT_RELOCATION_TIMEOUT_OPS 1000ULL

enum tee_v4_transaction_type {
    TEE_V4_TRANSACTION_CHUNK_COMMIT = 1,
    TEE_V4_TRANSACTION_RELOCATION = 2
};

enum tee_v4_transaction_state {
    TEE_V4_TRANSACTION_PREPARED = 1,
    TEE_V4_TRANSACTION_PERSISTED = 2
};

struct tee_v4_transaction_record {
    enum tee_v4_transaction_type type;
    uint64_t transaction_id;
    enum tee_v4_transaction_state state;
    uint8_t file_id;
    uint32_t chunk_id;
    uint32_t segment_index;
    uint64_t old_location;
    uint64_t new_location;
};

typedef int (*tee_v4_writeback_flush_fn)(
    void *opaque, const struct tee_v4_transaction_record *records,
    uint32_t count);

struct tee_v4_writeback {
    struct tee_v4_transaction_record *pending;
    uint32_t pending_count;
    uint32_t pending_capacity;
    uint64_t timeout_ops;
    uint64_t current_op;
    uint64_t first_pending_op;
    uint64_t next_transaction_id;
    tee_v4_writeback_flush_fn flush;
    void *flush_opaque;
    bool pending_commit_valid;
    struct tee_v4_transaction_record pending_commit;
};

int tee_v4_writeback_init(struct tee_v4_writeback *writeback,
                          struct tee_v4_transaction_record *records,
                          uint32_t capacity, uint64_t timeout_ops,
                          tee_v4_writeback_flush_fn flush,
                          void *flush_opaque);
int tee_v4_writeback_record_relocation(struct tee_v4_writeback *writeback,
                                       uint8_t file_id, uint32_t chunk_id,
                                       uint32_t segment_index,
                                       uint64_t old_location,
                                       uint64_t new_location);
int tee_v4_writeback_reserve_relocation(struct tee_v4_writeback *writeback,
                                        uint8_t file_id, uint32_t chunk_id,
                                        uint32_t segment_index,
                                        uint64_t old_location,
                                        uint64_t new_location);
int tee_v4_writeback_cancel_reserved(struct tee_v4_writeback *writeback,
                                     uint32_t count);
int tee_v4_writeback_commit_chunk(struct tee_v4_writeback *writeback,
                                  uint8_t file_id, uint32_t chunk_id);
int tee_v4_writeback_advance(struct tee_v4_writeback *writeback,
                             uint64_t ops);
int tee_v4_writeback_sync(struct tee_v4_writeback *writeback);

#endif
