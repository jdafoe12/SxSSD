#include "../tee/tee-v4-writeback.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct flush_log {
    uint32_t calls;
    uint32_t last_count;
    struct tee_v4_transaction_record last[4];
};

static int log_flush(void *opaque,
                     const struct tee_v4_transaction_record *records,
                     uint32_t count)
{
    struct flush_log *log = opaque;

    log->calls++;
    log->last_count = count;
    memcpy(log->last, records, sizeof(records[0]) * count);
    return 0;
}

static void test_relocation_flushes_on_batch_limit(void)
{
    struct tee_v4_writeback wb;
    struct tee_v4_transaction_record records[2];
    struct flush_log log;

    memset(&log, 0, sizeof(log));
    assert(tee_v4_writeback_init(&wb, records, 2, 1000, log_flush,
                                 &log) == 0);
    assert(tee_v4_writeback_record_relocation(&wb, 1, 2, 7, 100, 200) == 0);
    assert(log.calls == 0);
    assert(tee_v4_writeback_record_relocation(&wb, 1, 2, 8, 101, 201) == 0);

    assert(log.calls == 1);
    assert(log.last_count == 2);
    assert(log.last[0].type == TEE_V4_TRANSACTION_RELOCATION);
    assert(log.last[0].new_location == 200);
    assert(log.last[0].old_location == 100);
    assert(wb.pending_count == 0);
}

static void test_relocation_flushes_on_timeout_and_sync(void)
{
    struct tee_v4_writeback wb;
    struct tee_v4_transaction_record records[4];
    struct flush_log log;

    memset(&log, 0, sizeof(log));
    assert(tee_v4_writeback_init(&wb, records, 4, 10, log_flush, &log) == 0);
    assert(tee_v4_writeback_record_relocation(&wb, 3, 4, 5, 11, 12) == 0);
    tee_v4_writeback_advance(&wb, 9);
    assert(log.calls == 0);
    tee_v4_writeback_advance(&wb, 1);
    assert(log.calls == 1);

    assert(tee_v4_writeback_record_relocation(&wb, 3, 4, 6, 13, 14) == 0);
    assert(tee_v4_writeback_sync(&wb) == 0);
    assert(log.calls == 2);
    assert(log.last_count == 1);
    assert(log.last[0].segment_index == 6);
}

static void test_chunk_commit_flushes_immediately(void)
{
    struct tee_v4_writeback wb;
    struct tee_v4_transaction_record records[4];
    struct flush_log log;

    memset(&log, 0, sizeof(log));
    assert(tee_v4_writeback_init(&wb, records, 4, 1000, log_flush,
                                 &log) == 0);
    assert(tee_v4_writeback_commit_chunk(&wb, 9, 10) == 0);

    assert(log.calls == 1);
    assert(log.last_count == 1);
    assert(log.last[0].type == TEE_V4_TRANSACTION_CHUNK_COMMIT);
    assert(log.last[0].file_id == 9);
    assert(log.last[0].chunk_id == 10);
    assert(wb.pending_count == 0);
}

int main(void)
{
    test_relocation_flushes_on_batch_limit();
    test_relocation_flushes_on_timeout_and_sync();
    test_chunk_commit_flushes_immediately();
    puts("test_tee_v4_writeback: PASS");
    return 0;
}
