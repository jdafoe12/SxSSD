#include "../tee/tee-v4-writeback.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct flush_log {
    uint32_t calls;
    uint32_t last_count;
    struct tee_v4_transaction_record last[4];
    int result;
};

static int log_flush(void *opaque,
                     const struct tee_v4_transaction_record *records,
                     uint32_t count)
{
    struct flush_log *log = opaque;

    log->calls++;
    log->last_count = count;
    memcpy(log->last, records, sizeof(records[0]) * count);
    return log->result;
}

static void test_failed_sync_preserves_records_for_retry(void)
{
    struct tee_v4_writeback wb;
    struct tee_v4_transaction_record records[4];
    struct flush_log log;

    memset(&log, 0, sizeof(log));
    assert(tee_v4_writeback_init(&wb, records, 4, 1000, log_flush,
                                 &log) == 0);
    assert(tee_v4_writeback_record_relocation(&wb, 7, 9, 3, 44, 55) == 0);

    log.result = -1;
    assert(tee_v4_writeback_sync(&wb) != 0);
    assert(log.calls == 1);
    assert(wb.pending_count == 1);
    assert(wb.pending[0].old_location == 44);

    log.result = 0;
    assert(tee_v4_writeback_sync(&wb) == 0);
    assert(log.calls == 2);
    assert(wb.pending_count == 0);
}

static void test_failed_timeout_flush_preserves_records(void)
{
    struct tee_v4_writeback wb;
    struct tee_v4_transaction_record records[2];
    struct flush_log log;

    memset(&log, 0, sizeof(log));
    assert(tee_v4_writeback_init(&wb, records, 2, 5, log_flush, &log) == 0);
    assert(tee_v4_writeback_record_relocation(&wb, 2, 3, 4, 10, 20) == 0);
    log.result = -1;
    tee_v4_writeback_advance(&wb, 5);
    assert(log.calls == 1);
    assert(wb.pending_count == 1);
    assert(wb.pending[0].segment_index == 4);

    log.result = 0;
    tee_v4_writeback_advance(&wb, 1);
    assert(log.calls == 2);
    assert(wb.pending_count == 0);
}

static void test_cancel_reserved_relocations_is_atomic(void)
{
    struct tee_v4_writeback wb;
    struct tee_v4_transaction_record records[4];
    struct flush_log log;

    memset(&log, 0, sizeof(log));
    assert(tee_v4_writeback_init(&wb, records, 4, 1000, log_flush, &log) == 0);
    assert(tee_v4_writeback_reserve_relocation(&wb, 1, 2, 1, 10, 20) == 0);
    assert(tee_v4_writeback_reserve_relocation(&wb, 1, 2, 2, 11, 21) == 0);
    assert(wb.pending_count == 2);

    /* A failed post-media apply/advance must retract the whole reservation. */
    assert(tee_v4_writeback_cancel_reserved(&wb, 2) == 0);
    assert(wb.pending_count == 0);
    assert(wb.first_pending_op == 0);
    assert(log.calls == 0);
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

static void test_failed_full_batch_commit_is_retained_for_sync(void)
{
    struct tee_v4_writeback wb;
    struct tee_v4_transaction_record records[3];
    struct flush_log log;

    memset(&log,0,sizeof(log));
    assert(tee_v4_writeback_init(&wb,records,3,1000,log_flush,&log)==0);
    assert(tee_v4_writeback_reserve_relocation(&wb,1,2,1,10,20)==0);
    assert(tee_v4_writeback_reserve_relocation(&wb,1,2,2,11,21)==0);
    assert(wb.pending_count==2);
    log.result=-1;
    assert(tee_v4_writeback_commit_chunk(&wb,1,2)!=0);
    assert(log.calls==1 && log.last_count==3);
    assert(wb.pending_count==2);
    assert(wb.pending_commit_valid);
    assert(wb.pending[0].type==TEE_V4_TRANSACTION_RELOCATION);
    assert(wb.pending[1].type==TEE_V4_TRANSACTION_RELOCATION);
    assert(wb.pending_commit.type==TEE_V4_TRANSACTION_CHUNK_COMMIT);
    log.result=0;
    assert(tee_v4_writeback_sync(&wb)==0);
    assert(log.calls==2 && log.last_count==3);
    assert(log.last[2].type==TEE_V4_TRANSACTION_CHUNK_COMMIT);
    assert(wb.pending_count==0);
    assert(!wb.pending_commit_valid);
}

static void test_commit_survives_already_full_failed_batch(void)
{
    struct tee_v4_writeback wb;
    struct tee_v4_transaction_record records[2];
    struct flush_log log;

    memset(&log,0,sizeof(log));
    log.result=-1;
    assert(tee_v4_writeback_init(&wb,records,2,1000,log_flush,&log)==0);
    assert(tee_v4_writeback_record_relocation(&wb,4,5,1,30,40)==0);
    assert(tee_v4_writeback_record_relocation(&wb,4,5,2,31,41)!=0);
    assert(log.calls==1 && log.last_count==2);
    assert(wb.pending_count==2);

    /* The relocation buffer is still full. A failed commit attempt must
     * retain the commit behind those relocations instead of dropping it. */
    assert(tee_v4_writeback_commit_chunk(&wb,4,5)!=0);
    assert(wb.pending_count==2);

    log.result=0;
    assert(tee_v4_writeback_sync(&wb)==0);
    assert(log.last_count==3);
    assert(log.last[0].type==TEE_V4_TRANSACTION_RELOCATION);
    assert(log.last[0].segment_index==1);
    assert(log.last[1].type==TEE_V4_TRANSACTION_RELOCATION);
    assert(log.last[1].segment_index==2);
    assert(log.last[2].type==TEE_V4_TRANSACTION_CHUNK_COMMIT);
    assert(log.last[2].file_id==4 && log.last[2].chunk_id==5);
    assert(wb.pending_count==0);
}

int main(void)
{
    test_relocation_flushes_on_batch_limit();
    test_relocation_flushes_on_timeout_and_sync();
    test_chunk_commit_flushes_immediately();
    test_commit_survives_already_full_failed_batch();
    test_failed_full_batch_commit_is_retained_for_sync();
    test_failed_sync_preserves_records_for_retry();
    test_failed_timeout_flush_preserves_records();
    test_cancel_reserved_relocations_is_atomic();
    puts("test_tee_v4_writeback: PASS");
    return 0;
}
