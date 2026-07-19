#ifndef FEMU_POLICY_BPF_STATE_H
#define FEMU_POLICY_BPF_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qemu/thread.h"

struct pe_policy_state_store;
struct pe_policy_state_transaction;

struct pe_policy_state_store *pe_policy_state_store_create(void);
void pe_policy_state_store_destroy(struct pe_policy_state_store *store,
                                   uint64_t *global_bytes,
                                   QemuMutex *global_lock);
uint64_t pe_policy_state_store_bytes(const struct pe_policy_state_store *store);

struct pe_policy_state_transaction *
pe_policy_state_transaction_begin(struct pe_policy_state_store *base,
                                  uint64_t *global_bytes,
                                  QemuMutex *global_lock);
void pe_policy_state_transaction_abort(
    struct pe_policy_state_transaction *transaction);
int pe_policy_state_transaction_commit(
    struct pe_policy_state_transaction *transaction,
    struct pe_policy_state_store **store_out);

int64_t pe_policy_state_create(struct pe_policy_state_transaction *transaction,
                               uint32_t object_id, uint32_t element_size,
                               uint64_t element_count, uint32_t flags,
                               uint64_t initial_u64);
int64_t pe_policy_state_read(const struct pe_policy_state_store *store,
                             const struct pe_policy_state_transaction *transaction,
                             uint32_t object_id, uint64_t index,
                             uint32_t element_offset, void *destination,
                             uint32_t length);
int64_t pe_policy_state_write(struct pe_policy_state_store *store,
                              struct pe_policy_state_transaction *transaction,
                              bool init_phase, uint32_t object_id,
                              uint64_t index, uint32_t element_offset,
                              const void *source, uint32_t length);
int64_t pe_policy_state_fill_u64(
    struct pe_policy_state_store *store,
    struct pe_policy_state_transaction *transaction, bool init_phase,
    uint32_t object_id, uint64_t value);

#endif /* FEMU_POLICY_BPF_STATE_H */
