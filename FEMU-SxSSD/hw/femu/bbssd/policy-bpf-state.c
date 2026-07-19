#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "policy-bpf-state.h"
#include "policy/policy-bpf-abi.h"

#include <openssl/crypto.h>

struct pe_policy_state_object {
    uint32_t object_id;
    uint32_t element_size;
    uint64_t element_count;
    uint32_t flags;
    uint64_t bytes;
    uint8_t *data;
};

struct pe_policy_state_store {
    struct pe_policy_state_object objects[SXS_BPF_MAX_STATE_OBJECTS];
    uint32_t object_count;
    uint64_t bytes;
};

struct pe_policy_state_transaction {
    struct pe_policy_state_store *base;
    struct pe_policy_state_object staged[SXS_BPF_MAX_STATE_OBJECTS];
    uint32_t staged_count;
    uint64_t staged_bytes;
    uint64_t *global_bytes;
    QemuMutex *global_lock;
};

static void state_object_release(struct pe_policy_state_object *object)
{
    if (!object || !object->data) {
        return;
    }
    if (object->flags & SXS_BPF_STATE_SECRET) {
        OPENSSL_cleanse(object->data, object->bytes);
    }
    g_free(object->data);
    memset(object, 0, sizeof(*object));
}

static struct pe_policy_state_object *
state_store_find(struct pe_policy_state_store *store, uint32_t object_id)
{
    uint32_t i;

    if (!store || object_id == 0) {
        return NULL;
    }
    for (i = 0; i < store->object_count; i++) {
        if (store->objects[i].object_id == object_id) {
            return &store->objects[i];
        }
    }
    return NULL;
}

static const struct pe_policy_state_object *
state_store_find_const(const struct pe_policy_state_store *store,
                       uint32_t object_id)
{
    return state_store_find((struct pe_policy_state_store *)store, object_id);
}

static struct pe_policy_state_object *
state_transaction_find_staged(struct pe_policy_state_transaction *transaction,
                              uint32_t object_id)
{
    uint32_t i;

    if (!transaction) {
        return NULL;
    }
    for (i = 0; i < transaction->staged_count; i++) {
        if (transaction->staged[i].object_id == object_id) {
            return &transaction->staged[i];
        }
    }
    return NULL;
}

static const struct pe_policy_state_object *
state_find_const(const struct pe_policy_state_store *store,
                 const struct pe_policy_state_transaction *transaction,
                 uint32_t object_id)
{
    const struct pe_policy_state_object *object;

    object = state_store_find_const(store, object_id);
    if (object) {
        return object;
    }
    return state_transaction_find_staged(
        (struct pe_policy_state_transaction *)transaction, object_id);
}

static int state_access_offset(const struct pe_policy_state_object *object,
                               uint64_t index, uint32_t element_offset,
                               uint32_t length, uint64_t *offset_out)
{
    uint64_t element_base;

    if (!object || !offset_out || index >= object->element_count ||
        element_offset > object->element_size ||
        length > object->element_size - element_offset) {
        return -SXS_BPF_EINVAL;
    }
    if (index > UINT64_MAX / object->element_size) {
        return -SXS_BPF_EOVERFLOW;
    }
    element_base = index * object->element_size;
    if (element_base > object->bytes ||
        element_offset > object->bytes - element_base ||
        length > object->bytes - element_base - element_offset) {
        return -SXS_BPF_EOVERFLOW;
    }
    *offset_out = element_base + element_offset;
    return 0;
}

static int state_fill(struct pe_policy_state_object *object, uint64_t value)
{
    uint64_t encoded = cpu_to_le64(value);
    uint64_t offset;

    if (!object || object->element_size % sizeof(value) != 0) {
        return -SXS_BPF_EINVAL;
    }
    for (offset = 0; offset < object->bytes; offset += sizeof(value)) {
        memcpy(object->data + offset, &encoded, sizeof(encoded));
    }
    return 0;
}

struct pe_policy_state_store *pe_policy_state_store_create(void)
{
    return g_new0(struct pe_policy_state_store, 1);
}

void pe_policy_state_store_destroy(struct pe_policy_state_store *store,
                                   uint64_t *global_bytes,
                                   QemuMutex *global_lock)
{
    uint32_t i;

    if (!store) {
        return;
    }
    for (i = 0; i < store->object_count; i++) {
        state_object_release(&store->objects[i]);
    }
    if (global_bytes) {
        if (global_lock) {
            qemu_mutex_lock(global_lock);
        }
        g_assert(*global_bytes >= store->bytes);
        *global_bytes -= store->bytes;
        if (global_lock) {
            qemu_mutex_unlock(global_lock);
        }
    }
    g_free(store);
}

uint64_t pe_policy_state_store_bytes(const struct pe_policy_state_store *store)
{
    return store ? store->bytes : 0;
}

struct pe_policy_state_transaction *
pe_policy_state_transaction_begin(struct pe_policy_state_store *base,
                                  uint64_t *global_bytes,
                                  QemuMutex *global_lock)
{
    struct pe_policy_state_transaction *transaction;

    if (!global_bytes) {
        return NULL;
    }
    transaction = g_new0(struct pe_policy_state_transaction, 1);
    transaction->base = base;
    transaction->global_bytes = global_bytes;
    transaction->global_lock = global_lock;
    return transaction;
}

void pe_policy_state_transaction_abort(
    struct pe_policy_state_transaction *transaction)
{
    uint32_t i;

    if (!transaction) {
        return;
    }
    for (i = 0; i < transaction->staged_count; i++) {
        state_object_release(&transaction->staged[i]);
    }
    if (transaction->global_bytes) {
        if (transaction->global_lock) {
            qemu_mutex_lock(transaction->global_lock);
        }
        g_assert(*transaction->global_bytes >= transaction->staged_bytes);
        *transaction->global_bytes -= transaction->staged_bytes;
        if (transaction->global_lock) {
            qemu_mutex_unlock(transaction->global_lock);
        }
    }
    g_free(transaction);
}

int pe_policy_state_transaction_commit(
    struct pe_policy_state_transaction *transaction,
    struct pe_policy_state_store **store_out)
{
    struct pe_policy_state_store *store;
    uint32_t i;

    if (!transaction || !store_out) {
        return -1;
    }
    store = transaction->base;
    if (!store) {
        store = pe_policy_state_store_create();
        if (!store) {
            return -1;
        }
    }
    if (store->object_count + transaction->staged_count >
        SXS_BPF_MAX_STATE_OBJECTS) {
        if (!transaction->base) {
            g_free(store);
        }
        return -1;
    }
    for (i = 0; i < transaction->staged_count; i++) {
        store->objects[store->object_count++] = transaction->staged[i];
        memset(&transaction->staged[i], 0,
               sizeof(transaction->staged[i]));
    }
    store->bytes += transaction->staged_bytes;
    transaction->staged_count = 0;
    transaction->staged_bytes = 0;
    *store_out = store;
    g_free(transaction);
    return 0;
}

int64_t pe_policy_state_create(struct pe_policy_state_transaction *transaction,
                               uint32_t object_id, uint32_t element_size,
                               uint64_t element_count, uint32_t flags,
                               uint64_t initial_u64)
{
    struct pe_policy_state_object *existing;
    struct pe_policy_state_object *object;
    uint64_t bytes;
    uint64_t base_bytes;
    int64_t rc;

    if (!transaction || object_id == 0 || element_size == 0 ||
        element_size > SXS_BPF_MAX_STATE_ELEMENT_BYTES || element_count == 0 ||
        (flags & ~(SXS_BPF_STATE_INIT_U64 | SXS_BPF_STATE_SECRET)) != 0) {
        return -SXS_BPF_EINVAL;
    }
    if (transaction->global_lock) {
        qemu_mutex_lock(transaction->global_lock);
    }
    existing = state_store_find(transaction->base, object_id);
    if (!existing) {
        existing = state_transaction_find_staged(transaction, object_id);
    }
    if (existing) {
        if (existing->element_size != element_size ||
            existing->element_count != element_count ||
            existing->flags != flags) {
            rc = -SXS_BPF_EINVAL;
        } else {
            rc = 0;
        }
        goto out;
    }
    if (element_count > UINT64_MAX / element_size) {
        rc = -SXS_BPF_EOVERFLOW;
        goto out;
    }
    bytes = element_count * element_size;
    base_bytes = pe_policy_state_store_bytes(transaction->base);
    if (bytes > SXS_BPF_MAX_STATE_BYTES_PER_POLICY ||
        base_bytes > SXS_BPF_MAX_STATE_BYTES_PER_POLICY - bytes ||
        transaction->staged_bytes >
            SXS_BPF_MAX_STATE_BYTES_PER_POLICY - base_bytes - bytes) {
        rc = -SXS_BPF_ENOSPC;
        goto out;
    }

    if ((transaction->base ? transaction->base->object_count : 0) +
            transaction->staged_count >= SXS_BPF_MAX_STATE_OBJECTS) {
        rc = -SXS_BPF_ENOSPC;
        goto out;
    }
    if (*transaction->global_bytes > SXS_BPF_MAX_STATE_BYTES_GLOBAL - bytes) {
        rc = -SXS_BPF_ENOSPC;
        goto out;
    }

    object = &transaction->staged[transaction->staged_count];
    object->data = g_try_malloc0(bytes);
    if (!object->data) {
        rc = -SXS_BPF_ENOMEM;
        goto out;
    }
    object->object_id = object_id;
    object->element_size = element_size;
    object->element_count = element_count;
    object->flags = flags;
    object->bytes = bytes;
    if ((flags & SXS_BPF_STATE_INIT_U64) && state_fill(object, initial_u64) != 0) {
        state_object_release(object);
        rc = -SXS_BPF_EINVAL;
        goto out;
    }

    transaction->staged_count++;
    transaction->staged_bytes += bytes;
    *transaction->global_bytes += bytes;
    rc = 0;

out:
    if (transaction->global_lock) {
        qemu_mutex_unlock(transaction->global_lock);
    }
    return rc;
}

int64_t pe_policy_state_read(const struct pe_policy_state_store *store,
                             const struct pe_policy_state_transaction *transaction,
                             uint32_t object_id, uint64_t index,
                             uint32_t element_offset, void *destination,
                             uint32_t length)
{
    const struct pe_policy_state_object *object;
    uint64_t offset;
    int rc;

    if (!destination && length != 0) {
        return -SXS_BPF_EINVAL;
    }
    object = state_find_const(store, transaction, object_id);
    if (!object) {
        return -SXS_BPF_ENOENT;
    }
    rc = state_access_offset(object, index, element_offset, length, &offset);
    if (rc != 0) {
        return rc;
    }
    memcpy(destination, object->data + offset, length);
    return 0;
}

int64_t pe_policy_state_write(struct pe_policy_state_store *store,
                              struct pe_policy_state_transaction *transaction,
                              bool init_phase, uint32_t object_id,
                              uint64_t index, uint32_t element_offset,
                              const void *source, uint32_t length)
{
    struct pe_policy_state_object *object;
    uint64_t offset;
    int rc;

    if (!source && length != 0) {
        return -SXS_BPF_EINVAL;
    }
    if (init_phase) {
        object = state_transaction_find_staged(transaction, object_id);
    } else {
        object = state_store_find(store, object_id);
    }
    if (!object) {
        return init_phase ? -SXS_BPF_EPERM : -SXS_BPF_ENOENT;
    }
    rc = state_access_offset(object, index, element_offset, length, &offset);
    if (rc != 0) {
        return rc;
    }
    memcpy(object->data + offset, source, length);
    return 0;
}

int64_t pe_policy_state_fill_u64(
    struct pe_policy_state_store *store,
    struct pe_policy_state_transaction *transaction, bool init_phase,
    uint32_t object_id, uint64_t value)
{
    struct pe_policy_state_object *object;

    if (init_phase) {
        object = state_transaction_find_staged(transaction, object_id);
    } else {
        object = state_store_find(store, object_id);
    }
    if (!object) {
        return init_phase ? -SXS_BPF_EPERM : -SXS_BPF_ENOENT;
    }
    return state_fill(object, value);
}
