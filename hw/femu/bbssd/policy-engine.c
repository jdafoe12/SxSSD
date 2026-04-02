#include "policy-engine.h"
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*policy_init_fn)(struct ssd *ssd, struct FtlPolicyAPI *api);

struct policy_loader_ctx {
    void *dl_handle;
    int fd;
    char path[64];
};

static void print_byte_window(const char *label,
                              const uint8_t *data,
                              size_t total_len,
                              size_t start,
                              size_t len)
{
    size_t i;
    size_t end;

    if (!data || start >= total_len) {
        printf("[PolicyEngine] %s empty window start=%zu total=%zu\n",
               label, start, total_len);
        return;
    }

    end = start + len;
    if (end > total_len) {
        end = total_len;
    }

    printf("[PolicyEngine] %s window [%zu, %zu): ", label, start, end);
    for (i = start; i < end; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void debug_compare_payloads(const uint8_t *expected,
                                   const uint8_t *actual,
                                   size_t len)
{
    size_t i;

    if (!expected || !actual || len == 0) {
        return;
    }

    for (i = 0; i < len; i++) {
        if (expected[i] != actual[i]) {
            size_t window_start = (i >= 64) ? (i - 64) : 0;

            printf("[PolicyEngine] Payload mismatch at byte %zu expected=%02x actual=%02x\n",
                   i, expected[i], actual[i]);
            print_byte_window("Expected", expected, len, window_start, 160);
            print_byte_window("Actual", actual, len, window_start, 160);
            print_byte_window("Expected tail", expected, len,
                              len >= 256 ? len - 256 : 0, 256);
            print_byte_window("Actual tail", actual, len,
                              len >= 256 ? len - 256 : 0, 256);
            return;
        }
    }

    printf("[PolicyEngine] Payload compare matched for %zu bytes\n", len);
}

static int runtime_policy_slot_by_id(struct policy_engine *pe, uint32_t policy_id)
{
    int i;

    for (i = 0; i < MAX_RUNTIME_POLICIES; i++) {
        if (pe->runtime_policies[i].active &&
            pe->runtime_policies[i].policy_id == policy_id) {
            return i;
        }
    }

    return -1;
}

static int runtime_policy_free_slot(struct policy_engine *pe)
{
    int i;

    for (i = 0; i < MAX_RUNTIME_POLICIES; i++) {
        if (!pe->runtime_policies[i].active && pe->runtime_policies[i].loader_ctx == NULL) {
            return i;
        }
    }

    return -1;
}

static void runtime_policy_reset(struct runtime_policy_record *rec)
{
    if (!rec) {
        return;
    }

    memset(rec, 0, sizeof(*rec));
}

static void record_owned_hook(struct policy_engine *pe, int handle,
                              int *handle_array, int *count, int max_count)
{
    if (!pe || pe->current_loading_policy < 0 || handle < 0 ||
        !handle_array || !count || *count >= max_count) {
        return;
    }

    handle_array[(*count)++] = handle;
}

static void unregister_runtime_policy_hooks(struct policy_engine *pe,
                                            struct runtime_policy_record *rec)
{
    int i;

    for (i = rec->nvme_hook_count - 1; i >= 0; i--) {
        pe_unregister_nvme_hook(pe, rec->nvme_hook_handles[i]);
    }
    for (i = rec->backend_hook_count - 1; i >= 0; i--) {
        pe_unregister_backend_hook(pe, rec->backend_hook_handles[i]);
    }
    for (i = rec->pswd_hook_count - 1; i >= 0; i--) {
        pe_unregister_pswd_transition_hook(pe, rec->pswd_hook_handles[i]);
    }
    for (i = rec->background_hook_count - 1; i >= 0; i--) {
        pe_unregister_background_hook(pe, rec->background_hook_handles[i]);
    }

    rec->nvme_hook_count = 0;
    rec->backend_hook_count = 0;
    rec->pswd_hook_count = 0;
    rec->background_hook_count = 0;
}

static struct policy_loader_ctx *policy_loader_open_image(const uint8_t *image,
                                                          size_t image_size)
{
    int fd = -1;
    ssize_t written_total = 0;
    off_t file_size;
    struct policy_loader_ctx *loader = NULL;
    char memfd_name[64];

    if (!image) {
        return NULL;
    }

    snprintf(memfd_name, sizeof(memfd_name), "femu-policy-%d", getpid());
    fd = memfd_create(memfd_name, MFD_CLOEXEC);
    if (fd < 0) {
        perror("[PolicyEngine] memfd_create");
        return NULL;
    }

    while ((size_t)written_total < image_size) {
        ssize_t rc = write(fd, image + written_total, image_size - written_total);
        if (rc <= 0) {
            perror("[PolicyEngine] write memfd");
            close(fd);
            return NULL;
        }
        written_total += rc;
    }

    file_size = lseek(fd, 0, SEEK_END);
    if (file_size < 0) {
        perror("[PolicyEngine] lseek end");
        close(fd);
        return NULL;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("[PolicyEngine] lseek set");
        close(fd);
        return NULL;
    }

    loader = g_malloc0(sizeof(*loader));
    loader->fd = fd;
    snprintf(loader->path, sizeof(loader->path), "/proc/self/fd/%d", fd);
    loader->dl_handle = dlopen(loader->path, RTLD_NOW | RTLD_LOCAL);
    if (!loader->dl_handle) {
        printf("[PolicyEngine] dlopen failed: %s\n", dlerror());
        close(fd);
        g_free(loader);
        return NULL;
    }

    return loader;
}

static void policy_loader_close(struct policy_loader_ctx *loader)
{
    if (!loader) {
        return;
    }

    if (loader->dl_handle) {
        dlclose(loader->dl_handle);
    }
    if (loader->fd >= 0) {
        close(loader->fd);
    }
    g_free(loader);
}

int pe_read_policy_payload(struct ssd *ssd,
                           const struct policy_storage_desc *desc,
                           uint8_t **payload_out)
{
    uint32_t page_size;
    uint32_t pages_per_block;
    uint32_t page_count;
    struct ppa *ppa_list = NULL;
    uint8_t *payload = NULL;
    uint32_t i;
    int rc = -1;

    if (!ssd || !desc || !desc->blocks || !payload_out || desc->policy_size_bytes == 0) {
        return -1;
    }

    page_size = ssd->fb->sp.secs_per_pg * ssd->fb->sp.secsz;
    pages_per_block = ssd->fb->sp.pgs_per_blk;
    page_count = (desc->policy_size_bytes + page_size - 1) / page_size;

    payload = g_malloc0((size_t)page_count * page_size);
    ppa_list = g_malloc0(sizeof(struct ppa) * page_count);

    for (i = 0; i < page_count; i++) {
        uint32_t block_index = i / pages_per_block;
        uint32_t page_index = i % pages_per_block;

        if (block_index >= desc->block_count) {
            goto cleanup;
        }

        ppa_list[i].g.ch = desc->blocks[block_index].g.ch;
        ppa_list[i].g.lun = desc->blocks[block_index].g.lun;
        ppa_list[i].g.pl = desc->blocks[block_index].g.pl;
        ppa_list[i].g.blk = desc->blocks[block_index].g.blk;
        ppa_list[i].g.pg = page_index;
        ppa_list[i].g.sec = 0;
    }

    if (ftl_backend_raw_read(ssd->fb, payload, ppa_list, page_count, page_size, NULL) != 0) {
        goto cleanup;
    }

    *payload_out = payload;
    payload = NULL;
    rc = 0;

cleanup:
    g_free(ppa_list);
    g_free(payload);
    return rc;
}

static void unload_runtime_policy(struct policy_engine *pe,
                                  struct runtime_policy_record *rec)
{
    if (!pe || !rec || (!rec->active && rec->loader_ctx == NULL)) {
        return;
    }

    unregister_runtime_policy_hooks(pe, rec);

    policy_loader_close((struct policy_loader_ctx *)rec->loader_ctx);

    runtime_policy_reset(rec);
}

struct policy_engine *pe_create(void)
{
    struct policy_engine *pe = g_malloc0(sizeof(struct policy_engine));
    for (int i = 0; i < MAX_NVME_HOOKS; i++) {
        pe->nvme_hooks[i].active = false;
        pe->nvme_hooks[i].opcode = 0;
        pe->nvme_hooks[i].condition = NULL;
        pe->nvme_hooks[i].callback = NULL;
        pe->nvme_hooks[i].context = NULL;
    }
    for (int i = 0; i < MAX_BACKEND_EVENT_HOOKS; i++) {
        pe->backend_hooks[i].active = false;
        pe->backend_hooks[i].condition = NULL;
        pe->backend_hooks[i].callback = NULL;
        pe->backend_hooks[i].context = NULL;
    }
    for (int i = 0; i < MAX_PSWD_TRANSITION_HOOKS; i++) {
        pe->pswd_transition_hooks[i].active = false;
        pe->pswd_transition_hooks[i].condition = NULL;
        pe->pswd_transition_hooks[i].callback = NULL;
        pe->pswd_transition_hooks[i].context = NULL;
    }
    for (int i = 0; i < MAX_BACKGROUND_HOOKS; i++) {
        pe->background_hooks[i].active = false;
        pe->background_hooks[i].condition = NULL;
        pe->background_hooks[i].callback = NULL;
        pe->background_hooks[i].context = NULL;
    }
    pe->bbm_ctx = NULL;
    pe->current_loading_policy = -1;
    return pe;
}

void pe_set_bbm(struct policy_engine *pe, struct bbm *ctx)
{
    if (pe) {
        pe->bbm_ctx = ctx;
    }
}


uint64_t pe_dispatch_nvme_cmd(struct policy_engine *pe, struct ssd *ssd, struct NvmeCommandEvent *event)
{
    if (!pe || !ssd || !event) {
        return 0;
    }
    /* Iterate in reverse so newest-registered (policy) hooks are tried before defaults */
    for (int i = MAX_NVME_HOOKS - 1; i >= 0; i--) {
        struct NvmeHook *hook = &pe->nvme_hooks[i];
        if (!hook->active || !hook->callback || hook->opcode != event->opcode) {
            continue;
        }
        bool should_fire = (hook->condition == NULL) ||
            hook->condition(ssd, event, ssd->policy_api, hook->context);
        if (should_fire) {
            event->lat = hook->callback(ssd, event, ssd->policy_api, hook->context);
            return event->lat;
        }
    }
    /* No hook matched (e.g. unknown opcode); return 0 */
    event->lat = 0;
    return 0;
}

void pe_dispatch_backend_event(struct policy_engine *pe, struct FtlBackend *fb,
                               struct bbm *ctx, struct FtlBackendEvent *event)
{
    if (!pe || !fb || !ctx || !event) {
        return;
    }
    for (int i = 0; i < MAX_BACKEND_EVENT_HOOKS; i++) {
        struct BackendEventHook *hook = &pe->backend_hooks[i];
        if (!hook->active || !hook->callback) {
            continue;
        }
        bool should_fire = (hook->condition == NULL) ||
            hook->condition(event, ctx->policy_api, hook->context);
        if (should_fire) {
            hook->callback(fb, ctx, event, ctx->policy_api, hook->context);
        }
    }
}

void pe_dispatch_pswd_transition(struct FtlBackend *fb,
                                 const struct PswdStateTransitionEvent *event,
                                 void *notify_ctx)
{
    struct policy_engine *pe = (struct policy_engine *)notify_ctx;
    if (!pe || !fb || !event) {
        return;
    }
    struct bbm *ctx = pe->bbm_ctx;
    if (!ctx) {
        return;
    }
    for (int i = 0; i < MAX_PSWD_TRANSITION_HOOKS; i++) {
        struct PswdTransitionHook *hook = &pe->pswd_transition_hooks[i];
        if (!hook->active || !hook->callback) {
            continue;
        }
        bool should_fire = (hook->condition == NULL) ||
            hook->condition(event, ctx->policy_api, hook->context);
        if (should_fire) {
            hook->callback(fb, ctx, event, ctx->policy_api, hook->context);
        }
    }
}

void pe_dispatch_background_event(struct policy_engine *pe, struct ssd *ssd)
{
    if (!pe || !ssd) {
        return;
    }
    struct BackgroundEvent event = { .ssd = ssd };
    for (int i = 0; i < MAX_BACKGROUND_HOOKS; i++) {
        struct BackgroundHook *hook = &pe->background_hooks[i];
        if (!hook->active || !hook->callback) {
            continue;
        }
        bool should_fire = (hook->condition == NULL) ||
            hook->condition(ssd, &event, ssd->policy_api, hook->context);
        if (should_fire) {
            hook->callback(ssd, &event, ssd->policy_api, hook->context);
            return;  /* first match wins */
        }
    }
}

/* NVMe hook registration */
int pe_register_nvme_hook(struct policy_engine *pe, uint8_t opcode,
                          NvmeHookCondition condition,
                          NvmeHookCallback callback,
                          void *context)
{
    if (!pe || !callback) {
        return -1;
    }
    for (int i = 0; i < MAX_NVME_HOOKS; i++) {
        if (!pe->nvme_hooks[i].callback) {
            pe->nvme_hooks[i].opcode = opcode;
            pe->nvme_hooks[i].condition = condition;
            pe->nvme_hooks[i].callback = callback;
            pe->nvme_hooks[i].context = context;
            pe->nvme_hooks[i].active = true;
            if (pe->current_loading_policy >= 0) {
                struct runtime_policy_record *rec =
                    &pe->runtime_policies[pe->current_loading_policy];
                record_owned_hook(pe, i, rec->nvme_hook_handles,
                                  &rec->nvme_hook_count, MAX_NVME_HOOKS);
            }
            return i;
        }
    }
    return -1;
}

int pe_unregister_nvme_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_NVME_HOOKS) {
        return -1;
    }
    pe->nvme_hooks[hook_handle].active = false;
    pe->nvme_hooks[hook_handle].opcode = 0;
    pe->nvme_hooks[hook_handle].condition = NULL;
    pe->nvme_hooks[hook_handle].callback = NULL;
    pe->nvme_hooks[hook_handle].context = NULL;
    return 0;
}

int pe_inactivate_nvme_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_NVME_HOOKS) {
        return -1;
    }
    pe->nvme_hooks[hook_handle].active = false;
    return 0;
}

int pe_reactivate_nvme_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_NVME_HOOKS) {
        return -1;
    }
    if (pe->nvme_hooks[hook_handle].callback) {
        pe->nvme_hooks[hook_handle].active = true;
        return 0;
    }
    return -1;
}

/* Backend hook registration */
int pe_register_backend_hook(struct policy_engine *pe,
                             BackendEventHookCondition condition,
                             BackendEventHookCallback callback,
                             void *context)
{
    if (!pe || !callback) {
        return -1;
    }
    for (int i = 0; i < MAX_BACKEND_EVENT_HOOKS; i++) {
        if (!pe->backend_hooks[i].callback) {
            pe->backend_hooks[i].condition = condition;
            pe->backend_hooks[i].callback = callback;
            pe->backend_hooks[i].context = context;
            pe->backend_hooks[i].active = true;
            if (pe->current_loading_policy >= 0) {
                struct runtime_policy_record *rec =
                    &pe->runtime_policies[pe->current_loading_policy];
                record_owned_hook(pe, i, rec->backend_hook_handles,
                                  &rec->backend_hook_count, MAX_BACKEND_EVENT_HOOKS);
            }
            return i;
        }
    }
    return -1;
}

int pe_unregister_backend_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKEND_EVENT_HOOKS) {
        return -1;
    }
    pe->backend_hooks[hook_handle].active = false;
    pe->backend_hooks[hook_handle].condition = NULL;
    pe->backend_hooks[hook_handle].callback = NULL;
    pe->backend_hooks[hook_handle].context = NULL;
    return 0;
}

int pe_inactivate_backend_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKEND_EVENT_HOOKS) {
        return -1;
    }
    pe->backend_hooks[hook_handle].active = false;
    return 0;
}

int pe_reactivate_backend_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKEND_EVENT_HOOKS) {
        return -1;
    }
    pe->backend_hooks[hook_handle].active = true;
    return 0;
}

/* pSWD transition hook registration */
int pe_register_pswd_transition_hook(struct policy_engine *pe,
                                     PswdTransitionHookCondition condition,
                                     PswdTransitionHookCallback callback,
                                     void *context)
{
    if (!pe || !callback) {
        return -1;
    }
    for (int i = 0; i < MAX_PSWD_TRANSITION_HOOKS; i++) {
        if (!pe->pswd_transition_hooks[i].callback) {
            pe->pswd_transition_hooks[i].condition = condition;
            pe->pswd_transition_hooks[i].callback = callback;
            pe->pswd_transition_hooks[i].context = context;
            pe->pswd_transition_hooks[i].active = true;
            if (pe->current_loading_policy >= 0) {
                struct runtime_policy_record *rec =
                    &pe->runtime_policies[pe->current_loading_policy];
                record_owned_hook(pe, i, rec->pswd_hook_handles,
                                  &rec->pswd_hook_count, MAX_PSWD_TRANSITION_HOOKS);
            }
            return i;
        }
    }
    return -1;
}

int pe_unregister_pswd_transition_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_PSWD_TRANSITION_HOOKS) {
        return -1;
    }
    pe->pswd_transition_hooks[hook_handle].active = false;
    pe->pswd_transition_hooks[hook_handle].condition = NULL;
    pe->pswd_transition_hooks[hook_handle].callback = NULL;
    pe->pswd_transition_hooks[hook_handle].context = NULL;
    return 0;
}

int pe_inactivate_pswd_transition_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_PSWD_TRANSITION_HOOKS) {
        return -1;
    }
    pe->pswd_transition_hooks[hook_handle].active = false;
    return 0;
}

int pe_reactivate_pswd_transition_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_PSWD_TRANSITION_HOOKS) {
        return -1;
    }
    pe->pswd_transition_hooks[hook_handle].active = true;
    return 0;
}

/* Background hook registration */
int pe_register_background_hook(struct policy_engine *pe,
                                BackgroundHookCondition condition,
                                BackgroundHookCallback callback,
                                void *context)
{
    if (!pe || !callback) {
        return -1;
    }
    for (int i = 0; i < MAX_BACKGROUND_HOOKS; i++) {
        if (!pe->background_hooks[i].callback) {
            pe->background_hooks[i].condition = condition;
            pe->background_hooks[i].callback = callback;
            pe->background_hooks[i].context = context;
            pe->background_hooks[i].active = true;
            if (pe->current_loading_policy >= 0) {
                struct runtime_policy_record *rec =
                    &pe->runtime_policies[pe->current_loading_policy];
                record_owned_hook(pe, i, rec->background_hook_handles,
                                  &rec->background_hook_count, MAX_BACKGROUND_HOOKS);
            }
            return i;
        }
    }
    return -1;
}

int pe_unregister_background_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKGROUND_HOOKS) {
        return -1;
    }
    pe->background_hooks[hook_handle].active = false;
    pe->background_hooks[hook_handle].condition = NULL;
    pe->background_hooks[hook_handle].callback = NULL;
    pe->background_hooks[hook_handle].context = NULL;
    return 0;
}

int pe_inactivate_background_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKGROUND_HOOKS) {
        return -1;
    }
    pe->background_hooks[hook_handle].active = false;
    return 0;
}

int pe_reactivate_background_hook(struct policy_engine *pe, int hook_handle)
{
    if (!pe || hook_handle < 0 || hook_handle >= MAX_BACKGROUND_HOOKS) {
        return -1;
    }
    pe->background_hooks[hook_handle].active = true;
    return 0;
}

bool pe_has_nvme_hook(struct policy_engine *pe, uint8_t opcode)
{
    if (!pe) {
        return false;
    }
    for (int i = 0; i < MAX_NVME_HOOKS; i++) {
        if (pe->nvme_hooks[i].active && 
            pe->nvme_hooks[i].callback && 
            pe->nvme_hooks[i].opcode == opcode) {
            return true;
        }
    }
    return false;
}

int pe_activate_stored_policy(struct policy_engine *pe, struct ssd *ssd,
                              const struct policy_storage_desc *desc)
{
    int slot;
    struct runtime_policy_record *rec;
    uint8_t *payload = NULL;
    struct policy_loader_ctx *loader = NULL;
    policy_init_fn init_fn;
    int init_rc;

    if (!pe || !ssd || !desc || !desc->blocks) {
        return -1;
    }

    slot = runtime_policy_slot_by_id(pe, desc->policy_id);
    if (slot >= 0) {
        rec = &pe->runtime_policies[slot];
        return rec->active ? 0 : -1;
    }

    slot = runtime_policy_free_slot(pe);
    if (slot < 0) {
        return -1;
    }

    if (pe_read_policy_payload(ssd, desc, &payload) < 0) {
        printf("[PolicyEngine] Failed to read stored policy payload\n");
        return -1;
    }

    debug_compare_payloads(desc->expected_payload, payload, desc->policy_size_bytes);

    loader = policy_loader_open_image(payload, desc->policy_size_bytes);
    if (!loader) {
        printf("[PolicyEngine] Failed to open stored policy image\n");
        g_free(payload);
        return -1;
    }
    g_free(payload);

    init_fn = (policy_init_fn)dlsym(loader->dl_handle, "init_policy");
    if (!init_fn) {
        printf("[PolicyEngine] dlsym(init_policy) failed: %s\n", dlerror());
        policy_loader_close(loader);
        return -1;
    }

    rec = &pe->runtime_policies[slot];
    runtime_policy_reset(rec);
    rec->policy_id = desc->policy_id;
    rec->policy_version = desc->policy_version;
    rec->active = false;
    rec->loader_ctx = loader;

    pe->current_loading_policy = slot;
    init_rc = init_fn(ssd, ssd->policy_api);
    pe->current_loading_policy = -1;

    if (init_rc != 0) {
        unload_runtime_policy(pe, rec);
        return -1;
    }

    rec->active = true;
    return 0;
}

int pe_deactivate_policy(struct policy_engine *pe, uint32_t policy_id)
{
    int slot;

    if (!pe) {
        return -1;
    }

    slot = runtime_policy_slot_by_id(pe, policy_id);
    if (slot < 0) {
        return -1;
    }

    unload_runtime_policy(pe, &pe->runtime_policies[slot]);
    return 0;
}

bool pe_is_policy_active(struct policy_engine *pe, uint32_t policy_id)
{
    int slot;

    if (!pe) {
        return false;
    }

    slot = runtime_policy_slot_by_id(pe, policy_id);
    if (slot < 0) {
        return false;
    }

    return pe->runtime_policies[slot].active;
}
