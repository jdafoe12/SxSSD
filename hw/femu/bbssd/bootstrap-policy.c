#include "ftl.h"
#include "bbm.h"
#include "../backend/ftl-backend.h"  /* For BbmEvent */
#include <sys/mman.h>   /* For memfd_create */
#include <unistd.h>     /* For write, close, getpid */
#include <dlfcn.h>      /* For dlopen, dlsym */
#include <stdio.h>      /* For fprintf, printf */
#include <string.h>     /* For memcpy, memcmp, strerror */
#include <errno.h>      /* For errno */

/* Policy storage layout in reserved LPN range */
#define POLICY_METADATA_LPN_OFFSET 0        /* LPN 0: metadata page */
#define POLICY_INIT_TRIGGER_LPN_OFFSET 1    /* LPN 1: write here to trigger init */
#define POLICY_STORAGE_START_OFFSET 16      /* LPN 16+: actual .so files */
#define MAX_POLICIES 20

/* Metadata structure stored at first LPN of reserved area */
struct policy_metadata {
    uint32_t num_policies;              /* How many policies are stored */
    struct {
        uint32_t policy_id;
        uint64_t start_lpn_offset;      /* Offset from start_reserved_lpn */
        uint64_t size_in_pages;         /* How many pages this .so occupies */
        char policy_name[64];
    } policies[MAX_POLICIES];
};

struct policy_context {
    uint8_t shared_key[16];
    uint64_t start_reserved_lpn;
    uint64_t end_reserved_lpn;
    bool is_initialized;
};

/* Forward declarations for internal functions */
static bool is_event_in_reserved_range(struct policy_context *ctx, struct FtlEvent *event);
static bool default_ftl_read_condition(struct ssd *ssd, struct FtlEvent *event,
                                       struct FtlPolicyAPI *api, void *context);
static uint64_t default_ftl_read_callback(struct ssd *ssd, struct FtlEvent *event,
                                          struct FtlPolicyAPI *api, void *context);
static bool default_ftl_write_condition(struct ssd *ssd, struct FtlEvent *event,
                                        struct FtlPolicyAPI *api, void *context);
static uint64_t default_ftl_write_callback(struct ssd *ssd, struct FtlEvent *event,
                                           struct FtlPolicyAPI *api, void *context);
static bool policy_load_condition(struct ssd *ssd, struct FtlEvent *event,
                                  struct FtlPolicyAPI *api, void *context);
static uint64_t policy_load_callback(struct ssd *ssd, struct FtlEvent *event,
                                     struct FtlPolicyAPI *api, void *context);
static bool policy_init_condition(struct ssd *ssd, struct FtlEvent *event,
                                  struct FtlPolicyAPI *api, void *context);
static uint64_t policy_init_callback(struct ssd *ssd, struct FtlEvent *event,
                                     struct FtlPolicyAPI *api, void *context);

int init_policy(struct ssd *ssd) 
{
    struct policy_context *ctx = g_malloc0(sizeof(struct policy_context));
    uint8_t shared_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    memcpy(ctx->shared_key, shared_key, 16);
    
    /* Set up reserved LPN range (last 256 pages reserved for policy storage) */
    const struct bbm_geom *geom = ssd->bbm->geom;
    ctx->start_reserved_lpn = geom->tt_pgs_log - 256;
    ctx->end_reserved_lpn = geom->tt_pgs_log - 1;
    
    ctx->is_initialized = true;
    
    printf("[Bootstrap] Initialized with reserved range: LPN %lu-%lu\n",
           ctx->start_reserved_lpn, ctx->end_reserved_lpn);
    
    /* Register default I/O handlers (skip reserved range) */
    ftl_register_hook(ssd, default_ftl_read_condition, default_ftl_read_callback, ctx);
    ftl_register_hook(ssd, default_ftl_write_condition, default_ftl_write_callback, ctx);
    
    /* Register control channel handlers (for reserved range) */
    ftl_register_hook(ssd, policy_load_condition, policy_load_callback, ctx);
    ftl_register_hook(ssd, policy_init_condition, policy_init_callback, ctx);
    
    printf("[Bootstrap] Policy hooks registered successfully\n");
    
    return 0;
}

static bool is_event_in_reserved_range(struct policy_context *ctx, struct FtlEvent *event)
{
    return (event->start_lpn >= ctx->start_reserved_lpn && event->start_lpn <= ctx->end_reserved_lpn)
        || (event->end_lpn >= ctx->start_reserved_lpn && event->end_lpn <= ctx->end_reserved_lpn);
}

/* default read policy */

static bool default_ftl_read_condition(struct ssd *ssd, struct FtlEvent *event,
                                       struct FtlPolicyAPI *api, void *context)
{
    struct policy_context *ctx = (struct policy_context *)context;
    
    /* Handle all reads except those in reserved range */
    if (event->cmd != FTL_READ_EVENT) {
        return false;
    }
    
    return !is_event_in_reserved_range(ctx, event);
}

static uint64_t default_ftl_read_callback(struct ssd *ssd, struct FtlEvent *event,
                                          struct FtlPolicyAPI *api, void *context)
{
    return api->default_read(ssd, event->req);
}

/* default write policy */

static bool default_ftl_write_condition(struct ssd *ssd, struct FtlEvent *event,
                                        struct FtlPolicyAPI *api, void *context)
{
    struct policy_context *ctx = (struct policy_context *)context;
    
    /* Handle all writes except those in reserved range */
    if (event->cmd != FTL_WRITE_EVENT) {
        return false;
    }
    
    return !is_event_in_reserved_range(ctx, event);
}

static uint64_t default_ftl_write_callback(struct ssd *ssd, struct FtlEvent *event,
                                           struct FtlPolicyAPI *api, void *context)
{
    return api->default_write(ssd, event->req);
}

/* Basic write policy for loading policies into the reserved range */

static bool policy_load_condition(struct ssd *ssd, struct FtlEvent *event,
                                  struct FtlPolicyAPI *api, void *context)
{
    struct policy_context *ctx = (struct policy_context *)context;
    
    /* Handle writes to the reserved range (but not the init trigger LPN) */
    if (event->cmd != FTL_WRITE_EVENT) {
        return false;
    }
    
    uint64_t trigger_lpn = ctx->start_reserved_lpn + POLICY_INIT_TRIGGER_LPN_OFFSET;
    
    /* Allow writes to reserved area for storing .so files and metadata */
    bool in_reserved = is_event_in_reserved_range(ctx, event);
    bool is_trigger = (event->start_lpn == trigger_lpn);
    
    return in_reserved && !is_trigger;
}

static uint64_t policy_load_callback(struct ssd *ssd, struct FtlEvent *event,
                                     struct FtlPolicyAPI *api, void *context)
{
    /* Simply write the .so binary data to the reserved area using default write */
    printf("[Bootstrap] Storing policy data at LPN %lu-%lu\n", 
           event->start_lpn, event->end_lpn);
    
    /* Use default write to actually store the data */
    return api->default_write(ssd, event->req);
}

/* Basic write policy for initializing loaded policies */

static bool policy_init_condition(struct ssd *ssd, struct FtlEvent *event,
                                  struct FtlPolicyAPI *api, void *context)
{
    struct policy_context *ctx = (struct policy_context *)context;
    
    /* Only trigger on write to the special init trigger LPN */
    if (event->cmd != FTL_WRITE_EVENT) {
        return false;
    }
    
    uint64_t trigger_lpn = ctx->start_reserved_lpn + POLICY_INIT_TRIGGER_LPN_OFFSET;
    return (event->start_lpn == trigger_lpn);
}

static uint64_t policy_init_callback(struct ssd *ssd, struct FtlEvent *event,
                                     struct FtlPolicyAPI *api, void *context)
{
    struct policy_context *ctx = (struct policy_context *)context;
    
    printf("[Bootstrap] Policy initialization triggered!\n");
    
    /* Step 1: Read the metadata to find all stored policies */
    uint64_t metadata_lpn = ctx->start_reserved_lpn + POLICY_METADATA_LPN_OFFSET;
    const struct bbm_geom *geom = ssd->bbm->geom;
    const struct ssdparams *sp = &ssd->fb->sp;
    size_t page_size = geom->secs_per_pg * sp->secsz;
    
    /* Allocate buffer for metadata */
    uint8_t *meta_buffer = g_malloc0(page_size);
    
    /* Get the physical address for the metadata LPN */
    PseudoPpa meta_ppa = api->get_maptbl_ent(ssd, metadata_lpn);
    
    /* Read metadata directly from physical storage */
    struct BbmEvent read_event = {0};
    int ret = api->bbm_api->raw_read(ssd->fb, ssd->bbm, meta_buffer, 
                                      &meta_ppa, 1, page_size, &read_event);
    if (ret != 0) {
        fprintf(stderr, "[Bootstrap] Failed to read policy metadata (ret=%d)\n", ret);
        g_free(meta_buffer);
        return 0;
    }
    
    struct policy_metadata *meta = (struct policy_metadata *)meta_buffer;
    printf("[Bootstrap] Found %u policies to initialize\n", meta->num_policies);
    
    /* Step 2: For each stored policy, load and initialize it */
    for (uint32_t i = 0; i < meta->num_policies && i < MAX_POLICIES; i++) {
        uint64_t policy_start_lpn = ctx->start_reserved_lpn + meta->policies[i].start_lpn_offset;
        uint64_t policy_pages = meta->policies[i].size_in_pages;
        
        printf("[Bootstrap] Loading policy '%s' (ID=%u, %lu pages at LPN %lu)\n",
               meta->policies[i].policy_name,
               meta->policies[i].policy_id,
               policy_pages,
               policy_start_lpn);
        
        /* Allocate buffer for the .so file */
        size_t so_size = policy_pages * page_size;
        uint8_t *so_buffer = g_malloc0(so_size);
        
        /* Read all pages of the .so file from storage using raw reads */
        for (uint64_t page = 0; page < policy_pages; page++) {
            uint64_t current_lpn = policy_start_lpn + page;
            
            /* Get physical address for this LPN */
            PseudoPpa ppa = api->get_maptbl_ent(ssd, current_lpn);
            
            /* Read directly from physical storage */
            struct BbmEvent page_event = {0};
            int page_ret = api->bbm_api->raw_read(ssd->fb, ssd->bbm,
                                                   so_buffer + (page * page_size),
                                                   &ppa, 1, page_size, &page_event);
            if (page_ret != 0) {
                fprintf(stderr, "[Bootstrap] Failed to read page %lu (ret=%d)\n", 
                        page, page_ret);
            }
        }
        
        /* Create anonymous memory file descriptor (no filesystem needed!) */
        char memfd_name[64];
        snprintf(memfd_name, sizeof(memfd_name), "policy_%u", 
                 meta->policies[i].policy_id);
        
        int memfd = memfd_create(memfd_name, MFD_CLOEXEC);
        if (memfd < 0) {
            fprintf(stderr, "[Bootstrap] memfd_create failed: %s\n", strerror(errno));
            g_free(so_buffer);
            continue;
        }
        
        /* Write .so contents to the memory file descriptor */
        ssize_t written = write(memfd, so_buffer, so_size);
        if (written != (ssize_t)so_size) {
            fprintf(stderr, "[Bootstrap] Failed to write to memfd (wrote %zd of %zu bytes)\n",
                    written, so_size);
            close(memfd);
            g_free(so_buffer);
            continue;
        }
        
        /* Build path to the memfd via /proc/self/fd */
        char memfd_path[64];
        snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%d", memfd);
        
        /* Load with dlopen - completely in memory, no filesystem needed! */
        void *handle = dlopen(memfd_path, RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "[Bootstrap] dlopen failed: %s\n", dlerror());
            close(memfd);
            g_free(so_buffer);
            continue;
        }
        
        /* Find and call init_policy function */
        typedef int (*policy_init_fn)(struct ssd *, struct FtlPolicyAPI *);
        policy_init_fn init_fn = (policy_init_fn)dlsym(handle, "init_policy");
        
        if (!init_fn) {
            fprintf(stderr, "[Bootstrap] Policy '%s' missing init_policy symbol: %s\n",
                    meta->policies[i].policy_name, dlerror());
            dlclose(handle);
            close(memfd);
            g_free(so_buffer);
            continue;
        }
        
        /* Call the policy's initialization function */
        int result = init_fn(ssd, api);
        if (result == 0) {
            printf("[Bootstrap] Successfully initialized policy '%s'\n",
                   meta->policies[i].policy_name);
        } else {
            fprintf(stderr, "[Bootstrap] Policy '%s' init failed with code %d\n",
                    meta->policies[i].policy_name, result);
        }
        
        /* TODO: Store handle and memfd for later cleanup if needed */
        /* For now, keep them open as long as FEMU runs */
        
        g_free(so_buffer);
    }
    
    g_free(meta_buffer);
    printf("[Bootstrap] Policy initialization complete!\n");
    
    return 0;  /* No latency for control operations */
}