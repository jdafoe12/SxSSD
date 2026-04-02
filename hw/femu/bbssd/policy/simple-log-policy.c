#include "femu_policy.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct simple_log_policy_context {
    uint64_t backend_event_count;
};

static bool simple_log_backend_condition(struct FtlBackendEvent *event,
                                         struct BbmPolicyAPI *api,
                                         void *context)
{
    (void)event;
    (void)api;
    (void)context;
    return true;
}

static void simple_log_backend_callback(struct FtlBackend *fb,
                                        const struct bbm *ctx,
                                        struct FtlBackendEvent *event,
                                        struct BbmPolicyAPI *api,
                                        void *context)
{
    struct simple_log_policy_context *policy_ctx = context;

    (void)fb;
    (void)ctx;
    (void)event;
    (void)api;

    if (!policy_ctx) {
        return;
    }

    policy_ctx->backend_event_count++;
    if (policy_ctx->backend_event_count == 1 ||
        (policy_ctx->backend_event_count % 1024) == 0) {
        printf("[SimpleLogPolicy] active backend_events=%llu\n",
               (unsigned long long)policy_ctx->backend_event_count);
    }
}

int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    struct simple_log_policy_context *ctx;

    if (!ssd || !api) {
        return -1;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -1;
    }

    if (api->register_backend_hook(ssd, simple_log_backend_condition,
                                   simple_log_backend_callback, ctx) < 0) {
        free(ctx);
        return -1;
    }

    printf("[SimpleLogPolicy] initialized\n");
    return 0;
}
