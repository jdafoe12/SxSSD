#include "femu_ftl_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct test_policy_context {
    uint64_t start_lpn;
    uint64_t end_lpn;
};

static bool is_event_in_reserved_range(struct test_policy_context *ctx, struct FtlEvent *event)
{
    return (event->start_lpn >= ctx->start_lpn && event->start_lpn <= ctx->end_lpn)
        || (event->end_lpn >= ctx->start_lpn && event->end_lpn <= ctx->end_lpn);
}

static bool test_policy_condition(struct ssd *ssd, struct FtlEvent *event, struct FtlPolicyAPI *api, void *context)
{
    struct test_policy_context *ctx = (struct test_policy_context *)context;
    printf("[Test Policy] Condition!! YAY!\n");
    bool in_reserved_range = is_event_in_reserved_range(ctx, event);
    printf("[Test Policy] in reserved range: %d\n", in_reserved_range);
    bool is_write_event = event->cmd == FTL_WRITE_EVENT;
    printf("[Test Policy] is write event: %d\n", is_write_event);
    return in_reserved_range && is_write_event;
}

static uint64_t test_policy_callback(struct ssd *ssd, struct FtlEvent *event, struct FtlPolicyAPI *api, void *context)
{
    printf("[Test Policy] Callback!! YAY!\n");

    return api->default_write(ssd, event->req);
}

int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    printf("[Test Policy] Initializing policy\n");
    struct test_policy_context *ctx = calloc(1, sizeof(struct test_policy_context));
    printf("[Test Policy] HERE!!\n");
    uint64_t tt_pgs = api->get_total_logical_pages(ssd);
    printf("[Test Policy] after get total logical pages\n");
    ctx->start_lpn = tt_pgs - 256;
    ctx->end_lpn = tt_pgs - 1;
    printf("[Test Policy] before register hook\n");
    api->register_hook(ssd, test_policy_condition, test_policy_callback, ctx);
    printf("[Test Policy] after register hook\n");
    return 0;
}