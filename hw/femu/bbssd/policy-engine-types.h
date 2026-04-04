#ifndef POLICY_ENGINE_TYPES_H
#define POLICY_ENGINE_TYPES_H

#include "../backend/ftl-backend.h"

struct bbm;
struct BbmPolicyAPI;
struct ssd;
struct FtlPolicyAPI;

#define MAX_BACKEND_EVENT_HOOKS (256)
#define MAX_PSWD_TRANSITION_HOOKS (64)
#define MAX_BACKGROUND_HOOKS (64)
#define MAX_ADMIN_HOOKS (256)

/*
 * Backend (BBM) event hook types - for policies to react to backend read/write/erase events.
 */
typedef bool (*BackendEventHookCondition)(struct FtlBackendEvent *event,
                                          struct BbmPolicyAPI *api,
                                          void *context);
typedef void (*BackendEventHookCallback)(struct FtlBackend *fb,
                                         const struct bbm *ctx,
                                         struct FtlBackendEvent *event,
                                         struct BbmPolicyAPI *api,
                                         void *context);
struct BackendEventHook {
    BackendEventHookCondition condition;
    BackendEventHookCallback callback;
    void *context;
    bool active;
};

/*
 * pSWD state transition hook types - for policies to react to FREE/OPEN/CLOSED transitions.
 */
typedef bool (*PswdTransitionHookCondition)(const struct PswdStateTransitionEvent *event,
                                            struct BbmPolicyAPI *api,
                                            void *context);
typedef void (*PswdTransitionHookCallback)(struct FtlBackend *fb,
                                           const struct bbm *ctx,
                                           const struct PswdStateTransitionEvent *event,
                                           struct BbmPolicyAPI *api,
                                           void *context);
struct PswdTransitionHook {
    PswdTransitionHookCondition condition;
    PswdTransitionHookCallback callback;
    void *context;
    bool active;
};

/*
 * Background event: triggered from FTL thread (e.g. after each I/O). Policies register
 * condition + callback; first match runs (e.g. "if should_gc do_gc").
 */
struct BackgroundEvent {
    struct ssd *ssd;
};
typedef bool (*BackgroundHookCondition)(struct ssd *ssd,
                                        struct BackgroundEvent *event,
                                        struct FtlPolicyAPI *api,
                                        void *context);
typedef void (*BackgroundHookCallback)(struct ssd *ssd,
                                       struct BackgroundEvent *event,
                                       struct FtlPolicyAPI *api,
                                       void *context);
struct BackgroundHook {
    BackgroundHookCondition condition;
    BackgroundHookCallback callback;
    void *context;
    bool active;
};

#endif /* POLICY_ENGINE_TYPES_H */
