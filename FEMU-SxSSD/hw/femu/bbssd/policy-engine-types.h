#ifndef POLICY_ENGINE_TYPES_H
#define POLICY_ENGINE_TYPES_H

#define MAX_BACKEND_EVENT_HOOKS (256)
#define MAX_PSWD_TRANSITION_HOOKS (64)
#define MAX_BACKGROUND_HOOKS (64)
#define MAX_ADMIN_HOOKS (256)

/*
 * Privilege changes only the host functions a policy may import.  Origin is
 * independent: it records who owns the artifact and therefore its lifecycle.
 */
enum pe_policy_privilege {
    PE_PRIVILEGE_NORMAL = 0,
    PE_PRIVILEGE_PRIVILEGED,
};

enum pe_policy_origin {
    PE_ORIGIN_STORED = 0,
    PE_ORIGIN_FIRMWARE,
};

#endif /* POLICY_ENGINE_TYPES_H */
