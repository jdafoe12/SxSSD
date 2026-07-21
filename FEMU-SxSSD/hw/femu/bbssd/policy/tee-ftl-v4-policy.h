#ifndef TEE_FTL_V4_POLICY_H
#define TEE_FTL_V4_POLICY_H

#include "tee/tee-v4-admin-format.h"

struct ssd;
struct FtlPolicyAPI;

/* Initialize the inherited V1-V4 data path without claiming admin opcodes. */
int tee_v4_policy_state_init(struct ssd *ssd, struct FtlPolicyAPI *api);

#endif
