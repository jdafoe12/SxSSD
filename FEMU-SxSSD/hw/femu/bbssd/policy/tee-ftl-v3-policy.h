#ifndef TEE_FTL_V3_POLICY_H
#define TEE_FTL_V3_POLICY_H
#include "tee-ftl-v2-policy.h"
#include "tee/tee-v3-policy.h"
enum tee_v3_query_result tee_v3_policy_query_summary(uint8_t,uint32_t,uint32_t,struct tee_v3_read_summary*);
enum tee_v3_query_result tee_v3_policy_query_locations(uint8_t,uint32_t,uint32_t,uint64_t*,size_t,size_t*);
enum tee_v3_query_result tee_v3_policy_query_hmac_groups(uint8_t,uint32_t,uint32_t,struct tee_v3_hmac_group_item*,size_t,size_t*);
enum tee_v3_query_result tee_v3_policy_query_one_bit_proof(uint8_t,uint32_t,uint32_t,uint32_t*,size_t,size_t*,struct tee_v3_one_bit_proof*);
#endif
