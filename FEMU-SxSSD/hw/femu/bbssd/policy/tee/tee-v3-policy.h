#ifndef TEE_V3_POLICY_H
#define TEE_V3_POLICY_H
#include "tee-v3-storage.h"
#include "tee-v3-read.h"
#include "tee-v3-proof.h"
struct tee_v3_policy_context { struct tee_v2_write_context *write;struct tee_v3_storage *storage;struct tee_v3_pending_controller pending; };
void tee_v3_policy_context_init(struct tee_v3_policy_context*,struct tee_v2_write_context*,struct tee_v3_storage*);
int tee_v3_policy_persist_promotion(void*,const struct tee_v2_cache*,const struct tee_v2_passive_metadata*);
enum tee_v3_query_result tee_v3_policy_read_summary(struct tee_v3_policy_context*,uint8_t,uint32_t,uint32_t,struct tee_v3_read_summary*);
enum tee_v3_query_result tee_v3_policy_read_locations(struct tee_v3_policy_context*,uint8_t,uint32_t,uint32_t,uint64_t*,size_t,size_t*);
enum tee_v3_query_result tee_v3_policy_read_hmac_groups(struct tee_v3_policy_context*,uint8_t,uint32_t,uint32_t,struct tee_v3_hmac_group_item*,size_t,size_t*);
enum tee_v3_query_result tee_v3_policy_one_bit_proof(struct tee_v3_policy_context*,uint8_t,uint32_t,uint32_t,uint32_t*,size_t,size_t*,struct tee_v3_one_bit_proof*);
#endif
