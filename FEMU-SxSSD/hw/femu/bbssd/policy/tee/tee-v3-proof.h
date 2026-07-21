#ifndef TEE_V3_PROOF_H
#define TEE_V3_PROOF_H
#include "tee-v2-write.h"
#include "tee-v3-read.h"
#define TEE_V3_DEFAULT_TIMEOUT_OPS 1000ULL
enum tee_v3_proof_state { TEE_V3_PROOF_DONE=1,TEE_V3_PROOF_MISSING=2,TEE_V3_PROOF_ABOUT_TO_PERSIST=3,TEE_V3_PROOF_ERROR=4 };
struct tee_v3_one_bit_proof { enum tee_v3_proof_state state;uint8_t done_bit;uint8_t about_to_persist;uint32_t missing_count;uint32_t missing_page_count;int32_t last_error_code;uint32_t failed_segment_index; };
struct tee_v3_pending_controller { struct tee_v2_write_context *write;uint64_t current_op;uint64_t last_touch_op;uint64_t timeout_ops;int32_t last_error_code;uint32_t failed_segment_index;bool has_error; };
void tee_v3_pending_init(struct tee_v3_pending_controller*,struct tee_v2_write_context*,uint64_t);
void tee_v3_pending_touch_metadata(struct tee_v3_pending_controller*);
void tee_v3_pending_touch_group(struct tee_v3_pending_controller*);
void tee_v3_pending_touch_arrival(struct tee_v3_pending_controller*);
void tee_v3_pending_advance(struct tee_v3_pending_controller*,uint64_t);
void tee_v3_pending_record_error(struct tee_v3_pending_controller*,int32_t,uint32_t);
enum tee_v3_query_result tee_v3_one_bit_proof_query(struct tee_v3_pending_controller*,uint8_t,uint32_t,uint32_t,uint32_t*,size_t,size_t*,struct tee_v3_one_bit_proof*);
#endif
