#include "tee-v3-proof.h"
#include <string.h>
static void touch(struct tee_v3_pending_controller*c){if(c)c->last_touch_op=c->current_op;}
void tee_v3_pending_init(struct tee_v3_pending_controller*c,struct tee_v2_write_context*w,uint64_t timeout){if(!c)return;memset(c,0,sizeof(*c));c->write=w;c->timeout_ops=timeout?timeout:TEE_V3_DEFAULT_TIMEOUT_OPS;}
void tee_v3_pending_touch_metadata(struct tee_v3_pending_controller*c){touch(c);}void tee_v3_pending_touch_group(struct tee_v3_pending_controller*c){touch(c);}void tee_v3_pending_touch_arrival(struct tee_v3_pending_controller*c){touch(c);}
void tee_v3_pending_advance(struct tee_v3_pending_controller*c,uint64_t ops){if(!c)return;c->current_op+=ops;if(c->write&&c->write->active&&!c->write->active_promoted&&c->current_op-c->last_touch_op>=c->timeout_ops)tee_v2_write_abandon_active(c->write);}
void tee_v3_pending_record_error(struct tee_v3_pending_controller*c,int32_t e,uint32_t i){if(!c)return;c->has_error=true;c->last_error_code=e;c->failed_segment_index=i;}
enum tee_v3_query_result tee_v3_one_bit_proof_query(struct tee_v3_pending_controller*c,uint8_t file,uint32_t chunk,uint32_t offset,uint32_t*out,size_t cap,size_t*written,struct tee_v3_one_bit_proof*p)
{
 struct tee_v2_active_metadata*a;uint32_t i,missing=0,skip=0;size_t n=0;if(written)*written=0;if(!c||!c->write||!p||!written)return TEE_V3_QUERY_INVALID;memset(p,0,sizeof(*p));
 if(tee_v2_cache_find_passive(c->write->cache,file,chunk)){p->state=TEE_V3_PROOF_DONE;p->done_bit=1;return TEE_V3_QUERY_OK;}
 a=c->write->active;if(!a||a->file_id!=file||a->chunk_id!=chunk)return TEE_V3_QUERY_NOT_FOUND;touch(c);
 if(c->has_error){p->state=TEE_V3_PROOF_ERROR;p->last_error_code=c->last_error_code;p->failed_segment_index=c->failed_segment_index;return TEE_V3_QUERY_OK;}
 if(tee_v2_active_complete(a)){p->state=TEE_V3_PROOF_ABOUT_TO_PERSIST;p->about_to_persist=1;return TEE_V3_QUERY_OK;}
 if (!out || !cap) return TEE_V3_QUERY_INVALID;
 for (i = 0; i < a->segment_count; i++)
     if (!a->arrived[i]) missing++;
 if (offset > missing) return TEE_V3_QUERY_INVALID;
 for (i = 0; i < a->segment_count && n < cap; i++) {
     if (!a->arrived[i]) {
         if (skip++ < offset) continue;
         out[n++] = i + 1;
     }
 }
 p->state=TEE_V3_PROOF_MISSING;p->missing_count=missing;p->missing_page_count=(uint32_t)((missing+cap-1)/cap);*written=n;return TEE_V3_QUERY_OK;
}
