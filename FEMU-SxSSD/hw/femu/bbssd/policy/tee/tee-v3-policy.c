#include "tee-v3-policy.h"
#include <stdlib.h>
#include <string.h>
void tee_v3_policy_context_init(struct tee_v3_policy_context*c,struct tee_v2_write_context*w,struct tee_v3_storage*s){memset(c,0,sizeof(*c));c->write=w;c->storage=s;tee_v3_pending_init(&c->pending,w,TEE_V3_DEFAULT_TIMEOUT_OPS);}
int tee_v3_policy_persist_promotion(void*opaque,const struct tee_v2_cache*cache,const struct tee_v2_passive_metadata*passive)
{
 struct tee_v3_policy_context*c=opaque;struct tee_v1_bitmap bitmap={0};uint32_t i;int rc=-1;
 if(!c||!c->storage||!cache||!passive||tee_v1_bitmap_init(&bitmap,cache->protected_bitmap.bit_count)!=0)return-1;
 memcpy(bitmap.bits,cache->protected_bitmap.bits,(size_t)bitmap.byte_count);for(i=0;i<passive->segment_count;i++)if(tee_v1_bitmap_set(&bitmap,passive->segment_locations[i])!=0)goto out;
 if(cache->passive_count==0||cache->passive_records[cache->passive_count-1].file_id!=passive->file_id||cache->passive_records[cache->passive_count-1].chunk_id!=passive->chunk_id)goto out;
 rc=tee_v3_storage_persist(c->storage,&bitmap,cache->passive_records,cache->passive_count);if(rc!=0)tee_v3_pending_record_error(&c->pending,rc,0);
out:tee_v1_bitmap_destroy(&bitmap);return rc;
}
static struct tee_v2_passive_metadata*find(struct tee_v3_policy_context*c,uint8_t f,uint32_t k){return c&&c->write?tee_v2_cache_find_passive(c->write->cache,f,k):NULL;}
enum tee_v3_query_result tee_v3_policy_read_summary(struct tee_v3_policy_context*c,uint8_t f,uint32_t k,uint32_t p,struct tee_v3_read_summary*o){return tee_v3_read_summary(find(c,f,k),p,o);}
enum tee_v3_query_result tee_v3_policy_read_locations(struct tee_v3_policy_context*c,uint8_t f,uint32_t k,uint32_t off,uint64_t*o,size_t cap,size_t*w){return tee_v3_read_locations(find(c,f,k),off,o,cap,w);}
enum tee_v3_query_result tee_v3_policy_read_hmac_groups(struct tee_v3_policy_context*c,uint8_t f,uint32_t k,uint32_t off,struct tee_v3_hmac_group_item*o,size_t cap,size_t*w){return tee_v3_read_hmac_groups(find(c,f,k),off,o,cap,w);}
enum tee_v3_query_result tee_v3_policy_one_bit_proof(struct tee_v3_policy_context*c,uint8_t f,uint32_t k,uint32_t off,uint32_t*o,size_t cap,size_t*w,struct tee_v3_one_bit_proof*p){return c?tee_v3_one_bit_proof_query(&c->pending,f,k,off,o,cap,w,p):TEE_V3_QUERY_INVALID;}
