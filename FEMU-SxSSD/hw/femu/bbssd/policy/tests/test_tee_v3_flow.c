#include "../tee/tee-v1-guard.h"
#include "../tee/tee-v2-hmac-group.h"
#include "../tee/tee-v2-write.h"
#include "../tee/tee-v3-policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static int write_image(void *opaque,const uint8_t *data,size_t n){struct tee_v3_memory_backend*b=opaque;if(n>b->capacity)return-1;memcpy(b->bytes,data,n);b->size=n;return 0;}
int main(void){
 struct tee_v1_segment_layout layout;struct tee_v1_bitmap base_pending;struct tee_v2_cache cache;struct tee_v2_write_context write;struct tee_v2_format_config cfg;struct tee_v2_active_metadata active;struct tee_v2_hmac_group_spec spec;struct tee_v3_storage storage;struct tee_v3_memory_backend backend;struct tee_v3_policy_context v3;struct tee_v3_read_summary summary;struct tee_v3_one_bit_proof proof;uint8_t media[4096]={0},segment[512]={0},hmac[32];size_t count;
 assert(tee_v1_segment_layout_init(&layout,200,512,8));assert(tee_v1_bitmap_init(&base_pending,layout.visible_segments)==0);assert(tee_v1_check_write_allowed(&layout,NULL,&base_pending,192,1)!=NVME_SUCCESS);
 segment[0]=TEE_V2_SEGMENT_MAGIC;segment[1]=8;segment[2]=5;segment[5]=1;tee_v2_hmac_sha256(tee_v2_prototype_key,sizeof(tee_v2_prototype_key),segment,sizeof(segment),hmac);
 assert(tee_v2_format_config_init(&cfg,512,4096));spec.start_segment_index=1;spec.group_segment_count=1;spec.expected_hmac=hmac;assert(tee_v2_active_metadata_init(&active,&cfg,8,5,512,1,3,&spec,1)==0);assert(tee_v2_cache_init(&cache,layout.visible_segments,4)==0);assert(tee_v2_write_context_init(&write,&active,&cache,layout.visible_segments)==0);
 backend.bytes=media;backend.capacity=sizeof(media);backend.size=0;assert(tee_v3_storage_init(&storage,&layout,write_image,&backend)==0);tee_v3_policy_context_init(&v3,&write,&storage);tee_v2_write_set_promotion_hook(&write,tee_v3_policy_persist_promotion,&v3);
 assert(tee_v2_process_segment_write(&write,10,segment,sizeof(segment),NULL,NULL)==TEE_V2_WRITE_CHUNK_COMPLETE);assert(backend.size&&tee_v3_storage_validate_image(media,backend.size)==0);assert(tee_v3_policy_read_summary(&v3,8,5,4096,&summary)==TEE_V3_QUERY_OK&&summary.segment_count==1);assert(tee_v3_policy_one_bit_proof(&v3,8,5,0,NULL,0,&count,&proof)==TEE_V3_QUERY_OK&&proof.done_bit==1);
 tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);tee_v2_active_metadata_destroy(&active);tee_v1_bitmap_destroy(&base_pending);puts("test_tee_v3_flow: PASS");return 0;}
