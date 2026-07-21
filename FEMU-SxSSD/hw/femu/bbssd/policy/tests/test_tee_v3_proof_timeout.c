#include "../tee/tee-v3-proof.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct tee_v2_format_config cfg; struct tee_v2_active_metadata a;
    struct tee_v2_hmac_group_spec spec; struct tee_v2_cache cache;
    struct tee_v2_write_context write; struct tee_v3_pending_controller ctl;
    struct tee_v3_one_bit_proof proof; uint32_t missing[2]; size_t count;
    uint8_t hmac[32]={0}; uint64_t loc=9; struct tee_v2_passive_metadata passive={0};
    assert(tee_v2_format_config_init(&cfg,512,4096));
    spec.start_segment_index=1;spec.group_segment_count=3;spec.expected_hmac=hmac;
    assert(tee_v2_active_metadata_init(&a,&cfg,1,2,1536,3,4,&spec,1)==0);
    assert(tee_v2_cache_init(&cache,100,4)==0);
    assert(tee_v2_write_context_init(&write,&a,&cache,100)==0);
    tee_v3_pending_init(&ctl,&write,TEE_V3_DEFAULT_TIMEOUT_OPS);
    assert(tee_v3_one_bit_proof_query(&ctl,1,2,0,missing,2,&count,&proof)==TEE_V3_QUERY_OK);
    assert(proof.state==TEE_V3_PROOF_MISSING&&count==2&&missing[0]==1&&missing[1]==2&&proof.missing_count==3&&proof.missing_page_count==2);
    a.arrived[0]=a.arrived[1]=a.arrived[2]=true;a.groups[0].verified=true;
    assert(tee_v3_one_bit_proof_query(&ctl,1,2,0,missing,2,&count,&proof)==TEE_V3_QUERY_OK&&proof.state==TEE_V3_PROOF_ABOUT_TO_PERSIST&&proof.about_to_persist==1);
    tee_v3_pending_record_error(&ctl,77,3);
    assert(tee_v3_one_bit_proof_query(&ctl,1,2,0,missing,2,&count,&proof)==TEE_V3_QUERY_OK&&proof.state==TEE_V3_PROOF_ERROR&&proof.last_error_code==77&&proof.failed_segment_index==3);
    passive.file_id=1;passive.chunk_id=2;passive.segment_count=1;passive.segment_locations=&loc;
    assert(tee_v2_cache_store_passive(&cache,&passive)==0);
    assert(tee_v3_one_bit_proof_query(&ctl,1,2,0,missing,2,&count,&proof)==TEE_V3_QUERY_OK&&proof.state==TEE_V3_PROOF_DONE&&proof.done_bit==1);
    assert(tee_v3_one_bit_proof_query(&ctl,9,9,0,missing,2,&count,&proof)==TEE_V3_QUERY_NOT_FOUND);
    a.arrived[0]=false;a.pending[0]=true;a.segment_locations[0]=7;assert(tee_v1_bitmap_set(&write.pending_bitmap,7)==0);
    tee_v3_pending_touch_metadata(&ctl);tee_v3_pending_advance(&ctl,999);assert(write.active==&a);
    tee_v3_pending_touch_group(&ctl);tee_v3_pending_advance(&ctl,999);assert(write.active==&a);
    tee_v3_pending_touch_arrival(&ctl);tee_v3_pending_advance(&ctl,1000);assert(write.active==NULL&&!tee_v1_bitmap_test(&write.pending_bitmap,7));
    assert(tee_v2_cache_find_passive(&cache,1,2)!=NULL);
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);tee_v2_active_metadata_destroy(&a);
    puts("test_tee_v3_proof_timeout: PASS");return 0;
}
