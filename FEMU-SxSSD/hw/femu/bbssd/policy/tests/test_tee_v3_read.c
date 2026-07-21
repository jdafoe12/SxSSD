#include "../tee/tee-v3-read.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    uint64_t locations[] = {101,102,103,104,105};
    struct tee_v2_hmac_group_state groups[2] = {0};
    struct tee_v2_passive_metadata p = {0};
    struct tee_v3_read_summary s;
    struct tee_v3_hmac_group_item gi[1];
    uint64_t out[2]; size_t count;
    p.file_id=3;p.chunk_id=7;p.chunk_size_bytes=2500;p.segment_count=5;
    p.number_coefficient=11;p.segment_locations=locations;p.group_count=2;p.groups=groups;
    groups[0].start_segment_index=1;groups[0].group_segment_count=3;memset(groups[0].expected_hmac,0xaa,32);
    groups[1].start_segment_index=4;groups[1].group_segment_count=2;memset(groups[1].expected_hmac,0xbb,32);
    assert(tee_v3_normal_read_allowed(0,100));
    assert(tee_v3_read_summary(&p,16,&s)==TEE_V3_QUERY_OK);
    assert(s.chunk_size_bytes==2500&&s.segment_count==5&&s.number_coefficient==11);
    assert(s.location_item_count==5&&s.location_item_size==sizeof(uint64_t)&&s.location_page_count==3);
    assert(s.hmac_group_count==2&&s.hmac_group_item_size==sizeof(struct tee_v3_hmac_group_item)&&s.hmac_group_page_count==5);
    assert(tee_v3_read_locations(&p,2,out,2,&count)==TEE_V3_QUERY_OK&&count==2&&out[0]==103&&out[1]==104);
    assert(tee_v3_read_locations(&p,4,out,2,&count)==TEE_V3_QUERY_OK&&count==1&&out[0]==105);
    assert(tee_v3_read_hmac_groups(&p,1,gi,1,&count)==TEE_V3_QUERY_OK&&count==1);
    assert(gi[0].start_segment_index==4&&gi[0].group_segment_count==2&&gi[0].expected_hmac[0]==0xbb);
    assert(tee_v3_read_locations(NULL,0,out,2,&count)==TEE_V3_QUERY_NOT_FOUND);
    assert(tee_v3_read_locations(&p,6,out,2,&count)==TEE_V3_QUERY_INVALID);
    puts("test_tee_v3_read: PASS"); return 0;
}
