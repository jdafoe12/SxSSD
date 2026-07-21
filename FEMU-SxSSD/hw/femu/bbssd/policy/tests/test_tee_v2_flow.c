#include "../tee/tee-v1-guard.h"
#include "../tee/tee-v2-relocation.h"
#include "../tee/tee-v2-write.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

struct saved_segment { uint64_t location; uint8_t bytes[512]; };
static int read_saved(void *opaque,uint64_t location,uint8_t*out,size_t size)
{ struct saved_segment*s=opaque;if(location!=s->location||size!=512)return -1;memcpy(out,s->bytes,size);return 0; }
static void make_segment(uint8_t*s,uint32_t index,uint8_t fill)
{ memset(s,fill,512);s[0]=0xA7;s[1]=9;s[2]=0x33;s[3]=0x22;s[4]=0x11;s[5]=(uint8_t)index;s[6]=(uint8_t)(index>>8);s[7]=(uint8_t)(index>>16);s[8]=(uint8_t)(index>>24); }

int main(void)
{
    struct tee_v1_segment_layout v1; struct tee_v1_bitmap v1p,v1q;
    struct tee_v2_format_config cfg; struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec specs[2]; struct tee_v2_cache cache;
    struct tee_v2_write_context write; struct tee_v2_passive_metadata *passive=NULL;
    struct tee_v2_relocation_trace trace; struct saved_segment old;
    uint8_t seg[3][512],h0[32],h1[32],random[512]={0xA7}; uint32_t idx=0;

    assert(tee_v1_segment_layout_init(&v1,10000,512,4096));
    assert(tee_v1_bitmap_init(&v1p,v1.visible_segments)==0);
    assert(tee_v1_bitmap_init(&v1q,v1.visible_segments)==0);
    assert(tee_v1_check_write_allowed(&v1,&v1p,&v1q,10,1)==NVME_SUCCESS);
    tee_v1_bitmap_destroy(&v1p);tee_v1_bitmap_destroy(&v1q);

    assert(tee_v2_format_config_init(&cfg,0,4096));assert(cfg.segments_per_page==8);
    make_segment(seg[0],1,1);make_segment(seg[1],2,2);make_segment(seg[2],3,3);
    tee_v2_hmac_sha256(tee_v2_prototype_key,32,&seg[0][0],1024,h0);
    tee_v2_hmac_sha256(tee_v2_prototype_key,32,&seg[2][0],512,h1);
    specs[0]=(struct tee_v2_hmac_group_spec){1,2,h0};
    specs[1]=(struct tee_v2_hmac_group_spec){3,1,h1};
    assert(tee_v2_active_metadata_init(&active,&cfg,9,0x112233,1509,3,4,specs,2)==0);
    assert(tee_v2_cache_init(&cache,4096,8)==0);
    assert(tee_v2_write_context_init(&write,&active,&cache,4096)==0);
    assert(tee_v2_process_segment_write(&write,300,random,512,NULL,NULL)==TEE_V2_WRITE_NORMAL);
    assert(tee_v2_process_segment_write(&write,12,seg[0],512,NULL,NULL)==TEE_V2_WRITE_PENDING);
    assert(tee_v2_process_segment_write(&write,90,seg[1],512,NULL,NULL)==TEE_V2_WRITE_GROUP_VERIFIED);
    assert(tee_v2_process_segment_write(&write,44,seg[2],512,NULL,NULL)==TEE_V2_WRITE_CHUNK_COMPLETE);
    assert(tee_v2_process_segment_write(&write,100,seg[0],512,&passive,&idx)==TEE_V2_WRITE_RELOCATION);
    assert(passive && idx==1);
    old.location=12;memcpy(old.bytes,seg[0],512);
    assert(tee_v2_relocate_passive_segment(&cache,&write.pending_bitmap,passive,idx,100,
                                           seg[0],512,read_saved,&old,&trace)==TEE_V2_RELOCATED);
    assert(trace.events[0]==TEE_V2_RELOCATION_MARK_NEW && trace.events[1]==TEE_V2_RELOCATION_UNMARK_OLD);
    assert(!tee_v2_cache_is_protected(&cache,12)&&tee_v2_cache_is_protected(&cache,100));
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
    puts("test_tee_v2_flow: PASS");return 0;
}
