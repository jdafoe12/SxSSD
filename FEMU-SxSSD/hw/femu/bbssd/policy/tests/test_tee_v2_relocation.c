#include "../tee/tee-v2-relocation.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

struct read_fixture { uint64_t location; uint8_t bytes[512]; };
static int read_old(void *opaque, uint64_t location, uint8_t *out, size_t size)
{
    struct read_fixture *f=opaque;
    if(location!=f->location || size!=sizeof(f->bytes)) return -1;
    memcpy(out,f->bytes,size); return 0;
}

int main(void)
{
    struct tee_v2_cache cache; struct tee_v1_bitmap pending;
    struct tee_v2_passive_metadata passive={0}; uint64_t loc[1]={20};
    struct tee_v2_relocation_trace trace; struct read_fixture f={20,{0}};
    uint8_t incoming[512]={0};
    passive.file_id=1;passive.chunk_id=2;passive.segment_count=1;passive.segment_locations=loc;
    assert(tee_v2_cache_init(&cache,100,2)==0);
    assert(tee_v1_bitmap_init(&pending,100)==0);
    assert(tee_v2_cache_mark_protected(&cache,20)==0);
    memset(f.bytes,0x5A,512);memcpy(incoming,f.bytes,512);
    assert(tee_v2_relocate_passive_segment(&cache,&pending,&passive,1,30,
                                           incoming,512,read_old,&f,&trace)==TEE_V2_RELOCATED);
    assert(trace.count==2);
    assert(trace.events[0]==TEE_V2_RELOCATION_MARK_NEW);
    assert(trace.events[1]==TEE_V2_RELOCATION_UNMARK_OLD);
    assert(tee_v2_cache_is_protected(&cache,30));
    assert(!tee_v2_cache_is_protected(&cache,20));
    assert(passive.segment_locations[0]==30);

    f.location=30;memcpy(f.bytes,incoming,512);incoming[511]^=1;
    assert(tee_v2_relocate_passive_segment(&cache,&pending,&passive,1,40,
                                           incoming,512,read_old,&f,&trace)==TEE_V2_RELOCATION_CHANGED);
    assert(passive.segment_locations[0]==30 && trace.count==0);
    assert(!tee_v2_cache_is_protected(&cache,40));
    tee_v1_bitmap_destroy(&pending);tee_v2_cache_destroy(&cache);
    puts("test_tee_v2_relocation: PASS");return 0;
}
