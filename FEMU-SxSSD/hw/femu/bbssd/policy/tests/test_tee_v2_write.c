#include "../tee/tee-v2-write.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void segment(uint8_t *s, uint32_t index, uint8_t fill)
{
    memset(s, fill, 512); s[0]=TEE_V2_SEGMENT_MAGIC; s[1]=8;
    s[2]=3;s[3]=2;s[4]=1;s[5]=(uint8_t)index;s[6]=(uint8_t)(index>>8);
    s[7]=(uint8_t)(index>>16);s[8]=(uint8_t)(index>>24);
}

static void test_normal_and_guard_paths(void)
{
    struct tee_v2_cache cache;
    struct tee_v2_write_context write;
    uint8_t random[512] = {0xA6};
    assert(tee_v2_cache_init(&cache, 1000, 4)==0);
    assert(tee_v2_write_context_init(&write, NULL, &cache, 1000)==0);
    assert(tee_v2_process_segment_write(&write, 10, random, 512, NULL, NULL)==TEE_V2_WRITE_NORMAL);
    assert(!tee_v1_bitmap_any_set(&cache.protected_bitmap,10,1));
    assert(!tee_v1_bitmap_any_set(&write.pending_bitmap,10,1));
    assert(tee_v2_cache_mark_protected(&cache,11)==0);
    assert(tee_v2_process_segment_write(&write,11,random,512,NULL,NULL)==TEE_V2_WRITE_REJECTED);
    assert(tee_v1_bitmap_set(&write.pending_bitmap,12)==0);
    assert(tee_v2_process_segment_write(&write,12,random,512,NULL,NULL)==TEE_V2_WRITE_REJECTED);
    tee_v2_write_context_destroy(&write); tee_v2_cache_destroy(&cache);
}

static void test_active_group_and_promotion(void)
{
    struct tee_v2_format_config config;
    struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec spec;
    struct tee_v2_cache cache;
    struct tee_v2_write_context write;
    uint8_t s[2][512], expected[32];
    segment(s[0],1,0x11); segment(s[1],2,0x22);
    tee_v2_hmac_sha256(tee_v2_prototype_key,32,&s[0][0],sizeof(s),expected);
    assert(tee_v2_format_config_init(&config,512,4096));
    spec=(struct tee_v2_hmac_group_spec){1,2,expected};
    assert(tee_v2_active_metadata_init(&active,&config,8,0x010203,1006,2,3,&spec,1)==0);
    assert(tee_v2_cache_init(&cache,1000,4)==0);
    assert(tee_v2_write_context_init(&write,&active,&cache,1000)==0);
    assert(tee_v2_process_segment_write(&write,100,s[0],512,NULL,NULL)==TEE_V2_WRITE_PENDING);
    assert(tee_v1_bitmap_test(&write.pending_bitmap,100));
    assert(tee_v2_process_segment_write(&write,200,s[1],512,NULL,NULL)==TEE_V2_WRITE_CHUNK_COMPLETE);
    assert(!tee_v1_bitmap_test(&write.pending_bitmap,100));
    assert(tee_v2_cache_is_protected(&cache,100));
    assert(tee_v2_cache_is_protected(&cache,200));
    assert(tee_v2_cache_find_passive(&cache,8,0x010203));
    tee_v2_write_context_destroy(&write); tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}

static void test_hmac_failure_becomes_normal(void)
{
    struct tee_v2_format_config config; struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec spec; struct tee_v2_cache cache;
    struct tee_v2_write_context write; uint8_t s[512], bad[32]={0};
    segment(s,1,0x33); assert(tee_v2_format_config_init(&config,512,4096));
    spec=(struct tee_v2_hmac_group_spec){1,1,bad};
    assert(tee_v2_active_metadata_init(&active,&config,8,0x010203,503,1,1,&spec,1)==0);
    assert(tee_v2_cache_init(&cache,1000,2)==0);
    assert(tee_v2_write_context_init(&write,&active,&cache,1000)==0);
    assert(tee_v2_process_segment_write(&write,300,s,512,NULL,NULL)==TEE_V2_WRITE_HMAC_FAILED_NORMAL);
    assert(!tee_v1_bitmap_test(&write.pending_bitmap,300));
    assert(!tee_v2_cache_is_protected(&cache,300));
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}

int main(void){test_normal_and_guard_paths();test_active_group_and_promotion();test_hmac_failure_becomes_normal();puts("test_tee_v2_write: PASS");return 0;}
