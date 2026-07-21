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

static void test_preflight_is_non_mutating_and_abandon_clears_pending(void)
{
    struct tee_v2_format_config config; struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec spec; struct tee_v2_cache cache;
    struct tee_v2_write_context write; uint8_t s[512], expected[32];
    segment(s,1,0x44);
    tee_v2_hmac_sha256(tee_v2_prototype_key,32,s,512,expected);
    assert(tee_v2_format_config_init(&config,512,4096));
    spec=(struct tee_v2_hmac_group_spec){1,1,expected};
    assert(tee_v2_active_metadata_init(&active,&config,8,0x010203,503,1,1,&spec,1)==0);
    assert(tee_v2_cache_init(&cache,1000,2)==0);
    assert(tee_v2_write_context_init(&write,&active,&cache,1000)==0);
    assert(tee_v2_classify_segment_write(&write,400,s,512,NULL,NULL)==TEE_V2_WRITE_PENDING);
    assert(!active.arrived[0] && !tee_v1_bitmap_test(&write.pending_bitmap,400));
    assert(tee_v2_process_segment_write(&write,400,s,512,NULL,NULL)==TEE_V2_WRITE_CHUNK_COMPLETE);
    assert(tee_v2_cache_is_protected(&cache,400));
    tee_v2_write_abandon_active(&write);
    assert(write.active==NULL);
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}

static void test_range_guard(void)
{
    struct tee_v2_cache cache; struct tee_v2_write_context write;
    assert(tee_v2_cache_init(&cache,100,2)==0);
    assert(tee_v2_write_context_init(&write,NULL,&cache,100)==0);
    assert(tee_v2_write_range_allowed(&write,10,4));
    assert(tee_v2_cache_mark_protected(&cache,12)==0);
    assert(!tee_v2_write_range_allowed(&write,10,4));
    assert(tee_v2_cache_unmark_protected(&cache,12)==0);
    assert(tee_v1_bitmap_set(&write.pending_bitmap,13)==0);
    assert(!tee_v2_write_range_allowed(&write,10,4));
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);
}

static void test_request_preflight_rejects_duplicate_active_index(void)
{
    struct tee_v2_format_config config; struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec spec; struct tee_v2_cache cache;
    struct tee_v2_write_context write; uint8_t s[2][512], expected[32];
    enum tee_v2_write_result results[2];
    struct tee_v2_passive_metadata *passives[2]; uint32_t indices[2];
    segment(s[0],1,0x55);memcpy(s[1],s[0],512);
    tee_v2_hmac_sha256(tee_v2_prototype_key,32,s[0],512,expected);
    assert(tee_v2_format_config_init(&config,512,4096));
    spec=(struct tee_v2_hmac_group_spec){1,1,expected};
    assert(tee_v2_active_metadata_init(&active,&config,8,0x010203,503,1,1,&spec,1)==0);
    assert(tee_v2_cache_init(&cache,1000,2)==0);
    assert(tee_v2_write_context_init(&write,&active,&cache,1000)==0);
    assert(tee_v2_preflight_segment_request(&write,500,&s[0][0],512,2,
                                             results,passives,indices)==-1);
    assert(!active.arrived[0] && !tee_v1_bitmap_test(&write.pending_bitmap,500));
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}

static void test_request_preflight_rejects_duplicate_relocation(void)
{
    struct tee_v2_cache cache; struct tee_v2_write_context write;
    struct tee_v2_passive_metadata passive={0}; uint64_t location=20;
    uint8_t s[2][512]; enum tee_v2_write_result results[2];
    struct tee_v2_passive_metadata *passives[2]; uint32_t indices[2];
    passive.file_id=8;passive.chunk_id=0x010203;passive.segment_count=1;
    passive.segment_locations=&location;
    segment(s[0],1,0x66);memcpy(s[1],s[0],512);
    assert(tee_v2_cache_init(&cache,1000,2)==0);
    assert(tee_v2_cache_store_passive(&cache,&passive)==0);
    assert(tee_v2_write_context_init(&write,NULL,&cache,1000)==0);
    assert(!tee_v2_write_can_activate_identity(&write,8,0x010203));
    assert(tee_v2_write_can_activate_identity(&write,8,0x010204));
    assert(tee_v2_preflight_segment_request(&write,600,&s[0][0],512,2,
                                             results,passives,indices)==-1);
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);
}

static void test_page_expanded_guard(void)
{
    struct tee_v2_cache cache; struct tee_v2_write_context write;
    assert(tee_v2_cache_init(&cache,32,2)==0);
    assert(tee_v2_write_context_init(&write,NULL,&cache,32)==0);
    assert(tee_v2_cache_mark_protected(&cache,15)==0);
    assert(!tee_v2_write_page_range_allowed(&write,8,1,8));
    assert(tee_v2_write_page_range_allowed(&write,16,1,8));
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);
}

int main(void){test_normal_and_guard_paths();test_active_group_and_promotion();test_hmac_failure_becomes_normal();test_preflight_is_non_mutating_and_abandon_clears_pending();test_range_guard();test_request_preflight_rejects_duplicate_active_index();test_request_preflight_rejects_duplicate_relocation();test_page_expanded_guard();puts("test_tee_v2_write: PASS");return 0;}
