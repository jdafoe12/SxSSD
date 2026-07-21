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

static void test_media_completion_requires_all_bytes_and_pages(void)
{
    assert(tee_v2_media_write_complete(2,2,4096,4096));
    assert(!tee_v2_media_write_complete(2,1,4096,4096));
    assert(!tee_v2_media_write_complete(2,2,4096,2048));
}

static void test_failed_media_does_not_publish_active_state(void)
{
    struct tee_v2_format_config config; struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec spec; struct tee_v2_cache cache;
    struct tee_v2_write_context write; uint8_t s[512], expected[32];
    segment(s,1,0x77);tee_v2_hmac_sha256(tee_v2_prototype_key,32,s,512,expected);
    assert(tee_v2_format_config_init(&config,512,4096));
    spec=(struct tee_v2_hmac_group_spec){1,1,expected};
    assert(tee_v2_active_metadata_init(&active,&config,8,0x010203,503,1,1,&spec,1)==0);
    assert(tee_v2_cache_init(&cache,1000,2)==0);
    assert(tee_v2_write_context_init(&write,&active,&cache,1000)==0);
    assert(tee_v2_apply_segment_after_media(&write,false,700,s,512)==TEE_V2_WRITE_ERROR);
    assert(!active.arrived[0] && !tee_v1_bitmap_test(&write.pending_bitmap,700));
    assert(!tee_v2_cache_is_protected(&cache,700));
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}

struct promotion_log { int calls; int fail; int saw_staged; };
static int promotion_probe(void *opaque, const struct tee_v2_cache *cache,
                           const struct tee_v2_passive_metadata *passive)
{
    struct promotion_log *log=opaque; log->calls++;
    log->saw_staged=tee_v2_cache_find_passive((struct tee_v2_cache *)cache,
                                               passive->file_id,
                                               passive->chunk_id)!=NULL;
    return log->fail ? -1 : 0;
}

static void test_promotion_stages_before_hook_and_rolls_back(void)
{
    struct tee_v2_format_config cfg; struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec spec; struct tee_v2_cache cache;
    struct tee_v2_write_context write; struct promotion_log log={0,1,0};
    uint8_t s[512],hmac[32];
    segment(s,1,0x81);tee_v2_hmac_sha256(tee_v2_prototype_key,32,s,512,hmac);
    assert(tee_v2_format_config_init(&cfg,512,4096));
    spec=(struct tee_v2_hmac_group_spec){1,1,hmac};
    assert(tee_v2_active_metadata_init(&active,&cfg,8,0x010203,512,1,1,&spec,1)==0);
    assert(tee_v2_cache_init(&cache,1000,1)==0);
    assert(tee_v2_write_context_init(&write,&active,&cache,1000)==0);
    tee_v2_write_set_promotion_hook(&write,promotion_probe,&log);
    assert(tee_v2_process_segment_write(&write,80,s,512,NULL,NULL)==TEE_V2_WRITE_ERROR);
    assert(log.calls==1 && log.saw_staged);
    assert(cache.passive_count==0);
    assert(!write.active_promoted);
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}

static void test_cache_full_prevents_durable_hook(void)
{
    struct tee_v2_format_config cfg; struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec spec; struct tee_v2_cache cache;
    struct tee_v2_write_context write; struct promotion_log log={0,0,0};
    struct tee_v2_passive_metadata occupied={0}; uint64_t occupied_location=7;
    uint8_t s[512],hmac[32];
    segment(s,1,0x82);tee_v2_hmac_sha256(tee_v2_prototype_key,32,s,512,hmac);
    assert(tee_v2_format_config_init(&cfg,512,4096));
    spec=(struct tee_v2_hmac_group_spec){1,1,hmac};
    assert(tee_v2_active_metadata_init(&active,&cfg,8,0x010203,512,1,1,&spec,1)==0);
    assert(tee_v2_cache_init(&cache,1000,1)==0);
    occupied.file_id=7;occupied.chunk_id=9;occupied.segment_count=1;
    occupied.segment_locations=&occupied_location;
    assert(tee_v2_cache_store_passive(&cache,&occupied)==0);
    assert(tee_v2_write_context_init(&write,&active,&cache,1000)==0);
    tee_v2_write_set_promotion_hook(&write,promotion_probe,&log);
    assert(tee_v2_process_segment_write(&write,81,s,512,NULL,NULL)==TEE_V2_WRITE_ERROR);
    assert(log.calls==0);
    assert(cache.passive_count==1);
    assert(tee_v2_cache_find_passive(&cache,7,9)!=NULL);
    assert(tee_v2_cache_find_passive(&cache,8,0x010203)==NULL);
    tee_v2_write_context_destroy(&write);tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}

int main(void){test_normal_and_guard_paths();test_active_group_and_promotion();test_hmac_failure_becomes_normal();test_preflight_is_non_mutating_and_abandon_clears_pending();test_range_guard();test_request_preflight_rejects_duplicate_active_index();test_request_preflight_rejects_duplicate_relocation();test_page_expanded_guard();test_media_completion_requires_all_bytes_and_pages();test_failed_media_does_not_publish_active_state();test_promotion_stages_before_hook_and_rolls_back();test_cache_full_prevents_durable_hook();puts("test_tee_v2_write: PASS");return 0;}
