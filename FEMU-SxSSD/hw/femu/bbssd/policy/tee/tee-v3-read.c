#include "tee-v3-read.h"
#include <string.h>

static uint32_t pages(uint32_t count,uint32_t item,uint32_t page)
{ uint64_t bytes=(uint64_t)count*item; return (uint32_t)((bytes+page-1)/page); }
bool tee_v3_normal_read_allowed(uint64_t slba,uint64_t nlb){(void)slba;(void)nlb;return true;}
enum tee_v3_query_result tee_v3_read_summary(const struct tee_v2_passive_metadata *p,uint32_t page,struct tee_v3_read_summary *o)
{
    if(!p)return TEE_V3_QUERY_NOT_FOUND;
    if(!o||!page)return TEE_V3_QUERY_INVALID;
    memset(o,0,sizeof(*o));o->chunk_size_bytes=p->chunk_size_bytes;o->segment_count=p->segment_count;o->number_coefficient=p->number_coefficient;
    o->location_item_count=p->segment_count;o->location_item_size=sizeof(uint64_t);o->location_page_count=pages(p->segment_count,o->location_item_size,page);
    o->hmac_group_count=p->group_count;o->hmac_group_item_size=sizeof(struct tee_v3_hmac_group_item);o->hmac_group_page_count=pages(p->group_count,o->hmac_group_item_size,page);return TEE_V3_QUERY_OK;
}
enum tee_v3_query_result tee_v3_read_locations(const struct tee_v2_passive_metadata*p,uint32_t off,uint64_t*out,size_t cap,size_t*w)
{ size_t n;if(w)*w=0;if(!p)return TEE_V3_QUERY_NOT_FOUND;if(!out||!w||!cap||off>p->segment_count)return TEE_V3_QUERY_INVALID;n=p->segment_count-off;if(n>cap)n=cap;memcpy(out,p->segment_locations+off,n*sizeof(*out));*w=n;return TEE_V3_QUERY_OK; }
enum tee_v3_query_result tee_v3_read_hmac_groups(const struct tee_v2_passive_metadata*p,uint32_t off,struct tee_v3_hmac_group_item*out,size_t cap,size_t*w)
{ size_t n,i;if(w)*w=0;if(!p)return TEE_V3_QUERY_NOT_FOUND;if(!out||!w||!cap||off>p->group_count)return TEE_V3_QUERY_INVALID;n=p->group_count-off;if(n>cap)n=cap;for(i=0;i<n;i++){out[i].start_segment_index=p->groups[off+i].start_segment_index;out[i].group_segment_count=p->groups[off+i].group_segment_count;memcpy(out[i].expected_hmac,p->groups[off+i].expected_hmac,TEE_V2_HMAC_SIZE);}*w=n;return TEE_V3_QUERY_OK; }
