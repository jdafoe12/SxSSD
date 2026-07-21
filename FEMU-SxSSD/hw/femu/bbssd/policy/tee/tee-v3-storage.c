#include "tee-v3-storage.h"

#include <stdlib.h>
#include <string.h>

#define HEADER_SIZE 24U
#define RECORD_SIZE 25U
#define GROUP_SIZE (8U + TEE_V2_HMAC_SIZE)

static void put32(uint8_t *p, uint32_t v) { unsigned i; for (i=0;i<4;i++) p[i]=(uint8_t)(v>>(8*i)); }
static void put64(uint8_t *p, uint64_t v) { unsigned i; for (i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t get64(const uint8_t *p) { uint64_t v=0; int i; for(i=7;i>=0;i--) v=(v<<8)|p[i]; return v; }

static bool add_size(size_t *total, size_t add)
{
    if (add > SIZE_MAX - *total) return false;
    *total += add; return true;
}

int tee_v3_storage_init(struct tee_v3_storage *storage,
                        const struct tee_v1_segment_layout *layout,
                        tee_v3_storage_write_fn write, void *opaque)
{
    if (!storage || !layout || !write || !layout->hidden_lba_count ||
        !layout->lba_size || layout->hidden_lba_count > UINT64_MAX/layout->lba_size)
        return -1;
    storage->hidden_start_lba = layout->hidden_start_lba;
    storage->capacity_bytes = layout->hidden_lba_count * layout->lba_size;
    storage->write = write; storage->opaque = opaque;
    return 0;
}

int tee_v3_storage_persist(struct tee_v3_storage *storage,
                           const struct tee_v1_bitmap *bitmap,
                           const struct tee_v2_passive_metadata *records,
                           uint32_t count)
{
    size_t size = HEADER_SIZE, off; uint32_t i, j; uint8_t *image;
    if (!storage || !storage->write || !bitmap || !bitmap->bits || (count && !records) ||
        !add_size(&size, (size_t)bitmap->byte_count)) return -1;
    for (i=0;i<count;i++) {
        if (!records[i].segment_count || !records[i].segment_locations ||
            (records[i].group_count && !records[i].groups) ||
            !add_size(&size, RECORD_SIZE) ||
            records[i].segment_count > (SIZE_MAX-size)/8U) return -1;
        size += (size_t)records[i].segment_count*8U;
        if (records[i].group_count > (SIZE_MAX-size)/GROUP_SIZE) return -1;
        size += (size_t)records[i].group_count*GROUP_SIZE;
    }
    if ((uint64_t)size > storage->capacity_bytes || size > UINT32_MAX) return -1;
    image = calloc(size,1); if (!image) return -1;
    put32(image, TEE_V3_STORAGE_MAGIC); put32(image+4, TEE_V3_STORAGE_VERSION);
    put32(image+8, (uint32_t)size); put32(image+12,count); put64(image+16,bitmap->bit_count);
    memcpy(image+HEADER_SIZE, bitmap->bits, (size_t)bitmap->byte_count);
    off=HEADER_SIZE+(size_t)bitmap->byte_count;
    for(i=0;i<count;i++) {
        image[off]=records[i].file_id; put32(image+off+1,records[i].chunk_id);
        put64(image+off+5,records[i].chunk_size_bytes); put32(image+off+13,records[i].segment_count);
        put32(image+off+17,records[i].number_coefficient); put32(image+off+21,records[i].group_count); off+=RECORD_SIZE;
        for(j=0;j<records[i].segment_count;j++,off+=8) put64(image+off,records[i].segment_locations[j]);
        for(j=0;j<records[i].group_count;j++,off+=GROUP_SIZE) {
            put32(image+off,records[i].groups[j].start_segment_index);
            put32(image+off+4,records[i].groups[j].group_segment_count);
            memcpy(image+off+8,records[i].groups[j].expected_hmac,TEE_V2_HMAC_SIZE);
        }
    }
    i = storage->write(storage->opaque,image,size); free(image); return i;
}

static const uint8_t *record_at(const uint8_t *p,size_t n,uint32_t target,size_t *record_off)
{
    uint64_t bits; size_t off; uint32_t count,i;
    if (tee_v3_storage_validate_image(p,n)!=0) return NULL;
    count=get32(p+12); bits=get64(p+16); off=HEADER_SIZE+(size_t)((bits+7)/8);
    for(i=0;i<count;i++) {
        uint32_t segments=get32(p+off+13),groups=get32(p+off+21); size_t next=off+RECORD_SIZE+(size_t)segments*8+(size_t)groups*GROUP_SIZE;
        if(i==target){if(record_off)*record_off=off;return p+off;} off=next;
    } return NULL;
}

int tee_v3_storage_validate_image(const uint8_t *p,size_t n)
{
    uint64_t bits; size_t off; uint32_t count,i;
    if(!p||n<HEADER_SIZE||get32(p)!=TEE_V3_STORAGE_MAGIC||get32(p+4)!=TEE_V3_STORAGE_VERSION||get32(p+8)!=n) return -1;
    count=get32(p+12); bits=get64(p+16); if(bits>SIZE_MAX-7) return -1;
    off=HEADER_SIZE+(size_t)((bits+7)/8); if(off>n) return -1;
    for(i=0;i<count;i++) { uint32_t s,g; size_t add; if(n-off<RECORD_SIZE)return -1; s=get32(p+off+13);g=get32(p+off+21); if(!s)return -1; add=RECORD_SIZE; if(s>(SIZE_MAX-add)/8)return -1;add+=(size_t)s*8;if(g>(SIZE_MAX-add)/GROUP_SIZE)return -1;add+=(size_t)g*GROUP_SIZE;if(add>n-off)return -1;off+=add; }
    return off==n?0:-1;
}
uint32_t tee_v3_storage_image_record_count(const uint8_t*p,size_t n){return tee_v3_storage_validate_image(p,n)?0:get32(p+12);}
bool tee_v3_storage_image_bitmap_test(const uint8_t*p,size_t n,uint64_t bit){uint64_t bits;if(tee_v3_storage_validate_image(p,n))return false;bits=get64(p+16);return bit<bits&&(p[HEADER_SIZE+bit/8]&(1U<<(bit%8)));}
uint32_t tee_v3_storage_image_group_count(const uint8_t*p,size_t n,uint32_t r){const uint8_t*q=record_at(p,n,r,NULL);return q?get32(q+21):0;}
static const uint8_t *group_at(const uint8_t*p,size_t n,uint32_t r,uint32_t g){const uint8_t*q=record_at(p,n,r,NULL);uint32_t s,c;if(!q)return NULL;s=get32(q+13);c=get32(q+21);if(g>=c)return NULL;return q+RECORD_SIZE+(size_t)s*8+(size_t)g*GROUP_SIZE;}
uint32_t tee_v3_storage_image_group_start(const uint8_t*p,size_t n,uint32_t r,uint32_t g){const uint8_t*q=group_at(p,n,r,g);return q?get32(q):0;}
uint32_t tee_v3_storage_image_group_segments(const uint8_t*p,size_t n,uint32_t r,uint32_t g){const uint8_t*q=group_at(p,n,r,g);return q?get32(q+4):0;}
const uint8_t *tee_v3_storage_image_group_hmac(const uint8_t*p,size_t n,uint32_t r,uint32_t g){const uint8_t*q=group_at(p,n,r,g);return q?q+8:NULL;}
