#include "tee-v2-hmac-group.h"

#include <string.h>

const uint8_t tee_v2_prototype_key[TEE_V2_PROTOTYPE_KEY_SIZE] = {
    0x53,0x78,0x53,0x53,0x44,0x2d,0x56,0x32,
    0x2d,0x70,0x72,0x6f,0x74,0x6f,0x74,0x79,
    0x70,0x65,0x2d,0x48,0x4d,0x41,0x43,0x2d,
    0x6b,0x65,0x79,0x2d,0x30,0x30,0x30,0x31
};

struct sha256_ctx {
    uint32_t state[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
};

static const uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static uint32_t be32(const uint8_t *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void put_be32(uint8_t *p, uint32_t v) { p[0]=(uint8_t)(v>>24);p[1]=(uint8_t)(v>>16);p[2]=(uint8_t)(v>>8);p[3]=(uint8_t)v; }

static void sha_block(struct sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a,b,d,e,f,g,h,t1,t2,cc;
    unsigned i;
    for (i=0;i<16;i++) w[i]=be32(p+4*i);
    for (;i<64;i++) { uint32_t x=w[i-15],y=w[i-2]; w[i]=(rr(y,17)^rr(y,19)^(y>>10))+w[i-7]+(rr(x,7)^rr(x,18)^(x>>3))+w[i-16]; }
    a=c->state[0];b=c->state[1];cc=c->state[2];d=c->state[3];e=c->state[4];f=c->state[5];g=c->state[6];h=c->state[7];
    for(i=0;i<64;i++){ t1=h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^((~e)&g))+k[i]+w[i]; t2=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&cc)^(b&cc)); h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2; }
    c->state[0]+=a;c->state[1]+=b;c->state[2]+=cc;c->state[3]+=d;c->state[4]+=e;c->state[5]+=f;c->state[6]+=g;c->state[7]+=h;
}

static void sha_init(struct sha256_ctx *c)
{
    static const uint32_t init[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(c->state,init,sizeof(init)); c->bits=0;c->used=0;
}

static void sha_update(struct sha256_ctx *c,const uint8_t *p,size_t n)
{
    c->bits+=(uint64_t)n*8;
    while(n){ size_t take=64-c->used; if(take>n)take=n; memcpy(c->block+c->used,p,take);c->used+=take;p+=take;n-=take;if(c->used==64){sha_block(c,c->block);c->used=0;} }
}

static void sha_final(struct sha256_ctx *c,uint8_t out[32])
{
    unsigned i; uint64_t bits=c->bits;
    c->block[c->used++]=0x80;
    if(c->used>56){memset(c->block+c->used,0,64-c->used);sha_block(c,c->block);c->used=0;}
    memset(c->block+c->used,0,56-c->used);
    for(i=0;i<8;i++)c->block[63-i]=(uint8_t)(bits>>(8*i));
    sha_block(c,c->block); for(i=0;i<8;i++)put_be32(out+4*i,c->state[i]);
}

void tee_v2_hmac_sha256(const uint8_t *key, size_t key_size,
                        const uint8_t *data, size_t data_size,
                        uint8_t output[TEE_V2_HMAC_SIZE])
{
    uint8_t kb[64]={0}, ipad[64], opad[64], inner[32];
    struct sha256_ctx c; size_t i;
    if(key_size>64){sha_init(&c);sha_update(&c,key,key_size);sha_final(&c,kb);}else if(key_size)memcpy(kb,key,key_size);
    for(i=0;i<64;i++){ipad[i]=(uint8_t)(kb[i]^0x36);opad[i]=(uint8_t)(kb[i]^0x5c);}
    sha_init(&c);sha_update(&c,ipad,64);sha_update(&c,data,data_size);sha_final(&c,inner);
    sha_init(&c);sha_update(&c,opad,64);sha_update(&c,inner,32);sha_final(&c,output);
}

static void reset_group(struct tee_v2_active_metadata *active,
                        struct tee_v2_hmac_group_state *group)
{
    uint32_t i;
    for(i=0;i<group->group_segment_count;i++){
        uint32_t slot=group->start_segment_index-1+i;
        active->arrived[slot]=false; active->pending[slot]=false;
        active->segment_locations[slot]=TEE_V2_LOCATION_UNSET;
        memset(active->segment_bytes+(size_t)slot*active->config.segment_size,0,active->config.segment_size);
    }
    group->arrived_count=0; group->verified=false;
}

enum tee_v2_hmac_result tee_v2_verify_hmac_group(
    struct tee_v2_active_metadata *active,
    struct tee_v2_hmac_group_state *group,
    const uint8_t *key, size_t key_size)
{
    uint8_t actual[TEE_V2_HMAC_SIZE]; size_t offset,size;
    if(!active||!group||!key) return TEE_V2_HMAC_FAILED;
    if(group->verified) return TEE_V2_HMAC_REUSED;
    if(group->arrived_count!=group->group_segment_count) return TEE_V2_HMAC_NOT_READY;
    offset=(size_t)(group->start_segment_index-1)*active->config.segment_size;
    size=(size_t)group->group_segment_count*active->config.segment_size;
    tee_v2_hmac_sha256(key,key_size,active->segment_bytes+offset,size,actual);
    if(memcmp(actual,group->expected_hmac,TEE_V2_HMAC_SIZE)!=0){reset_group(active,group);return TEE_V2_HMAC_FAILED;}
    group->verified=true; return TEE_V2_HMAC_VERIFIED;
}
