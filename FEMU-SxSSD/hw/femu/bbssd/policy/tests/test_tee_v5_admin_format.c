#include "../tee/tee-v5-admin-format.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_v4_commands_remain_wire_compatible(void)
{
    assert(TEE_V4_ADMIN_CMD_READ_SUMMARY == 1);
    assert(TEE_V4_ADMIN_CMD_READ_LOCATIONS == 2);
    assert(TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS == 3);
    assert(TEE_V4_ADMIN_CMD_ONE_BIT_PROOF == 4);
    assert(TEE_V4_ADMIN_CMD_SYNC_METADATA == 5);
    assert(TEE_V4_ADMIN_CMD_SET_ACTIVE_METADATA == 6);
}

static void test_v5_mutation_commands_are_stable(void)
{
    assert(TEE_V5_ADMIN_CMD_DELETE == 7);
    assert(TEE_V5_ADMIN_CMD_ABORT_ACTIVE == 8);
}

static void test_chunk_identity_is_exact_packed_payload(void)
{
    struct tee_v5_chunk_identity_payload identity;

    memset(&identity, 0, sizeof(identity));
    identity.file_id = 0x5a;
    identity.chunk_id = 0x00ffffffU;

    assert(sizeof(identity) == 8);
    assert(TEE_V5_CHUNK_IDENTITY_PAYLOAD_SIZE == 8);
    assert(tee_v5_chunk_identity_payload_valid(&identity, sizeof(identity)));

    assert(!tee_v5_chunk_identity_payload_valid(&identity,
                                                 sizeof(identity) - 1));
    assert(!tee_v5_chunk_identity_payload_valid(&identity,
                                                 sizeof(identity) + 1));
    identity.reserved[1] = 1;
    assert(!tee_v5_chunk_identity_payload_valid(&identity, sizeof(identity)));

    memset(identity.reserved, 0, sizeof(identity.reserved));
    identity.chunk_id = 0x01000000U;
    assert(!tee_v5_chunk_identity_payload_valid(&identity, sizeof(identity)));
}

int main(void)
{
    test_v4_commands_remain_wire_compatible();
    test_v5_mutation_commands_are_stable();
    test_chunk_identity_is_exact_packed_payload();
    puts("test_tee_v5_admin_format: PASS");
    return 0;
}
