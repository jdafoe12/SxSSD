/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <fcntl.h>
#include <linux/nvme_ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../device-trust.h"
#include "../policy/include/key-sharing.h"
#include "../policy-crypto.h"
#include "host-crypto.h"

static int send_admin_cmd(const char *device, uint8_t opcode, void *buffer,
                          uint32_t data_len, int quiet)
{
    struct nvme_admin_cmd cmd = {0};
    int fd;
    int ioctl_rc;
    int rc = -1;

    fd = open(device, O_RDWR);
    if (fd < 0) {
        perror("open device");
        return -1;
    }
    cmd.opcode = opcode;
    cmd.addr = (uintptr_t)buffer;
    cmd.data_len = data_len;
    cmd.cdw12 = data_len;
    ioctl_rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
    if (ioctl_rc < 0) {
        if (!quiet) {
            perror("ioctl");
        }
    } else if (ioctl_rc != 0) {
        if (!quiet) {
            fprintf(stderr, "NVMe opcode 0x%02x failed with status 0x%x\n",
                    opcode, ioctl_rc);
        }
    } else if (cmd.result != 0) {
        fprintf(stderr, "NVMe command failed with result 0x%x\n", cmd.result);
    } else {
        rc = 0;
    }
    close(fd);
    return rc;
}

static int sign_tapp_request(struct key_sharing_request *request,
                             const char *private_key_path)
{
    static const uint8_t domain[] = KEY_SHARING_TAPP_AUTH_DOMAIN;
    uint8_t message[(sizeof(domain) - 1) + 2 * KEY_SHARING_FIELD_SIZE];
    uint8_t private_key[32];
    size_t offset = 0;
    int rc = -1;

    memcpy(message + offset, domain, sizeof(domain) - 1);
    offset += sizeof(domain) - 1;
    memcpy(message + offset, request->owner_nonce, KEY_SHARING_FIELD_SIZE);
    offset += KEY_SHARING_FIELD_SIZE;
    memcpy(message + offset, request->owner_ephemeral_public_key,
           KEY_SHARING_FIELD_SIZE);

    if (sxs_host_read_hex(private_key_path, private_key,
                          sizeof(private_key)) != 0 ||
        pe_crypto_ed25519_sign(private_key, message, sizeof(message),
                                request->tapp_signature) != 0) {
        fprintf(stderr, "failed to sign key-sharing request\n");
        goto cleanup;
    }
    rc = 0;

cleanup:
    pe_crypto_secure_zero(private_key, sizeof(private_key));
    return rc;
}

static int generate_x25519_keypair(uint8_t public_key[32],
                                   uint8_t private_key[32])
{
    if (sxs_host_random(private_key, 32) != 0 ||
        pe_crypto_x25519_public(private_key, public_key) != 0) {
        pe_crypto_secure_zero(public_key, 32);
        pe_crypto_secure_zero(private_key, 32);
        return -1;
    }
    return 0;
}

static int derive_shared_key(const uint8_t private_key[32],
                             const uint8_t policy_public_key[32],
                             const uint8_t owner_nonce[32],
                             uint8_t shared_key[32])
{
    static const uint8_t info[] = KEY_SHARING_KDF_INFO;
    uint8_t shared_secret[32];
    int rc = -1;

    if (pe_crypto_x25519_shared(private_key, policy_public_key,
                                 shared_secret) == 0 &&
        pe_crypto_hkdf_sha256(shared_secret, sizeof(shared_secret),
                               owner_nonce, 32, info, sizeof(info) - 1,
                               shared_key, 32) == 0) {
        rc = 0;
    }
    pe_crypto_secure_zero(shared_secret, sizeof(shared_secret));
    if (rc != 0) {
        pe_crypto_secure_zero(shared_key, 32);
    }
    return rc;
}

static int verify_bootstrap_signature(
    const struct key_sharing_request *request,
    const struct key_sharing_response *response)
{
    uint8_t message[SXS_KEY_BOOTSTRAP_MESSAGE_SIZE];
    size_t offset = 0;

    memcpy(message + offset, SXS_KEY_BOOTSTRAP_DOMAIN,
           SXS_KEY_BOOTSTRAP_DOMAIN_SIZE);
    offset += SXS_KEY_BOOTSTRAP_DOMAIN_SIZE;
    memcpy(message + offset, request->owner_nonce, 32);
    offset += 32;
    memcpy(message + offset, request->owner_ephemeral_public_key, 32);
    offset += 32;
    memcpy(message + offset, response->policy_ephemeral_public_key, 32);

    return pe_crypto_ed25519_verify(SXS_DEVICE_PUBLIC_KEY, message,
                                     sizeof(message),
                                     response->device_signature);
}

static int compute_key_confirmation(
    const uint8_t shared_key[32], const struct key_sharing_request *request,
    const uint8_t policy_public_key[32], uint8_t confirmation[32])
{
    static const uint8_t domain[] = KEY_SHARING_CONFIRMATION_DOMAIN;
    uint8_t message[(sizeof(domain) - 1) + 3 * KEY_SHARING_FIELD_SIZE];
    size_t offset = 0;

    memcpy(message + offset, domain, sizeof(domain) - 1);
    offset += sizeof(domain) - 1;
    memcpy(message + offset, request->owner_nonce, 32);
    offset += 32;
    memcpy(message + offset, request->owner_ephemeral_public_key, 32);
    offset += 32;
    memcpy(message + offset, policy_public_key, 32);
    return pe_crypto_hmac_sha256(shared_key, 32, message, sizeof(message),
                                  confirmation);
}

int main(int argc, char **argv)
{
    struct key_sharing_request request = {0};
    struct key_sharing_response response = {0};
    uint8_t owner_private_key[32] = {0};
    uint8_t shared_key[32] = {0};
    uint8_t expected_confirmation[32] = {0};
    int rc = 1;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <device> <TApp-private-key.hex>\n",
                argv[0]);
        return 1;
    }
    if (sxs_host_random(request.owner_nonce,
                        sizeof(request.owner_nonce)) != 0 ||
        generate_x25519_keypair(request.owner_ephemeral_public_key,
                                owner_private_key) != 0 ||
        sign_tapp_request(&request, argv[2]) != 0 ||
        send_admin_cmd(argv[1], KEY_SHARING_SUBMIT_OPCODE, &request,
                       sizeof(request), 0) != 0 ||
        send_admin_cmd(argv[1], KEY_SHARING_FETCH_OPCODE, &response,
                       sizeof(response), 0) != 0 ||
        verify_bootstrap_signature(&request, &response) != 0 ||
        derive_shared_key(owner_private_key,
                          response.policy_ephemeral_public_key,
                          request.owner_nonce, shared_key) != 0 ||
        compute_key_confirmation(shared_key, &request,
                                 response.policy_ephemeral_public_key,
                                 expected_confirmation) != 0 ||
        !pe_crypto_equal(expected_confirmation, response.key_confirmation,
                          sizeof(expected_confirmation))) {
        fprintf(stderr, "key sharing verification failed\n");
        goto cleanup;
    }

    request.tapp_signature[0] ^= 1;
    if (send_admin_cmd(argv[1], KEY_SHARING_SUBMIT_OPCODE, &request,
                       sizeof(request), 1) == 0) {
        fprintf(stderr, "policy accepted an invalid TApp signature\n");
        goto cleanup;
    }

    printf("key sharing passed; invalid TApp authentication rejected\n");
    rc = 0;

cleanup:
    pe_crypto_secure_zero(owner_private_key, sizeof(owner_private_key));
    pe_crypto_secure_zero(shared_key, sizeof(shared_key));
    pe_crypto_secure_zero(expected_confirmation,
                           sizeof(expected_confirmation));
    pe_crypto_secure_zero(&request, sizeof(request));
    pe_crypto_secure_zero(&response, sizeof(response));
    return rc;
}
