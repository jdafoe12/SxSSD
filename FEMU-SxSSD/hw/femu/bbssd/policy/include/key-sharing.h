/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef SXS_KEY_SHARING_H
#define SXS_KEY_SHARING_H

#include <stdint.h>

#define KEY_SHARING_SUBMIT_OPCODE 0xe3
#define KEY_SHARING_FETCH_OPCODE  0xe2

#define KEY_SHARING_FIELD_SIZE 32
#define KEY_SHARING_SIGNATURE_SIZE 64
#define KEY_SHARING_CONFIRMATION_SIZE 32

#define KEY_SHARING_KDF_INFO "SxSSD-Policy-Shared-Key-v1"
#define KEY_SHARING_TAPP_AUTH_DOMAIN \
    "SxSSD-TApp-Key-Bootstrap-Request-v1"
#define KEY_SHARING_CONFIRMATION_DOMAIN \
    "SxSSD-Policy-Key-Confirmation-v1"

struct key_sharing_request {
    uint8_t owner_nonce[KEY_SHARING_FIELD_SIZE];
    uint8_t owner_ephemeral_public_key[KEY_SHARING_FIELD_SIZE];
    uint8_t tapp_signature[KEY_SHARING_SIGNATURE_SIZE];
} __attribute__((packed));

struct key_sharing_response {
    uint8_t policy_ephemeral_public_key[KEY_SHARING_FIELD_SIZE];
    uint8_t device_signature[KEY_SHARING_SIGNATURE_SIZE];
    uint8_t key_confirmation[KEY_SHARING_CONFIRMATION_SIZE];
} __attribute__((packed));

#endif /* SXS_KEY_SHARING_H */
