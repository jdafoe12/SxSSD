#ifndef SXS_DEVICE_IDENTITY_H
#define SXS_DEVICE_IDENTITY_H

#include <stdint.h>

/*
 * Public half of the simulated device identity key. Fixed firmware uses the
 * key for identity and attestation signatures. Ordinary policies can request
 * only a policy-key-bootstrap signature over a fixed domain and fixed-length
 * fields, so that signature cannot be reused as another SxSSD message type.
 */
static const uint8_t SXS_DEVICE_PUBLIC_KEY[32] = {
    0xfa, 0x8c, 0xfa, 0xd2, 0xd0, 0x39, 0x12, 0x55,
    0xf3, 0x73, 0xa2, 0x4b, 0x1c, 0x1c, 0x58, 0xdc,
    0xbe, 0x52, 0x04, 0x60, 0xa8, 0x2a, 0xde, 0xa6,
    0x94, 0x60, 0xbd, 0xa1, 0xab, 0x3f, 0x7b, 0x6b,
};

#endif /* SXS_DEVICE_IDENTITY_H */
