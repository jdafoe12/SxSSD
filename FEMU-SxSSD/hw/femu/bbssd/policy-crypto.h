/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef FEMU_POLICY_CRYPTO_H
#define FEMU_POLICY_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

struct pe_crypto_buffer {
    const uint8_t *data;
    size_t length;
};

void pe_crypto_secure_zero(void *data, size_t length);
int pe_crypto_equal(const void *left, const void *right, size_t length);

int pe_crypto_ed25519_public(const uint8_t private_key[32],
                             uint8_t public_key[32]);
int pe_crypto_ed25519_sign(const uint8_t private_key[32],
                           const uint8_t *message, size_t message_length,
                           uint8_t signature[64]);
int pe_crypto_ed25519_verify(const uint8_t public_key[32],
                             const uint8_t *message, size_t message_length,
                             const uint8_t signature[64]);

int pe_crypto_x25519_public(const uint8_t private_key[32],
                            uint8_t public_key[32]);
int pe_crypto_x25519_shared(const uint8_t private_key[32],
                            const uint8_t peer_public_key[32],
                            uint8_t shared_secret[32]);

int pe_crypto_hmac_sha256v(const uint8_t *key, size_t key_length,
                           const struct pe_crypto_buffer *parts,
                           size_t part_count, uint8_t output[32]);
int pe_crypto_hmac_sha256(const uint8_t *key, size_t key_length,
                          const uint8_t *message, size_t message_length,
                          uint8_t output[32]);
int pe_crypto_sha256v(const struct pe_crypto_buffer *parts,
                      size_t part_count, uint8_t output[32]);
int pe_crypto_sha256(const uint8_t *message, size_t message_length,
                     uint8_t output[32]);

int pe_crypto_hkdf_sha256(const uint8_t *key, size_t key_length,
                          const uint8_t *salt, size_t salt_length,
                          const uint8_t *info, size_t info_length,
                          uint8_t *output, size_t output_length);

int pe_crypto_aes256_gcm_encrypt(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_length,
                                 const uint8_t *plaintext,
                                 size_t plaintext_length,
                                 uint8_t *ciphertext, uint8_t tag[16]);
int pe_crypto_aes256_gcm_decrypt(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_length,
                                 const uint8_t *ciphertext,
                                 size_t ciphertext_length,
                                 const uint8_t tag[16],
                                 uint8_t *plaintext);

#endif /* FEMU_POLICY_CRYPTO_H */
