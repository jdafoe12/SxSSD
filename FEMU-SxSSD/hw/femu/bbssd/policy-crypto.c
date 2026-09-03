/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "policy-crypto.h"

#include <nettle/curve25519.h>
#include <nettle/eddsa.h>
#include <nettle/gcm.h>
#include <nettle/hkdf.h>
#include <nettle/hmac.h>
#include <nettle/memops.h>
#include <nettle/sha2.h>
#include <nettle/version.h>
#include <string.h>

#define PE_SHA256_SIZE 32
#define PE_GCM_TAG_SIZE 16
#define PE_HKDF_MAX_OUTPUT (255U * PE_SHA256_SIZE)

#if NETTLE_VERSION_MAJOR >= 4
#define PE_SHA256_DIGEST(context, output) \
    sha256_digest((context), (output))
#define PE_HMAC_SHA256_DIGEST(context, output) \
    hmac_sha256_digest((context), (output))
#define PE_GCM_AES256_DIGEST(context, output) \
    gcm_aes256_digest((context), (output))
#else
#define PE_SHA256_DIGEST(context, output) \
    sha256_digest((context), PE_SHA256_SIZE, (output))
#define PE_HMAC_SHA256_DIGEST(context, output) \
    hmac_sha256_digest((context), PE_SHA256_SIZE, (output))
#define PE_GCM_AES256_DIGEST(context, output) \
    gcm_aes256_digest((context), PE_GCM_TAG_SIZE, (output))
#endif

static const uint8_t pe_crypto_empty;

static int pe_crypto_buffers_valid(const struct pe_crypto_buffer *parts,
                                   size_t part_count)
{
    size_t i;

    if (!parts && part_count != 0) {
        return 0;
    }
    for (i = 0; i < part_count; i++) {
        if (!parts[i].data && parts[i].length != 0) {
            return 0;
        }
    }
    return 1;
}

void pe_crypto_secure_zero(void *data, size_t length)
{
    typedef void *(*memset_fn)(void *, int, size_t);
    /* Volatile indirection prevents dead-store elimination of the wipe. */
    static memset_fn volatile secure_memset = memset;

    if (data && length != 0) {
        secure_memset(data, 0, length);
    }
}

int pe_crypto_equal(const void *left, const void *right, size_t length)
{
    if (length == 0) {
        return 1;
    }
    if (!left || !right) {
        return 0;
    }
    return memeql_sec(left, right, length);
}

int pe_crypto_ed25519_public(const uint8_t private_key[32],
                             uint8_t public_key[32])
{
    if (!private_key || !public_key) {
        return -1;
    }
    ed25519_sha512_public_key(public_key, private_key);
    return 0;
}

int pe_crypto_ed25519_sign(const uint8_t private_key[32],
                           const uint8_t *message, size_t message_length,
                           uint8_t signature[64])
{
    uint8_t public_key[32];

    if (!private_key || (!message && message_length != 0) || !signature) {
        return -1;
    }
    ed25519_sha512_public_key(public_key, private_key);
    ed25519_sha512_sign(public_key, private_key, message_length,
                       message ? message : &pe_crypto_empty, signature);
    pe_crypto_secure_zero(public_key, sizeof(public_key));
    return 0;
}

int pe_crypto_ed25519_verify(const uint8_t public_key[32],
                             const uint8_t *message, size_t message_length,
                             const uint8_t signature[64])
{
    if (!public_key || (!message && message_length != 0) || !signature) {
        return -1;
    }
    return ed25519_sha512_verify(public_key, message_length,
                                message ? message : &pe_crypto_empty,
                                signature) ? 0 : -1;
}

int pe_crypto_x25519_public(const uint8_t private_key[32],
                            uint8_t public_key[32])
{
    if (!private_key || !public_key) {
        return -1;
    }
    curve25519_mul_g(public_key, private_key);
    return 0;
}

int pe_crypto_x25519_shared(const uint8_t private_key[32],
                            const uint8_t peer_public_key[32],
                            uint8_t shared_secret[32])
{
    static const uint8_t zero[32];

    if (!private_key || !peer_public_key || !shared_secret) {
        return -1;
    }
    curve25519_mul(shared_secret, private_key, peer_public_key);
    if (pe_crypto_equal(shared_secret, zero, sizeof(zero))) {
        pe_crypto_secure_zero(shared_secret, 32);
        return -1;
    }
    return 0;
}

int pe_crypto_hmac_sha256v(const uint8_t *key, size_t key_length,
                           const struct pe_crypto_buffer *parts,
                           size_t part_count, uint8_t output[32])
{
    struct hmac_sha256_ctx context;
    size_t i;

    if ((!key && key_length != 0) ||
        !pe_crypto_buffers_valid(parts, part_count) || !output) {
        return -1;
    }
    hmac_sha256_set_key(&context, key_length,
                        key_length ? key : &pe_crypto_empty);
    for (i = 0; i < part_count; i++) {
        if (parts[i].length != 0) {
            hmac_sha256_update(&context, parts[i].length, parts[i].data);
        }
    }
    PE_HMAC_SHA256_DIGEST(&context, output);
    pe_crypto_secure_zero(&context, sizeof(context));
    return 0;
}

int pe_crypto_hmac_sha256(const uint8_t *key, size_t key_length,
                          const uint8_t *message, size_t message_length,
                          uint8_t output[32])
{
    const struct pe_crypto_buffer part = { message, message_length };

    return pe_crypto_hmac_sha256v(key, key_length, &part, 1, output);
}

int pe_crypto_sha256v(const struct pe_crypto_buffer *parts,
                      size_t part_count, uint8_t output[32])
{
    struct sha256_ctx context;
    size_t i;

    if (!pe_crypto_buffers_valid(parts, part_count) || !output) {
        return -1;
    }
    sha256_init(&context);
    for (i = 0; i < part_count; i++) {
        if (parts[i].length != 0) {
            sha256_update(&context, parts[i].length, parts[i].data);
        }
    }
    PE_SHA256_DIGEST(&context, output);
    pe_crypto_secure_zero(&context, sizeof(context));
    return 0;
}

int pe_crypto_sha256(const uint8_t *message, size_t message_length,
                     uint8_t output[32])
{
    const struct pe_crypto_buffer part = { message, message_length };

    return pe_crypto_sha256v(&part, 1, output);
}

int pe_crypto_hkdf_sha256(const uint8_t *key, size_t key_length,
                          const uint8_t *salt, size_t salt_length,
                          const uint8_t *info, size_t info_length,
                          uint8_t *output, size_t output_length)
{
    struct hmac_sha256_ctx context;
    uint8_t pseudorandom_key[PE_SHA256_SIZE];

    if ((!key && key_length != 0) || (!salt && salt_length != 0) ||
        (!info && info_length != 0) || (!output && output_length != 0) ||
        output_length > PE_HKDF_MAX_OUTPUT) {
        return -1;
    }
    if (output_length == 0) {
        return 0;
    }

    hmac_sha256_set_key(&context, salt_length,
                        salt_length ? salt : &pe_crypto_empty);
#if NETTLE_VERSION_MAJOR >= 4
    hkdf_extract(&context,
                 (nettle_hash_update_func *)hmac_sha256_update,
                 (nettle_hash_digest_func *)hmac_sha256_digest,
                 key_length, key_length ? key : &pe_crypto_empty,
                 pseudorandom_key);
#else
    hkdf_extract(&context,
                 (nettle_hash_update_func *)hmac_sha256_update,
                 (nettle_hash_digest_func *)hmac_sha256_digest,
                 PE_SHA256_SIZE, key_length,
                 key_length ? key : &pe_crypto_empty, pseudorandom_key);
#endif
    hmac_sha256_set_key(&context, sizeof(pseudorandom_key),
                        pseudorandom_key);
    hkdf_expand(&context,
                (nettle_hash_update_func *)hmac_sha256_update,
                (nettle_hash_digest_func *)hmac_sha256_digest,
                PE_SHA256_SIZE, info_length,
                info_length ? info : &pe_crypto_empty,
                output_length, output);
    pe_crypto_secure_zero(pseudorandom_key, sizeof(pseudorandom_key));
    pe_crypto_secure_zero(&context, sizeof(context));
    return 0;
}

int pe_crypto_aes256_gcm_encrypt(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_length,
                                 const uint8_t *plaintext,
                                 size_t plaintext_length,
                                 uint8_t *ciphertext, uint8_t tag[16])
{
    struct gcm_aes256_ctx context;

    if (!key || !nonce || (!aad && aad_length != 0) ||
        (!plaintext && plaintext_length != 0) ||
        (!ciphertext && plaintext_length != 0) || !tag) {
        return -1;
    }
    gcm_aes256_set_key(&context, key);
    gcm_aes256_set_iv(&context, 12, nonce);
    if (aad_length != 0) {
        gcm_aes256_update(&context, aad_length, aad);
    }
    if (plaintext_length != 0) {
        gcm_aes256_encrypt(&context, plaintext_length, ciphertext, plaintext);
    }
    PE_GCM_AES256_DIGEST(&context, tag);
    pe_crypto_secure_zero(&context, sizeof(context));
    return 0;
}

int pe_crypto_aes256_gcm_decrypt(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_length,
                                 const uint8_t *ciphertext,
                                 size_t ciphertext_length,
                                 const uint8_t tag[16],
                                 uint8_t *plaintext)
{
    struct gcm_aes256_ctx context;
    uint8_t computed_tag[PE_GCM_TAG_SIZE];
    int rc = -1;

    if (!key || !nonce || (!aad && aad_length != 0) ||
        (!ciphertext && ciphertext_length != 0) || !tag ||
        (!plaintext && ciphertext_length != 0)) {
        return -1;
    }
    gcm_aes256_set_key(&context, key);
    gcm_aes256_set_iv(&context, 12, nonce);
    if (aad_length != 0) {
        gcm_aes256_update(&context, aad_length, aad);
    }
    if (ciphertext_length != 0) {
        gcm_aes256_decrypt(&context, ciphertext_length, plaintext, ciphertext);
    }
    PE_GCM_AES256_DIGEST(&context, computed_tag);
    if (pe_crypto_equal(computed_tag, tag, sizeof(computed_tag))) {
        rc = 0;
    } else if (plaintext) {
        pe_crypto_secure_zero(plaintext, ciphertext_length);
    }
    pe_crypto_secure_zero(computed_tag, sizeof(computed_tag));
    pe_crypto_secure_zero(&context, sizeof(context));
    return rc;
}
