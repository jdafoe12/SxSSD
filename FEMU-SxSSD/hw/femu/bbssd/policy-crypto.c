#include "qemu/osdep.h"
#include "policy-crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

int pe_crypto_random(uint8_t *output, size_t length)
{
    if ((!output && length != 0) || length > INT_MAX) {
        return -1;
    }
    return length == 0 || RAND_bytes(output, length) == 1 ? 0 : -1;
}

int pe_crypto_ed25519_verify(const uint8_t public_key[32],
                             const uint8_t *message, size_t message_length,
                             const uint8_t signature[64])
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *context = NULL;
    int rc = -1;

    if (!public_key || (!message && message_length != 0) || !signature) {
        return -1;
    }
    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                      public_key, 32);
    context = EVP_MD_CTX_new();
    if (key && context &&
        EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestVerify(context, signature, 64, message,
                         message_length) == 1) {
        rc = 0;
    }
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return rc;
}

int pe_crypto_x25519_public(const uint8_t private_key[32],
                            uint8_t public_key[32])
{
    EVP_PKEY *key = NULL;
    size_t length = 32;
    int rc = -1;

    if (!private_key || !public_key) {
        return -1;
    }
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                       private_key, 32);
    if (key && EVP_PKEY_get_raw_public_key(key, public_key, &length) == 1 &&
        length == 32) {
        rc = 0;
    }
    EVP_PKEY_free(key);
    if (rc != 0) {
        OPENSSL_cleanse(public_key, 32);
    }
    return rc;
}

int pe_crypto_x25519_shared(const uint8_t private_key[32],
                            const uint8_t peer_public_key[32],
                            uint8_t shared_secret[32])
{
    EVP_PKEY *private = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *context = NULL;
    size_t length = 32;
    int rc = -1;

    if (!private_key || !peer_public_key || !shared_secret) {
        return -1;
    }
    private = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                           private_key, 32);
    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                       peer_public_key, 32);
    context = private ? EVP_PKEY_CTX_new(private, NULL) : NULL;
    if (private && peer && context &&
        EVP_PKEY_derive_init(context) == 1 &&
        EVP_PKEY_derive_set_peer(context, peer) == 1 &&
        EVP_PKEY_derive(context, shared_secret, &length) == 1 &&
        length == 32) {
        rc = 0;
    }
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(private);
    if (rc != 0) {
        OPENSSL_cleanse(shared_secret, 32);
    }
    return rc;
}

int pe_crypto_hmac_sha256(const uint8_t *key, size_t key_length,
                          const uint8_t *message, size_t message_length,
                          uint8_t output[32])
{
    unsigned int output_length = 0;

    if ((!key && key_length != 0) ||
        (!message && message_length != 0) || !output ||
        key_length > INT_MAX) {
        return -1;
    }
    if (!HMAC(EVP_sha256(), key, key_length, message, message_length,
              output, &output_length) || output_length != 32) {
        OPENSSL_cleanse(output, 32);
        return -1;
    }
    return 0;
}

int pe_crypto_sha256(const uint8_t *message, size_t message_length,
                     uint8_t output[32])
{
    EVP_MD_CTX *context = NULL;
    unsigned int output_length = 0;
    int rc = -1;

    if ((!message && message_length != 0) || !output) {
        return -1;
    }
    context = EVP_MD_CTX_new();
    if (context &&
        EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
        (!message_length ||
         EVP_DigestUpdate(context, message, message_length) == 1) &&
        EVP_DigestFinal_ex(context, output, &output_length) == 1 &&
        output_length == 32) {
        rc = 0;
    }
    EVP_MD_CTX_free(context);
    if (rc != 0) {
        OPENSSL_cleanse(output, 32);
    }
    return rc;
}

int pe_crypto_hkdf_sha256(const uint8_t *key, size_t key_length,
                          const uint8_t *info, size_t info_length,
                          uint8_t *output, size_t output_length)
{
    static const uint8_t empty = 0;
    const uint8_t *key_input = key_length ? key : &empty;
    const uint8_t *info_input = info_length ? info : &empty;
    EVP_PKEY_CTX *context = NULL;
    size_t derived_length = output_length;
    int rc = -1;

    if ((!key && key_length) || (!info && info_length) ||
        (!output && output_length) || key_length > INT_MAX ||
        info_length > INT_MAX) {
        return -1;
    }
    context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (context && EVP_PKEY_derive_init(context) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(context, key_input,
                                   (int)key_length) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(context, info_input,
                                    (int)info_length) == 1 &&
        EVP_PKEY_derive(context, output, &derived_length) == 1 &&
        derived_length == output_length) {
        rc = 0;
    }
    EVP_PKEY_CTX_free(context);
    if (rc != 0 && output) {
        OPENSSL_cleanse(output, output_length);
    }
    return rc;
}

int pe_crypto_aes256_gcm_decrypt(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_length,
                                 const uint8_t *ciphertext,
                                 size_t ciphertext_length,
                                 const uint8_t tag[16],
                                 uint8_t *plaintext)
{
    EVP_CIPHER_CTX *context = NULL;
    int output_length = 0;
    int final_length = 0;
    int rc = -1;

    if (!key || !nonce || (!aad && aad_length) ||
        (!ciphertext && ciphertext_length) || !tag ||
        (!plaintext && ciphertext_length) ||
        aad_length > INT_MAX || ciphertext_length > INT_MAX) {
        return -1;
    }
    context = EVP_CIPHER_CTX_new();
    if (!context ||
        EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) !=
            1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(context, NULL, NULL, key, nonce) != 1 ||
        (aad_length &&
         EVP_DecryptUpdate(context, NULL, &output_length, aad,
                           (int)aad_length) != 1) ||
        (ciphertext_length &&
         EVP_DecryptUpdate(context, plaintext, &output_length, ciphertext,
                           (int)ciphertext_length) != 1) ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16,
                            (void *)tag) != 1 ||
        EVP_DecryptFinal_ex(context, plaintext + output_length,
                            &final_length) != 1 ||
        (size_t)(output_length + final_length) != ciphertext_length) {
        goto cleanup;
    }
    rc = 0;

cleanup:
    EVP_CIPHER_CTX_free(context);
    if (rc != 0 && plaintext) {
        OPENSSL_cleanse(plaintext, ciphertext_length);
    }
    return rc;
}
