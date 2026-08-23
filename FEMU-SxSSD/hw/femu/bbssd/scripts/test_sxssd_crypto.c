/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../policy-crypto.h"

static int expect_hex(const char *name, const uint8_t *actual, size_t length,
                      const char *expected)
{
    static const char digits[] = "0123456789abcdef";
    char encoded[2 * 64 + 1];
    size_t i;

    if (length > 64 || strlen(expected) != 2 * length) {
        fprintf(stderr, "%s: invalid test-vector length\n", name);
        return -1;
    }
    for (i = 0; i < length; i++) {
        encoded[2 * i] = digits[actual[i] >> 4];
        encoded[2 * i + 1] = digits[actual[i] & 0xf];
    }
    encoded[2 * length] = '\0';
    if (strcmp(encoded, expected) != 0) {
        fprintf(stderr, "%s mismatch:\n  got  %s\n  want %s\n",
                name, encoded, expected);
        return -1;
    }
    return 0;
}

static void fill_sequence(uint8_t *output, size_t length, uint8_t first)
{
    size_t i;

    for (i = 0; i < length; i++) {
        output[i] = first + (uint8_t)i;
    }
}

int main(void)
{
    static const uint8_t message[] = "SxSSD-Nettle-compatibility";
    static const uint8_t info[] = "SxSSD-info";
    static const uint8_t aad[] = "SxSSD-aad";
    static const uint8_t plaintext[] =
        "SxSSD AES-GCM compatibility plaintext";
    uint8_t private_key[32];
    uint8_t peer_private_key[32];
    uint8_t public_key[32];
    uint8_t peer_public_key[32];
    uint8_t shared_secret[32];
    uint8_t signature[64];
    uint8_t output[64];
    uint8_t key[32];
    uint8_t salt[32];
    uint8_t nonce[12];
    uint8_t ciphertext[sizeof(plaintext) - 1];
    uint8_t decrypted[sizeof(plaintext) - 1];
    uint8_t tag[16];
    uint8_t bad_tag[16];
    size_t i;

    fill_sequence(private_key, sizeof(private_key), 0);
    fill_sequence(peer_private_key, sizeof(peer_private_key), 32);
    if (pe_crypto_ed25519_public(private_key, public_key) != 0 ||
        expect_hex("Ed25519 public key", public_key, sizeof(public_key),
                   "03a107bff3ce10be1d70dd18e74bc0996"
                   "7e4d6309ba50d5f1ddc8664125531b8") != 0 ||
        pe_crypto_ed25519_sign(private_key, message, sizeof(message) - 1,
                                signature) != 0 ||
        expect_hex("Ed25519 signature", signature, sizeof(signature),
                   "7017de90a27b2acbe11f815d2ebfcd57"
                   "dda0431e87d1fe1037f139c136a6db47"
                   "5998b8117b4fc45a7b4d082b9d56dc29"
                   "d9fb1734b323c203177a6d9765025d01") != 0 ||
        pe_crypto_ed25519_verify(public_key, message, sizeof(message) - 1,
                                  signature) != 0) {
        return 1;
    }
    signature[0] ^= 1;
    if (pe_crypto_ed25519_verify(public_key, message, sizeof(message) - 1,
                                  signature) == 0) {
        fprintf(stderr, "modified Ed25519 signature verified\n");
        return 1;
    }

    if (pe_crypto_x25519_public(private_key, public_key) != 0 ||
        expect_hex("X25519 public key", public_key, sizeof(public_key),
                   "8f40c5adb68f25624ae5b214ea767a6e"
                   "c94d829d3d7b5e1ad1ba6f3e2138285f") != 0 ||
        pe_crypto_x25519_public(peer_private_key, peer_public_key) != 0 ||
        expect_hex("X25519 peer public key", peer_public_key,
                   sizeof(peer_public_key),
                   "358072d6365880d1aeea329adf912138"
                   "3851ed21a28e3b75e965d0d2cd166254") != 0 ||
        pe_crypto_x25519_shared(private_key, peer_public_key,
                                 shared_secret) != 0 ||
        expect_hex("X25519 shared secret", shared_secret,
                   sizeof(shared_secret),
                   "9663aa1da97e848a914a436d04163dfb"
                   "b89178f107f1b5b77ed3854203382854") != 0) {
        return 1;
    }
    memset(peer_public_key, 0, sizeof(peer_public_key));
    memset(shared_secret, 0xa5, sizeof(shared_secret));
    if (pe_crypto_x25519_shared(private_key, peer_public_key,
                                 shared_secret) == 0) {
        fprintf(stderr, "all-zero X25519 peer key was accepted\n");
        return 1;
    }
    for (i = 0; i < sizeof(shared_secret); i++) {
        if (shared_secret[i] != 0) {
            fprintf(stderr, "rejected X25519 secret was not cleared\n");
            return 1;
        }
    }

    fill_sequence(key, 16, 0);
    if (pe_crypto_hmac_sha256(key, 16, message, sizeof(message) - 1,
                               output) != 0 ||
        expect_hex("HMAC-SHA256", output, 32,
                   "79b45eb3d139f7dd80cdc17a67ce3abe"
                   "3fd8d7b99bf9b26232b9fb577c882d6a") != 0 ||
        pe_crypto_sha256(message, sizeof(message) - 1, output) != 0 ||
        expect_hex("SHA-256", output, 32,
                   "25f23140ac64414670fe440c148956b90"
                   "d268bebd2a293016059d74701a39a1d") != 0) {
        return 1;
    }

    fill_sequence(key, sizeof(key), 0);
    fill_sequence(salt, sizeof(salt), 0);
    if (pe_crypto_hkdf_sha256(key, sizeof(key), NULL, 0,
                               info, sizeof(info) - 1, output, 42) != 0 ||
        expect_hex("HKDF-SHA256 without salt", output, 42,
                   "6068c57f4a701837e9c6d44361df910b"
                   "45be51fc869179060148ccba44c04fe8"
                   "c9b41cd56684a8504a10") != 0 ||
        pe_crypto_hkdf_sha256(key, sizeof(key), salt, sizeof(salt),
                               info, sizeof(info) - 1, output, 42) != 0 ||
        expect_hex("HKDF-SHA256 with salt", output, 42,
                   "112a2032835b2f7041504acac7ef3f20"
                   "52d4e26e2193dbdc085b3854fb7ec637"
                   "80c35497f7f6853a4d51") != 0) {
        return 1;
    }

    fill_sequence(nonce, sizeof(nonce), 0);
    if (pe_crypto_aes256_gcm_encrypt(key, nonce, aad, sizeof(aad) - 1,
                                      plaintext, sizeof(plaintext) - 1,
                                      ciphertext, tag) != 0 ||
        expect_hex("AES-256-GCM ciphertext", ciphertext, sizeof(ciphertext),
                   "147a854881c5835ede6cd0c8fcc91b02"
                   "eea6e6409919361051139ca56d0561d"
                   "b6f64cb84db") != 0 ||
        expect_hex("AES-256-GCM tag", tag, sizeof(tag),
                   "b31a04821e048d0b30720c2d7ff38969") != 0 ||
        pe_crypto_aes256_gcm_decrypt(key, nonce, aad, sizeof(aad) - 1,
                                      ciphertext, sizeof(ciphertext), tag,
                                      decrypted) != 0 ||
        !pe_crypto_equal(decrypted, plaintext, sizeof(decrypted))) {
        return 1;
    }
    memcpy(bad_tag, tag, sizeof(bad_tag));
    bad_tag[0] ^= 1;
    memset(decrypted, 0xa5, sizeof(decrypted));
    if (pe_crypto_aes256_gcm_decrypt(key, nonce, aad, sizeof(aad) - 1,
                                      ciphertext, sizeof(ciphertext), bad_tag,
                                      decrypted) == 0) {
        fprintf(stderr, "modified AES-GCM tag was accepted\n");
        return 1;
    }
    for (i = 0; i < sizeof(decrypted); i++) {
        if (decrypted[i] != 0) {
            fprintf(stderr,
                    "unauthenticated AES-GCM plaintext was not cleared\n");
            return 1;
        }
    }

    pe_crypto_secure_zero(private_key, sizeof(private_key));
    for (i = 0; i < sizeof(private_key); i++) {
        if (private_key[i] != 0) {
            fprintf(stderr, "secure zero failed\n");
            return 1;
        }
    }
    printf("SxSSD crypto compatibility tests passed\n");
    return 0;
}
