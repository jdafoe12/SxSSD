/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "host-crypto.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <sys/random.h>

#include "../policy-crypto.h"

int sxs_host_random(uint8_t *output, size_t length)
{
    size_t offset = 0;

    if (!output && length != 0) {
        return -1;
    }
    while (offset < length) {
        ssize_t result = getrandom(output + offset, length - offset, 0);

        if (result > 0) {
            offset += (size_t)result;
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            if (output) {
                pe_crypto_secure_zero(output, length);
            }
            return -1;
        }
    }
    return 0;
}

static int sxs_hex_value(int character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

int sxs_host_read_hex(const char *path, uint8_t *output, size_t length)
{
    FILE *file;
    size_t nibble = 0;
    int character;
    int rc = -1;

    if (!path || (!output && length != 0) || length > SIZE_MAX / 2) {
        return -1;
    }
    file = fopen(path, "r");
    if (!file) {
        return -1;
    }
    while ((character = fgetc(file)) != EOF) {
        int value;

        if (isspace((unsigned char)character)) {
            continue;
        }
        value = sxs_hex_value(character);
        if (value < 0 || nibble >= 2 * length) {
            goto cleanup;
        }
        if ((nibble & 1U) == 0) {
            output[nibble / 2] = (uint8_t)(value << 4);
        } else {
            output[nibble / 2] |= (uint8_t)value;
        }
        nibble++;
    }
    if (!ferror(file) && nibble == 2 * length) {
        rc = 0;
    }

cleanup:
    fclose(file);
    if (rc != 0 && output) {
        pe_crypto_secure_zero(output, length);
    }
    return rc;
}
