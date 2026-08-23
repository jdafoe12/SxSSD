/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef SXS_HOST_CRYPTO_H
#define SXS_HOST_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int sxs_host_random(uint8_t *output, size_t length);
int sxs_host_read_hex(const char *path, uint8_t *output, size_t length);

#endif /* SXS_HOST_CRYPTO_H */
