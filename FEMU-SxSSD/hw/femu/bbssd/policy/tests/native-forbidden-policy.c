/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>

#define FORBIDDEN_HOST_SYMBOL "pe_test_forbidden_host_function"
#define FORBIDDEN_HOST_RESULT 0x53585353484f5354ULL

typedef uint64_t (*forbidden_host_fn)(void);

/*
 * Insecure control: native policy code can resolve symbols in FEMU's process
 * irrespective of any callback API presented to it.
 */
int init_policy(void *ssd, void *legacy_api)
{
    forbidden_host_fn forbidden_host_function;

    (void)ssd;
    (void)legacy_api;

    forbidden_host_function =
        (forbidden_host_fn)dlsym(RTLD_DEFAULT, FORBIDDEN_HOST_SYMBOL);
    if (!forbidden_host_function) {
        return 1;
    }

    return forbidden_host_function() == FORBIDDEN_HOST_RESULT ? 0 : 2;
}
