#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>

struct ssd;
struct FtlPolicyAPI;

#define FORBIDDEN_HOST_SYMBOL "pe_test_forbidden_host_function"
#define FORBIDDEN_HOST_RESULT 0x53585353484f5354ULL

typedef uint64_t (*forbidden_host_fn)(void);

/*
 * Insecure control: native policy code can resolve symbols in FEMU's process
 * even when those symbols are absent from FtlPolicyAPI.
 */
int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    forbidden_host_fn forbidden_host_function;

    (void)ssd;
    (void)api;

    forbidden_host_function =
        (forbidden_host_fn)dlsym(RTLD_DEFAULT, FORBIDDEN_HOST_SYMBOL);
    if (!forbidden_host_function) {
        return 1;
    }

    return forbidden_host_function() == FORBIDDEN_HOST_RESULT ? 0 : 2;
}
