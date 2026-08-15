#ifndef FEMU_SXSSD_POLICY_WAMR_H
#define FEMU_SXSSD_POLICY_WAMR_H

#include "policy-engine.h"

#include <stddef.h>
#include <stdint.h>

#define PE_WAMR_INSTRUCTION_LIMIT 10000000
#define PE_WAMR_PAGE_BYTES 65536U
#define PE_WAMR_MAX_LINEAR_MEMORY_PAGES 4096U
#define PE_WAMR_EXEC_ENV_STACK_BYTES 65536U

struct pe_policy_execution;
struct pe_wamr_vm;

struct pe_wamr_load_config {
    enum pe_policy_privilege privilege;
};

int pe_wamr_runtime_initialize(char **error_out);
int pe_wamr_vm_validate(const uint8_t *wasm, size_t wasm_size,
                        char **error_out);
struct pe_wamr_vm *pe_wamr_vm_create(const uint8_t *wasm, size_t wasm_size,
                                     char **error_out);
struct pe_wamr_vm *pe_wamr_vm_create_with_config(
    const uint8_t *wasm, size_t wasm_size,
    const struct pe_wamr_load_config *config, char **error_out);
void pe_wamr_vm_destroy(struct pe_wamr_vm *vm);
int pe_wamr_vm_execute(struct pe_wamr_vm *vm,
                       struct pe_policy_execution *execution,
                       uint64_t *result_out);

#endif /* FEMU_SXSSD_POLICY_WAMR_H */
