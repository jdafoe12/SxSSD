#ifndef FEMU_POLICY_BPF_VM_H
#define FEMU_POLICY_BPF_VM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Production GC scans a complete eSWD (16,384 pages with the default FEMU
 * geometry). Policies are trusted, while safe uBPF memory and helper checks
 * provide the capability boundary, so retain a generous finite runaway guard.
 */
#define PE_BPF_INSTRUCTION_LIMIT 10000000U
#define PE_BPF_STACK_BYTES 4096U

struct pe_bpf_vm;

/* Performs structural validation and a complete load without retaining a VM. */
int pe_bpf_vm_validate(const uint8_t *elf, size_t elf_size, char **error_out);

/* Repeats validation and returns a retained safe, interpreter-only VM. */
struct pe_bpf_vm *pe_bpf_vm_create(const uint8_t *elf, size_t elf_size,
                                    char **error_out);
void pe_bpf_vm_destroy(struct pe_bpf_vm *policy_vm);
int pe_bpf_vm_execute(struct pe_bpf_vm *policy_vm, void *context,
                      size_t context_size, uint64_t *result_out);

#endif /* FEMU_POLICY_BPF_VM_H */
