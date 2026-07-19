#ifndef FEMU_POLICY_BPF_HELPERS_H
#define FEMU_POLICY_BPF_HELPERS_H

struct ubpf_vm;

int pe_bpf_helpers_register(struct ubpf_vm *vm);

#endif /* FEMU_POLICY_BPF_HELPERS_H */
