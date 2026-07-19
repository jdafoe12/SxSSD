BPF_CC ?= clang
BPF_READELF ?= $(shell command -v llvm-readelf 2>/dev/null || command -v readelf 2>/dev/null)
BPF_OBJDUMP ?= $(shell command -v llvm-objdump 2>/dev/null || command -v objdump 2>/dev/null)
BPF_CFLAGS = -target bpfel -O2 -g0 -Wall -Wextra -ffreestanding \
	-fno-stack-protector -I.

PRODUCTION_POLICIES = \
	block-interface-policy-eval.bpf.o \
	block-interface-policy-baseline.bpf.o \
	block-interface-policy-flashguard.bpf.o \
	block-interface-flashguard-policy.bpf.o \
	zns-policy.bpf.o \
	signing-test-policy.bpf.o \
	key-sharing-policy.bpf.o \
	ubpf-smoke-policy.bpf.o
NEGATIVE_FIXTURES = ubpf-forbidden-policy.bpf.o
TEST_POLICIES = \
	ubpf-isolation-policy.bpf.o \
	ubpf-state-policy.bpf.o \
	ubpf-transaction-fail-policy.bpf.o \
	ubpf-order-policy.bpf.o \
	ubpf-limit-policy.bpf.o \
	ubpf-runtime-fault-policy.bpf.o
GENERATED = $(PRODUCTION_POLICIES) $(NEGATIVE_FIXTURES) $(TEST_POLICIES) \
	native-forbidden-policy.so
LEGACY_NATIVE_ARTIFACTS = \
	block-interface-policy-eval.so \
	block-interface-policy-baseline.so \
	block-interface-policy-flashguard.so \
	block-interface-flashguard-policy.so \
	zns-policy.so signing-test-policy.so key-sharing-policy.so

.PHONY: all tool bpf fixtures isolation-test check-toolchain clean

all: check-toolchain $(PRODUCTION_POLICIES) $(NEGATIVE_FIXTURES) \
	$(TEST_POLICIES) native-forbidden-policy.so

tool bpf: all

fixtures: check-toolchain $(NEGATIVE_FIXTURES) $(TEST_POLICIES) \
	native-forbidden-policy.so

isolation-test: all

check-toolchain:
	@command -v $(BPF_CC) >/dev/null 2>&1 || { \
		echo "error: clang is required to build uBPF policies" >&2; exit 1; }
	@printf 'int x;\n' | $(BPF_CC) -target bpfel -x c -c -o /dev/null - \
		>/dev/null 2>&1 || { \
		echo "error: $(BPF_CC) has no BPF target; install clang/llvm" >&2; exit 1; }
	@test -n "$(BPF_READELF)" || { \
		echo "error: llvm-readelf or readelf is required" >&2; exit 1; }
	@test -n "$(BPF_OBJDUMP)" || { \
		echo "error: llvm-objdump or objdump is required" >&2; exit 1; }

BLOCK_DEPS = block-policy-bpf-core.h policy-bpf-abi.h
FLASHGUARD_DEPS = flashguard-bpf-core.h $(BLOCK_DEPS)

block-interface-policy-eval.bpf.o: block-interface-policy-eval.c $(BLOCK_DEPS)
block-interface-policy-baseline.bpf.o: block-interface-policy-baseline.c $(BLOCK_DEPS)
block-interface-policy-flashguard.bpf.o: block-interface-policy-flashguard.c $(FLASHGUARD_DEPS)
block-interface-flashguard-policy.bpf.o: block-interface-flashguard-policy.c $(FLASHGUARD_DEPS)
zns-policy.bpf.o: zns-policy.c zns-policy.h policy-bpf-abi.h
signing-test-policy.bpf.o: signing-test-policy.c policy-bpf-abi.h
key-sharing-policy.bpf.o: key-sharing-policy.c key-sharing.h policy-bpf-abi.h
ubpf-smoke-policy.bpf.o: ubpf-smoke-policy.c policy-bpf-abi.h
ubpf-forbidden-policy.bpf.o: ubpf-forbidden-policy.c policy-bpf-abi.h
ubpf-isolation-policy.bpf.o: ubpf-isolation-policy.c policy-bpf-abi.h
ubpf-state-policy.bpf.o: ubpf-state-policy.c policy-bpf-abi.h
ubpf-transaction-fail-policy.bpf.o: ubpf-transaction-fail-policy.c policy-bpf-abi.h
ubpf-order-policy.bpf.o: ubpf-order-policy.c policy-bpf-abi.h
ubpf-limit-policy.bpf.o: ubpf-limit-policy.c policy-bpf-abi.h
ubpf-runtime-fault-policy.bpf.o: ubpf-runtime-fault-policy.c policy-bpf-abi.h

%.bpf.o:
	$(BPF_CC) $(BPF_CFLAGS) -c -o $@ $<
	@./check-bpf-policy.sh "$@" "$(BPF_READELF)" "$(BPF_OBJDUMP)" \
		"$(@:ubpf-forbidden-policy.bpf.o=negative)"

# Source-only native fixture: it is never a production policy target.
native-forbidden-policy.so: native-forbidden-policy.c
	$(CC) -Wall -Wextra -O2 -fPIC -I. -Iinc -shared -o $@ $< -ldl

clean:
	rm -f $(GENERATED) $(LEGACY_NATIVE_ARTIFACTS)
