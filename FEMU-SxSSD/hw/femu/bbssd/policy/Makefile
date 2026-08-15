# Prefer the unversioned compiler when it has the WebAssembly backend.  Older
# Ubuntu guests may ship an unversioned clang without that backend alongside a
# usable versioned compiler (for example clang-12).
WASM_CC ?= $(shell \
	for cc in clang clang-22 clang-21 clang-20 clang-19 clang-18 clang-17 \
		clang-16 clang-15 clang-14 clang-13 clang-12 clang-11 clang-10; do \
		if command -v $$cc >/dev/null 2>&1 && \
			$$cc --print-targets 2>/dev/null | grep -q 'wasm32'; then \
			printf '%s\n' $$cc; exit 0; \
		fi; \
	done; \
	printf '%s\n' clang)
WASM_CFLAGS = --target=wasm32-unknown-unknown -O2 -g0 -Wall -Wextra \
	-ffreestanding -fno-builtin -fno-stack-protector -nostdlib \
	-mno-atomics -mno-bulk-memory -mno-reference-types -mno-simd128 \
	-mllvm -disable-loop-idiom-all -I.

# wasm-ld learned --export-memory after LLVM 12.  LLVM 12 can still produce
# the required exported fixed memory with --export-all; that broader export
# requires feature checking to be disabled for mutable globals.
WASM_HAS_EXPORT_MEMORY := $(shell \
	ld_path="$$($(WASM_CC) --target=wasm32-unknown-unknown \
		-print-prog-name=wasm-ld 2>/dev/null)"; \
	"$$ld_path" --help 2>/dev/null | grep -q -- '--export-memory' && \
		printf '%s\n' yes)
ifeq ($(WASM_HAS_EXPORT_MEMORY),yes)
WASM_MEMORY_EXPORT_FLAGS = -Wl,--export-memory
else
WASM_MEMORY_EXPORT_FLAGS = -Wl,--export-all,--no-check-features
endif

WASM_LDFLAGS = -Wl,--no-entry,--strip-all $(WASM_MEMORY_EXPORT_FLAGS) \
	-Wl,--initial-memory=65536,--max-memory=65536 \
	-Wl,-z,stack-size=16384
# Memory is part of each policy artifact's declaration. Block policies reserve
# their fixed-size maps, and ZNS reserves one partial-page buffer per zone.
# Policies without large fixed state keep the 64 KiB default above.
BLOCK_WASM_LDFLAGS = -Wl,--no-entry,--strip-all $(WASM_MEMORY_EXPORT_FLAGS) \
	-Wl,--initial-memory=71303168,--max-memory=71303168 \
	-Wl,-z,stack-size=16384
FLASHGUARD_WASM_LDFLAGS = \
	-Wl,--no-entry,--strip-all $(WASM_MEMORY_EXPORT_FLAGS) \
	-Wl,--initial-memory=220200960,--max-memory=220200960 \
	-Wl,-z,stack-size=16384
ZNS_WASM_LDFLAGS = -Wl,--no-entry,--strip-all $(WASM_MEMORY_EXPORT_FLAGS) \
	-Wl,--initial-memory=2097152,--max-memory=2097152 \
	-Wl,-z,stack-size=16384
WASM_IMPORT_ALLOWLIST = wasm-imports.allow
PRIVILEGED_WASM_IMPORT_ALLOWLIST = privileged-wasm-imports.allow
WASM_IMPORT_CATALOG = policy-imports.def
WASM_IMPORT_GENERATOR = generate-policy-import-allowlists.sh
META_INTERFACE_POLICY = meta-interface-policy.wasm
META_INTERFACE_LDFLAGS = \
	-Wl,--no-entry,--strip-all $(WASM_MEMORY_EXPORT_FLAGS) \
	-Wl,--initial-memory=2097152,--max-memory=2097152 \
	-Wl,-z,stack-size=65536

PRODUCTION_POLICIES = \
	block-interface-policy-baseline.wasm \
	block-interface-policy-flashguard.wasm \
	block-interface-flashguard-policy.wasm \
	zns-policy.wasm \
	signing-test-policy.wasm \
	key-sharing-policy.wasm \
	wasm-smoke-policy.wasm
EXPERIMENT_POLICIES = \
	block-interface-policy-streams-1.wasm \
	block-interface-policy-streams-2.wasm \
	block-interface-policy-streams-4.wasm
TEST_POLICIES = \
	wasm-isolation-policy.wasm \
	wasm-state-policy.wasm \
	wasm-transaction-fail-policy.wasm \
	wasm-order-policy.wasm \
	wasm-limit-policy.wasm \
	wasm-runtime-fault-policy.wasm
NEGATIVE_FIXTURES = wasm-forbidden-policy.wasm \
		wasm-privileged-forbidden-policy.wasm native-forbidden-policy.so
GENERATED = $(PRODUCTION_POLICIES) $(EXPERIMENT_POLICIES) \
		$(TEST_POLICIES) $(NEGATIVE_FIXTURES) $(META_INTERFACE_POLICY)
LEGACY_ARTIFACTS = \
	block-interface-policy-baseline.so \
	block-interface-policy-flashguard.so \
	block-interface-flashguard-policy.so \
	zns-policy.so signing-test-policy.so key-sharing-policy.so

.PHONY: all tool wasm experiments fixtures isolation-test reproducible \
	check-toolchain check-imports clean

all: check-toolchain check-imports $(PRODUCTION_POLICIES) \
		$(EXPERIMENT_POLICIES) $(TEST_POLICIES) $(NEGATIVE_FIXTURES) \
		$(META_INTERFACE_POLICY)

tool wasm: all

experiments: check-toolchain check-imports $(EXPERIMENT_POLICIES)

fixtures: check-toolchain check-imports $(TEST_POLICIES) $(NEGATIVE_FIXTURES)

isolation-test: all

check-toolchain:
	@command -v $(WASM_CC) >/dev/null 2>&1 || { \
		echo "error: clang is required to build WebAssembly policies" >&2; exit 1; }
	@printf 'int f(void) { return 0; }\n' | $(WASM_CC) \
		--target=wasm32-unknown-unknown -nostdlib -Wl,--no-entry \
		-Wl,--export=f -x c -o /dev/null - >/dev/null 2>&1 || { \
		echo "error: $(WASM_CC) has no wasm32 target or wasm-ld; install clang/lld" >&2; exit 1; }

check-imports:
	@./$(WASM_IMPORT_GENERATOR) --check $(WASM_IMPORT_CATALOG) \
		$(WASM_IMPORT_ALLOWLIST) $(PRIVILEGED_WASM_IMPORT_ALLOWLIST)

BLOCK_DEPS = block-policy-wasm-core.h policy-wasm-abi.h
STREAM_DEPS = stream-policy-wasm-core.h policy-wasm-abi.h
FLASHGUARD_DEPS = flashguard-wasm-core.h $(BLOCK_DEPS)
POLICY_BUILD_DEPS = check-wasm-policy.sh $(WASM_IMPORT_ALLOWLIST) \
	$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) $(WASM_IMPORT_CATALOG) \
	$(WASM_IMPORT_GENERATOR)

BLOCK_POLICIES = block-interface-policy-baseline.wasm
STREAM_POLICIES = block-interface-policy-streams-1.wasm \
		block-interface-policy-streams-2.wasm \
		block-interface-policy-streams-4.wasm

$(BLOCK_POLICIES): %.wasm: %.c $(BLOCK_DEPS) $(POLICY_BUILD_DEPS)
	$(WASM_CC) $(WASM_CFLAGS) $(BLOCK_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ $<
	@./check-wasm-policy.sh "$@"
$(STREAM_POLICIES): %.wasm: %.c $(STREAM_DEPS) $(POLICY_BUILD_DEPS)
	$(WASM_CC) $(WASM_CFLAGS) $(BLOCK_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ $<
	@./check-wasm-policy.sh "$@"
block-interface-policy-flashguard.wasm: block-interface-policy-flashguard.c \
		$(FLASHGUARD_DEPS) $(POLICY_BUILD_DEPS)
	$(WASM_CC) $(WASM_CFLAGS) $(FLASHGUARD_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ $<
	@./check-wasm-policy.sh "$@"
block-interface-flashguard-policy.wasm: block-interface-flashguard-policy.c \
		$(FLASHGUARD_DEPS) $(POLICY_BUILD_DEPS)
	$(WASM_CC) $(WASM_CFLAGS) $(FLASHGUARD_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ $<
	@./check-wasm-policy.sh "$@"
zns-policy.wasm: zns-policy.c zns-policy.h policy-wasm-abi.h \
		$(POLICY_BUILD_DEPS)
	$(WASM_CC) $(WASM_CFLAGS) $(ZNS_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ $<
	@./check-wasm-policy.sh "$@"
signing-test-policy.wasm: signing-test-policy.c policy-wasm-abi.h
key-sharing-policy.wasm: key-sharing-policy.c key-sharing.h policy-wasm-abi.h
meta-interface-policy.wasm: ../meta-interface-policy.c \
		../meta-interface-protocol.h \
		policy-wasm-abi.h policy-privileged-wasm-abi.h \
		check-wasm-policy.sh \
		$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) $(WASM_IMPORT_CATALOG) \
		$(WASM_IMPORT_GENERATOR)
	@./$(WASM_IMPORT_GENERATOR) --check $(WASM_IMPORT_CATALOG) \
		$(WASM_IMPORT_ALLOWLIST) $(PRIVILEGED_WASM_IMPORT_ALLOWLIST)
	$(WASM_CC) $(WASM_CFLAGS) -I.. $(META_INTERFACE_LDFLAGS) \
		-Wl,--allow-undefined-file=$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) -o $@ $<
	@./check-wasm-policy.sh "$@"

%.wasm: %.c policy-wasm-abi.h check-wasm-policy.sh $(WASM_IMPORT_ALLOWLIST) \
		$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) $(WASM_IMPORT_CATALOG) \
		$(WASM_IMPORT_GENERATOR)
	@./$(WASM_IMPORT_GENERATOR) --check $(WASM_IMPORT_CATALOG) \
		$(WASM_IMPORT_ALLOWLIST) $(PRIVILEGED_WASM_IMPORT_ALLOWLIST)
	$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ $<
	@./check-wasm-policy.sh "$@"

# This fixture intentionally names one symbol outside the capability ABI.
wasm-forbidden-policy.wasm: wasm-forbidden-policy.c policy-wasm-abi.h \
		check-wasm-policy.sh $(WASM_IMPORT_CATALOG)
	$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) -Wl,--allow-undefined -o $@ $<
	@./check-wasm-policy.sh "$@"

# Valid Wasm that deliberately requests the privileged namespace.
wasm-privileged-forbidden-policy.wasm: wasm-privileged-forbidden-policy.c \
		policy-wasm-abi.h policy-privileged-wasm-abi.h \
		check-wasm-policy.sh \
		$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) $(WASM_IMPORT_CATALOG) \
		$(WASM_IMPORT_GENERATOR)
	@./$(WASM_IMPORT_GENERATOR) --check $(WASM_IMPORT_CATALOG) \
		$(WASM_IMPORT_ALLOWLIST) $(PRIVILEGED_WASM_IMPORT_ALLOWLIST)
	$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) -o $@ $<
	@./check-wasm-policy.sh "$@"

reproducible: all
	@tmp_dir=$$(mktemp -d); trap 'rm -rf "$$tmp_dir"' EXIT; \
	for artifact in $(filter-out $(BLOCK_POLICIES) $(STREAM_POLICIES) \
		block-interface-policy-flashguard.wasm \
		block-interface-flashguard-policy.wasm zns-policy.wasm,$(PRODUCTION_POLICIES) \
		$(TEST_POLICIES)); do \
		source=$${artifact%.wasm}.c; \
		$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) \
			-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) \
			-o "$$tmp_dir/$$artifact" "$$source" || exit 1; \
		cmp -s "$$artifact" "$$tmp_dir/$$artifact" || { \
			echo "error: non-reproducible artifact $$artifact" >&2; exit 1; }; \
	done; \
	$(WASM_CC) $(WASM_CFLAGS) $(ZNS_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) \
		-o "$$tmp_dir/zns-policy.wasm" zns-policy.c; \
	cmp -s zns-policy.wasm "$$tmp_dir/zns-policy.wasm" || { \
		echo "error: non-reproducible artifact zns-policy.wasm" >&2; exit 1; }; \
	for artifact in $(BLOCK_POLICIES) $(STREAM_POLICIES); do \
		source=$${artifact%.wasm}.c; \
		$(WASM_CC) $(WASM_CFLAGS) $(BLOCK_WASM_LDFLAGS) \
			-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) \
			-o "$$tmp_dir/$$artifact" "$$source" || exit 1; \
		cmp -s "$$artifact" "$$tmp_dir/$$artifact" || exit 1; \
	done; \
	for artifact in block-interface-policy-flashguard.wasm \
		block-interface-flashguard-policy.wasm; do \
		source=$${artifact%.wasm}.c; \
		$(WASM_CC) $(WASM_CFLAGS) $(FLASHGUARD_WASM_LDFLAGS) \
			-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) \
			-o "$$tmp_dir/$$artifact" "$$source" || exit 1; \
		cmp -s "$$artifact" "$$tmp_dir/$$artifact" || exit 1; \
	done; \
	$(WASM_CC) $(WASM_CFLAGS) -I.. $(META_INTERFACE_LDFLAGS) \
		-Wl,--allow-undefined-file=$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) \
		-o "$$tmp_dir/$(META_INTERFACE_POLICY)" ../meta-interface-policy.c; \
	cmp -s "$(META_INTERFACE_POLICY)" "$$tmp_dir/$(META_INTERFACE_POLICY)" || { \
		echo "error: non-reproducible artifact $(META_INTERFACE_POLICY)" >&2; exit 1; }

# Source-only native fixture: it must be rejected by the policy loader.
native-forbidden-policy.so: native-forbidden-policy.c
	$(CC) -Wall -Wextra -O2 -fPIC -I. -Iinc -shared -o $@ $< -ldl

clean:
	rm -f $(GENERATED) $(LEGACY_ARTIFACTS)
