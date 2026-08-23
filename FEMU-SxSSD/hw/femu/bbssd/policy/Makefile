# SPDX-License-Identifier: GPL-2.0-or-later

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
	-mllvm -disable-loop-idiom-all -Iinclude -Isrc
# The shared block implementation and its selected variant are separate source
# files. Preserve whole-policy optimization across that source boundary.
BLOCK_WASM_CFLAGS = $(WASM_CFLAGS) -flto

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
WASM_IMPORT_CATALOG = include/policy-imports.def
WASM_IMPORT_GENERATOR = generate-policy-import-allowlists.sh
SRC_DIR = src
TEST_DIR = tests
INCLUDE_DIR = include
META_INTERFACE_POLICY = meta-interface-policy.wasm
META_INTERFACE_LDFLAGS = \
	-Wl,--no-entry,--strip-all $(WASM_MEMORY_EXPORT_FLAGS) \
	-Wl,--initial-memory=2097152,--max-memory=2097152 \
	-Wl,-z,stack-size=65536

POLICIES = \
	block-interface-policy-baseline.wasm \
	block-interface-policy-flashguard.wasm \
	zns-policy.wasm \
	key-sharing-policy.wasm
EXPERIMENT_POLICIES = \
	block-interface-policy-streams-1.wasm \
	block-interface-policy-streams-2.wasm \
	block-interface-policy-streams-4.wasm
TEST_POLICIES = \
	signing-test-policy.wasm \
	wasm-smoke-policy.wasm \
	wasm-isolation-policy.wasm \
	wasm-state-policy.wasm \
	wasm-transaction-fail-policy.wasm \
	wasm-order-policy.wasm \
	wasm-limit-policy.wasm \
	wasm-runtime-fault-policy.wasm \
	wasm-flash-error-policy.wasm
NEGATIVE_FIXTURES = wasm-forbidden-policy.wasm \
		wasm-privileged-forbidden-policy.wasm native-forbidden-policy.so
GENERATED = $(POLICIES) $(EXPERIMENT_POLICIES) \
		$(TEST_POLICIES) $(NEGATIVE_FIXTURES) $(META_INTERFACE_POLICY)
LEGACY_ARTIFACTS = \
	block-interface-policy-baseline.so \
	block-interface-policy-flashguard.so \
	block-interface-flashguard-policy.so \
	block-interface-flashguard-policy.wasm \
	zns-policy.so signing-test-policy.so key-sharing-policy.so

.PHONY: all tool wasm experiments fixtures isolation-test reproducible \
	check-toolchain check-imports clean

all: check-toolchain check-imports $(POLICIES) \
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

POLICY_ABI = $(INCLUDE_DIR)/policy-wasm-abi.h \
	$(INCLUDE_DIR)/policy-imports.def
PRIVILEGED_POLICY_ABI = $(INCLUDE_DIR)/policy-privileged-wasm-abi.h \
	$(POLICY_ABI)
BLOCK_SOURCES = $(SRC_DIR)/block-policy.c
BLOCK_DEPS = $(SRC_DIR)/block-policy.h $(POLICY_ABI)
STREAM_SOURCE = $(SRC_DIR)/stream-policy.c
POLICY_BUILD_DEPS = check-wasm-policy.sh $(WASM_IMPORT_ALLOWLIST) \
	$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) $(WASM_IMPORT_CATALOG) \
	$(WASM_IMPORT_GENERATOR)

STREAM_POLICIES = block-interface-policy-streams-1.wasm \
		block-interface-policy-streams-2.wasm \
		block-interface-policy-streams-4.wasm

block-interface-policy-baseline.wasm: $(BLOCK_SOURCES) \
		$(SRC_DIR)/block-baseline.c $(BLOCK_DEPS) $(POLICY_BUILD_DEPS)
	$(WASM_CC) $(BLOCK_WASM_CFLAGS) $(BLOCK_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ \
		$(BLOCK_SOURCES) $(SRC_DIR)/block-baseline.c
	@./check-wasm-policy.sh "$@"

block-interface-policy-streams-1.wasm: STREAM_COUNT = 1
block-interface-policy-streams-2.wasm: STREAM_COUNT = 2
block-interface-policy-streams-4.wasm: STREAM_COUNT = 4
$(STREAM_POLICIES): $(STREAM_SOURCE) $(POLICY_ABI) $(POLICY_BUILD_DEPS)
	$(WASM_CC) $(WASM_CFLAGS) $(BLOCK_WASM_LDFLAGS) \
		-DSTREAM_PLACEMENT_STREAMS=$(STREAM_COUNT) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ \
		$(STREAM_SOURCE)
	@./check-wasm-policy.sh "$@"

block-interface-policy-flashguard.wasm: $(BLOCK_SOURCES) \
		$(SRC_DIR)/flashguard-policy.c $(BLOCK_DEPS) \
		$(POLICY_BUILD_DEPS)
	$(WASM_CC) $(BLOCK_WASM_CFLAGS) $(FLASHGUARD_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ \
		$(BLOCK_SOURCES) $(SRC_DIR)/flashguard-policy.c
	@./check-wasm-policy.sh "$@"

zns-policy.wasm: $(SRC_DIR)/zns-policy.c \
		$(SRC_DIR)/zns-policy.h $(POLICY_ABI) \
		$(POLICY_BUILD_DEPS)
	$(WASM_CC) $(WASM_CFLAGS) $(ZNS_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ \
		$(SRC_DIR)/zns-policy.c
	@./check-wasm-policy.sh "$@"

key-sharing-policy.wasm: $(SRC_DIR)/key-sharing-policy.c \
		$(INCLUDE_DIR)/key-sharing.h $(POLICY_ABI) $(POLICY_BUILD_DEPS)
	$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ \
		$(SRC_DIR)/key-sharing-policy.c
	@./check-wasm-policy.sh "$@"

$(TEST_POLICIES): %.wasm: $(TEST_DIR)/%.c $(POLICY_ABI) \
		$(POLICY_BUILD_DEPS)
	$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) -o $@ $<
	@./check-wasm-policy.sh "$@"

meta-interface-policy.wasm: ../meta-interface-policy.c \
		../meta-interface-protocol.h \
		$(PRIVILEGED_POLICY_ABI) \
		check-wasm-policy.sh \
		$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) $(WASM_IMPORT_CATALOG) \
		$(WASM_IMPORT_GENERATOR)
	@./$(WASM_IMPORT_GENERATOR) --check $(WASM_IMPORT_CATALOG) \
		$(WASM_IMPORT_ALLOWLIST) $(PRIVILEGED_WASM_IMPORT_ALLOWLIST)
	$(WASM_CC) $(WASM_CFLAGS) -I.. $(META_INTERFACE_LDFLAGS) \
		-Wl,--allow-undefined-file=$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) -o $@ $<
	@./check-wasm-policy.sh "$@"

# This fixture intentionally names one symbol outside the capability ABI.
wasm-forbidden-policy.wasm: $(TEST_DIR)/wasm-forbidden-policy.c \
		$(POLICY_ABI) \
		check-wasm-policy.sh $(WASM_IMPORT_CATALOG)
	$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) -Wl,--allow-undefined -o $@ $<
	@./check-wasm-policy.sh "$@"

# Valid Wasm that deliberately requests the privileged namespace.
wasm-privileged-forbidden-policy.wasm: \
		$(TEST_DIR)/wasm-privileged-forbidden-policy.c \
		$(PRIVILEGED_POLICY_ABI) \
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
	$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) \
		-o "$$tmp_dir/key-sharing-policy.wasm" \
		$(SRC_DIR)/key-sharing-policy.c; \
	cmp -s key-sharing-policy.wasm "$$tmp_dir/key-sharing-policy.wasm" || \
		exit 1; \
	for artifact in $(TEST_POLICIES); do \
		source=$(TEST_DIR)/$${artifact%.wasm}.c; \
		$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) \
			-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) \
			-o "$$tmp_dir/$$artifact" "$$source" || exit 1; \
		cmp -s "$$artifact" "$$tmp_dir/$$artifact" || { \
			echo "error: non-reproducible artifact $$artifact" >&2; exit 1; }; \
	done; \
	$(WASM_CC) $(WASM_CFLAGS) $(ZNS_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) \
		-o "$$tmp_dir/zns-policy.wasm" $(SRC_DIR)/zns-policy.c; \
	cmp -s zns-policy.wasm "$$tmp_dir/zns-policy.wasm" || { \
		echo "error: non-reproducible artifact zns-policy.wasm" >&2; exit 1; }; \
	$(WASM_CC) $(BLOCK_WASM_CFLAGS) $(BLOCK_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) \
		-o "$$tmp_dir/block-interface-policy-baseline.wasm" \
		$(BLOCK_SOURCES) $(SRC_DIR)/block-baseline.c; \
	cmp -s block-interface-policy-baseline.wasm \
		"$$tmp_dir/block-interface-policy-baseline.wasm" || exit 1; \
	$(WASM_CC) $(BLOCK_WASM_CFLAGS) $(FLASHGUARD_WASM_LDFLAGS) \
		-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) \
		-o "$$tmp_dir/block-interface-policy-flashguard.wasm" \
		$(BLOCK_SOURCES) $(SRC_DIR)/flashguard-policy.c; \
	cmp -s block-interface-policy-flashguard.wasm \
		"$$tmp_dir/block-interface-policy-flashguard.wasm" || exit 1; \
	for count in 1 2 4; do \
		artifact=block-interface-policy-streams-$$count.wasm; \
		$(WASM_CC) $(WASM_CFLAGS) $(BLOCK_WASM_LDFLAGS) \
			-DSTREAM_PLACEMENT_STREAMS=$$count \
			-Wl,--allow-undefined-file=$(WASM_IMPORT_ALLOWLIST) \
			-o "$$tmp_dir/$$artifact" $(STREAM_SOURCE) || exit 1; \
		cmp -s "$$artifact" "$$tmp_dir/$$artifact" || exit 1; \
	done; \
	$(WASM_CC) $(WASM_CFLAGS) -I.. $(META_INTERFACE_LDFLAGS) \
		-Wl,--allow-undefined-file=$(PRIVILEGED_WASM_IMPORT_ALLOWLIST) \
		-o "$$tmp_dir/$(META_INTERFACE_POLICY)" ../meta-interface-policy.c; \
	cmp -s "$(META_INTERFACE_POLICY)" "$$tmp_dir/$(META_INTERFACE_POLICY)" || { \
		echo "error: non-reproducible artifact $(META_INTERFACE_POLICY)" >&2; exit 1; }

# Source-only native fixture: it must be rejected by the policy loader.
native-forbidden-policy.so: $(TEST_DIR)/native-forbidden-policy.c
	$(CC) -Wall -Wextra -O2 -fPIC -shared -o $@ $< -ldl

clean:
	rm -f $(GENERATED) $(LEGACY_ARTIFACTS)
