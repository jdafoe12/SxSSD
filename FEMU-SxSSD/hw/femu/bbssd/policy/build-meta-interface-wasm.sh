#!/bin/sh
set -eu

output=${1:?usage: build-meta-interface-wasm.sh OUTPUT INPUT ALLOWLIST}
input=${2:?usage: build-meta-interface-wasm.sh OUTPUT INPUT ALLOWLIST}
allowlist=${3:?usage: build-meta-interface-wasm.sh OUTPUT INPUT ALLOWLIST}
script_dir=$(dirname "$0")

"$script_dir/generate-policy-import-allowlists.sh" --check \
    "$script_dir/policy-imports.def" \
    "$script_dir/wasm-imports.allow" \
    "$script_dir/privileged-wasm-imports.allow"

if [ -n "${WASM_CC:-}" ]; then
    compiler=$WASM_CC
else
    compiler=
    for candidate in clang clang-22 clang-21 clang-20 clang-19 clang-18 \
                     clang-17 clang-16 clang-15 clang-14 clang-13 clang-12 \
                     clang-11 clang-10; do
        if command -v "$candidate" >/dev/null 2>&1 &&
           "$candidate" --print-targets 2>/dev/null | grep -q wasm32; then
            compiler=$candidate
            break
        fi
    done
fi

[ -n "$compiler" ] || {
    echo "error: no clang compiler with a wasm32 backend was found" >&2
    exit 1
}

linker=$("$compiler" --target=wasm32-unknown-unknown \
    -print-prog-name=wasm-ld)
if "$linker" --help 2>/dev/null | grep -q -- --export-memory; then
    memory_export=--export-memory
else
    memory_export=--export-all,--no-check-features
fi

"$compiler" --target=wasm32-unknown-unknown -O2 -g0 -Wall -Wextra \
    -ffreestanding -fno-builtin -fno-stack-protector -nostdlib \
    -mno-atomics -mno-bulk-memory -mno-reference-types -mno-simd128 \
    -mllvm -disable-loop-idiom-all -I"$(dirname "$input")" \
    -Wl,--no-entry,--strip-all -Wl,"$memory_export" \
    -Wl,--export=__stack_pointer \
    -Wl,--initial-memory=2097152,--max-memory=2097152 \
    -Wl,-z,stack-size=65536 -Wl,--allow-undefined-file="$allowlist" \
    -o "$output" "$input"

"$script_dir/check-wasm-policy.sh" "$output"
