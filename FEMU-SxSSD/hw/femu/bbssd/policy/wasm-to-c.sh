#!/bin/sh
set -eu

input=${1:?usage: wasm-to-c.sh INPUT.wasm OUTPUT.c SYMBOL}
output=${2:?usage: wasm-to-c.sh INPUT.wasm OUTPUT.c SYMBOL}
symbol=${3:?usage: wasm-to-c.sh INPUT.wasm OUTPUT.c SYMBOL}
temporary="${output}.tmp"

{
    echo '/* Generated WebAssembly artifact; do not edit manually. */'
    echo '#include <stddef.h>'
    echo '#include <stdint.h>'
    echo
    echo "const uint8_t ${symbol}[] = {"
    od -An -v -t u1 "$input" |
        awk '{
            printf "    "
            for (i = 1; i <= NF; i++) {
                printf "%s%s", $i, (i == NF ? "" : ", ")
            }
            print ","
        }'
    echo '};'
    echo
    echo "const size_t ${symbol}_size ="
    echo "    sizeof(${symbol});"
} >"$temporary"
mv "$temporary" "$output"
