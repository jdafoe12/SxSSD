#!/bin/sh
set -eu

artifact=$1
readelf_tool=$2
objdump_tool=$3
mode=${4:-production}
maximum_size=1048576
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

fail()
{
    echo "error: invalid BPF policy $artifact: $*" >&2
    exit 1
}

size=$(wc -c < "$artifact")
[ "$size" -gt 0 ] && [ "$size" -le "$maximum_size" ] ||
    fail "artifact size $size is outside 1..$maximum_size bytes"

header=$($readelf_tool -h "$artifact")
printf '%s\n' "$header" | grep -Eq 'Class:.*ELF64' || fail "not ELF64"
printf '%s\n' "$header" | grep -Eq 'Data:.*little endian|Data:.*2.s complement, little endian' ||
    fail "not little-endian"
printf '%s\n' "$header" | grep -Eq 'Type:.*REL' || fail "not relocatable ELF"
printf '%s\n' "$header" | grep -Eq 'Machine:.*(BPF|Linux BPF)' || fail "not EM_BPF"

symbols=$($readelf_tool --wide -s "$artifact")
[ "$(printf '%s\n' "$symbols" | awk '$5 == "GLOBAL" && $7 != "UND" && $8 == "policy_main" { n++ } END { print n+0 }')" -eq 1 ] ||
    fail "must export exactly one policy_main"

sections=$($readelf_tool --wide -S "$artifact")
printf '%s\n' "$sections" | grep -Eq '\.(data|bss|maps)([[:space:]]|$)' &&
    fail "writable policy section is forbidden"
printf '%s\n' "$sections" | awk '
    /^  \[[[:space:]]*[0-9]+\]/ {
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^[A-Z]+$/ && $i ~ /A/ && $i ~ /W/) bad = 1
        }
    }
    END { exit bad ? 0 : 1 }
' && fail "allocated writable section is forbidden"
printf '%s\n' "$sections" | awk '
    /^  \[[[:space:]]*[0-9]+\]/ {
        if ($1 == "[") {
            type = $4
            flags = $9
        } else {
            type = $3
            flags = $8
        }
        if ((flags ~ /A/ && type != "PROGBITS") ||
            (flags ~ /X/ && flags !~ /A/) || flags ~ /[CT]/) bad = 1
    }
    END { exit bad ? 0 : 1 }
' && fail "unsupported allocated or executable section"

allowed_helpers=$(awk '
    /^extern sxs_s64 sxs_/ {
        name=$3
        sub(/\(.*/, "", name)
        print name
    }
' "$script_dir/policy-bpf-abi.h")
unknown=$(
    printf '%s\n' "$symbols" |
        awk '$7 == "UND" && $8 != "" { print $8 }' |
        while IFS= read -r symbol; do
            printf '%s\n' "$allowed_helpers" | grep -Fx "$symbol" >/dev/null ||
                printf '%s\n' "$symbol"
        done
)
if [ -n "$unknown" ] && [ "$mode" != negative ]; then
    fail "unregistered symbol(s): $(printf '%s' "$unknown" | tr '\n' ' ')"
fi
if [ "$mode" = negative ] && [ -z "$unknown" ]; then
    fail "negative fixture unexpectedly uses only registered helpers"
fi

relocations=$($readelf_tool --wide -r "$artifact")
bad_relocations=$(printf '%s\n' "$relocations" |
    awk '$3 ~ /^R_BPF_/ && $3 != "R_BPF_64_64" && $3 != "R_BPF_64_32" { print $3 }')
[ -z "$bad_relocations" ] || fail "unsupported relocation: $bad_relocations"

$objdump_tool -h "$artifact" >/dev/null || fail "objdump cannot parse artifact"
