#!/bin/sh
set -eu

mode=${1:?usage: generate-policy-import-allowlists.sh --write|--check CATALOG COMMON PRIVILEGED}
catalog=${2:?usage: generate-policy-import-allowlists.sh --write|--check CATALOG COMMON PRIVILEGED}
common=${3:?usage: generate-policy-import-allowlists.sh --write|--check CATALOG COMMON PRIVILEGED}
privileged=${4:?usage: generate-policy-import-allowlists.sh --write|--check CATALOG COMMON PRIVILEGED}

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
generated_common=$tmp_dir/wasm-imports.allow
generated_privileged=$tmp_dir/privileged-wasm-imports.allow

awk -v common_out="$generated_common" -v privileged_out="$generated_privileged" '
function trim(value)
{
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
    return value
}

/^SXS_COMMON_IMPORT\(/ {
    line = $0
    while (line !~ /\)[[:space:]]*$/ && getline continuation > 0) {
        line = line continuation
    }
    sub(/^SXS_COMMON_IMPORT\(/, "", line)
    sub(/\)[[:space:]]*$/, "", line)
    count = split(line, field, ",")
    if (count != 5) {
        print "error: malformed common import: " $0 > "/dev/stderr"
        failed = 1
        next
    }
    linker_symbol = trim(field[2])
    meta_access = trim(field[5])
    print linker_symbol > common_out
    if (meta_access == "META") {
        print linker_symbol > privileged_out
    } else if (meta_access != "NO_META") {
        print "error: invalid meta access: " meta_access > "/dev/stderr"
        failed = 1
    }
}

/^SXS_PRIVILEGED_IMPORT\(/ {
    line = $0
    while (line !~ /\)[[:space:]]*$/ && getline continuation > 0) {
        line = line continuation
    }
    sub(/^SXS_PRIVILEGED_IMPORT\(/, "", line)
    sub(/\)[[:space:]]*$/, "", line)
    count = split(line, field, ",")
    if (count != 4) {
        print "error: malformed privileged import: " $0 > "/dev/stderr"
        failed = 1
        next
    }
    print trim(field[2]) > privileged_out
}

END {
    if (failed) {
        exit 1
    }
}
' "$catalog"

case "$mode" in
--write)
    cp "$generated_common" "$common"
    cp "$generated_privileged" "$privileged"
    ;;
--check)
    cmp -s "$generated_common" "$common" || {
        echo "error: $common is stale; regenerate it from $catalog" >&2
        diff -u "$common" "$generated_common" || true
        exit 1
    }
    cmp -s "$generated_privileged" "$privileged" || {
        echo "error: $privileged is stale; regenerate it from $catalog" >&2
        diff -u "$privileged" "$generated_privileged" || true
        exit 1
    }
    ;;
*)
    echo "error: mode must be --write or --check" >&2
    exit 1
    ;;
esac
