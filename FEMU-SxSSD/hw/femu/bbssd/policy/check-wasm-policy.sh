#!/bin/sh
set -eu

artifact=${1:?usage: check-wasm-policy.sh POLICY.wasm}

[ -f "$artifact" ] || { echo "error: missing $artifact" >&2; exit 1; }
[ "$(wc -c < "$artifact")" -le 1048576 ] || {
    echo "error: $artifact exceeds the 1 MiB policy limit" >&2
    exit 1
}
[ "$(od -An -tx1 -N8 "$artifact" | tr -d ' \n')" = "0061736d01000000" ] || {
    echo "error: $artifact is not a WebAssembly Core 1.0 module" >&2
    exit 1
}

# Runtime loading remains authoritative. These cheap build-time checks catch
# accidental linker changes before an artifact reaches the controller.
for export_name in sxs_policy_init sxs_policy_condition sxs_policy_action; do
    strings "$artifact" | grep -Fx "$export_name" >/dev/null || {
        echo "error: $artifact lacks export $export_name" >&2
        exit 1
    }
done
strings "$artifact" | grep -Fx sxs_v1 >/dev/null || {
    echo "error: $artifact has no sxs_v1 common-API imports" >&2
    exit 1
}
