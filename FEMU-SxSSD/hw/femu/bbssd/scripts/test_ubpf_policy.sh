#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$(cd "$SCRIPT_DIR/../policy" && pwd)"
DEVICE="${1:-/dev/nvme0}"
POLICY_ID="${POLICY_ID:-4000}"
POLICY_VERSION="${POLICY_VERSION:-1}"
POLICY_PATH="${POLICY_PATH:-$POLICY_DIR/ubpf-smoke-policy.bpf.o}"
NATIVE_POLICY_ID="${NATIVE_POLICY_ID:-4001}"
NATIVE_POLICY_PATH="${NATIVE_POLICY_PATH:-$POLICY_DIR/native-forbidden-policy.so}"
FORBIDDEN_POLICY_ID="${FORBIDDEN_POLICY_ID:-4002}"
FORBIDDEN_POLICY_PATH="${FORBIDDEN_POLICY_PATH:-$POLICY_DIR/ubpf-forbidden-policy.bpf.o}"
SMOKE_RESULT="0x42504601"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail()
{
    echo "[ubpf-test] ERROR: $*" >&2
    exit 1
}

if [ "${EUID}" -ne 0 ]; then
    fail "Run this test with sudo"
fi

if [ "${SKIP_BUILD:-0}" != "1" ]; then
    make -C "$POLICY_DIR" isolation-test
    make -C "$SCRIPT_DIR" tool
fi

[ -x "$SCRIPT_DIR/policyctl" ] || fail "Missing policyctl"
[ -f "$POLICY_PATH" ] || fail "Missing smoke policy: $POLICY_PATH"
[ -f "$NATIVE_POLICY_PATH" ] || fail "Missing native negative fixture"
[ -f "$FORBIDDEN_POLICY_PATH" ] || fail "Missing unknown-helper fixture"
[ -e "$DEVICE" ] || fail "Missing controller: $DEVICE"
command -v python3 >/dev/null || fail "python3 is required for loader fixtures"
command -v llvm-objcopy >/dev/null ||
    fail "llvm-objcopy is required for loader fixtures"

"$SCRIPT_DIR/verify_simulation_identity.sh"
rm -f /tmp/policyctl-session-state
"$SCRIPT_DIR/policyctl" --mode normal session "$DEVICE" >/dev/null

echo "[ubpf-test] valid BPF: install, activate, condition, and action"
"$SCRIPT_DIR/policyctl" install "$DEVICE" "$POLICY_PATH" \
    "$POLICY_ID" "$POLICY_VERSION" >/dev/null
"$SCRIPT_DIR/policyctl" activate "$DEVICE" "$POLICY_ID" >/dev/null

matched_result=$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe1 0xc0de)
[ "$matched_result" = "$SMOKE_RESULT" ] ||
    fail "matched smoke command returned $matched_result, expected $SMOKE_RESULT"
unmatched_result=$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe1 0)
[ "$unmatched_result" = "0x00000000" ] ||
    fail "no-match path executed the action: $unmatched_result"

attestation=$("$SCRIPT_DIR/policyctl" attest "$DEVICE" consistency --history full)
grep -E "policy id=$POLICY_ID generation=[0-9]+ active=1" \
    <<<"$attestation" >/dev/null ||
    fail "attestation did not report the BPF policy active"
echo "[ubpf-test] PASS: observable INIT -> CONDITION -> ACTION dispatch"

"$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$POLICY_ID" >/dev/null
"$SCRIPT_DIR/policyctl" remove "$DEVICE" "$POLICY_ID" >/dev/null

before=$("$SCRIPT_DIR/policyctl" attest "$DEVICE" consistency --history full)
before_head=$(sed -n '1p' <<<"$before")

reject_without_history()
{
    local image=$1
    local policy_id=$2
    local description=$3
    local after
    local after_head

    if "$SCRIPT_DIR/policyctl" install "$DEVICE" "$image" \
            "$policy_id" "$POLICY_VERSION" >/tmp/sxs-policy-rejection.log 2>&1; then
        fail "$description was accepted"
    fi
    "$SCRIPT_DIR/policyctl" --mode normal session "$DEVICE" >/dev/null
    after=$("$SCRIPT_DIR/policyctl" attest "$DEVICE" consistency --history full)
    after_head=$(sed -n '1p' <<<"$after")
    [ "$before_head" = "$after_head" ] ||
        fail "$description changed attested state or history"
    grep -E "policy id=$policy_id " <<<"$after" >/dev/null &&
        fail "$description appeared in attestation"
    echo "[ubpf-test] PASS: rejected $description before lifecycle commit"
}

reject_without_history "$NATIVE_POLICY_PATH" "$NATIVE_POLICY_ID" \
    "native ELF policy"
reject_without_history "$FORBIDDEN_POLICY_PATH" "$FORBIDDEN_POLICY_ID" \
    "BPF policy with unknown host symbol"

echo "[ubpf-test] strict ELF loader rejection matrix"
python3 - "$POLICY_PATH" "$TMP_DIR" <<'PY'
import pathlib
import struct
import sys

source = pathlib.Path(sys.argv[1]).read_bytes()
output = pathlib.Path(sys.argv[2])

wrong_endian = bytearray(source)
wrong_endian[5] = 2
(output / "wrong-endian.o").write_bytes(wrong_endian)
(output / "malformed.o").write_bytes(b"\x7fELF")
(output / "missing-entry.o").write_bytes(
    source.replace(b"policy_main", b"policy_none")
)

invalid_relocation = bytearray(source)
section_offset = struct.unpack_from("<Q", source, 40)[0]
section_size = struct.unpack_from("<H", source, 58)[0]
section_count = struct.unpack_from("<H", source, 60)[0]
for index in range(section_count):
    header = section_offset + index * section_size
    if struct.unpack_from("<I", source, header + 4)[0] != 9:  # SHT_REL
        continue
    relocation_offset = struct.unpack_from("<Q", source, header + 24)[0]
    relocation_size = struct.unpack_from("<Q", source, header + 32)[0]
    if relocation_size:
        info = struct.unpack_from("<Q", source, relocation_offset + 8)[0]
        struct.pack_into("<Q", invalid_relocation, relocation_offset + 8,
                         (info & ~0xffffffff) | 1)
        break
else:
    raise SystemExit("smoke fixture has no relocation")
(output / "invalid-relocation.o").write_bytes(invalid_relocation)
PY

printf '\0' >"$TMP_DIR/one-byte"
llvm-objcopy --add-section .data="$TMP_DIR/one-byte" \
    --set-section-flags .data=alloc,data \
    "$POLICY_PATH" "$TMP_DIR/writable-global.o"
truncate -s 524288 "$TMP_DIR/instruction-bytes"
llvm-objcopy --add-section .overlimit="$TMP_DIR/instruction-bytes" \
    --set-section-flags .overlimit=alloc,code,readonly \
    "$POLICY_PATH" "$TMP_DIR/over-limit.o"
cp "$POLICY_PATH" "$TMP_DIR/oversized.o"
truncate -s 1048577 "$TMP_DIR/oversized.o"

next_rejection_id=$((FORBIDDEN_POLICY_ID + 1))
for fixture in \
    "wrong-endian.o:wrong-endian ELF" \
    "malformed.o:malformed ELF" \
    "missing-entry.o:ELF missing policy_main" \
    "writable-global.o:ELF with writable globals" \
    "invalid-relocation.o:ELF with invalid relocation" \
    "oversized.o:oversized ELF" \
    "over-limit.o:over-limit BPF program"; do
    path=${fixture%%:*}
    description=${fixture#*:}
    reject_without_history "$TMP_DIR/$path" "$next_rejection_id" \
        "$description"
    next_rejection_id=$((next_rejection_id + 1))
done

install_activate()
{
    local image=$1
    local policy_id=$2
    local version=${3:-1}

    "$SCRIPT_DIR/policyctl" install "$DEVICE" "$image" \
        "$policy_id" "$version" >/dev/null
    "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$policy_id" >/dev/null
}

deactivate_remove()
{
    local policy_id=$1

    "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$policy_id" >/dev/null
    "$SCRIPT_DIR/policyctl" remove "$DEVICE" "$policy_id" >/dev/null
}

echo "[ubpf-test] authoritative phase and owner isolation"
ISOLATION_ID=4200
install_activate "$POLICY_DIR/ubpf-isolation-policy.bpf.o" "$ISOLATION_ID"
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe5 0)" = "0x49534f4c" ] ||
    fail "condition effects or public phase forgery bypassed isolation"
deactivate_remove "$ISOLATION_ID"

echo "[ubpf-test] same-generation state preservation and update reset"
STATE_ID=4201
install_activate "$POLICY_DIR/ubpf-state-policy.bpf.o" "$STATE_ID"
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe8 0)" = "0x53540001" ] ||
    fail "state counter did not begin at one"
"$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$STATE_ID" >/dev/null
"$SCRIPT_DIR/policyctl" activate "$DEVICE" "$STATE_ID" >/dev/null
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe8 0)" = "0x53540002" ] ||
    fail "same-generation reactivation did not preserve state"
"$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$STATE_ID" >/dev/null
"$SCRIPT_DIR/policyctl" update "$DEVICE" \
    "$POLICY_DIR/ubpf-state-policy.bpf.o" "$STATE_ID" 2 >/dev/null
"$SCRIPT_DIR/policyctl" activate "$DEVICE" "$STATE_ID" >/dev/null
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe8 0)" = "0x53540001" ] ||
    fail "new generation inherited old state"
deactivate_remove "$STATE_ID"

echo "[ubpf-test] newest-first, first-match admin ordering"
ORDER_A=4202
ORDER_B=4203
install_activate "$POLICY_DIR/ubpf-order-policy.bpf.o" "$ORDER_A" 17
install_activate "$POLICY_DIR/ubpf-order-policy.bpf.o" "$ORDER_B" 34
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xea 0)" = "0x00000022" ] ||
    fail "newest active admin policy did not run first"
"$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$ORDER_B" >/dev/null
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xea 0)" = "0x00000011" ] ||
    fail "admin dispatch did not fall back to the older matching policy"
"$SCRIPT_DIR/policyctl" remove "$DEVICE" "$ORDER_B" >/dev/null
deactivate_remove "$ORDER_A"

echo "[ubpf-test] subscription ownership and 64-row limit"
LIMIT_ID=4204
install_activate "$POLICY_DIR/ubpf-limit-policy.bpf.o" "$LIMIT_ID"
deactivate_remove "$LIMIT_ID"

echo "[ubpf-test] failed INIT transaction rollback"
TRANSACTION_ID=4205
"$SCRIPT_DIR/policyctl" install "$DEVICE" \
    "$POLICY_DIR/ubpf-transaction-fail-policy.bpf.o" \
    "$TRANSACTION_ID" 1 >/dev/null
transaction_before=$("$SCRIPT_DIR/policyctl" attest \
    "$DEVICE" consistency --history full | sed -n '1p')
for attempt in $(seq 1 20); do
    if "$SCRIPT_DIR/policyctl" activate "$DEVICE" \
            "$TRANSACTION_ID" >/tmp/sxs-activation-rejection.log 2>&1; then
        fail "failed-INIT policy activated on attempt $attempt"
    fi
    "$SCRIPT_DIR/policyctl" --mode normal session "$DEVICE" >/dev/null
done
transaction_after=$("$SCRIPT_DIR/policyctl" attest \
    "$DEVICE" consistency --history full | sed -n '1p')
[ "$transaction_before" = "$transaction_after" ] ||
    fail "failed INIT changed lifecycle history"
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe9 0)" = "0x00000000" ] ||
    fail "failed INIT published a subscription"
"$SCRIPT_DIR/policyctl" remove "$DEVICE" "$TRANSACTION_ID" >/dev/null

echo "[ubpf-test] safe-memory and finite instruction-limit runtime faults"
FAULT_ID=4206
install_activate "$POLICY_DIR/ubpf-runtime-fault-policy.bpf.o" "$FAULT_ID"
if "$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe6 0 \
        >/tmp/sxs-oob-fault.log 2>&1; then
    fail "out-of-bounds context access did not fault"
fi
if "$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe7 0 \
        >/tmp/sxs-loop-fault.log 2>&1; then
    fail "infinite policy execution did not hit the instruction limit"
fi
deactivate_remove "$FAULT_ID"

echo "[ubpf-test] all uBPF loader, isolation, lifecycle, and runtime tests passed"
