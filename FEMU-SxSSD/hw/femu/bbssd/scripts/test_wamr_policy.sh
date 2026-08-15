#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$(cd "$SCRIPT_DIR/../policy" && pwd)"
DEVICE="${1:-/dev/nvme0}"
POLICY_ID="${POLICY_ID:-4000}"
POLICY_VERSION="${POLICY_VERSION:-1}"
POLICY_PATH="${POLICY_PATH:-$POLICY_DIR/wasm-smoke-policy.wasm}"
NATIVE_POLICY_ID="${NATIVE_POLICY_ID:-4001}"
NATIVE_POLICY_PATH="${NATIVE_POLICY_PATH:-$POLICY_DIR/native-forbidden-policy.so}"
FORBIDDEN_POLICY_ID="${FORBIDDEN_POLICY_ID:-4002}"
FORBIDDEN_POLICY_PATH="${FORBIDDEN_POLICY_PATH:-$POLICY_DIR/wasm-forbidden-policy.wasm}"
PRIVILEGED_FORBIDDEN_POLICY_ID="${PRIVILEGED_FORBIDDEN_POLICY_ID:-4003}"
PRIVILEGED_FORBIDDEN_POLICY_PATH="${PRIVILEGED_FORBIDDEN_POLICY_PATH:-$POLICY_DIR/wasm-privileged-forbidden-policy.wasm}"
SMOKE_RESULT="0x5741534d"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail()
{
    echo "[wamr-test] ERROR: $*" >&2
    exit 1
}

if [ "${EUID}" -ne 0 ]; then
    fail "Run this test with sudo"
fi

if [ "${SKIP_BUILD:-0}" != "1" ]; then
    make -C "$POLICY_DIR" isolation-test
    # These directories may be copied from a newer host distribution.  Force
    # guest-native helper binaries so an apparently up-to-date host binary
    # cannot retain an incompatible dependency such as libssl.so.3.
    make -C "$SCRIPT_DIR" -B tool
fi

[ -x "$SCRIPT_DIR/policyctl" ] || fail "Missing policyctl"
[ -f "$POLICY_PATH" ] || fail "Missing smoke policy: $POLICY_PATH"
[ -f "$NATIVE_POLICY_PATH" ] || fail "Missing native negative fixture"
[ -f "$FORBIDDEN_POLICY_PATH" ] || fail "Missing unknown-import fixture"
[ -f "$PRIVILEGED_FORBIDDEN_POLICY_PATH" ] ||
    fail "Missing privileged-import fixture"
[ -e "$DEVICE" ] || fail "Missing controller: $DEVICE"
command -v python3 >/dev/null || fail "python3 is required for loader fixtures"

"$SCRIPT_DIR/verify_simulation_identity.sh"
rm -f /tmp/policyctl-session-state
"$SCRIPT_DIR/policyctl" --mode normal session "$DEVICE" >/dev/null

echo "[wamr-test] valid Wasm: install, activate, condition, and action"
echo "[wamr-test]   installing policy id=$POLICY_ID"
"$SCRIPT_DIR/policyctl" install "$DEVICE" "$POLICY_PATH" \
    "$POLICY_ID" "$POLICY_VERSION" >/dev/null
echo "[wamr-test]   activating policy id=$POLICY_ID (runs sxs_policy_init)"
"$SCRIPT_DIR/policyctl" activate "$DEVICE" "$POLICY_ID" >/dev/null

echo "[wamr-test]   probing matched condition/action path"
matched_result=$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe1 0xc0de)
[ "$matched_result" = "$SMOKE_RESULT" ] ||
    fail "matched smoke command returned $matched_result, expected $SMOKE_RESULT"
unmatched_result=$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe1 0)
[ "$unmatched_result" = "0x00000000" ] ||
    fail "no-match path executed the action: $unmatched_result"

attestation=$("$SCRIPT_DIR/policyctl" attest "$DEVICE" consistency --history full)
grep -E "policy id=$POLICY_ID generation=[0-9]+ active=1" \
    <<<"$attestation" >/dev/null ||
    fail "attestation did not report the Wasm policy active"
echo "[wamr-test] PASS: observable INIT -> CONDITION -> ACTION dispatch"

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
    echo "[wamr-test] PASS: rejected $description before lifecycle commit"
}

reject_without_history "$NATIVE_POLICY_PATH" "$NATIVE_POLICY_ID" \
    "native ELF policy"
reject_without_history "$FORBIDDEN_POLICY_PATH" "$FORBIDDEN_POLICY_ID" \
    "Wasm policy with unknown host import"
reject_without_history "$PRIVILEGED_FORBIDDEN_POLICY_PATH" \
    "$PRIVILEGED_FORBIDDEN_POLICY_ID" \
    "normal Wasm policy requesting sxs_privileged_v1"
reject_without_history "$POLICY_PATH" 4294901761 \
    "stored policy using the reserved firmware-policy identity"

echo "[wamr-test] strict Wasm loader rejection matrix"
python3 - "$POLICY_PATH" "$TMP_DIR" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_bytes()
output = pathlib.Path(sys.argv[2])

def uleb(value):
    encoded = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)

def read_uleb(data, offset):
    value = 0
    shift = 0
    start = offset
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, offset, start
        shift += 7

def section(data, wanted):
    offset = 8
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, body, size_start = read_uleb(data, offset)
        if section_id == wanted:
            return size_start, body, body + size
        offset = body + size
    raise ValueError(f"section {wanted} missing")

wrong_version = bytearray(source)
wrong_version[4] = 2
(output / "wrong-version.wasm").write_bytes(wrong_version)
(output / "malformed.wasm").write_bytes(b"\0asm")
(output / "truncated.wasm").write_bytes(source[:-1])
(output / "missing-entry.wasm").write_bytes(
    source.replace(b"sxs_policy_action", b"sxs_policy_actioX")
)
(output / "wasi-import.wasm").write_bytes(
    source.replace(b"sxs_v1", b"wasiX1", 1)
)

memory = bytearray(source)
_, memory_body, _ = section(memory, 5)
# vector count, explicit-min/max flags, minimum, maximum
assert memory[memory_body:memory_body + 4] == b"\x01\x01\x01\x01"
memory[memory_body + 3] = 2
(output / "wrong-memory.wasm").write_bytes(memory)

def name(value):
    encoded = value.encode()
    return uleb(len(encoded)) + encoded

def imported_object(kind, descriptor):
    payload = uleb(1) + name("sxs_v1") + name("bad") + bytes((kind,)) + descriptor
    return b"\0asm\x01\0\0\0" + b"\x02" + uleb(len(payload)) + payload

(output / "imported-memory.wasm").write_bytes(
    imported_object(2, b"\x01\x01\x01")
)
(output / "imported-table.wasm").write_bytes(
    imported_object(1, b"\x70\x01\x00\x00")
)
(output / "imported-global.wasm").write_bytes(
    imported_object(3, b"\x7f\x00")
)

# Keep a known import name but change one parameter from i32 to i64. The
# trusted allowlist must bind names and exact function types together.
wrong_signature = bytearray(source)
_, import_body, import_end = section(wrong_signature, 2)
import_count, cursor, _ = read_uleb(wrong_signature, import_body)
subscribe_type = None
for _ in range(import_count):
    module_len, cursor, _ = read_uleb(wrong_signature, cursor)
    cursor += module_len
    name_len, cursor, _ = read_uleb(wrong_signature, cursor)
    import_name = bytes(wrong_signature[cursor:cursor + name_len])
    cursor += name_len
    kind = wrong_signature[cursor]
    cursor += 1
    assert kind == 0
    type_index, cursor, _ = read_uleb(wrong_signature, cursor)
    if import_name == b"sxs_subscribe":
        subscribe_type = type_index
assert cursor == import_end and subscribe_type is not None

_, type_body, type_end = section(wrong_signature, 1)
type_count, cursor, _ = read_uleb(wrong_signature, type_body)
for type_index in range(type_count):
    assert wrong_signature[cursor] == 0x60
    cursor += 1
    parameter_count, cursor, _ = read_uleb(wrong_signature, cursor)
    if type_index == subscribe_type:
        assert parameter_count == 4 and wrong_signature[cursor] == 0x7f
        wrong_signature[cursor] = 0x7e
    cursor += parameter_count
    result_count, cursor, _ = read_uleb(wrong_signature, cursor)
    cursor += result_count
assert cursor == type_end
(output / "wrong-import-signature.wasm").write_bytes(wrong_signature)

(output / "wamr-aot.aot").write_bytes(b"\0aot" + b"\0" * 12)
PY

cp "$POLICY_PATH" "$TMP_DIR/oversized.wasm"
truncate -s 1048577 "$TMP_DIR/oversized.wasm"

next_rejection_id=$((FORBIDDEN_POLICY_ID + 1))
for fixture in \
    "wrong-version.wasm:wrong Wasm version" \
    "malformed.wasm:malformed Wasm" \
    "truncated.wasm:truncated Wasm" \
    "missing-entry.wasm:Wasm missing action export" \
    "wasi-import.wasm:WASI/foreign import namespace" \
    "wrong-memory.wasm:non-fixed Wasm memory" \
    "imported-memory.wasm:imported Wasm memory" \
    "imported-table.wasm:imported Wasm table" \
    "imported-global.wasm:imported Wasm global" \
    "wrong-import-signature.wasm:Wasm import signature mismatch" \
    "wamr-aot.aot:WAMR AOT policy" \
    "oversized.wasm:oversized Wasm"; do
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

echo "[wamr-test] authoritative phase and owner isolation"
ISOLATION_ID=4200
install_activate "$POLICY_DIR/wasm-isolation-policy.wasm" "$ISOLATION_ID"
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe5 0)" = "0x49534f4c" ] ||
    fail "condition memory or public phase checks bypassed isolation"
deactivate_remove "$ISOLATION_ID"

echo "[wamr-test] policy-owned memory lifecycle"
STATE_ID=4201
install_activate "$POLICY_DIR/wasm-state-policy.wasm" "$STATE_ID"
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe8 0)" = "0x53540001" ] ||
    fail "state counter did not begin at one"
"$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$STATE_ID" >/dev/null
"$SCRIPT_DIR/policyctl" activate "$DEVICE" "$STATE_ID" >/dev/null
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe8 0)" = "0x53540001" ] ||
    fail "reactivated policy did not receive fresh linear memory"
"$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$STATE_ID" >/dev/null
"$SCRIPT_DIR/policyctl" update "$DEVICE" \
    "$POLICY_DIR/wasm-state-policy.wasm" "$STATE_ID" 2 >/dev/null
"$SCRIPT_DIR/policyctl" activate "$DEVICE" "$STATE_ID" >/dev/null
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe8 0)" = "0x53540001" ] ||
    fail "new generation inherited old state"
deactivate_remove "$STATE_ID"

echo "[wamr-test] newest-first, first-match admin ordering"
ORDER_A=4202
ORDER_B=4203
install_activate "$POLICY_DIR/wasm-order-policy.wasm" "$ORDER_A" 17
install_activate "$POLICY_DIR/wasm-order-policy.wasm" "$ORDER_B" 34
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xea 0)" = "0x00000022" ] ||
    fail "newest active admin policy did not run first"
"$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$ORDER_B" >/dev/null
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xea 0)" = "0x00000011" ] ||
    fail "admin dispatch did not fall back to the older matching policy"
"$SCRIPT_DIR/policyctl" remove "$DEVICE" "$ORDER_B" >/dev/null
deactivate_remove "$ORDER_A"

echo "[wamr-test] subscription ownership and 64-row limit"
LIMIT_ID=4204
install_activate "$POLICY_DIR/wasm-limit-policy.wasm" "$LIMIT_ID"
deactivate_remove "$LIMIT_ID"

echo "[wamr-test] failed INIT transaction rollback"
TRANSACTION_ID=4205
"$SCRIPT_DIR/policyctl" install "$DEVICE" \
    "$POLICY_DIR/wasm-transaction-fail-policy.wasm" \
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
if "$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe9 0 \
        >/tmp/sxs-failed-init-probe.log 2>&1; then
    fail "failed INIT exposed an executable subscription"
fi
"$SCRIPT_DIR/policyctl" remove "$DEVICE" "$TRANSACTION_ID" >/dev/null

echo "[wamr-test] safe-memory and finite instruction-limit runtime faults"
FAULT_ID=4206
install_activate "$POLICY_DIR/wasm-runtime-fault-policy.wasm" "$FAULT_ID"
if "$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe6 0 \
        >/tmp/sxs-oob-fault.log 2>&1; then
    fail "out-of-bounds context access did not fault"
fi
if "$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe7 0 \
        >/tmp/sxs-loop-fault.log 2>&1; then
    fail "infinite policy execution did not hit the instruction limit"
fi
[ "$("$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xeb 0)" = "0x5245434f" ] ||
    fail "policy VM did not recover after runtime faults"
deactivate_remove "$FAULT_ID"

echo "[wamr-test] all WAMR loader, isolation, lifecycle, and runtime tests passed"
