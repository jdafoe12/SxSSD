#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BBSSD_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
POLICY_DIR="$BBSSD_DIR/policy"
DEVICE="${1:-/dev/nvme0}"
BASE_POLICY_ID="${2:-100}"
BASE_POLICY_VERSION="${3:-1}"
POLICY_PATH="${4:-$POLICY_DIR/signing-test-policy.wasm}"
SIGNING_POLICY_PATH="$POLICY_DIR/signing-test-policy.wasm"
KEY_SHARING_POLICY_PATH="$POLICY_DIR/key-sharing-policy.wasm"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

EXPECTED_HASH=""

log() {
    echo "[meta-test] $*"
}

fail() {
    echo "[meta-test] ERROR: $*" >&2
    exit 1
}

run_policyctl() {
    local output

    log "Running: $*" >&2
    if ! output="$("$@" 2>&1)"; then
        echo "$output" >&2
        fail "Command failed: $*"
    fi
    printf '%s\n' "$output"
}

assert_contains() {
    local output="$1"
    local expected="$2"

    if ! grep -F -- "$expected" <<<"$output" >/dev/null; then
        echo "$output" >&2
        fail "Expected text not found: $expected"
    fi
}

assert_not_contains() {
    local output="$1"
    local unexpected="$2"

    if grep -F -- "$unexpected" <<<"$output" >/dev/null; then
        echo "$output" >&2
        fail "Unexpected text found: $unexpected"
    fi
}

attest_checkpoint() {
    local report_type="$1"
    local path="$2"

    run_policyctl "$SCRIPT_DIR/policyctl" attest "$DEVICE" "$report_type" \
        --save-checkpoint "$path"
}

attest_delta() {
    local report_type="$1"
    local previous="$2"
    local next="$3"

    run_policyctl "$SCRIPT_DIR/policyctl" attest "$DEVICE" "$report_type" \
        --since "$previous" --save-checkpoint "$next"
}

if [ "${SKIP_BUILD:-0}" != "1" ]; then
    log "Building policies and host tools"
    make -C "$POLICY_DIR" tool
    make -C "$SCRIPT_DIR" tool
else
    log "SKIP_BUILD=1: using manually built policies and tools"
fi

[ -x "$SCRIPT_DIR/policyctl" ] || fail "Missing policyctl"
[ -x "$SCRIPT_DIR/test_device_signing" ] || fail "Missing test_device_signing"
[ -x "$SCRIPT_DIR/key-sharing-client" ] || fail "Missing key-sharing-client"
[ -f "$POLICY_PATH" ] || fail "Missing policy image: $POLICY_PATH"
[ -f "$SIGNING_POLICY_PATH" ] || fail "Missing signing test policy"
[ -f "$KEY_SHARING_POLICY_PATH" ] || fail "Missing key-sharing policy"

"$SCRIPT_DIR/verify_simulation_identity.sh"
EXPECTED_HASH="$(sha256sum "$POLICY_PATH" | awk '{print $1}')"
[ -n "$EXPECTED_HASH" ] || fail "Failed to hash $POLICY_PATH"

# Attestation is public and must work before an administrator session exists.
rm -f /tmp/policyctl-session-state
output="$(attest_checkpoint security "$TMP_DIR/public.checkpoint")"
assert_contains "$output" "report=security"
assert_contains "$output" "events=0"

run_lifecycle_suite() {
    local mode="$1"
    local policy_id="$2"
    local current="$TMP_DIR/$mode-0.checkpoint"
    local next="$TMP_DIR/$mode-1.checkpoint"
    local output

    log "Lifecycle suite: mode=$mode policy_id=$policy_id"
    run_policyctl "$SCRIPT_DIR/policyctl" --mode "$mode" session "$DEVICE" >/dev/null
    attest_checkpoint security "$current" >/dev/null

    run_policyctl "$SCRIPT_DIR/policyctl" install "$DEVICE" "$POLICY_PATH" \
        "$policy_id" "$BASE_POLICY_VERSION" >/dev/null
    output="$(attest_delta consistency "$current" "$next")"
    assert_contains "$output" "events=1"
    assert_contains "$output" "operation=install policy_id=$policy_id generation=1"
    assert_contains "$output" "policy id=$policy_id generation=1 active=0 hash=$EXPECTED_HASH"
    current="$next"; next="$TMP_DIR/$mode-2.checkpoint"

    # A successful no-op must not advance history.
    run_policyctl "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$policy_id" >/dev/null
    output="$(attest_delta security "$current" "$next")"
    assert_contains "$output" "events=0"
    current="$next"; next="$TMP_DIR/$mode-3.checkpoint"

    run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$policy_id" >/dev/null
    output="$(attest_delta security "$current" "$next")"
    assert_contains "$output" "operation=activate policy_id=$policy_id generation=1"
    assert_contains "$output" "policy id=$policy_id generation=1 active=1"
    current="$next"; next="$TMP_DIR/$mode-4.checkpoint"

    run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$policy_id" >/dev/null
    output="$(attest_delta security "$current" "$next")"
    assert_contains "$output" "events=0"
    current="$next"; next="$TMP_DIR/$mode-5.checkpoint"

    run_policyctl "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$policy_id" >/dev/null
    output="$(attest_delta security "$current" "$next")"
    assert_contains "$output" "operation=deactivate policy_id=$policy_id generation=1"
    current="$next"; next="$TMP_DIR/$mode-6.checkpoint"

    run_policyctl "$SCRIPT_DIR/policyctl" update "$DEVICE" "$POLICY_PATH" \
        "$policy_id" "$((BASE_POLICY_VERSION + 1))" >/dev/null
    output="$(attest_delta consistency "$current" "$next")"
    assert_contains "$output" "operation=update policy_id=$policy_id generation=2"
    assert_contains "$output" "policy id=$policy_id generation=2 active=0 hash=$EXPECTED_HASH"
    current="$next"; next="$TMP_DIR/$mode-7.checkpoint"

    run_policyctl "$SCRIPT_DIR/policyctl" remove "$DEVICE" "$policy_id" >/dev/null
    output="$(attest_delta security "$current" "$next")"
    assert_contains "$output" "operation=remove policy_id=$policy_id generation=2"
    assert_not_contains "$output" "policy id=$policy_id "
    current="$next"; next="$TMP_DIR/$mode-8.checkpoint"

    run_policyctl "$SCRIPT_DIR/policyctl" install "$DEVICE" "$POLICY_PATH" \
        "$policy_id" "$((BASE_POLICY_VERSION + 2))" >/dev/null
    output="$(attest_delta security "$current" "$next")"
    assert_contains "$output" "operation=install policy_id=$policy_id generation=3"
    run_policyctl "$SCRIPT_DIR/policyctl" remove "$DEVICE" "$policy_id" >/dev/null
}

run_lifecycle_suite normal "$BASE_POLICY_ID"
run_lifecycle_suite confidential "$((BASE_POLICY_ID + 1000))"

# The fixture rejects reserved meta hooks, accepts one ordinary hook, and allows
# multiple policies to remain active simultaneously.
MULTI_A="$((BASE_POLICY_ID + 2000))"
MULTI_B="$((BASE_POLICY_ID + 2001))"
run_policyctl "$SCRIPT_DIR/policyctl" --mode normal session "$DEVICE" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" install "$DEVICE" "$SIGNING_POLICY_PATH" "$MULTI_A" 1 >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" install "$DEVICE" "$SIGNING_POLICY_PATH" "$MULTI_B" 1 >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$MULTI_A" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$MULTI_B" >/dev/null
output="$(attest_checkpoint security "$TMP_DIR/multiple-active.checkpoint")"
assert_contains "$output" "policy id=$MULTI_A generation=1 active=1"
assert_contains "$output" "policy id=$MULTI_B generation=1 active=1"
output="$(run_policyctl "$SCRIPT_DIR/policyctl" probe "$DEVICE" 0xe4 0)"
assert_contains "$output" "0x50415353"
run_policyctl "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$MULTI_A" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$MULTI_B" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" remove "$DEVICE" "$MULTI_A" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" remove "$DEVICE" "$MULTI_B" >/dev/null

# Detect a transient policy change even when current state is restored.
EXPECTED_ID="$((BASE_POLICY_ID + 3000))"
OTHER_ID="$((BASE_POLICY_ID + 3001))"
run_policyctl "$SCRIPT_DIR/policyctl" install "$DEVICE" "$SIGNING_POLICY_PATH" "$EXPECTED_ID" 1 >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" install "$DEVICE" "$SIGNING_POLICY_PATH" "$OTHER_ID" 1 >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$EXPECTED_ID" >/dev/null
attest_checkpoint security "$TMP_DIR/toctou-before.checkpoint" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$EXPECTED_ID" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$OTHER_ID" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$OTHER_ID" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$EXPECTED_ID" >/dev/null
output="$(attest_delta security "$TMP_DIR/toctou-before.checkpoint" "$TMP_DIR/toctou-after.checkpoint")"
assert_contains "$output" "events=4"
assert_contains "$output" "operation=deactivate policy_id=$EXPECTED_ID generation=1"
assert_contains "$output" "operation=activate policy_id=$OTHER_ID generation=1"
assert_contains "$output" "policy id=$EXPECTED_ID generation=1 active=1"
run_policyctl "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$EXPECTED_ID" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" remove "$DEVICE" "$EXPECTED_ID" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" remove "$DEVICE" "$OTHER_ID" >/dev/null

# Exercise the canonical TApp/policy exchange with mutual key confirmation:
# the policy authenticates the TApp, and the device authenticates its response.
KEY_SHARING_ID="$((BASE_POLICY_ID + 4000))"
run_policyctl "$SCRIPT_DIR/policyctl" install "$DEVICE" \
    "$KEY_SHARING_POLICY_PATH" "$KEY_SHARING_ID" 1 >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" \
    "$KEY_SHARING_ID" >/dev/null
output="$(run_policyctl "$SCRIPT_DIR/key-sharing-client" "$DEVICE" \
    "$BBSSD_DIR/admin-simulation/admin_private.hex")"
assert_contains "$output" "key sharing passed"
assert_contains "$output" "invalid TApp authentication rejected"
run_policyctl "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" \
    "$KEY_SHARING_ID" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" remove "$DEVICE" \
    "$KEY_SHARING_ID" >/dev/null

# Full mode independently recomputes the complete hash chain from H0.
output="$(run_policyctl "$SCRIPT_DIR/policyctl" attest "$DEVICE" consistency --history full)"
assert_contains "$output" "report=consistency"

log "All signing, key sharing, lifecycle history, delta, full, and TOCTOU tests passed"
