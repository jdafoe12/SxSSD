#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$(cd "$SCRIPT_DIR/../policy" && pwd)"
DEVICE="${1:-/dev/nvme0}"
BASE_POLICY_ID="${2:-100}"
BASE_POLICY_VERSION="${3:-1}"
POLICY_PATH="${4:-$POLICY_DIR/block-interface-policy.so}"

EXPECTED_HASH=""
ZERO_HASH="0000000000000000000000000000000000000000000000000000000000000000"

log() {
    echo "[meta-test] $*"
}

fail() {
    echo "[meta-test] ERROR: $*" >&2
    exit 1
}

run_policyctl() {
    local output

    log "Running: $*"
    if ! output="$("$@" 2>&1)"; then
        echo "$output" >&2
        fail "Command failed: $*"
    fi
    if [ -n "$output" ]; then
        echo "$output"
    fi
}

assert_line() {
    local output="$1"
    local expected="$2"

    if ! grep -Fx -- "$expected" <<<"$output" >/dev/null; then
        echo "$output" >&2
        fail "Expected line not found: $expected"
    fi
}

assert_security_report() {
    local policy_id="$1"
    local installed="$2"
    local active="$3"
    local output

    output="$(run_policyctl "$SCRIPT_DIR/policyctl" attest "$DEVICE" "$policy_id" security)"
    assert_line "$output" "policy_id=$policy_id report=security installed=$installed active=$active"
}

assert_consistency_report() {
    local policy_id="$1"
    local installed="$2"
    local active="$3"
    local expected_hash="$4"
    local output

    output="$(run_policyctl "$SCRIPT_DIR/policyctl" attest "$DEVICE" "$policy_id" consistency)"
    assert_line "$output" "policy_id=$policy_id report=consistency installed=$installed active=$active"
    assert_line "$output" "hash=$expected_hash"
}

run_mode_suite() {
    local mode="$1"
    local policy_id="$2"
    local install_version="$3"
    local update_version="$4"

    log "==== Starting $mode mode suite for policy_id=$policy_id ===="

    run_policyctl "$SCRIPT_DIR/policyctl" --mode "$mode" session "$DEVICE" >/dev/null

    assert_security_report "$policy_id" 0 0
    assert_consistency_report "$policy_id" 0 0 "$ZERO_HASH"

    run_policyctl "$SCRIPT_DIR/policyctl" install "$DEVICE" "$POLICY_PATH" "$policy_id" "$install_version" >/dev/null
    assert_security_report "$policy_id" 1 0
    assert_consistency_report "$policy_id" 1 0 "$EXPECTED_HASH"

    run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$policy_id" >/dev/null
    assert_security_report "$policy_id" 1 1
    assert_consistency_report "$policy_id" 1 1 "$EXPECTED_HASH"

    run_policyctl "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$policy_id" >/dev/null
    assert_security_report "$policy_id" 1 0

    run_policyctl "$SCRIPT_DIR/policyctl" update "$DEVICE" "$POLICY_PATH" "$policy_id" "$update_version" >/dev/null
    assert_security_report "$policy_id" 1 0
    assert_consistency_report "$policy_id" 1 0 "$EXPECTED_HASH"

    run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$policy_id" >/dev/null
    assert_security_report "$policy_id" 1 1

    run_policyctl "$SCRIPT_DIR/policyctl" deactivate "$DEVICE" "$policy_id" >/dev/null
    run_policyctl "$SCRIPT_DIR/policyctl" remove "$DEVICE" "$policy_id" >/dev/null
    assert_security_report "$policy_id" 0 0
    assert_consistency_report "$policy_id" 0 0 "$ZERO_HASH"

    log "==== Completed $mode mode suite for policy_id=$policy_id ===="
}

if [ ! -f "$POLICY_PATH" ]; then
    fail "Missing policy image: $POLICY_PATH"
fi

log "Building policyctl and policy image..."
make -C "$POLICY_DIR" tool
make -C "$SCRIPT_DIR" tool
if [ ! -x "$SCRIPT_DIR/policyctl" ]; then
    fail "Failed to build policyctl"
fi

EXPECTED_HASH="$(sha256sum "$POLICY_PATH" | awk '{print $1}')"
if [ -z "$EXPECTED_HASH" ]; then
    fail "Failed to compute expected hash for $POLICY_PATH"
fi

run_mode_suite "normal" "$BASE_POLICY_ID" "$BASE_POLICY_VERSION" "$((BASE_POLICY_VERSION + 1))"
run_mode_suite "confidential" "$((BASE_POLICY_ID + 1000))" "$BASE_POLICY_VERSION" "$((BASE_POLICY_VERSION + 1))"

log "All meta interface tests passed on $DEVICE"
