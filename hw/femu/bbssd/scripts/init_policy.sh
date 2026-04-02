#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$(cd "$SCRIPT_DIR/../policy" && pwd)"

DEVICE="/dev/nvme0n1"
POLICY_PATH="${1:-$POLICY_DIR/block-interface-policy.so}"
POLICY_ID="${2:-100}"
POLICY_VERSION="1"
SESSION_MODE="confidential"

log() {
    echo "[meta-init] $*"
}

fail() {
    echo "[meta-init] ERROR: $*" >&2
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

if [ ! -f "$POLICY_PATH" ]; then
    fail "Missing policy image: $POLICY_PATH"
fi

if [[ "$POLICY_PATH" != *.so ]]; then
    fail "Policy path must point to a .so file: $POLICY_PATH"
fi

log "Building policyctl and policy image..."
make -C "$POLICY_DIR" tool
make -C "$SCRIPT_DIR" tool

if [ ! -x "$SCRIPT_DIR/policyctl" ]; then
    fail "Failed to build policyctl"
fi

run_policyctl "$SCRIPT_DIR/policyctl" --mode "$SESSION_MODE" session "$DEVICE" >/dev/null
run_policyctl "$SCRIPT_DIR/policyctl" install "$DEVICE" "$POLICY_PATH" "$POLICY_ID" "$POLICY_VERSION"
run_policyctl "$SCRIPT_DIR/policyctl" activate "$DEVICE" "$POLICY_ID"

log "Session established, policy installed, and policy activated"
log "device=$DEVICE mode=$SESSION_MODE policy=$POLICY_PATH policy_id=$POLICY_ID version=$POLICY_VERSION"
