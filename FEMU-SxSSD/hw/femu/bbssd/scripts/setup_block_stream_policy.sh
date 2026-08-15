#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$(cd "$SCRIPT_DIR/../policy" && pwd)"
STREAM_COUNT="${STREAM_COUNT:-${1:-4}}"
CTRL_DEVICE="${CTRL_DEVICE:-/dev/nvme0}"
NS_DEVICE="${NS_DEVICE:-/dev/nvme0n1}"
POLICY_VERSION="${POLICY_VERSION:-1}"
SESSION_MODE="${SESSION_MODE:-confidential}"

fail() {
    echo "[setup-block-streams] ERROR: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

case "$STREAM_COUNT" in
1)
    POLICY_ID="${POLICY_ID:-111}"
    POLICY_NAME="block-interface-policy-streams-1"
    ;;
2)
    POLICY_ID="${POLICY_ID:-112}"
    POLICY_NAME="block-interface-policy-streams-2"
    ;;
4)
    POLICY_ID="${POLICY_ID:-114}"
    POLICY_NAME="block-interface-policy-streams-4"
    ;;
*)
    fail "STREAM_COUNT must be 1, 2, or 4"
    ;;
esac
POLICY_PATH="${POLICY_PATH:-$POLICY_DIR/${POLICY_NAME}.wasm}"

[ "${EUID}" -eq 0 ] || fail "Run this script with sudo"
require_cmd nvme
[ -e "$CTRL_DEVICE" ] || fail "Missing controller device: $CTRL_DEVICE"

echo "[setup-block-streams] Building $POLICY_NAME and policyctl"
make -C "$POLICY_DIR" "${POLICY_NAME}.wasm"
make -C "$SCRIPT_DIR" policyctl

[ -f "$POLICY_PATH" ] || fail "Missing policy image after build: $POLICY_PATH"
[ -x "$SCRIPT_DIR/policyctl" ] || fail "Missing policyctl after build"

echo "[setup-block-streams] Opening session on $CTRL_DEVICE"
"$SCRIPT_DIR/policyctl" --mode "$SESSION_MODE" session "$CTRL_DEVICE"

echo "[setup-block-streams] Installing $STREAM_COUNT-stream placement policy"
"$SCRIPT_DIR/policyctl" install "$CTRL_DEVICE" "$POLICY_PATH" \
    "$POLICY_ID" "$POLICY_VERSION"

echo "[setup-block-streams] Activating policy id=$POLICY_ID"
"$SCRIPT_DIR/policyctl" activate "$CTRL_DEVICE" "$POLICY_ID"

echo "[setup-block-streams] Rescanning namespaces"
nvme ns-rescan "$CTRL_DEVICE"
sleep 1

[ -b "$NS_DEVICE" ] || fail "Namespace device did not appear: $NS_DEVICE"

echo "[setup-block-streams] Ready: $NS_DEVICE"
echo "[setup-block-streams] Placement frontiers: $STREAM_COUNT"
nvme id-ns "$NS_DEVICE"
