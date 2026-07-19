#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$(cd "$SCRIPT_DIR/../policy" && pwd)"
CTRL_DEVICE="${CTRL_DEVICE:-/dev/nvme0}"
NS_DEVICE="${NS_DEVICE:-/dev/nvme0n1}"
POLICY_ID="${POLICY_ID:-103}"
POLICY_VERSION="${POLICY_VERSION:-1}"
SESSION_MODE="${SESSION_MODE:-confidential}"
POLICY_PATH="${POLICY_PATH:-$POLICY_DIR/block-interface-flashguard-policy.bpf.o}"

fail() {
    echo "[setup-flashguard] ERROR: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

if [ "${EUID}" -ne 0 ]; then
    fail "Run this script with sudo"
fi

require_cmd nvme

[ -e "$CTRL_DEVICE" ] || fail "Missing controller device: $CTRL_DEVICE"

echo "[setup-flashguard] Building policy image and policyctl"
make -C "$POLICY_DIR"
make -C "$SCRIPT_DIR"

[ -f "$POLICY_PATH" ] || fail "Missing policy image after build: $POLICY_PATH"
[ -x "$SCRIPT_DIR/policyctl" ] || fail "Missing policyctl after build"

echo "[setup-flashguard] Opening session on $CTRL_DEVICE"
"$SCRIPT_DIR/policyctl" --mode "$SESSION_MODE" session "$CTRL_DEVICE"

echo "[setup-flashguard] Installing FlashGuard policy"
"$SCRIPT_DIR/policyctl" install "$CTRL_DEVICE" "$POLICY_PATH" "$POLICY_ID" "$POLICY_VERSION"

echo "[setup-flashguard] Activating FlashGuard policy"
"$SCRIPT_DIR/policyctl" activate "$CTRL_DEVICE" "$POLICY_ID"

echo "[setup-flashguard] Rescanning namespaces"
nvme ns-rescan "$CTRL_DEVICE"
sleep 1

[ -b "$NS_DEVICE" ] || fail "Namespace device did not appear: $NS_DEVICE"

echo "[setup-flashguard] Ready: $NS_DEVICE"
echo "[setup-flashguard] FlashGuard admin commands available: FLASHGUARD_LIST (0xe0), FLASHGUARD_READ (0xe1)"
nvme id-ns "$NS_DEVICE"
