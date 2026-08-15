#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$(cd "$SCRIPT_DIR/../policy" && pwd)"
CTRL_DEVICE="${CTRL_DEVICE:-/dev/nvme0}"
NS_DEVICE="${NS_DEVICE:-/dev/nvme0n1}"
POLICY_ID="${POLICY_ID:-200}"
POLICY_VERSION="${POLICY_VERSION:-1}"
SESSION_MODE="${SESSION_MODE:-confidential}"
POLICY_PATH="${POLICY_PATH:-$POLICY_DIR/zns-policy.wasm}"

fail() {
    echo "[setup-zns] ERROR: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

has_nvme_zns() {
    nvme help 2>/dev/null | grep -qE '^[[:space:]]+zns[[:space:]]'
}

if [ "${EUID}" -ne 0 ]; then
    fail "Run this script with sudo"
fi

require_cmd nvme
require_cmd blockdev
require_cmd dd
require_cmd timeout

[ -e "$CTRL_DEVICE" ] || fail "Missing controller device: $CTRL_DEVICE"

echo "[setup-zns] Building policy image and policyctl"
make -C "$POLICY_DIR"
make -C "$SCRIPT_DIR"

[ -f "$POLICY_PATH" ] || fail "Missing policy image after build: $POLICY_PATH"
[ -x "$SCRIPT_DIR/policyctl" ] || fail "Missing policyctl after build"

echo "[setup-zns] Opening session on $CTRL_DEVICE"
"$SCRIPT_DIR/policyctl" --mode "$SESSION_MODE" session "$CTRL_DEVICE"

echo "[setup-zns] Installing ZNS policy"
"$SCRIPT_DIR/policyctl" install "$CTRL_DEVICE" "$POLICY_PATH" "$POLICY_ID" "$POLICY_VERSION"

echo "[setup-zns] Activating ZNS policy"
"$SCRIPT_DIR/policyctl" activate "$CTRL_DEVICE" "$POLICY_ID"

echo "[setup-zns] Rescanning namespaces"
nvme ns-rescan "$CTRL_DEVICE"
sleep 1

[ -b "$NS_DEVICE" ] || fail "Namespace device did not appear: $NS_DEVICE"

echo "[setup-zns] Ready: $NS_DEVICE"
cat "/sys/block/$(basename "$NS_DEVICE")/queue/zoned"

namespace_bytes="$(blockdev --getsize64 "$NS_DEVICE")"
[ "$namespace_bytes" -ge 4096 ] || fail "Namespace is smaller than one 4 KiB block"
echo "[setup-zns] Checking an unwritten block at the namespace endpoint"
if ! timeout 10 dd if="$NS_DEVICE" of=/dev/null bs=4096 \
        skip="$((namespace_bytes / 4096 - 1))" count=1 iflag=direct \
        status=none; then
    fail "Endpoint read failed; do not run ZNS workloads"
fi

nvme ns-descs "$NS_DEVICE"
if has_nvme_zns; then
    nvme zns id-ns "$NS_DEVICE"
else
    echo "[setup-zns] nvme-cli has no zns subcommand; skipping 'nvme zns id-ns'"
    blkzone report "$NS_DEVICE" | sed -n '1,12p'
fi
