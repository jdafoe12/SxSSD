#!/bin/bash
set -euo pipefail

NS_DEVICE="${1:-/dev/nvme0n1}"
CTRL_DEVICE="${CTRL_DEVICE:-}"
BS="${BS:-64k}"
SMOKE_WRITE_SIZE="${SMOKE_WRITE_SIZE:-64m}"

fail() {
    echo "[zns-check] ERROR: $*" >&2
    exit 1
}

note() {
    echo "[zns-check] $*"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

optional_cmd() {
    command -v "$1" >/dev/null 2>&1
}

has_nvme_zns() {
    nvme help 2>/dev/null | grep -qE '^[[:space:]]+zns[[:space:]]'
}

find_blktests_check() {
    if command -v blktests >/dev/null 2>&1; then
        command -v blktests
        return 0
    fi
    if [ -n "${BLKTESTS_DIR:-}" ] && [ -x "${BLKTESTS_DIR}/check" ]; then
        echo "${BLKTESTS_DIR}/check"
        return 0
    fi
    if [ -n "${SUDO_USER:-}" ]; then
        local user_home
        user_home="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
        if [ -n "$user_home" ] && [ -x "${user_home}/tools/blktests/check" ]; then
            echo "${user_home}/tools/blktests/check"
            return 0
        fi
    fi
    return 1
}

if [ "${EUID}" -ne 0 ]; then
    fail "Run this script with sudo"
fi

require_cmd nvme
require_cmd blkzone

[ -b "$NS_DEVICE" ] || fail "Namespace device does not exist: $NS_DEVICE"

NS_NAME="$(basename "$NS_DEVICE")"
if [ -z "$CTRL_DEVICE" ]; then
    CTRL_DEVICE="/dev/${NS_NAME%n*}"
fi
[ -e "$CTRL_DEVICE" ] || fail "Controller device does not exist: $CTRL_DEVICE"

SYS_BLOCK="/sys/block/$NS_NAME"
[ -d "$SYS_BLOCK" ] || fail "Missing sysfs entry for $NS_NAME"

note "Controller=$CTRL_DEVICE Namespace=$NS_DEVICE"

note "Checking Linux zoned block exposure"
ZONED_STATE="$(cat "$SYS_BLOCK/queue/zoned" 2>/dev/null || true)"
[ "$ZONED_STATE" = "host-managed" ] || fail "Expected host-managed zoned device, got: ${ZONED_STATE:-<empty>}"
cat "$SYS_BLOCK/queue/zoned"

note "Checking namespace descriptor CSI"
NS_DESCS_OUT="$(nvme ns-descs "$NS_DEVICE")"
echo "$NS_DESCS_OUT"
if echo "$NS_DESCS_OUT" | grep -q 'csi[[:space:]]*:'; then
    echo "$NS_DESCS_OUT" | grep -q 'csi[[:space:]]*:[[:space:]]*0x2' || fail "Namespace descriptor does not report CSI 0x2"
else
    note "nvme-cli ns-descs output does not expose CSI on this guest; accepting Linux zoned exposure as fallback"
fi

note "Checking namespace identify data"
nvme id-ns "$NS_DEVICE"

if has_nvme_zns; then
    note "Checking ZNS identify data"
    nvme zns id-ctrl "$CTRL_DEVICE"
    nvme zns id-ns "$NS_DEVICE"

    note "Checking zone reports"
    REPORT_OUT="$(nvme zns report-zones "$NS_DEVICE")"
    echo "$REPORT_OUT"
    echo "$REPORT_OUT" | grep -q 'nr_zones:' || fail "Zone report did not return nr_zones"
else
    note "nvme-cli has no zns subcommand; relying on blkzone and Linux zoned interfaces"
fi

note "Checking Linux blkzone view"
blkzone report "$NS_DEVICE" | sed -n '1,20p'

note "Resetting all zones to a known state"
blkzone reset "$NS_DEVICE"

note "Checking post-reset zone state"
POST_RESET_BLKZONE="$(blkzone report "$NS_DEVICE" | sed -n '1,20p')"
echo "$POST_RESET_BLKZONE"
echo "$POST_RESET_BLKZONE" | grep -Eq 'empty|zcond:[[:space:]]*1\(em\)' || fail "No empty zones found after reset"

if optional_cmd fio; then
    note "Running fio smoke write to one zone"
    fio --name=zns_smoke_write \
        --filename="$NS_DEVICE" \
        --ioengine=psync \
        --direct=1 \
        --rw=write \
        --bs="$BS" \
        --zonemode=zbd \
        --size="$SMOKE_WRITE_SIZE" \
        --numjobs=1 \
        --group_reporting

    note "Checking that write pointer/state changed after fio smoke write"
    POST_WRITE_BLKZONE="$(blkzone report "$NS_DEVICE" | sed -n '1,20p')"
    echo "$POST_WRITE_BLKZONE"
    echo "$POST_WRITE_BLKZONE" | grep -Eq 'imp_open|exp_open|closed|full|zcond:[[:space:]]*[234e]\(|zcond:[[:space:]]*14\(fu\)' || fail "No written/open/closed/full zone found after smoke write"
else
    note "Skipping fio smoke write: fio not installed"
fi

if optional_cmd xnvme; then
    note "Running xNVMe zoned report"
    xnvme zoned report "$NS_DEVICE" || fail "xNVMe zoned report failed"
else
    note "Skipping xNVMe checks: xnvme not installed"
fi

BLKTESTS_CHECK=""
if BLKTESTS_CHECK="$(find_blktests_check)"; then
    note "Running blktests zbd group"
    note "This may take a while and may require local blktests configuration"
    BLKTESTS_DIR_REAL="$(cd "$(dirname "$BLKTESTS_CHECK")" && pwd)"
    cat > "${BLKTESTS_DIR_REAL}/config" <<EOF
TEST_DEVS=($NS_DEVICE)
RUN_ZONED_TESTS=1
QUICK_RUN=1
TIMEOUT=30
DEVICE_ONLY=1
EOF
    (cd "$BLKTESTS_DIR_REAL" && ./check block zbd) || fail "blktests zbd failed"
else
    note "Skipping blktests: blktests not installed"
fi

note "Checks completed"
note "This is a practical open-source validation pass, not a formal NVMe compliance certification"
