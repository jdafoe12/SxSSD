#!/bin/bash
set -euo pipefail

DEVICE="${1:-/dev/nvme0n1}"
PASSES="${PASSES:-5}"
NUMJOBS="${NUMJOBS:-8}"
BS="${BS:-256k}"
IOENGINE="${IOENGINE:-psync}"

fail() {
    echo "[zns-multifill] ERROR: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

if [ "${EUID}" -ne 0 ]; then
    fail "Run this script with sudo"
fi

require_cmd fio
require_cmd nvme
require_cmd blkzone

[ -b "$DEVICE" ] || fail "Device does not exist: $DEVICE"

DEV_NAME="$(basename "$DEVICE")"
SYS_BLOCK="/sys/block/$DEV_NAME"
ZONED_STATE="$(cat "$SYS_BLOCK/queue/zoned" 2>/dev/null || true)"
[ "$ZONED_STATE" = "host-managed" ] || fail "$DEVICE is not a host-managed zoned block device"

DEVICE_SIZE_BYTES="$(blockdev --getsize64 "$DEVICE" 2>/dev/null || true)"
[ -n "$DEVICE_SIZE_BYTES" ] || fail "Failed to read device size"

LBA_SIZE="$(cat "$SYS_BLOCK/queue/logical_block_size")"
[ -n "$LBA_SIZE" ] || fail "Failed to read logical block size"

ZSZE_HEX="$(nvme zns id-ns "$DEVICE" | awk '/lbafe  0:/{for (i = 1; i <= NF; i++) if ($i ~ /^zsze:/) {split($i, a, ":"); print a[2]; exit}}')"
[ -n "$ZSZE_HEX" ] || fail "Failed to read zone size from nvme zns id-ns"

ZONE_SIZE_LBAS=$((ZSZE_HEX))
ZONE_SIZE_BYTES=$((ZONE_SIZE_LBAS * LBA_SIZE))
[ "$ZONE_SIZE_BYTES" -gt 0 ] || fail "Computed zone size is zero"

if [ $((ZONE_SIZE_BYTES % 1048576)) -eq 0 ]; then
    FIO_ZONE_SIZE_ARG="$((ZONE_SIZE_BYTES / 1048576))m"
elif [ $((ZONE_SIZE_BYTES % 1024)) -eq 0 ]; then
    FIO_ZONE_SIZE_ARG="$((ZONE_SIZE_BYTES / 1024))k"
else
    FIO_ZONE_SIZE_ARG="$ZONE_SIZE_BYTES"
fi

if [ $((DEVICE_SIZE_BYTES % 1048576)) -eq 0 ]; then
    FIO_DEVICE_SIZE_ARG="$((DEVICE_SIZE_BYTES / 1048576))m"
elif [ $((DEVICE_SIZE_BYTES % 1024)) -eq 0 ]; then
    FIO_DEVICE_SIZE_ARG="$((DEVICE_SIZE_BYTES / 1024))k"
else
    FIO_DEVICE_SIZE_ARG="$DEVICE_SIZE_BYTES"
fi

echo "[zns-multifill] device=$DEVICE passes=$PASSES jobs=$NUMJOBS bs=$BS zone_size=$FIO_ZONE_SIZE_ARG device_size=$FIO_DEVICE_SIZE_ARG"

for pass in $(seq 1 "$PASSES"); do
    echo "[zns-multifill] Pass $pass/$PASSES: resetting all zones"
    blkzone reset "$DEVICE"

    echo "[zns-multifill] Pass $pass/$PASSES: filling device once"
    fio --name="zns_fill_pass_${pass}" \
        --filename="$DEVICE" \
        --ioengine="$IOENGINE" \
        --direct=1 \
        --rw=write \
        --bs="$BS" \
        --zonemode=zbd \
        --zonesize="$FIO_ZONE_SIZE_ARG" \
        --size="$FIO_DEVICE_SIZE_ARG" \
        --numjobs="$NUMJOBS" \
        --max_open_zones="$NUMJOBS" \
        --group_reporting
done
