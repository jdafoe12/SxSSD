#!/bin/bash
set -euo pipefail

DEVICE="${1:-/dev/nvme0n1}"
RUNTIME="${RUNTIME:-30}"
NUMJOBS="${NUMJOBS:-8}"
BS="${BS:-256k}"
IOENGINE="${IOENGINE:-psync}"

fail() {
    echo "[zns-bench] ERROR: $*" >&2
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

ZONED_STATE="$(cat "/sys/block/$(basename "$DEVICE")/queue/zoned" 2>/dev/null || true)"
[ "$ZONED_STATE" = "host-managed" ] || fail "$DEVICE is not a host-managed zoned block device"

LBA_SIZE="$(cat "/sys/block/$(basename "$DEVICE")/queue/logical_block_size")"
[ -n "$LBA_SIZE" ] || fail "Failed to read logical block size"

ZSZE_HEX="$(nvme zns id-ns "$DEVICE" | awk '/lbafe  0:/{for (i = 1; i <= NF; i++) if ($i ~ /^zsze:/) {split($i, a, ":"); print a[2]; exit}}')"
[ -n "$ZSZE_HEX" ] || fail "Failed to read zone size from nvme zns id-ns"

ZONE_SIZE_LBAS=$((ZSZE_HEX))
ZONE_SIZE_BYTES=$((ZONE_SIZE_LBAS * LBA_SIZE))
[ "$ZONE_SIZE_BYTES" -gt 0 ] || fail "Computed zone size is zero"
TOTAL_WORKING_SET_BYTES=$((ZONE_SIZE_BYTES * NUMJOBS))

if [ $((ZONE_SIZE_BYTES % 1048576)) -eq 0 ]; then
    FIO_ZONE_SIZE_ARG="$((ZONE_SIZE_BYTES / 1048576))m"
elif [ $((ZONE_SIZE_BYTES % 1024)) -eq 0 ]; then
    FIO_ZONE_SIZE_ARG="$((ZONE_SIZE_BYTES / 1024))k"
else
    FIO_ZONE_SIZE_ARG="$ZONE_SIZE_BYTES"
fi

echo "[zns-bench] Resetting zones on $DEVICE"
blkzone reset "$DEVICE"

echo "[zns-bench] Running fixed max-write workload: runtime=${RUNTIME}s jobs=${NUMJOBS} bs=${BS} zone_size=${FIO_ZONE_SIZE_ARG} total_working_set_bytes=${TOTAL_WORKING_SET_BYTES}"
fio --name=zns_max_write \
    --filename="$DEVICE" \
    --ioengine="$IOENGINE" \
    --direct=1 \
    --rw=write \
    --time_based=1 \
    --runtime="$RUNTIME" \
    --bs="$BS" \
    --zonemode=zbd \
    --zonesize="$FIO_ZONE_SIZE_ARG" \
    --offset_increment="$FIO_ZONE_SIZE_ARG" \
    --size="$FIO_ZONE_SIZE_ARG" \
    --numjobs="$NUMJOBS" \
    --max_open_zones="$NUMJOBS" \
    --group_reporting
