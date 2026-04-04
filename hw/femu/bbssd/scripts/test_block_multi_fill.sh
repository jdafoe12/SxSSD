#!/bin/bash
set -euo pipefail

DEVICE="${1:-/dev/nvme0n1}"
PASSES="${PASSES:-5}"
NUMJOBS="${NUMJOBS:-8}"
BS="${BS:-256k}"
IOENGINE="${IOENGINE:-psync}"

fail() {
    echo "[block-multifill] ERROR: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

if [ "${EUID}" -ne 0 ]; then
    fail "Run this script with sudo"
fi

require_cmd fio

[ -b "$DEVICE" ] || fail "Device does not exist: $DEVICE"

DEVICE_SIZE_BYTES="$(blockdev --getsize64 "$DEVICE" 2>/dev/null || true)"
[ -n "$DEVICE_SIZE_BYTES" ] || fail "Failed to read device size"

if [ $((DEVICE_SIZE_BYTES % 1048576)) -eq 0 ]; then
    FIO_DEVICE_SIZE_ARG="$((DEVICE_SIZE_BYTES / 1048576))m"
elif [ $((DEVICE_SIZE_BYTES % 1024)) -eq 0 ]; then
    FIO_DEVICE_SIZE_ARG="$((DEVICE_SIZE_BYTES / 1024))k"
else
    FIO_DEVICE_SIZE_ARG="$DEVICE_SIZE_BYTES"
fi

echo "[block-multifill] device=$DEVICE passes=$PASSES jobs=$NUMJOBS bs=$BS device_size=$FIO_DEVICE_SIZE_ARG"

for pass in $(seq 1 "$PASSES"); do
    echo "[block-multifill] Pass $pass/$PASSES: filling device once"
    fio --name="block_fill_pass_${pass}" \
        --filename="$DEVICE" \
        --ioengine="$IOENGINE" \
        --direct=1 \
        --rw=write \
        --bs="$BS" \
        --size="$FIO_DEVICE_SIZE_ARG" \
        --numjobs="$NUMJOBS" \
        --group_reporting
done
