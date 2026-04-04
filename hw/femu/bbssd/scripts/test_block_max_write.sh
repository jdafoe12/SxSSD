#!/bin/bash
set -euo pipefail

DEVICE="${1:-/dev/nvme0n1}"
RUNTIME="${RUNTIME:-30}"
NUMJOBS="${NUMJOBS:-8}"
BS="${BS:-256k}"
IOENGINE="${IOENGINE:-psync}"
REGION_SIZE="${REGION_SIZE:-64m}"

fail() {
    echo "[block-bench] ERROR: $*" >&2
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

echo "[block-bench] Running fixed max-write workload: runtime=${RUNTIME}s jobs=${NUMJOBS} bs=${BS} region_size=${REGION_SIZE}"
fio --name=block_max_write \
    --filename="$DEVICE" \
    --ioengine="$IOENGINE" \
    --direct=1 \
    --rw=write \
    --time_based=1 \
    --runtime="$RUNTIME" \
    --bs="$BS" \
    --offset_increment="$REGION_SIZE" \
    --size="$REGION_SIZE" \
    --numjobs="$NUMJOBS" \
    --group_reporting
