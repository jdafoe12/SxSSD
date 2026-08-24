#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

DEVICE="${DEVICE:-/dev/nvme0n1}"
HOST_RESULTS_MOUNT="${HOST_RESULTS_MOUNT:-/mnt/femu-host-results}"
OUT_DIR="${OUT_DIR:-${HOST_RESULTS_MOUNT}/max_io/json}"
SYSTEM_LABEL="${SYSTEM_LABEL:-unknown}"
RUNTIME="${RUNTIME:-60}"
BS="${BS:-4k}"
IODEPTH="${IODEPTH:-32}"
NUMJOBS="${NUMJOBS:-1}"
SIZE="${SIZE:-4G}"
OFFSET="${OFFSET:-0}"
IOENGINE="${IOENGINE:-libaio}"

fail() {
    echo "[max-io] ERROR: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

require_host_results_mount() {
    [ -d "$HOST_RESULTS_MOUNT" ] || fail "Host results mount does not exist: $HOST_RESULTS_MOUNT"
    if command -v mountpoint >/dev/null 2>&1; then
        mountpoint -q "$HOST_RESULTS_MOUNT" || fail "Host results path is not a mountpoint: $HOST_RESULTS_MOUNT"
    fi
    [ -w "$HOST_RESULTS_MOUNT" ] || fail "Host results mount is not writable: $HOST_RESULTS_MOUNT"
}

if [ "${EUID}" -ne 0 ]; then
    fail "Run this script with sudo"
fi

require_cmd fio
[ -b "$DEVICE" ] || fail "Device does not exist: $DEVICE"
require_host_results_mount

mkdir -p "$OUT_DIR"
ts="$(date +%Y%m%d-%H%M%S)"
out="${OUT_DIR}/${SYSTEM_LABEL}_max_seq_write_${ts}.json"

echo "[max-io] Running max sequential-write workload on ${DEVICE}"
echo "[max-io] Output: ${out}"

fio \
    --name=max_seq_write \
    --filename="$DEVICE" \
    --rw=write \
    --bs="$BS" \
    --iodepth="$IODEPTH" \
    --numjobs="$NUMJOBS" \
    --ioengine="$IOENGINE" \
    --direct=1 \
    --size="$SIZE" \
    --offset="$OFFSET" \
    --time_based=1 \
    --runtime="$RUNTIME" \
    --group_reporting=1 \
    --output-format=json \
    --output="$out"

echo "[max-io] Wrote ${out}"
