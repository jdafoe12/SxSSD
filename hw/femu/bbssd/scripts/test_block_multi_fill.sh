#!/bin/bash
set -euo pipefail

DEVICE="${1:-/dev/nvme0n1}"
PASSES="${PASSES:-5}"
NUMJOBS="${NUMJOBS:-2}"
BS="${BS:-64k}"
IOENGINE="${IOENGINE:-psync}"
REGION_PCTS="${REGION_PCTS:-50}"

fail() {
    echo "[block-multifill] ERROR: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

bytes_to_fio_arg() {
    local bytes="$1"

    if [ "$bytes" -le 0 ]; then
        return 1
    fi

    if [ $((bytes % 1048576)) -eq 0 ]; then
        printf '%sm' "$((bytes / 1048576))"
    elif [ $((bytes % 1024)) -eq 0 ]; then
        printf '%sk' "$((bytes / 1024))"
    else
        printf '%s' "$bytes"
    fi
}

if [ "${EUID}" -ne 0 ]; then
    fail "Run this script with sudo"
fi

require_cmd fio

[ -b "$DEVICE" ] || fail "Device does not exist: $DEVICE"

DEVICE_SIZE_BYTES="$(blockdev --getsize64 "$DEVICE" 2>/dev/null || true)"
[ -n "$DEVICE_SIZE_BYTES" ] || fail "Failed to read device size"

FIO_DEVICE_SIZE_ARG="$(bytes_to_fio_arg "$DEVICE_SIZE_BYTES")"

echo "[block-multifill] device=$DEVICE passes=$PASSES jobs=$NUMJOBS bs=$BS device_size=$FIO_DEVICE_SIZE_ARG region_pcts=\"$REGION_PCTS\""

for pct in $REGION_PCTS; do
    case "$pct" in
        ''|*[!0-9]*)
            fail "Invalid percentage in REGION_PCTS: $pct"
            ;;
    esac

    [ "$pct" -ge 1 ] && [ "$pct" -le 100 ] || fail "Percentage out of range in REGION_PCTS: $pct"

    REGION_BYTES=$((DEVICE_SIZE_BYTES * pct / 100))
    [ "$REGION_BYTES" -gt 0 ] || fail "Computed region size is zero for ${pct}%"

    REGION_ARG="$(bytes_to_fio_arg "$REGION_BYTES")"
    CYCLES_PER_PASS=$(((DEVICE_SIZE_BYTES + REGION_BYTES - 1) / REGION_BYTES))
    echo "[block-multifill] region=${pct}% size=${REGION_ARG} cycles_per_pass=${CYCLES_PER_PASS}"

    for pass in $(seq 1 "$PASSES"); do
        for cycle in $(seq 1 "$CYCLES_PER_PASS"); do
            echo "[block-multifill] region=${pct}% pass $pass/$PASSES cycle $cycle/$CYCLES_PER_PASS: writing region"
            fio --name="block_fill_${pct}pct_pass_${pass}_cycle_${cycle}" \
                --filename="$DEVICE" \
                --ioengine="$IOENGINE" \
                --direct=1 \
                --rw=write \
                --bs="$BS" \
                --offset=0 \
                --size="$REGION_ARG" \
                --numjobs="$NUMJOBS" \
                --group_reporting
        done
    done
done
