#!/bin/bash
set -euo pipefail

DEVICE="${1:-/dev/nvme0n1}"
PASSES="${PASSES:-5}"
NUMJOBS="${NUMJOBS:-2}"
BS="${BS:-64k}"
IOENGINE="${IOENGINE:-psync}"
REGION_PCTS="${REGION_PCTS:-50}"

fail() {
    echo "[zns-multifill] ERROR: $*" >&2
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

FIO_ZONE_SIZE_ARG="$(bytes_to_fio_arg "$ZONE_SIZE_BYTES")"
FIO_DEVICE_SIZE_ARG="$(bytes_to_fio_arg "$DEVICE_SIZE_BYTES")"
TOTAL_ZONES=$((DEVICE_SIZE_BYTES / ZONE_SIZE_BYTES))
[ "$TOTAL_ZONES" -gt 0 ] || fail "Computed total zone count is zero"

echo "[zns-multifill] device=$DEVICE passes=$PASSES jobs=$NUMJOBS bs=$BS zone_size=$FIO_ZONE_SIZE_ARG device_size=$FIO_DEVICE_SIZE_ARG region_pcts=\"$REGION_PCTS\""

for pct in $REGION_PCTS; do
    case "$pct" in
        ''|*[!0-9]*)
            fail "Invalid percentage in REGION_PCTS: $pct"
            ;;
    esac

    [ "$pct" -ge 1 ] && [ "$pct" -le 100 ] || fail "Percentage out of range in REGION_PCTS: $pct"

    REGION_ZONES=$((TOTAL_ZONES * pct / 100))
    if [ "$REGION_ZONES" -lt 1 ]; then
        REGION_ZONES=1
    fi

    REGION_BYTES=$((REGION_ZONES * ZONE_SIZE_BYTES))
    REGION_ARG="$(bytes_to_fio_arg "$REGION_BYTES")"
    CYCLES_PER_PASS=$(((DEVICE_SIZE_BYTES + REGION_BYTES - 1) / REGION_BYTES))
    echo "[zns-multifill] region=${pct}% zones=${REGION_ZONES}/${TOTAL_ZONES} size=${REGION_ARG} cycles_per_pass=${CYCLES_PER_PASS}"

    for pass in $(seq 1 "$PASSES"); do
        for cycle in $(seq 1 "$CYCLES_PER_PASS"); do
            echo "[zns-multifill] region=${pct}% pass $pass/$PASSES cycle $cycle/$CYCLES_PER_PASS: resetting all zones"
            blkzone reset "$DEVICE"

            echo "[zns-multifill] region=${pct}% pass $pass/$PASSES cycle $cycle/$CYCLES_PER_PASS: writing region"
            fio --name="zns_fill_${pct}pct_pass_${pass}_cycle_${cycle}" \
                --filename="$DEVICE" \
                --ioengine="$IOENGINE" \
                --direct=1 \
                --rw=write \
                --bs="$BS" \
                --zonemode=zbd \
                --zonesize="$FIO_ZONE_SIZE_ARG" \
                --offset=0 \
                --size="$REGION_ARG" \
                --numjobs="$NUMJOBS" \
                --max_open_zones="$NUMJOBS" \
                --group_reporting
        done
    done
done
