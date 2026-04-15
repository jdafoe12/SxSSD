#!/bin/bash
set -euo pipefail

DEVICE="${1:-/dev/nvme0n1}"
PASSES="${PASSES:-5}"
NUMJOBS="${NUMJOBS:-2}"
BS="${BS:-64k}"
IOENGINE="${IOENGINE:-psync}"
REGION_PCTS="${REGION_PCTS:-50}"
# RW_MODE controls what kind of writes are used for the cyclic overwrite passes.
# "write"     - sequential (fast, but produces trivially 0% valid GC victims
#               when the hot region perfectly fits the OP window)
# "randwrite" - random within the region (realistic; eSWDs accumulate invalids
#               gradually so GC sees a meaningful valid-page distribution)
RW_MODE="${RW_MODE:-randwrite}"

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
    echo "[block-multifill] region=${pct}% size=${REGION_ARG} jobs=$NUMJOBS rw=$RW_MODE cycles_per_pass=${CYCLES_PER_PASS}"

    for pass in $(seq 1 "$PASSES"); do
        # Cycle 1 of every pass is always a sequential write to ensure the region
        # is fully and cleanly written before the overwrite cycles begin.
        echo "[block-multifill] region=${pct}% pass $pass/$PASSES cycle 1/$CYCLES_PER_PASS: sequential fill"
        fio --name="block_fill_${pct}pct_pass_${pass}_cycle_1" \
            --filename="$DEVICE" \
            --ioengine="$IOENGINE" \
            --direct=1 \
            --rw=write \
            --bs="$BS" \
            --offset=0 \
            --size="$REGION_ARG" \
            --numjobs=1 \
            --group_reporting

        # Subsequent cycles use RW_MODE (default: randwrite) so that GC victims
        # accumulate invalids gradually rather than being wiped out completely
        # before GC ever runs.  Sequential full-coverage overwrites cause every
        # hot eSWD to reach 0% valid at the exact moment GC triggers (due to
        # geometry alignment), producing a trivially-perfect WAF=1.0 result that
        # does not reflect real hot/cold separation behaviour.
        for cycle in $(seq 2 "$CYCLES_PER_PASS"); do
            echo "[block-multifill] region=${pct}% pass $pass/$PASSES cycle $cycle/$CYCLES_PER_PASS: ${RW_MODE} overwrite"
            fio --name="block_fill_${pct}pct_pass_${pass}_cycle_${cycle}" \
                --filename="$DEVICE" \
                --ioengine="$IOENGINE" \
                --direct=1 \
                --rw="$RW_MODE" \
                --bs="$BS" \
                --offset=0 \
                --size="$REGION_ARG" \
                --numjobs="$NUMJOBS" \
                --group_reporting
        done
    done
done
