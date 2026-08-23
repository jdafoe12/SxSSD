#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

DEVICE="${DEVICE:-/dev/nvme0n1}"
WORKING_SET_BYTES="${WORKING_SET_BYTES:-12884901888}"
RUNTIME="${RUNTIME:-600}"
RAMP_TIME="${RAMP_TIME:-60}"
BS="${BS:-4k}"
IODEPTH="${IODEPTH:-32}"
IOENGINE="${IOENGINE:-libaio}"
MAX_OPEN_ZONES="${MAX_OPEN_ZONES:-32}"
ZONE_RESET_THRESHOLD="${ZONE_RESET_THRESHOLD:-0.75}"

fail() {
    echo "[zns-block-benchmark] ERROR: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

invoking_user_home() {
    local home

    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
        [ -n "$home" ] || fail "Could not find the home directory for $SUDO_USER"
        printf '%s\n' "$home"
    else
        printf '%s\n' "$HOME"
    fi
}

initialize_run() {
    local policy="$1"
    local timestamp

    [ "${EUID}" -eq 0 ] || fail "Run this script with sudo"
    require_cmd blockdev
    require_cmd fio
    require_cmd lsblk
    require_cmd nvme
    [ -b "$DEVICE" ] || fail "Device does not exist: $DEVICE"

    RESULTS_ROOT="${RESULTS_ROOT:-$(invoking_user_home)/fio-zns-block-results}"
    timestamp="$(date +%Y%m%d-%H%M%S)"
    OUT_DIR="${RESULTS_ROOT}/${policy}-${timestamp}"
    mkdir -p "$OUT_DIR"

    exec > >(tee -a "$OUT_DIR/run.log") 2>&1

    echo "[zns-block-benchmark] Policy: $policy"
    echo "[zns-block-benchmark] Device: $DEVICE"
    echo "[zns-block-benchmark] Results: $OUT_DIR"
}

confirm_destructive_run() {
    if [ "${ASSUME_YES:-0}" = "1" ]; then
        return
    fi

    echo
    echo "This benchmark will destroy all data in the first $WORKING_SET_BYTES bytes of $DEVICE."
    read -r -p "Type the complete device path ($DEVICE) to continue: " answer
    [ "$answer" = "$DEVICE" ] || fail "Confirmation did not match; nothing was written"
}

device_zoned_model() {
    local block_name

    block_name="$(basename "$DEVICE")"
    cat "/sys/class/block/${block_name}/queue/zoned"
}

assert_device_capacity() {
    local capacity

    capacity="$(blockdev --getsize64 "$DEVICE")"
    [ "$capacity" -ge "$WORKING_SET_BYTES" ] ||
        fail "$DEVICE has $capacity bytes, less than the $WORKING_SET_BYTES-byte working set"
}

write_parameters() {
    local policy="$1"
    local zone_size_bytes="${2:-not-applicable}"

    {
        printf 'POLICY=%q\n' "$policy"
        printf 'DEVICE=%q\n' "$DEVICE"
        printf 'WORKING_SET_BYTES=%q\n' "$WORKING_SET_BYTES"
        printf 'RUNTIME=%q\n' "$RUNTIME"
        printf 'RAMP_TIME=%q\n' "$RAMP_TIME"
        printf 'BS=%q\n' "$BS"
        printf 'IODEPTH=%q\n' "$IODEPTH"
        printf 'IOENGINE=%q\n' "$IOENGINE"
        printf 'ZONE_SIZE_BYTES=%q\n' "$zone_size_bytes"
        printf 'MAX_OPEN_ZONES=%q\n' "$MAX_OPEN_ZONES"
        printf 'ZONE_RESET_THRESHOLD=%q\n' "$ZONE_RESET_THRESHOLD"
    } > "$OUT_DIR/parameters.env"
}

capture_metadata() {
    local label="$1"
    local block_name
    local metadata_file

    block_name="$(basename "$DEVICE")"
    metadata_file="$OUT_DIR/metadata-${label}.txt"

    if ! {
        echo "capture=$label"
        echo "timestamp=$(date --iso-8601=seconds)"
        echo "device=$DEVICE"
        echo "zoned=$(device_zoned_model)"
        echo "capacity_bytes=$(blockdev --getsize64 "$DEVICE")"
        echo "logical_block_bytes=$(blockdev --getss "$DEVICE")"
        echo
        fio --version
        uname -a
        echo
        lsblk -b -o NAME,TYPE,SIZE,LOG-SEC,PHY-SEC,ROTA,MOUNTPOINT "$DEVICE"
        echo
        nvme id-ns "$DEVICE"
        if [ "$(device_zoned_model)" != "none" ]; then
            echo
            echo "chunk_sectors=$(cat "/sys/class/block/${block_name}/queue/chunk_sectors")"
            blkzone report "$DEVICE"
        fi
    } > "$metadata_file" 2>&1; then
        cat "$metadata_file" >&2
        fail "Could not capture $label metadata; details are above and in $metadata_file"
    fi
}

run_fio() {
    local label="$1"
    shift

    {
        printf 'fio'
        printf ' %q' "$@"
        printf '\n'
    } > "$OUT_DIR/${label}.command"

    echo "[zns-block-benchmark] Starting $label at $(date --iso-8601=seconds)"
    fio "$@" \
        --eta=never \
        --output-format=json \
        --output="$OUT_DIR/${label}.json"
    echo "[zns-block-benchmark] Finished $label at $(date --iso-8601=seconds)"
}

sequential_arguments() {
    local log_prefix="$1"

    SEQUENTIAL_ARGS=(
        --name=sequential
        --filename="$DEVICE"
        --direct=1
        --ioengine="$IOENGINE"
        --rw=write
        --bs=128k
        --iodepth="$IODEPTH"
        --numjobs=1
        --size="$WORKING_SET_BYTES"
        --group_reporting=1
        --percentile_list=50:90:95:99:99.9:99.99
        --write_bw_log="$OUT_DIR/${log_prefix}"
        --write_iops_log="$OUT_DIR/${log_prefix}"
        --write_lat_log="$OUT_DIR/${log_prefix}"
        --log_avg_msec=1000
    )
}

steady_common_arguments() {
    local log_prefix="$1"

    STEADY_ARGS=(
        --name=steady
        --filename="$DEVICE"
        --direct=1
        --ioengine="$IOENGINE"
        --rw=randwrite
        --bs="$BS"
        --iodepth="$IODEPTH"
        --numjobs=1
        --size="$WORKING_SET_BYTES"
        --time_based=1
        --runtime="$RUNTIME"
        --ramp_time="$RAMP_TIME"
        --group_reporting=1
        --percentile_list=50:90:95:99:99.9:99.99
        --write_bw_log="$OUT_DIR/${log_prefix}"
        --write_iops_log="$OUT_DIR/${log_prefix}"
        --write_lat_log="$OUT_DIR/${log_prefix}"
        --log_avg_msec=1000
    )
}

finish_run() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$OUT_DIR"
    fi

    echo
    echo "[zns-block-benchmark] Complete. Results are in:"
    echo "$OUT_DIR"
}
