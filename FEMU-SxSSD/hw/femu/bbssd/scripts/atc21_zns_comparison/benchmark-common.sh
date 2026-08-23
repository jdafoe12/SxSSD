#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

DEVICE="${DEVICE:-/dev/nvme0n1}"
WORKING_SET_BYTES="${WORKING_SET_BYTES:-12884901888}"
ZONE_SIZE_BYTES="${ZONE_SIZE_BYTES:-67108864}"
BS_BYTES="${BS_BYTES:-65536}"
STREAMS="${STREAMS:-4}"
IODEPTH="${IODEPTH:-32}"
RAMP_TIME="${RAMP_TIME:-60}"
RUNTIME="${RUNTIME:-600}"
OFFSET_BYTES="${OFFSET_BYTES:-0}"
POLICY_VARIANT="${POLICY_VARIANT:-unspecified}"
PLACEMENT_GROUPS="${PLACEMENT_GROUPS:-unspecified}"

fail() {
    echo "[atc21-comparison] ERROR: $*" >&2
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

device_zoned_model() {
    cat "/sys/class/block/$(basename "$DEVICE")/queue/zoned"
}

initialize_run() {
    local mode="$1"
    local timestamp

    [ "${EUID}" -eq 0 ] || fail "Run this script with sudo"
    require_cmd blockdev
    require_cmd lsblk
    require_cmd make
    require_cmd nvme
    [ -b "$DEVICE" ] || fail "Device does not exist: $DEVICE"

    make -C "$SCRIPT_DIR"

    RESULTS_ROOT="${RESULTS_ROOT:-$(invoking_user_home)/atc21-zns-results}"
    timestamp="$(date +%Y%m%d-%H%M%S)"
    OUT_DIR="${RESULTS_ROOT}/${mode}-${timestamp}"
    mkdir -p "$OUT_DIR"
    exec > >(tee -a "$OUT_DIR/run.log") 2>&1

    echo "[atc21-comparison] Mode: $mode"
    echo "[atc21-comparison] Device: $DEVICE"
    echo "[atc21-comparison] Results: $OUT_DIR"
    echo "[atc21-comparison] Requirement: use a freshly started FEMU instance"
}

validate_parameters() {
    local mode="$1"
    local capacity

    capacity="$(blockdev --getsize64 "$DEVICE")"
    [ "$((OFFSET_BYTES + WORKING_SET_BYTES))" -le "$capacity" ] ||
        fail "Working set exceeds the $capacity-byte device"
    [ "$((WORKING_SET_BYTES % ZONE_SIZE_BYTES))" -eq 0 ] ||
        fail "WORKING_SET_BYTES must be divisible by ZONE_SIZE_BYTES"
    [ "$((ZONE_SIZE_BYTES % BS_BYTES))" -eq 0 ] ||
        fail "ZONE_SIZE_BYTES must be divisible by BS_BYTES"
    [ "$((IODEPTH % STREAMS))" -eq 0 ] ||
        fail "IODEPTH must be divisible by STREAMS"
    [ "$((WORKING_SET_BYTES / ZONE_SIZE_BYTES))" -ge "$STREAMS" ] ||
        fail "The working set must contain at least STREAMS regions"
    [ "$(((WORKING_SET_BYTES / ZONE_SIZE_BYTES) % STREAMS))" -eq 0 ] ||
        fail "The number of regions must be divisible by STREAMS"
    if [ "$mode" = "block" ] &&
       [ "$WORKING_SET_BYTES" -gt "$((capacity * 3 / 4))" ] &&
       [ "${ALLOW_LOW_SPARE_AREA:-0}" != "1" ]; then
        fail "The block policy requires at least 25% of its eSWDs as spare area for this workload; reduce WORKING_SET_BYTES or set ALLOW_LOW_SPARE_AREA=1 for an intentional stress test"
    fi
}

confirm_destructive_run() {
    local answer

    if [ "${ASSUME_YES:-0}" = "1" ]; then
        return
    fi
    echo
    echo "This benchmark will destroy all data in the first $WORKING_SET_BYTES bytes of $DEVICE."
    read -r -p "Type the complete device path ($DEVICE) to continue: " answer
    [ "$answer" = "$DEVICE" ] || fail "Confirmation did not match; nothing was written"
}

write_parameters() {
    local mode="$1"

    {
        printf 'MODE=%q\n' "$mode"
        printf 'DEVICE=%q\n' "$DEVICE"
        printf 'WORKING_SET_BYTES=%q\n' "$WORKING_SET_BYTES"
        printf 'ZONE_SIZE_BYTES=%q\n' "$ZONE_SIZE_BYTES"
        printf 'BS_BYTES=%q\n' "$BS_BYTES"
        printf 'STREAMS=%q\n' "$STREAMS"
        printf 'IODEPTH=%q\n' "$IODEPTH"
        printf 'RAMP_TIME=%q\n' "$RAMP_TIME"
        printf 'RUNTIME=%q\n' "$RUNTIME"
        printf 'OFFSET_BYTES=%q\n' "$OFFSET_BYTES"
        printf 'POLICY_VARIANT=%q\n' "$POLICY_VARIANT"
        printf 'PLACEMENT_GROUPS=%q\n' "$PLACEMENT_GROUPS"
    } > "$OUT_DIR/parameters.env"
}

capture_metadata() {
    local label="$1"
    local block_name
    local output

    block_name="$(basename "$DEVICE")"
    output="$OUT_DIR/metadata-${label}.txt"
    {
        echo "capture=$label"
        echo "timestamp=$(date --iso-8601=seconds)"
        echo "zoned=$(device_zoned_model)"
        echo "capacity_bytes=$(blockdev --getsize64 "$DEVICE")"
        echo "logical_block_bytes=$(blockdev --getss "$DEVICE")"
        echo
        uname -a
        lsblk -b -o NAME,TYPE,SIZE,LOG-SEC,PHY-SEC,ROTA,MOUNTPOINT "$DEVICE"
        echo
        nvme id-ns "$DEVICE"
        if [ "$(device_zoned_model)" != "none" ]; then
            echo
            echo "chunk_sectors=$(cat "/sys/class/block/${block_name}/queue/chunk_sectors")"
            echo "nr_zones=$(cat "/sys/class/block/${block_name}/queue/nr_zones")"
            blkzone report "$DEVICE"
        fi
    } > "$output" 2>&1
}

run_benchmark() {
    local mode="$1"
    local command=(
        "$SCRIPT_DIR/atc21-write"
        --mode "$mode"
        --device "$DEVICE"
        --output-dir "$OUT_DIR"
        --offset "$OFFSET_BYTES"
        --working-set "$WORKING_SET_BYTES"
        --zone-size "$ZONE_SIZE_BYTES"
        --bs "$BS_BYTES"
        --streams "$STREAMS"
        --iodepth "$IODEPTH"
        --warmup "$RAMP_TIME"
        --runtime "$RUNTIME"
    )

    {
        printf '%q' "${command[0]}"
        printf ' %q' "${command[@]:1}"
        printf '\n'
    } > "$OUT_DIR/benchmark.command"
    "${command[@]}"
}

finish_run() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$OUT_DIR"
    fi
    echo
    echo "[atc21-comparison] Complete. Results are in:"
    echo "$OUT_DIR"
}
