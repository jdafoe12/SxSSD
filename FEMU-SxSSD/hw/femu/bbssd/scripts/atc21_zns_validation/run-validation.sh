#!/bin/bash

# Short Figure 5-style validation of SxSSD's block and ZNS policies.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-}"

DEVICE="${DEVICE:-/dev/nvme0n1}"
RESULTS_ROOT="${RESULTS_ROOT:-}"
ZONE_SIZE_BYTES="${ZONE_SIZE_BYTES:-67108864}"
PRECONDITION_PASSES="${PRECONDITION_PASSES:-2}"
RUNTIME_SECONDS="${RUNTIME_SECONDS:-90}"
RAMP_SECONDS="${RAMP_SECONDS:-30}"
IOENGINE="${IOENGINE:-io_uring}"
CALIBRATION_ONLY="${CALIBRATION_ONLY:-0}"
ZNS_PEAK_MIB="${ZNS_PEAK_MIB:-}"
ASSUME_YES="${ASSUME_YES:-0}"

fail() {
    echo "[atc21-validation] ERROR: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

invoking_user_home() {
    local home

    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
        [ -n "$home" ] || fail "Could not determine $SUDO_USER's home directory"
        printf '%s\n' "$home"
    else
        printf '%s\n' "$HOME"
    fi
}

device_zoned_model() {
    cat "/sys/class/block/$(basename "$DEVICE")/queue/zoned"
}

mode_parameters() {
    case "$MODE" in
    zns)
        POLICY_LABEL="zns-0-data-op"
        WORKING_SET_BYTES="$((256 * ZONE_SIZE_BYTES))"
        EXPECTED_ZONED="host-managed"
        FIO_ZONE_OPTIONS=""
        ;;
    block-7)
        POLICY_LABEL="block-7-effective-op"
        WORKING_SET_BYTES="$((239 * ZONE_SIZE_BYTES))"
        EXPECTED_ZONED="none"
        FIO_ZONE_OPTIONS="zonesize=64m
zonecapacity=64m"
        ;;
    block-28)
        POLICY_LABEL="block-28-effective-op"
        WORKING_SET_BYTES="$((200 * ZONE_SIZE_BYTES))"
        EXPECTED_ZONED="none"
        FIO_ZONE_OPTIONS="zonesize=64m
zonecapacity=64m"
        ;;
    *)
        fail "Usage: $0 zns|block-7|block-28"
        ;;
    esac
}

capture_metadata() {
    local label="$1"
    local output="$OUT_DIR/metadata-${label}.txt"
    local block_name

    block_name="$(basename "$DEVICE")"
    {
        echo "capture=$label"
        echo "timestamp=$(date --iso-8601=seconds)"
        echo "mode=$MODE"
        echo "policy_label=$POLICY_LABEL"
        echo "device=$DEVICE"
        echo "zoned=$(device_zoned_model)"
        echo "capacity_bytes=$(blockdev --getsize64 "$DEVICE")"
        echo "logical_block_bytes=$(blockdev --getss "$DEVICE")"
        echo "fio_version=$(fio --version)"
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

confirm_destructive_run() {
    local answer

    if [ "$ASSUME_YES" = "1" ]; then
        return
    fi
    echo
    echo "This benchmark will discard or overwrite the first $WORKING_SET_BYTES bytes of $DEVICE."
    read -r -p "Type the complete device path ($DEVICE) to continue: " answer
    [ "$answer" = "$DEVICE" ] || fail "Confirmation did not match; nothing was written"
}

reset_working_set() {
    if [ "$MODE" = "zns" ]; then
        echo "[atc21-validation] Resetting all ZNS zones"
        blkzone reset "$DEVICE"
    else
        echo "[atc21-validation] Discarding the block working set"
        blkdiscard -o 0 -l "$WORKING_SET_BYTES" "$DEVICE"
    fi
}

write_parameters() {
    {
        printf 'MODE=%q\n' "$MODE"
        printf 'POLICY_LABEL=%q\n' "$POLICY_LABEL"
        printf 'DEVICE=%q\n' "$DEVICE"
        printf 'WORKING_SET_BYTES=%q\n' "$WORKING_SET_BYTES"
        printf 'ZONE_SIZE_BYTES=%q\n' "$ZONE_SIZE_BYTES"
        printf 'ACTIVE_ZONES=%q\n' 4
        printf 'WRITER_IODEPTH=%q\n' 1
        printf 'READER_IODEPTH=%q\n' 1
        printf 'PRECONDITION_PASSES=%q\n' "$PRECONDITION_PASSES"
        printf 'RUNTIME_SECONDS=%q\n' "$RUNTIME_SECONDS"
        printf 'RAMP_SECONDS=%q\n' "$RAMP_SECONDS"
        printf 'IOENGINE=%q\n' "$IOENGINE"
        printf 'ZNS_PEAK_MIB=%q\n' "$ZNS_PEAK_MIB"
    } > "$OUT_DIR/parameters.env"
}

write_fio_file() {
    local fio_file="$1"
    local precondition_bytes="$((WORKING_SET_BYTES * PRECONDITION_PASSES))"
    local target

    {
        echo "[global]"
        echo "filename=$DEVICE"
        echo "ioengine=$IOENGINE"
        echo "direct=1"
        echo "zonemode=zbd"
        printf '%s\n' "$FIO_ZONE_OPTIONS"
        echo "max_open_zones=4"
        echo "iodepth=1"
        echo "norandommap=1"
        echo "randrepeat=0"
        echo "offset=0"
        echo "size=$WORKING_SET_BYTES"
        echo "group_reporting=0"
        echo
        echo "[precondition_writer]"
        echo "rw=randwrite"
        echo "bs=64k"
        echo "io_size=$precondition_bytes"
        echo "write_bw_log=$OUT_DIR/precondition"
        echo "log_avg_msec=1000"
        echo
        echo "[peak_writer]"
        echo "stonewall=1"
        echo "rw=randwrite"
        echo "bs=64k"
        echo "time_based=1"
        echo "runtime=$RUNTIME_SECONDS"
        echo "ramp_time=$RAMP_SECONDS"

        if [ "$CALIBRATION_ONLY" = "1" ]; then
            return
        fi

        echo
        echo "[mixed_000_reader]"
        echo "stonewall=1"
        echo "rw=randread"
        echo "bs=4k"
        echo "time_based=1"
        echo "runtime=$RUNTIME_SECONDS"
        echo "ramp_time=$RAMP_SECONDS"
        echo "read_beyond_wp=0"

        while read -r target; do
            [ -n "$target" ] || continue
            echo
            echo "[mixed_${target}_writer]"
            echo "stonewall=1"
            echo "rw=randwrite"
            echo "bs=64k"
            echo "rate=${target}m"
            echo "time_based=1"
            echo "runtime=$RUNTIME_SECONDS"
            echo "ramp_time=$RAMP_SECONDS"
            echo
            echo "[mixed_${target}_reader]"
            echo "rw=randread"
            echo "bs=4k"
            echo "time_based=1"
            echo "runtime=$RUNTIME_SECONDS"
            echo "ramp_time=$RAMP_SECONDS"
            echo "read_beyond_wp=0"
        done < <(python3 "$SCRIPT_DIR/summarize.py" targets "$ZNS_PEAK_MIB")
    } > "$fio_file"
}

read_reference_peak() {
    local reference_file="$RESULTS_ROOT/zns-reference.env"

    if [ -n "$ZNS_PEAK_MIB" ]; then
        return
    fi
    [ -f "$reference_file" ] ||
        fail "Run CALIBRATION_ONLY=1 $0 zns first, or set ZNS_PEAK_MIB"
    # shellcheck disable=SC1090
    source "$reference_file"
    ZNS_PEAK_MIB="${ZNS_PEAK_MIB:-}"
    [ -n "$ZNS_PEAK_MIB" ] || fail "Reference file does not define ZNS_PEAK_MIB"
}

store_zns_reference() {
    local peak_mib="$1"

    {
        printf 'ZNS_PEAK_MIB=%q\n' "$peak_mib"
        printf 'CALIBRATION_RESULT=%q\n' "$OUT_DIR"
        printf 'CALIBRATION_TIMESTAMP=%q\n' "$(date --iso-8601=seconds)"
    } > "$RESULTS_ROOT/zns-reference.env"
}

main() {
    local timestamp
    local capacity
    local zoned
    local fio_file
    local peak_mib

    [ "${EUID}" -eq 0 ] || fail "Run this script with sudo"
    mode_parameters
    require_cmd fio
    require_cmd python3
    require_cmd blockdev
    require_cmd blkdiscard
    require_cmd nvme
    [ -b "$DEVICE" ] || fail "Device does not exist: $DEVICE"
    if [ "$MODE" = "zns" ]; then
        require_cmd blkzone
    fi

    zoned="$(device_zoned_model)"
    [ "$zoned" = "$EXPECTED_ZONED" ] ||
        fail "Mode $MODE requires zoned=$EXPECTED_ZONED; device reports $zoned"
    capacity="$(blockdev --getsize64 "$DEVICE")"
    [ "$capacity" -ge "$WORKING_SET_BYTES" ] ||
        fail "Working set is larger than device capacity"
    [ "$((WORKING_SET_BYTES % ZONE_SIZE_BYTES))" -eq 0 ] ||
        fail "Working set must be zone aligned"

    if [ "$MODE" = "zns" ]; then
        local block_name="$(basename "$DEVICE")"
        local reported_zone_bytes
        reported_zone_bytes="$(( $(cat "/sys/class/block/${block_name}/queue/chunk_sectors") * 512 ))"
        [ "$reported_zone_bytes" -eq "$ZONE_SIZE_BYTES" ] ||
            fail "Expected ${ZONE_SIZE_BYTES}-byte zones, got $reported_zone_bytes"
        [ "$(cat "/sys/class/block/${block_name}/queue/nr_zones")" -eq 256 ] ||
            fail "Expected 256 ZNS zones"
    fi

    RESULTS_ROOT="${RESULTS_ROOT:-$(invoking_user_home)/atc21-zns-validation-results}"
    mkdir -p "$RESULTS_ROOT"
    if [ "$CALIBRATION_ONLY" != "1" ]; then
        read_reference_peak
    fi
    timestamp="$(date +%Y%m%d-%H%M%S)"
    OUT_DIR="$RESULTS_ROOT/${MODE}-${timestamp}"
    mkdir -p "$OUT_DIR"
    exec > >(tee -a "$OUT_DIR/run.log") 2>&1

    echo "[atc21-validation] Mode: $MODE"
    echo "[atc21-validation] Device: $DEVICE"
    echo "[atc21-validation] Results: $OUT_DIR"
    echo "[atc21-validation] Calibration only: $CALIBRATION_ONLY"
    if [ "$CALIBRATION_ONLY" != "1" ]; then
        echo "[atc21-validation] Normalized to ZNS peak: $ZNS_PEAK_MIB MiB/s"
    fi

    confirm_destructive_run
    capture_metadata before
    reset_working_set
    write_parameters
    fio_file="$OUT_DIR/validation.fio"
    write_fio_file "$fio_file"
    fio --output-format=json --output="$OUT_DIR/fio-validation.json" "$fio_file"
    capture_metadata after

    peak_mib="$(python3 "$SCRIPT_DIR/summarize.py" peak "$OUT_DIR/fio-validation.json")"
    echo "[atc21-validation] Peak write throughput: $peak_mib MiB/s"
    if [ "$CALIBRATION_ONLY" = "1" ]; then
        store_zns_reference "$peak_mib"
        echo "[atc21-validation] Wrote $RESULTS_ROOT/zns-reference.env"
    else
        python3 "$SCRIPT_DIR/summarize.py" summarize "$OUT_DIR" "$MODE"
    fi

    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$OUT_DIR"
    fi
    echo "[atc21-validation] Complete: $OUT_DIR"
}

main
