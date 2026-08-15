#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=benchmark-common.sh
source "$SCRIPT_DIR/benchmark-common.sh"

initialize_run zns
require_cmd blkzone
assert_device_capacity

zoned_model="$(device_zoned_model)"
[ "$zoned_model" != "none" ] ||
    fail "$DEVICE is not zoned; activate the ZNS policy first"

block_name="$(basename "$DEVICE")"
logical_block_bytes="$(blockdev --getss "$DEVICE")"
chunk_sectors="$(cat "/sys/class/block/${block_name}/queue/chunk_sectors")"
zone_size_bytes="$((chunk_sectors * logical_block_bytes))"
[ "$zone_size_bytes" -gt 0 ] || fail "The kernel reported a zero-byte zone size"
[ "$((WORKING_SET_BYTES % zone_size_bytes))" -eq 0 ] ||
    fail "WORKING_SET_BYTES must be an exact multiple of the $zone_size_bytes-byte zone size"

case "$BS" in
    4k|4K|4096) block_size_bytes=4096 ;;
    *) fail "Automatic zone reset calculation currently requires BS=4k or BS=4096" ;;
esac

zone_reset_frequency="${ZONE_RESET_FREQUENCY:-$(awk -v bs="$block_size_bytes" -v zone="$zone_size_bytes" 'BEGIN { printf "%.12f", bs / zone }')}"

write_parameters zns "$zone_size_bytes"
{
    printf 'ZONE_RESET_FREQUENCY=%q\n' "$zone_reset_frequency"
} >> "$OUT_DIR/parameters.env"

confirm_destructive_run
capture_metadata before

echo "[zns-block-benchmark] Resetting every zone before the sequential measurement"
blkzone reset "$DEVICE"

sequential_arguments zns-sequential
SEQUENTIAL_ARGS+=(--zonemode=zbd)
run_fio sequential "${SEQUENTIAL_ARGS[@]}"
capture_metadata after-sequential

# Start the measured experiment empty. ramp_time lets fio establish occupancy
# and begin its reset cycle before it records steady-state statistics.
echo "[zns-block-benchmark] Resetting every zone before the steady-state workload"
blkzone reset "$DEVICE"

steady_common_arguments zns-steady
STEADY_ARGS+=(
    --zonemode=zbd
    --max_open_zones="$MAX_OPEN_ZONES"
    --zone_reset_threshold="$ZONE_RESET_THRESHOLD"
    --zone_reset_frequency="$zone_reset_frequency"
)
run_fio steady "${STEADY_ARGS[@]}"
capture_metadata after-steady
finish_run
