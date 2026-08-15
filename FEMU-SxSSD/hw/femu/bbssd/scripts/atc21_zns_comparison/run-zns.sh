#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=benchmark-common.sh
source "$SCRIPT_DIR/benchmark-common.sh"

POLICY_VARIANT="zns"
PLACEMENT_GROUPS="host-managed-zones"

initialize_run "$POLICY_VARIANT"
require_cmd blkzone
[ "$(device_zoned_model)" != "none" ] ||
    fail "Activate the ZNS policy before this run"

logical_block_bytes="$(blockdev --getss "$DEVICE")"
chunk_sectors="$(cat "/sys/class/block/$(basename "$DEVICE")/queue/chunk_sectors")"
reported_zone_size="$((chunk_sectors * logical_block_bytes))"
if [ -n "${ZONE_SIZE_BYTES_OVERRIDE:-}" ]; then
    ZONE_SIZE_BYTES="$ZONE_SIZE_BYTES_OVERRIDE"
else
    ZONE_SIZE_BYTES="$reported_zone_size"
fi
[ "$ZONE_SIZE_BYTES" -eq "$reported_zone_size" ] ||
    fail "ZONE_SIZE_BYTES=$ZONE_SIZE_BYTES does not match the device zone size $reported_zone_size"

validate_parameters zns
write_parameters zns
confirm_destructive_run
capture_metadata before
run_benchmark zns
capture_metadata after
finish_run
