#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUESTED_PLACEMENT_GROUPS="${PLACEMENT_GROUPS:-${1:-4}}"
# shellcheck source=benchmark-common.sh
source "$SCRIPT_DIR/benchmark-common.sh"

PLACEMENT_GROUPS="$REQUESTED_PLACEMENT_GROUPS"
case "$PLACEMENT_GROUPS" in
1|2|4) ;;
*) fail "placement stream count must be 1, 2, or 4" ;;
esac
POLICY_VARIANT="block-streams-${PLACEMENT_GROUPS}"
POLICY_REGION_BYTES="${POLICY_REGION_BYTES:-67108864}"

[ "$ZONE_SIZE_BYTES" -eq "$POLICY_REGION_BYTES" ] ||
    fail "ZONE_SIZE_BYTES must equal the policy region size $POLICY_REGION_BYTES"

initialize_run "$POLICY_VARIANT"
[ "$(device_zoned_model)" = "none" ] ||
    fail "Activate the block stream-placement policy before this run"
validate_parameters block
write_parameters block
confirm_destructive_run
capture_metadata before
run_benchmark block
capture_metadata after
finish_run
