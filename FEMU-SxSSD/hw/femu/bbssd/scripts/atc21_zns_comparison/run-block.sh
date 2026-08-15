#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=benchmark-common.sh
source "$SCRIPT_DIR/benchmark-common.sh"

POLICY_VARIANT="block-baseline"
PLACEMENT_GROUPS=1

initialize_run "$POLICY_VARIANT"
[ "$(device_zoned_model)" = "none" ] ||
    fail "Activate the block-interface policy before this run"
validate_parameters block
write_parameters block
confirm_destructive_run
capture_metadata before
run_benchmark block
capture_metadata after
finish_run
