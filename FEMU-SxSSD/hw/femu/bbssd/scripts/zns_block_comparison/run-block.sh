#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=benchmark-common.sh
source "$SCRIPT_DIR/benchmark-common.sh"

initialize_run block
assert_device_capacity

zoned_model="$(device_zoned_model)"
[ "$zoned_model" = "none" ] ||
    fail "$DEVICE reports zoned=$zoned_model; activate the block-interface policy first"

write_parameters block
confirm_destructive_run
capture_metadata before

# This measurement also fills the working set before the overwrite workload.
sequential_arguments block-sequential
run_fio sequential "${SEQUENTIAL_ARGS[@]}"
capture_metadata after-sequential

steady_common_arguments block-steady
run_fio steady "${STEADY_ARGS[@]}"
capture_metadata after-steady
finish_run
