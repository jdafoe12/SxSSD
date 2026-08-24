#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later

# Source this file from your shell before following REVIEWER_EVALUATION.md.
# Example:
#   cd /path/to/SxSSD
#   source ./reviewer_env.sh

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Source this script instead of executing it:"
    echo "  source ./reviewer_env.sh"
    exit 1
fi

# Set this to the root of the unpacked artifact.
if [[ -z "${ARTIFACT_ROOT:-}" ]]; then
    export ARTIFACT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

# VM image location used by run-blackbox.sh.
export FEMU_IMAGE_DIR="${FEMU_IMAGE_DIR:-$HOME/images}"
export FEMU_OS_IMAGE="${FEMU_OS_IMAGE:-$FEMU_IMAGE_DIR/u20s.qcow2}"

# Host-side result directories.
export BASELINE_RESULTS="${BASELINE_RESULTS:-$ARTIFACT_ROOT/FEMU/hw/femu/bbssd/workload-eval/workload_sets/results}"
export SXSSD_RESULTS="${SXSSD_RESULTS:-$ARTIFACT_ROOT/FEMU-SxSSD/hw/femu/bbssd/workload-eval/workload_sets/results}"

# Optional outputs used by specific evaluation steps.
export SXSSD_META_TIMING_DIR="${SXSSD_META_TIMING_DIR:-$SXSSD_RESULTS/meta_interface_timing}"
export FEMU_META_DEVICE_TIMING_CSV="${FEMU_META_DEVICE_TIMING_CSV:-$SXSSD_META_TIMING_DIR/device_timing.csv}"
export FLASHGUARD_RESULTS="${FLASHGUARD_RESULTS:-/path/to/flashguard/results}"

mkdir -p "$BASELINE_RESULTS" "$SXSSD_RESULTS" "$SXSSD_META_TIMING_DIR"

echo "Reviewer environment loaded."
echo "ARTIFACT_ROOT=$ARTIFACT_ROOT"
echo "FEMU_IMAGE_DIR=$FEMU_IMAGE_DIR"
echo "FEMU_OS_IMAGE=$FEMU_OS_IMAGE"
echo "BASELINE_RESULTS=$BASELINE_RESULTS"
echo "SXSSD_RESULTS=$SXSSD_RESULTS"
echo "SXSSD_META_TIMING_DIR=$SXSSD_META_TIMING_DIR"
