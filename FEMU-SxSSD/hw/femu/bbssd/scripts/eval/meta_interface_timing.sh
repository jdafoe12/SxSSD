#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
POLICY_DIR="$(cd "$SCRIPTS_DIR/../policy" && pwd)"

DEVICE="${1:-/dev/nvme0}"
POLICY_PATH="${2:-$POLICY_DIR/block-interface-policy.so}"
RUNS="${3:-10}"
BASE_POLICY_ID="${4:-100}"
SESSION_MODES="${SESSION_MODES:-normal confidential}"
ATTESTATION_ORDER="${ATTESTATION_ORDER:-alternate}"
COMMAND_PAUSE_SECS="${COMMAND_PAUSE_SECS:-0}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/results/meta-interface-$(date +%Y%m%d-%H%M%S)}"

POLICYCTL="$SCRIPTS_DIR/policyctl"
HOST_CSV="$OUT_DIR/policyctl_timing.csv"

log() {
    echo "[meta-timing] $*"
}

fail() {
    echo "[meta-timing] ERROR: $*" >&2
    exit 1
}

run_step() {
    "$@"
    if [ "$COMMAND_PAUSE_SECS" != "0" ]; then
        sleep "$COMMAND_PAUSE_SECS"
    fi
}

attestation_order_for_run() {
    local run="$1"

    case "$ATTESTATION_ORDER" in
        security-first)
            printf '%s\n' 'security consistency'
            ;;
        consistency-first)
            printf '%s\n' 'consistency security'
            ;;
        random)
            if (( RANDOM % 2 )); then
                printf '%s\n' 'security consistency'
            else
                printf '%s\n' 'consistency security'
            fi
            ;;
        alternate|*)
            if (( run % 2 )); then
                printf '%s\n' 'security consistency'
            else
                printf '%s\n' 'consistency security'
            fi
            ;;
    esac
}

if [ ! -f "$POLICY_PATH" ]; then
    fail "Missing policy image: $POLICY_PATH"
fi

mkdir -p "$OUT_DIR"
rm -f "$HOST_CSV"

log "Building policyctl and policy image..."
make -C "$POLICY_DIR" tool
make -C "$SCRIPTS_DIR" tool

if [ ! -x "$POLICYCTL" ]; then
    fail "Missing policyctl binary after build: $POLICYCTL"
fi

policy_size_bytes="$(stat -c '%s' "$POLICY_PATH")"
policy_size_pages="$(( (policy_size_bytes + 4095) / 4096 ))"

cat > "$OUT_DIR/run_config.txt" <<EOF
device=$DEVICE
policy_path=$POLICY_PATH
policy_size_bytes=$policy_size_bytes
policy_size_pages=$policy_size_pages
runs=$RUNS
base_policy_id=$BASE_POLICY_ID
session_modes=$SESSION_MODES
attestation_order=$ATTESTATION_ORDER
command_pause_secs=$COMMAND_PAUSE_SECS
host_timing_csv_prefix=$HOST_CSV
device_timing_csv_env=FEMU_META_DEVICE_TIMING_CSV
EOF

log "Policy size: ${policy_size_bytes} bytes (${policy_size_pages} pages)"
log "Host timing CSV: $HOST_CSV"
log "Device timing CSV: set FEMU_META_DEVICE_TIMING_CSV in the QEMU environment before launch"

for mode in $SESSION_MODES; do
    mode_csv="$OUT_DIR/policyctl_timing_${mode}.csv"
    rm -f "$mode_csv"
    export FEMU_META_POLICYCTL_TIMING_CSV="$mode_csv"

    log "Timing session mode: $mode"
    for run in $(seq 1 "$RUNS"); do
        policy_id="$((BASE_POLICY_ID + run))"
        install_version="$run"
        update_version="$((run + 1000))"
        attestation_order="$(attestation_order_for_run "$run")"
        first_attestation="$(printf '%s\n' "$attestation_order" | awk '{print $1}')"
        second_attestation="$(printf '%s\n' "$attestation_order" | awk '{print $2}')"

        log "Run $run/$RUNS policy_id=$policy_id mode=$mode attestation_order=$attestation_order"

        run_step "$POLICYCTL" --mode "$mode" session "$DEVICE"
        run_step "$POLICYCTL" install "$DEVICE" "$POLICY_PATH" "$policy_id" "$install_version"
        run_step "$POLICYCTL" activate "$DEVICE" "$policy_id"
        run_step "$POLICYCTL" attest "$DEVICE" "$policy_id" "$first_attestation"
        run_step "$POLICYCTL" attest "$DEVICE" "$policy_id" "$second_attestation"
        run_step "$POLICYCTL" deactivate "$DEVICE" "$policy_id"
        run_step "$POLICYCTL" update "$DEVICE" "$POLICY_PATH" "$policy_id" "$update_version"
        run_step "$POLICYCTL" activate "$DEVICE" "$policy_id"
        run_step "$POLICYCTL" deactivate "$DEVICE" "$policy_id"
        run_step "$POLICYCTL" remove "$DEVICE" "$policy_id"
    done
done

log "Completed $RUNS runs"
