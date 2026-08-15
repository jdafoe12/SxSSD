#!/bin/bash

set -euo pipefail

RESULTS_ROOT="${1:-${RESULTS_ROOT:-$HOME/fio-zns-block-results}}"
SUMMARY_CSV="$RESULTS_ROOT/comparison-summary.csv"
SUMMARY_TXT="$RESULTS_ROOT/comparison-summary.txt"

fail() {
    echo "[zns-block-summary] ERROR: $*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail "python3 is required"
[ -d "$RESULTS_ROOT" ] || fail "Results directory does not exist: $RESULTS_ROOT"

mapfile -d '' result_files < <(find "$RESULTS_ROOT" -mindepth 2 -maxdepth 2 \
    -type f \( -name sequential.json -o -name steady.json \) -print0 | sort -z)
[ "${#result_files[@]}" -gt 0 ] || fail "No benchmark JSON results found below $RESULTS_ROOT"

echo 'run,phase,bandwidth_MiB_s,iops,mean_clat_ms,p50_clat_ms,p99_clat_ms,p99_9_clat_ms,total_write_GiB' > "$SUMMARY_CSV"

for result_file in "${result_files[@]}"; do
    run_name="$(basename "$(dirname "$result_file")")"
    phase="$(basename "$result_file" .json)"
    python3 - "$run_name" "$phase" "$result_file" >> "$SUMMARY_CSV" <<'PY'
import csv
import json
import sys

run_name, phase, result_file = sys.argv[1:]
with open(result_file, encoding="utf-8") as source:
    write = json.load(source)["jobs"][0]["write"]

percentiles = write.get("clat_ns", {}).get("percentile", {})
row = [
    run_name,
    phase,
    write.get("bw_bytes", 0) / 1048576,
    write.get("iops", 0),
    write.get("clat_ns", {}).get("mean", 0) / 1000000,
    percentiles.get("50.000000", 0) / 1000000,
    percentiles.get("99.000000", 0) / 1000000,
    percentiles.get("99.900000", 0) / 1000000,
    write.get("io_bytes", 0) / 1073741824,
]
csv.writer(sys.stdout).writerow(row)
PY
done

{
    echo "ZNS and block-policy fio results"
    echo "Generated: $(date --iso-8601=seconds)"
    echo
    column -s, -t < "$SUMMARY_CSV" 2>/dev/null || cat "$SUMMARY_CSV"
    echo
    echo "Raw JSON and one-second bandwidth, IOPS, and latency logs remain in each run directory."
} | tee "$SUMMARY_TXT"

echo
echo "[zns-block-summary] CSV: $SUMMARY_CSV"
echo "[zns-block-summary] Text: $SUMMARY_TXT"
