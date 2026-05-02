#!/usr/bin/env python3
"""Generate peak random read/write throughput CSV for FEMU vs SxSSD."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
FIGS_DIR = SCRIPT_DIR.parent
CSV_DIR = FIGS_DIR / "csv"
DEFAULT_FEMU_RESULTS = Path(
    "FEMU/hw/femu/bbssd/workload-eval/workload_sets/results"
)
DEFAULT_FEMUEX_RESULTS = Path(
    "FEMU-SxSSD/hw/femu/bbssd/workload-eval/workload_sets/results"
)
DEFAULT_OUTPUT = CSV_DIR / "peak_rand_throughput_mib_s.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create CSV for peak random read/write throughput bars."
    )
    parser.add_argument("--femu-results", type=Path, default=DEFAULT_FEMU_RESULTS)
    parser.add_argument("--femuex-results", type=Path, default=DEFAULT_FEMUEX_RESULTS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--precision", type=int, default=3)
    return parser.parse_args()


def latest_json(results_dir: Path, system_prefix: str, op: str) -> Path:
    pattern = f"{system_prefix}_max_{op}_*.json"
    paths = sorted((results_dir / "max_io" / "json").glob(pattern))
    if not paths:
        raise FileNotFoundError(f"no files matched {pattern} under {results_dir / 'max_io' / 'json'}")
    return paths[-1]


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def throughput_mib_s(fio_json: dict, op: str) -> float:
    section = fio_json["jobs"][0][op]
    if section.get("bw_bytes") is not None:
        return float(section["bw_bytes"]) / (1024.0 * 1024.0)
    return float(section.get("bw", 0.0)) / 1024.0


def percent_diff(baseline: float, sxssd: float) -> float:
    denom = (abs(baseline) + abs(sxssd)) / 2.0
    if denom == 0.0:
        return 0.0
    return (sxssd - baseline) / denom * 100.0


def main() -> int:
    args = parse_args()
    rows = []

    for op in ("read", "write"):
        femu_path = latest_json(args.femu_results, "FEMU", op)
        sxssd_path = latest_json(args.femuex_results, "SxSSD", op)
        femu_value = throughput_mib_s(load_json(femu_path), op)
        sxssd_value = throughput_mib_s(load_json(sxssd_path), op)
        rows.append(
            [
                "Random read" if op == "read" else "Random write",
                f"{femu_value:.{args.precision}f}",
                f"{sxssd_value:.{args.precision}f}",
                f"{percent_diff(femu_value, sxssd_value):.{args.precision}f}",
            ]
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Workload",
                "Baseline (MiB/s)",
                "SxSSD (MiB/s)",
                "Percent difference",
            ]
        )
        writer.writerows(rows)

    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
