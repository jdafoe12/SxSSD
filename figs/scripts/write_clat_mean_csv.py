#!/usr/bin/env python3
"""Generate mean write completion latency CSV for baseline, SxSSD-Block, and SxSSD-FlashGuard."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
FIGS_DIR = SCRIPT_DIR.parent
CSV_DIR = FIGS_DIR / "csv"
SEM_EQ_SCRIPT = SCRIPT_DIR / "semantic_equivalence_csv.py"
DEFAULT_OUTPUT = CSV_DIR / "write_clat_mean_us.csv"


def load_semantic_module():
    spec = importlib.util.spec_from_file_location("semantic_equivalence_csv", SEM_EQ_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SEM_EQ_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def parse_args() -> argparse.Namespace:
    sem = load_semantic_module()
    parser = argparse.ArgumentParser(
        description=(
            "Create a CSV for grouped bar charts of mean write completion latency "
            "in microseconds for baseline, SxSSD-Block, and SxSSD-FlashGuard."
        )
    )
    parser.add_argument("--femu-results", type=Path, default=sem.DEFAULT_FEMU_RESULTS)
    parser.add_argument(
        "--block-results",
        type=Path,
        required=True,
        help="Results tree for the SxSSD block-interface policy runs.",
    )
    parser.add_argument(
        "--flashguard-results",
        type=Path,
        required=True,
        help="Results tree for the SxSSD-FlashGuard runs.",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--femu-duplicate-policy",
        choices=["latest", "earliest", "error"],
        default="latest",
        help="How to handle duplicate completed baseline runs for the same workload.",
    )
    parser.add_argument(
        "--block-duplicate-policy",
        choices=["latest", "earliest", "error"],
        default="latest",
        help="How to handle duplicate completed SxSSD-Block runs for the same workload.",
    )
    parser.add_argument(
        "--flashguard-duplicate-policy",
        choices=["latest", "earliest", "error"],
        default="latest",
        help="How to handle duplicate completed SxSSD-FlashGuard runs for the same workload.",
    )
    parser.add_argument(
        "--precision",
        type=int,
        default=3,
        help="Decimal places for microsecond latency and percent differences.",
    )
    return parser.parse_args()


def load_fio_jsons(results_dir: Path, duplicate_policy: str):
    meta_dir = results_dir / "meta"
    json_dir = results_dir / "json"
    runs_by_unit = {}

    if not meta_dir.is_dir():
        raise FileNotFoundError(f"missing meta directory: {meta_dir}")
    if not json_dir.is_dir():
        raise FileNotFoundError(f"missing json directory: {json_dir}")

    for meta_path in sorted(meta_dir.glob("*.json")):
        with meta_path.open("r", encoding="utf-8") as f:
            meta = json.load(f)

        if meta.get("phase") != "normal_long":
            continue

        json_path = json_dir / Path(meta["json_path"]).name
        if not json_path.exists():
            raise FileNotFoundError(f"missing fio JSON for {meta_path}: {json_path}")

        with json_path.open("r", encoding="utf-8") as f:
            fio_json = json.load(f)

        runs_by_unit.setdefault(meta["unit"], []).append((meta["timestamp"], fio_json))

    selected = {}
    for unit, runs in runs_by_unit.items():
        if len(runs) > 1:
            if duplicate_policy == "error":
                raise ValueError(f"duplicate completed runs for {unit} in {results_dir}")
            runs = sorted(runs, key=lambda item: item[0])
            chosen = runs[-1] if duplicate_policy == "latest" else runs[0]
            print(
                f"warning: {results_dir} has {len(runs)} runs for {unit}; "
                f"using {duplicate_policy} timestamp {chosen[0]}",
                file=sys.stderr,
            )
        else:
            chosen = runs[0]
        selected[unit] = chosen[1]

    return selected


def write_clat_mean_ns(fio_json) -> float:
    return float(fio_json["jobs"][0]["write"]["clat_ns"]["mean"])


def main() -> int:
    sem = load_semantic_module()
    args = parse_args()

    femu_runs = load_fio_jsons(args.femu_results, args.femu_duplicate_policy)
    block_runs = load_fio_jsons(args.block_results, args.block_duplicate_policy)
    flashguard_runs = load_fio_jsons(args.flashguard_results, args.flashguard_duplicate_policy)
    workloads = sem.matched_workloads(femu_runs, block_runs)
    workloads = sem.matched_workloads({unit: femu_runs[unit] for unit in workloads}, flashguard_runs)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Workload",
                "Baseline (us)",
                "SxSSD-Block (us)",
                "SxSSD-FlashGuard (us)",
                "Block percent difference",
                "FlashGuard percent difference",
            ]
        )
        for unit in workloads:
            baseline_us = write_clat_mean_ns(femu_runs[unit]) / 1000.0
            block_us = write_clat_mean_ns(block_runs[unit]) / 1000.0
            flashguard_us = write_clat_mean_ns(flashguard_runs[unit]) / 1000.0
            block_pct = sem.percent_diff(baseline_us, block_us, "symmetric")
            flashguard_pct = sem.percent_diff(baseline_us, flashguard_us, "symmetric")
            writer.writerow(
                [
                    sem.workload_id(unit),
                    f"{baseline_us:.{args.precision}f}",
                    f"{block_us:.{args.precision}f}",
                    f"{flashguard_us:.{args.precision}f}",
                    f"{block_pct:.{args.precision}f}",
                    f"{flashguard_pct:.{args.precision}f}",
                ]
            )

    print(f"wrote {args.output}")
    print(f"workloads={len(workloads)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
