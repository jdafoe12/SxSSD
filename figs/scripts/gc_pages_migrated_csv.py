#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

"""Generate a focused GC pages migrated CSV for FEMU vs SxSSD."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
FIGS_DIR = SCRIPT_DIR.parent
CSV_DIR = FIGS_DIR / "csv"
SEM_EQ_SCRIPT = SCRIPT_DIR / "semantic_equivalence_csv.py"
DEFAULT_OUTPUT = CSV_DIR / "gc_pages_migrated.csv"


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
            "Create a 3-row CSV for GC pages migrated: baseline FEMU, SxSSD, "
            "and percent difference."
        )
    )
    parser.add_argument("--femu-results", type=Path, default=sem.DEFAULT_FEMU_RESULTS)
    parser.add_argument("--femuex-results", type=Path, default=sem.DEFAULT_FEMUEX_RESULTS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--duplicate-policy",
        choices=["latest", "earliest", "error"],
        default="latest",
        help="How to handle duplicate completed runs for the same workload.",
    )
    parser.add_argument("--precision", type=int, default=3, help="Decimal places for percent difference.")
    return parser.parse_args()


def main() -> int:
    sem = load_semantic_module()
    args = parse_args()

    femu_runs = sem.load_runs(args.femu_results, args.duplicate_policy)
    femuex_runs = sem.load_runs(args.femuex_results, args.duplicate_policy)
    workloads = sem.matched_workloads(femu_runs, femuex_runs)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["GC Pages Migrated", *[sem.workload_id(unit) for unit in workloads]])

        baseline = [
            int(sem.semantic_value(femu_runs[unit], "gc_pages_migrated", "femu", sem.FEMU_BLOCKS_PER_LINE))
            for unit in workloads
        ]
        sxssd = [
            int(
                sem.semantic_value(
                    femuex_runs[unit], "gc_pages_migrated", "femuex", sem.FEMU_BLOCKS_PER_LINE
                )
            )
            for unit in workloads
        ]
        pct = [
            sem.format_percent(
                sem.percent_diff(float(base), float(ex), "symmetric"),
                args.precision,
            )
            for base, ex in zip(baseline, sxssd)
        ]

        writer.writerow(["Baseline", *baseline])
        writer.writerow(["SxSSD", *sxssd])
        writer.writerow(["Percent difference", *pct])

    print(f"wrote {args.output}")
    print(f"workloads={len(workloads)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
