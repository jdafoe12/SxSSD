#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

"""Generate semantic-equivalence percent-difference CSV for FEMU vs SxSSD.

The output table is intended for the paper: rows are internal behavior metrics,
columns are matched workloads, and entries are percent differences.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[2]
FIGS_DIR = REPO_ROOT / "figs"
CSV_DIR = FIGS_DIR / "csv"

DEFAULT_FEMU_RESULTS = (
    REPO_ROOT / "FEMU/hw/femu/bbssd/workload-eval/workload_sets/results"
)
DEFAULT_FEMUEX_RESULTS = (
    REPO_ROOT / "FEMU-SxSSD/hw/femu/bbssd/workload-eval/workload_sets/results"
)
DEFAULT_OUTPUT = CSV_DIR / "semantic_equivalence_percent_diff.csv"

WORKLOAD_ORDER = [
    "systor_11",
    "systor_06",
    "systor_05",
    "msr_prxy_0",
    "msr_prn_0",
    "msr_mds_0",
    "fiu_web_02",
    "fiu_mail_03",
    "fiu_homes_02",
    "alibaba_08",
    "alibaba_01",
]

WORKLOAD_IDS = {
    "systor_11": "S11",
    "systor_06": "S6",
    "systor_05": "S5",
    "msr_prxy_0": "M-prxy",
    "msr_prn_0": "M-prn",
    "msr_mds_0": "M-mds",
    "fiu_web_02": "F-web2",
    "fiu_mail_03": "F-mail3",
    "fiu_homes_02": "F-homes2",
    "alibaba_08": "A8",
    "alibaba_01": "A1",
}

FEMU_BLOCKS_PER_LINE = 64

# These rows compare semantic quantities, not necessarily raw counter names.
#
# Accounting differences observed in the current implementations:
# - FEMU phys_page_programs includes host page programs and GC migration writes.
#   SxSSD phys_page_programs counts host page programs, while GC migration
#   writes are represented by gc_pages_migrated in the migration path.
# - FEMU block_erases increments once for each physical block in a line.
#   SxSSD block_erases increments once for the erased eSWD/victim.
METRICS = [
    ("Physical page writes", "phys_page_writes"),
    ("GC invocations", "gc_invocations"),
    ("GC pages migrated", "gc_pages_migrated"),
    ("Block erases", "erase_units"),
]


@dataclass(frozen=True)
class Run:
    unit: str
    timestamp: str
    meta_path: Path
    stats_path: Path
    stats: Dict[str, int]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a CSV where each cell is the percent difference between "
            "FEMU and SxSSD for a semantic-equivalence metric."
        )
    )
    parser.add_argument("--femu-results", type=Path, default=DEFAULT_FEMU_RESULTS)
    parser.add_argument("--femuex-results", type=Path, default=DEFAULT_FEMUEX_RESULTS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--formula",
        choices=["symmetric", "femu-baseline"],
        default="symmetric",
        help=(
            "Signed percent-difference formula. symmetric = (ex-femu) / mean(femu,ex). "
            "femu-baseline = (ex-femu) / femu."
        ),
    )
    parser.add_argument(
        "--duplicate-policy",
        choices=["latest", "earliest", "error"],
        default="latest",
        help=(
            "How to handle multiple completed runs for the same workload in one tree. "
            "The current FEMU data has duplicate alibaba_08 runs."
        ),
    )
    parser.add_argument(
        "--precision",
        type=int,
        default=3,
        help="Decimal places to write for percent differences.",
    )
    parser.add_argument(
        "--cell-format",
        choices=["percent", "percent-absolute"],
        default="percent",
        help=(
            "CSV cell format. percent writes only the percent difference. "
            "percent-absolute writes '<pct>%% (FEMU=<v>, SxSSD=<v>, delta=<v>)'."
        ),
    )
    parser.add_argument(
        "--femu-blocks-per-line",
        type=float,
        default=FEMU_BLOCKS_PER_LINE,
        help=(
            "Number of physical blocks erased per FEMU line erase. Used to normalize "
            "FEMU raw block_erases to the SxSSD eSWD erase unit."
        ),
    )
    return parser.parse_args()


def load_runs(results_dir: Path, duplicate_policy: str) -> Dict[str, Run]:
    meta_dir = results_dir / "meta"
    stats_dir = results_dir / "stats"
    runs_by_unit: Dict[str, List[Run]] = {}

    if not meta_dir.is_dir():
        raise FileNotFoundError(f"missing meta directory: {meta_dir}")
    if not stats_dir.is_dir():
        raise FileNotFoundError(f"missing stats directory: {stats_dir}")

    for meta_path in sorted(meta_dir.glob("*.json")):
        with meta_path.open("r", encoding="utf-8") as f:
            meta = json.load(f)

        if meta.get("phase") != "normal_long":
            continue

        unit = meta["unit"]
        stats_file = meta["femu_stats_file"]
        stats_path = stats_dir / stats_file
        if not stats_path.exists():
            raise FileNotFoundError(f"missing stats file for {meta_path}: {stats_path}")

        with stats_path.open("r", encoding="utf-8") as f:
            stats = json.load(f)

        run = Run(
            unit=unit,
            timestamp=meta["timestamp"],
            meta_path=meta_path,
            stats_path=stats_path,
            stats=stats,
        )
        runs_by_unit.setdefault(unit, []).append(run)

    selected: Dict[str, Run] = {}
    for unit, runs in runs_by_unit.items():
        if len(runs) > 1:
            if duplicate_policy == "error":
                paths = ", ".join(str(run.meta_path) for run in runs)
                raise ValueError(f"duplicate completed runs for {unit}: {paths}")
            runs = sorted(runs, key=lambda run: run.timestamp)
            chosen = runs[-1] if duplicate_policy == "latest" else runs[0]
            print(
                f"warning: {results_dir} has {len(runs)} runs for {unit}; "
                f"using {duplicate_policy} timestamp {chosen.timestamp}",
                file=sys.stderr,
            )
        else:
            chosen = runs[0]
        selected[unit] = chosen

    return selected


def percent_diff(femu: float, femuex: float, formula: str) -> float:
    if femu == 0 and femuex == 0:
        return 0.0

    if formula == "symmetric":
        denom = (abs(femu) + abs(femuex)) / 2.0
    elif formula == "femu-baseline":
        denom = abs(femu)
    else:
        raise ValueError(f"unknown formula: {formula}")

    if denom == 0:
        return math.copysign(math.inf, femuex - femu)
    return (femuex - femu) / denom * 100.0


def semantic_value(run: Run, metric: str, side: str, femu_blocks_per_line: float) -> float:
    stats = run.stats

    if metric == "phys_page_writes":
        value = float(stats["phys_page_programs"])
        if side == "femuex":
            value += float(stats["gc_pages_migrated"])
        return value

    if metric == "gc_invocations":
        return float(stats["gc_invocations"])

    if metric == "gc_pages_migrated":
        return float(stats["gc_pages_migrated"])

    if metric == "erase_units":
        value = float(stats["block_erases"])
        if side == "femu":
            value /= femu_blocks_per_line
        return value

    raise ValueError(f"unknown metric: {metric}")


def format_percent(value: float, precision: int) -> str:
    if math.isinf(value):
        return "inf"
    return f"{value:.{precision}f}"


def format_value(value: float) -> str:
    if math.isinf(value):
        return "inf"
    if value.is_integer():
        return str(int(value))
    return f"{value:.3f}"


def format_cell(
    percent: float,
    femu_value: float,
    femuex_value: float,
    precision: int,
    cell_format: str,
) -> str:
    percent_text = format_percent(percent, precision)
    if cell_format == "percent":
        return percent_text
    delta = femuex_value - femu_value
    return (
        f"{percent_text}% "
        f"(FEMU={format_value(femu_value)}, "
        f"SxSSD={format_value(femuex_value)}, "
        f"delta={format_value(delta)})"
    )


def matched_workloads(femu_runs: Dict[str, Run], femuex_runs: Dict[str, Run]) -> List[str]:
    common = set(femu_runs) & set(femuex_runs)
    ordered = [unit for unit in WORKLOAD_ORDER if unit in common]
    extras = sorted(common - set(ordered))
    return ordered + extras


def workload_id(unit: str) -> str:
    return WORKLOAD_IDS.get(unit, unit)


def write_csv(
    output: Path,
    workloads: Iterable[str],
    femu_runs: Dict[str, Run],
    femuex_runs: Dict[str, Run],
    formula: str,
    precision: int,
    femu_blocks_per_line: float,
    cell_format: str,
) -> None:
    workloads = list(workloads)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Internal Behavior", *[workload_id(unit) for unit in workloads]])
        for label, field in METRICS:
            row = [label]
            for unit in workloads:
                femu_value = semantic_value(
                    femu_runs[unit], field, "femu", femu_blocks_per_line
                )
                femuex_value = semantic_value(
                    femuex_runs[unit], field, "femuex", femu_blocks_per_line
                )
                pct = percent_diff(femu_value, femuex_value, formula)
                row.append(format_cell(pct, femu_value, femuex_value, precision, cell_format))
            writer.writerow(row)


def main() -> int:
    args = parse_args()

    femu_runs = load_runs(args.femu_results, args.duplicate_policy)
    femuex_runs = load_runs(args.femuex_results, args.duplicate_policy)
    workloads = matched_workloads(femu_runs, femuex_runs)

    missing_femu = sorted(set(femuex_runs) - set(femu_runs))
    missing_femuex = sorted(set(femu_runs) - set(femuex_runs))
    if missing_femu:
        print(f"warning: workloads missing from FEMU: {', '.join(missing_femu)}", file=sys.stderr)
    if missing_femuex:
        print(
            f"warning: workloads missing from SxSSD: {', '.join(missing_femuex)}",
            file=sys.stderr,
        )

    write_csv(
        args.output,
        workloads,
        femu_runs,
        femuex_runs,
        args.formula,
        args.precision,
        args.femu_blocks_per_line,
        args.cell_format,
    )
    print(f"wrote {args.output}")
    print(f"formula={args.formula}; cell_format={args.cell_format}; workloads={len(workloads)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
