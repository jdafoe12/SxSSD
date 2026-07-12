#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


def count_backwards(values: Sequence[int]) -> int:
    drops = 0
    prev = None
    for value in values:
        if prev is not None and value < prev:
            drops += 1
        prev = value
    return drops


def sort_csv_rows(rows: List[List[str]]) -> List[List[str]]:
    indexed = list(enumerate(rows))
    indexed.sort(key=lambda item: (int(item[1][0]), item[0]))
    return [row for _, row in indexed]


def sort_iolog_rows(rows: List[str]) -> List[str]:
    indexed = list(enumerate(rows))
    indexed.sort(key=lambda item: (int(item[1].split(" ", 1)[0]), item[0]))
    return [row for _, row in indexed]


def load_csv_rows(path: Path) -> Tuple[List[str], List[List[str]]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)
    return header, rows


def write_csv_rows(path: Path, header: List[str], rows: List[List[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def build_iolog_lines(
    rows: Sequence[List[str]],
    *,
    cap_us: Optional[int] = None,
    scale_entry: Optional[Dict[str, object]] = None,
) -> List[str]:
    if not rows:
        return ["fio version 3 iolog", "0 /TRACE_TARGET add", "0 /TRACE_TARGET open"]

    first_ts = int(rows[0][0])
    prev_ts = first_ts
    replay_ts = 0

    lines = ["fio version 3 iolog", "0 /TRACE_TARGET add", "0 /TRACE_TARGET open"]
    for index, row in enumerate(rows):
        raw_ts = int(row[0])
        if index == 0:
            replay_ts = 0
        else:
            delta = raw_ts - prev_ts
            if cap_us is not None and delta > cap_us:
                delta = cap_us
            replay_ts += delta
        prev_ts = raw_ts

        offset = int(row[1])
        if scale_entry is not None:
            offset = scale_offset(offset, scale_entry)
        size = int(row[2])
        op = "read" if row[3] == "r" else "write"
        lines.append(f"{replay_ts} /TRACE_TARGET {op} {offset} {size}")
    return lines


def scale_offset(offset: int, scale_entry: Dict[str, object]) -> int:
    origin = int(scale_entry["origin"])
    align = int(scale_entry["align_bytes"])
    if bool(scale_entry.get("shift_only")):
        scaled = offset - origin
    else:
        scale = float(scale_entry["scale"])
        scaled = int(((offset - origin) * scale) // align) * align
    return max(0, scaled)


def load_scale_params(path: Path) -> Dict[str, Dict[str, object]]:
    return json.loads(path.read_text(encoding="utf-8"))


def repair_csv(path: Path, dry_run: bool) -> Tuple[bool, int, int, List[List[str]]]:
    header, rows = load_csv_rows(path)
    timestamps = [int(row[0]) for row in rows]
    before = count_backwards(timestamps)
    if before == 0:
        return False, 0, 0, rows

    sorted_rows = sort_csv_rows(rows)
    after = count_backwards([int(row[0]) for row in sorted_rows])

    if not dry_run:
        write_csv_rows(path, header, sorted_rows)

    return True, before, after, sorted_rows


def iolog_stats(path: Path) -> Tuple[int, int]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 4:
        return 0, 0
    body = lines[3:]
    timestamps = [int(line.split(" ", 1)[0]) for line in body]
    backwards = count_backwards(timestamps)
    negatives = sum(1 for ts in timestamps if ts < 0)
    return backwards, negatives


def maybe_write_iolog(path: Path, lines: List[str], dry_run: bool) -> None:
    if dry_run:
        return
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def iter_systor_csvs(root: Path) -> Iterable[Path]:
    selected_tiers = ACTIVE_TIERS
    for tier_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        if selected_tiers and tier_dir.name not in selected_tiers:
            continue
        source_dir = tier_dir / "source"
        if not source_dir.is_dir():
            continue
        for path in sorted(source_dir.glob("systor*.csv")):
            if not path.exists():
                continue
            yield path


def iter_systor_iologs(root: Path) -> Iterable[Path]:
    selected_tiers = ACTIVE_TIERS
    for tier_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        if selected_tiers and tier_dir.name not in selected_tiers:
            continue
        for iolog_dir in sorted(tier_dir.glob("fio_iolog*")):
            if not iolog_dir.is_dir():
                continue
            for path in sorted(iolog_dir.glob("systor*.iolog")):
                yield path


ACTIVE_TIERS: Optional[set[str]] = None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Repair unsorted SYSTOR trace timestamps in CSV and fio iolog files."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="workload_sets root",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report files that would be rewritten without changing them.",
    )
    parser.add_argument(
        "--tier",
        action="append",
        default=[],
        help="Limit the repair to one or more workload-set subdirectories.",
    )
    args = parser.parse_args()

    global ACTIVE_TIERS
    ACTIVE_TIERS = set(args.tier) if args.tier else None

    csv_fixed = 0
    iolog_fixed = 0

    sorted_rows_by_stem: Dict[str, List[List[str]]] = {}
    for path in iter_systor_csvs(args.root):
        changed, before, after, sorted_rows = repair_csv(path, args.dry_run)
        sorted_rows_by_stem[path.stem] = sorted_rows
        if changed:
            csv_fixed += 1
            print(f"csv {path}: backwards {before} -> {after}")

    for path in iter_systor_iologs(args.root):
        stem = path.stem
        rows = sorted_rows_by_stem.get(stem)
        if rows is None:
            _, rows = load_csv_rows(path.parents[1] / "source" / f"{stem}.csv")
            rows = sort_csv_rows(rows)

        scale_entry = None
        scale_path = path.parent / "scale_params.json"
        if scale_path.exists():
            scale_params = load_scale_params(scale_path)
            unit = stem.split("__", 1)[0]
            scale_entry = scale_params.get(unit)

        cap_us = None
        dir_name = path.parent.name
        if "cap_10ms" in dir_name:
            cap_us = 10_000
        elif "cap_50ms" in dir_name:
            cap_us = 50_000

        before_backwards, before_negatives = iolog_stats(path)
        new_lines = build_iolog_lines(rows, cap_us=cap_us, scale_entry=scale_entry)
        after_timestamps = [int(line.split(" ", 1)[0]) for line in new_lines[3:]]
        after_backwards = count_backwards(after_timestamps)
        after_negatives = sum(1 for ts in after_timestamps if ts < 0)

        if before_backwards or before_negatives:
            iolog_fixed += 1
            print(
                f"iolog {path}: backwards {before_backwards} -> {after_backwards}, "
                f"negatives {before_negatives} -> {after_negatives}"
            )
        maybe_write_iolog(path, new_lines, args.dry_run)

    print(
        f"done: fixed {csv_fixed} csv files and {iolog_fixed} iolog files"
        + (" (dry-run)" if args.dry_run else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
