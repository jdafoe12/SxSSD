#!/usr/bin/env python3
"""Build a paper table from the device-side meta timing CSV.

This reads the device timing log emitted by `meta-interface-policy.c` and
produces a compact summary table with one row per logical command.

The parser is robust to:
- leading stray rows before the first full run
- either attestation order (`security -> consistency` or the reverse)
- old CSVs without the newer `report_type` column
"""

from __future__ import annotations

import argparse
import csv
import statistics
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StepSpec:
    label: str
    size_pages: int | None
    command: str
    detail: str
    report_type: str = ""


def step(label: str, size_pages: int | None, command: str, detail: str, report_type: str = "") -> StepSpec:
    return StepSpec(label, size_pages, command, detail, report_type)


def run_patterns(use_report_type: bool) -> tuple[tuple[StepSpec, ...], tuple[StepSpec, ...]]:
    sec = "security" if use_report_type else ""
    con = "consistency" if use_report_type else ""

    common_prefix = (
        step("INIT_SESSION", None, "session", "submit"),
        step("INIT_SESSION", None, "session", "fetch"),
        step("INSTALL_POLICY", 6, "install", "submit"),
        step("ACTIVATE_POLICY", 6, "activate", "submit"),
    )

    common_suffix = (
        step("DEACTIVATE_POLICY", 6, "deactivate", "submit"),
        step("UPDATE_POLICY", 6, "update", "submit"),
        step("ACTIVATE_POLICY", 6, "activate", "submit"),
        step("DEACTIVATE_POLICY", 6, "deactivate", "submit"),
        step("REMOVE_POLICY", 6, "remove", "submit"),
    )

    security_first = common_prefix + (
        step("POLICY_ATTESTATION (Security)", None, "attest", "submit", sec),
        step("POLICY_ATTESTATION (Security)", None, "attest", "fetch", sec),
        step("POLICY_ATTESTATION (Consistency)", 6, "attest", "submit", con),
        step("POLICY_ATTESTATION (Consistency)", 6, "attest", "fetch", con),
    ) + common_suffix

    consistency_first = common_prefix + (
        step("POLICY_ATTESTATION (Consistency)", 6, "attest", "submit", con),
        step("POLICY_ATTESTATION (Consistency)", 6, "attest", "fetch", con),
        step("POLICY_ATTESTATION (Security)", None, "attest", "submit", sec),
        step("POLICY_ATTESTATION (Security)", None, "attest", "fetch", sec),
    ) + common_suffix

    return security_first, consistency_first


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def row_key(row: dict[str, str]) -> tuple[str, str, str]:
    return row.get("command", ""), row.get("detail", ""), row.get("report_type", "")


def match_pattern(rows: list[dict[str, str]], start: int, pattern: tuple[StepSpec, ...]) -> tuple[int, dict[str, list[int]]] | None:
    if start + len(pattern) > len(rows):
        return None

    by_label: dict[str, list[int]] = {}
    for offset, spec in enumerate(pattern):
        row = rows[start + offset]
        if row.get("command") != spec.command:
            return None
        if row.get("detail") != spec.detail:
            return None
        if spec.report_type and row.get("report_type", "") != spec.report_type:
            return None
        if not spec.report_type and "report_type" in row and row.get("report_type", "") not in ("", spec.report_type):
            # Old CSVs have no report_type column; new CSVs have it.
            # For rows where we do not care, accept an empty value only.
            return None

        size = int(row["policy_size_pages"])
        if spec.size_pages is not None and size != spec.size_pages:
            return None

        by_label.setdefault(spec.label, []).append(int(row["elapsed_ns"]))

    return start + len(pattern), by_label


def aggregate_mode(rows: list[dict[str, str]], mode: str, use_report_type: bool) -> dict[str, list[int]]:
    mode_rows = [row for row in rows if row.get("mode") == mode]
    patterns = run_patterns(use_report_type)
    by_label: dict[str, list[int]] = {}

    index = 0
    while index < len(mode_rows):
        matched = None
        for pattern in patterns:
            matched = match_pattern(mode_rows, index, pattern)
            if matched is not None:
                break
        if matched is None:
            index += 1
            continue

        next_index, chunk_values = matched
        for label, values in chunk_values.items():
            by_label.setdefault(label, []).extend(values)
        index = next_index

    return by_label


def build_summary(rows: list[dict[str, str]]) -> list[list[str]]:
    use_report_type = any(row.get("report_type", "") for row in rows)
    normal = aggregate_mode(rows, "normal", use_report_type)
    confidential = aggregate_mode(rows, "confidential", use_report_type)

    output_order = [
        ("INIT_SESSION", None),
        ("INSTALL_POLICY", 6),
        ("UPDATE_POLICY", 6),
        ("REMOVE_POLICY", 6),
        ("ACTIVATE_POLICY", 6),
        ("DEACTIVATE_POLICY", 6),
        ("POLICY_ATTESTATION (Security)", None),
        ("POLICY_ATTESTATION (Consistency)", 6),
    ]

    def display_label(label: str) -> str:
        mapping = {
            "INIT_SESSION": r"\texttt{INIT\_SESSION}",
            "INSTALL_POLICY": r"\texttt{INSTALL\_POLICY}",
            "ACTIVATE_POLICY": r"\texttt{ACTIVATE\_POLICY}",
            "DEACTIVATE_POLICY": r"\texttt{DEACTIVATE\_POLICY}",
            "UPDATE_POLICY": r"\texttt{UPDATE\_POLICY}",
            "REMOVE_POLICY": r"\texttt{REMOVE\_POLICY}",
            "POLICY_ATTESTATION (Security)": r"\texttt{POLICY\_ATTESTATION (S)}",
            "POLICY_ATTESTATION (Consistency)": r"\texttt{POLICY\_ATTESTATION (C)}",
        }
        return mapping[label]

    table_rows: list[list[str]] = []
    for label, size_pages in output_order:
        normal_values = normal.get(label, [])
        confidential_values = confidential.get(label, [])
        if not normal_values or not confidential_values:
            raise ValueError(f"Missing samples for {label}")

        normal_ms = statistics.mean(normal_values) / 1_000_000.0
        confidential_ms = statistics.mean(confidential_values) / 1_000_000.0
        table_rows.append(
            [
                display_label(label),
                "--" if size_pages is None else str(size_pages),
                f"{normal_ms:.3f}",
                f"{confidential_ms:.3f}",
            ]
        )

    return table_rows


def write_summary(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["command", "size", "normal", "confidential"])
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path(__file__).resolve().parent / "meta_timing.csv")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "paper_table.csv")
    args = parser.parse_args()

    rows = load_rows(args.input)
    summary = build_summary(rows)
    write_summary(args.output, summary)
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
