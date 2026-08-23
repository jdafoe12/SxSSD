#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import csv
import json
import pathlib
import sys


FIELDS = [
    "run",
    "mode",
    "policy_variant",
    "placement_groups",
    "throughput_mib_s",
    "iops",
    "write_latency_mean_us",
    "write_latency_p50_us",
    "write_latency_p95_us",
    "write_latency_p99_us",
    "write_latency_p99_9_us",
    "region_reclamations",
    "errors",
]


def read_parameters(path: pathlib.Path):
    parameters = {}
    if not path.exists():
        return parameters
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            parameters[key] = value
    return parameters


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                        pathlib.Path.home() / "atc21-zns-results")
    rows = []
    for path in sorted(root.glob("*/summary.json")):
        with path.open(encoding="utf-8") as stream:
            row = json.load(stream)
        row["run"] = path.parent.name
        parameters = read_parameters(path.parent / "parameters.env")
        row["policy_variant"] = parameters.get(
            "POLICY_VARIANT", row["mode"])
        row["placement_groups"] = parameters.get(
            "PLACEMENT_GROUPS", "unknown")
        rows.append(row)

    if not rows:
        print(f"No completed runs under {root}", file=sys.stderr)
        return 1

    writer = csv.DictWriter(sys.stdout, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)

    latest = {}
    for row in rows:
        if not row["errors"]:
            latest[row["policy_variant"]] = row

    baseline = latest.get("block-baseline", latest.get("block"))
    if baseline and baseline["throughput_mib_s"]:
        baseline_rate = baseline["throughput_mib_s"]
        print("\nLatest successful throughput by policy:")
        print(f"  {'block-baseline':18s} {baseline_rate:10.3f} MiB/s "
              "(1.000x baseline)")
        for variant in ("block-streams-1", "block-streams-2",
                        "block-streams-4", "zns"):
            row = latest.get(variant)
            if not row:
                continue
            rate = row["throughput_mib_s"]
            print(f"  {variant:18s} {rate:10.3f} MiB/s "
                  f"({rate / baseline_rate:.3f}x baseline)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
