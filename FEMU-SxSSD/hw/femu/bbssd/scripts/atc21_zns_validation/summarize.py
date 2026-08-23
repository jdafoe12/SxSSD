#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

"""Extract compact, comparable results from the validation fio JSON."""

import csv
import json
import pathlib
import sys


def mib_per_second(section):
    if "bw_bytes" in section:
        return float(section["bw_bytes"]) / (1024 * 1024)
    return float(section.get("bw", 0)) / 1024


def mean_us(section):
    for key, scale in (("lat_ns", 1000), ("clat_ns", 1000),
                       ("lat_us", 1), ("clat_us", 1)):
        values = section.get(key)
        if values and "mean" in values:
            return float(values["mean"]) / scale
    return 0.0


def percentile_us(section, percentile):
    for key, scale in (("clat_ns", 1000), ("lat_ns", 1000),
                       ("clat_us", 1), ("lat_us", 1)):
        values = section.get(key, {}).get("percentile")
        if not values:
            continue
        wanted = float(percentile)
        nearest = min(values, key=lambda item: abs(float(item) - wanted))
        return float(values[nearest]) / scale
    return 0.0


def load_jobs(path):
    with open(path, encoding="utf-8") as source:
        return {job["jobname"]: job for job in json.load(source)["jobs"]}


def peak(path):
    job = load_jobs(path)["peak_writer"]
    print(f"{mib_per_second(job['write']):.3f}")


def targets(peak_mib):
    peak = float(peak_mib)
    values = []
    for fraction in (0.05, 0.15, 0.30, 0.50, 1.00):
        target = max(1, int((peak * fraction) // 5) * 5)
        if target not in values:
            values.append(target)
    for target in values:
        print(target)


def summarize(result_directory, mode):
    result_path = pathlib.Path(result_directory)
    jobs = load_jobs(result_path / "fio-validation.json")
    peak_job = jobs["peak_writer"]
    rows = []

    baseline = jobs["mixed_000_reader"]
    rows.append({
        "mode": mode,
        "target_mib_s": 0,
        "achieved_write_mib_s": 0,
        "read_mib_s": mib_per_second(baseline["read"]),
        "read_mean_us": mean_us(baseline["read"]),
        "read_p50_us": percentile_us(baseline["read"], 50),
        "read_p95_us": percentile_us(baseline["read"], 95),
        "read_p99_us": percentile_us(baseline["read"], 99),
    })

    for name, writer in jobs.items():
        if not name.startswith("mixed_") or not name.endswith("_writer"):
            continue
        target = int(name.split("_")[1])
        reader = jobs[f"mixed_{target}_reader"]
        rows.append({
            "mode": mode,
            "target_mib_s": target,
            "achieved_write_mib_s": mib_per_second(writer["write"]),
            "read_mib_s": mib_per_second(reader["read"]),
            "read_mean_us": mean_us(reader["read"]),
            "read_p50_us": percentile_us(reader["read"], 50),
            "read_p95_us": percentile_us(reader["read"], 95),
            "read_p99_us": percentile_us(reader["read"], 99),
        })

    rows.sort(key=lambda row: row["target_mib_s"])
    with open(result_path / "summary.csv", "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with open(result_path / "peak.csv", "w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(["mode", "peak_write_mib_s"])
        writer.writerow([mode, f"{mib_per_second(peak_job['write']):.3f}"])


def usage():
    raise SystemExit("usage: summarize.py peak <fio.json> | targets <peak-mib> | summarize <directory> <mode>")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "peak":
        peak(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "targets":
        targets(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "summarize":
        summarize(sys.argv[2], sys.argv[3])
    else:
        usage()
