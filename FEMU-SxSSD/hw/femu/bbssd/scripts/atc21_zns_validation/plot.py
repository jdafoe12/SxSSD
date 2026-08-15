#!/usr/bin/env python3

"""Create simple Figure 5-style SVGs from completed validation directories."""

import csv
import html
import pathlib
import sys


SERIES = (
    ("zns", "ZNS (0% FTL data OP)", "#177e89"),
    ("block-7", "Block (7% effective OP)", "#c84c09"),
    ("block-28", "Block (28% effective OP)", "#674ea7"),
)


def load_series(results_root):
    root = pathlib.Path(results_root)
    data = {}
    for mode, _label, _color in SERIES:
        candidates = sorted(root.glob(f"{mode}-*/summary.csv"))
        if not candidates:
            raise SystemExit(f"missing summary.csv for {mode}")
        with open(candidates[-1], newline="", encoding="utf-8") as source:
            data[mode] = list(csv.DictReader(source))
    return data


def scale(value, lower, upper, pixels_low, pixels_high):
    if upper == lower:
        return (pixels_low + pixels_high) / 2
    return pixels_low + (value - lower) * (pixels_high - pixels_low) / (upper - lower)


def tick_values(upper, count=5):
    if upper <= 0:
        return [0]
    raw = upper / count
    magnitude = 10 ** int(len(str(int(raw))) - 1)
    step = max(magnitude, round(raw / magnitude) * magnitude)
    values = list(range(0, int(upper) + step, step))
    return values


def write_chart(path, title, y_label, series_data, y_key, diagonal=False):
    width, height = 900, 520
    left, right, top, bottom = 95, 35, 55, 80
    chart_width = width - left - right
    chart_height = height - top - bottom
    points = [row for rows in series_data.values() for row in rows]
    x_upper = max(float(row["target_mib_s"]) for row in points)
    y_upper = max(float(row[y_key]) for row in points)
    if diagonal:
        y_upper = max(y_upper, x_upper)
    y_upper *= 1.1
    x_ticks = tick_values(x_upper)
    y_ticks = tick_values(y_upper)

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{left}" y="30" font-family="sans-serif" font-size="20">{html.escape(title)}</text>',
        f'<line x1="{left}" y1="{top + chart_height}" x2="{left + chart_width}" y2="{top + chart_height}" stroke="#222"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + chart_height}" stroke="#222"/>',
    ]
    for tick in x_ticks:
        x = scale(tick, 0, x_upper, left, left + chart_width)
        lines.append(f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{top + chart_height}" stroke="#e5e5e5"/>')
        lines.append(f'<text x="{x:.1f}" y="{top + chart_height + 22}" text-anchor="middle" font-family="sans-serif" font-size="12">{tick}</text>')
    for tick in y_ticks:
        y = scale(tick, 0, y_upper, top + chart_height, top)
        lines.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + chart_width}" y2="{y:.1f}" stroke="#e5e5e5"/>')
        lines.append(f'<text x="{left - 10}" y="{y + 4:.1f}" text-anchor="end" font-family="sans-serif" font-size="12">{tick}</text>')
    if diagonal:
        end = min(x_upper, y_upper)
        lines.append(
            f'<line x1="{left}" y1="{top + chart_height}" x2="{scale(end, 0, x_upper, left, left + chart_width):.1f}" y2="{scale(end, 0, y_upper, top + chart_height, top):.1f}" stroke="#777" stroke-dasharray="5 5"/>'
        )
    for mode, label, color in SERIES:
        rows = series_data[mode]
        coords = []
        for row in rows:
            x = scale(float(row["target_mib_s"]), 0, x_upper, left, left + chart_width)
            y = scale(float(row[y_key]), 0, y_upper, top + chart_height, top)
            coords.append((x, y))
        point_list = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
        lines.append(f'<polyline points="{point_list}" fill="none" stroke="{color}" stroke-width="2.5"/>')
        for x, y in coords:
            lines.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{color}"/>')
    legend_y = top + 15
    for index, (_mode, label, color) in enumerate(SERIES):
        legend_x = left + 270 + index * 155
        lines.append(f'<line x1="{legend_x}" y1="{legend_y}" x2="{legend_x + 20}" y2="{legend_y}" stroke="{color}" stroke-width="3"/>')
        lines.append(f'<text x="{legend_x + 26}" y="{legend_y + 4}" font-family="sans-serif" font-size="11">{html.escape(label)}</text>')
    lines.append(f'<text x="{left + chart_width / 2}" y="{height - 20}" text-anchor="middle" font-family="sans-serif" font-size="14">Requested write throughput (MiB/s)</text>')
    lines.append(f'<text x="20" y="{top + chart_height / 2}" transform="rotate(-90 20 {top + chart_height / 2})" text-anchor="middle" font-family="sans-serif" font-size="14">{html.escape(y_label)}</text>')
    lines.append('</svg>')
    path.write_text("\n".join(lines), encoding="utf-8")


def write_comparison(path, data):
    peaks = {}
    for mode, _label, _color in SERIES:
        candidates = sorted(path.glob(f"{mode}-*/peak.csv"))
        with open(candidates[-1], newline="", encoding="utf-8") as source:
            peaks[mode] = float(next(csv.DictReader(source))["peak_write_mib_s"])
    with open(path / "validation-comparison.csv", "w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(["metric", "paper", "sxs_value"])
        writer.writerow(["block_7_peak_over_zns_peak", "0.366", f"{peaks['block-7'] / peaks['zns']:.3f}"])
        writer.writerow(["block_28_peak_over_zns_peak", "0.584", f"{peaks['block-28'] / peaks['zns']:.3f}"])


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: plot.py <results-root>")
    root = pathlib.Path(sys.argv[1])
    data = load_series(root)
    write_chart(root / "figure5a-validation.svg", "Validation: achieved write throughput", "Achieved write throughput (MiB/s)", data, "achieved_write_mib_s", diagonal=True)
    write_chart(root / "figure5b-validation.svg", "Validation: mean random-read latency", "Mean read latency (microseconds)", data, "read_mean_us")
    write_comparison(root, data)


if __name__ == "__main__":
    main()
