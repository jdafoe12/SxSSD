# Workload Sets Usage Guide

Note: the workload trace files themselves are intentionally omitted from this packaged artifact to save space. Reviewers should use the VM-provided copy of `workload_sets/` when running the evaluation. The scripts and manifests left in this directory describe the expected layout and replay procedure.

This directory contains the canonical generated workload sets for trace-based evaluation.

The tiers are shared across all source families, including MSR, FIU, Systor, and the Alibaba write-heavy subset.

## Directory Layout

- `dev/`
- `core/`
- `long_gc/`
- `manifests/`

Each tier contains:

- `source/`: normalized CSV traces
- `fio_iolog/`: ready-to-run fio iolog traces

The manifest files are in `manifests/`:

- `workload_manifest.csv`
- `workload_manifest.json`
- `summary.json`

## What The Tiers Mean

### `dev`

Use this for:

- code iteration
- instrumentation validation
- quick regression checks
- verifying that a new change did not obviously break performance

Characteristics:

- smallest set
- shortest runtime
- enough diversity to catch obvious problems

Do not use `dev` as your only paper-quality result set.

### `core`

Use this for:

- main trace-based evaluation
- headline overhead figures
- most correctness and policy-equivalence figures

Characteristics:

- broader and more representative than `dev`
- still practical to rerun across multiple configurations
- intended default for serious experiments

If you are unsure which tier to use, start with `core`.

### `long_gc`

Use this for:

- GC-sensitive figures
- `WAF`
- migrated pages
- erase count
- free-space trajectory
- longer steady-state policy behavior

Characteristics:

- built from longer contiguous sequences where needed
- slower than `dev` and `core`
- not ideal for fast iteration

Use `long_gc` when the figure depends on internal storage evolution over longer runs.

## Alibaba Write-Heavy Subset

The Alibaba write-heavy drives are now incorporated into the same tier layout instead of living in a separate top-level folder.

Selection rule:

1. Rank the largest processed Alibaba device traces by file size.
2. Sample the first 10,000 requests from the top 35 by file size.
3. Keep the top 10 by sampled write-byte ratio, then write-op ratio, then file size.

The selected drives are distributed across `dev`, `core`, and `long_gc` using the same `warmup / normal_short / normal_long` split as the other families.

Use Alibaba alongside the other traces like this:

- `dev`: quick debugging and instrumentation checks
- `core`: main workload-diverse evaluation set
- `long_gc`: write-heavy / GC-sensitive validation

## What The Segment Names Mean

Each workload unit is split into three segments:

- `warmup`
- `normal_short`
- `normal_long`

These are independent files.

### `warmup`

Use this first.

Purpose:

- precondition the device
- move the system toward a stable internal state before measurement

This should normally be replayed without collecting final performance numbers.

### `normal_short`

Use this for fast measured runs.

Recommended for:

- average latency
- percentile latency
- throughput
- normalized overhead
- queue-depth sensitivity
- replay-rate sensitivity

This is the default measured slice for most overhead figures.

### `normal_long`

Use this when a short slice is too small to stabilize the internal behavior.

Recommended for:

- `WAF`
- GC count
- migrated pages
- erase count
- free-space trajectory
- victim quality / policy-faithfulness

If a figure depends on GC or internal policy state, prefer `normal_long`.

## How To Run A Workload Unit

For each selected unit, the normal procedure is:

1. reset emulator statistics
2. pre-fill the device if your experiment requires it
3. replay the matching `warmup` file
4. replay either `normal_short` or `normal_long`
5. collect fio JSON and emulator stats

Example logic:

- use `warmup + normal_short` for overhead figures
- use `warmup + normal_long` for GC and `WAF` figures

## Which Tier To Use For Which Figure

Use `dev` for:

- code validation
- debugging
- sanity checks

Use `core` for:

- correctness / behavioral equivalence
- steady-state overhead
- tail latency
- workload sensitivity
- most trace-based comparisons

Use `long_gc` for:

- `WAF`
- GC execution time
- GC count and migrated pages
- long-horizon policy behavior

## How To Choose Between `normal_short` and `normal_long`

Use `normal_short` when:

- the result is mainly end-to-end latency/throughput
- you need many repeated runs
- you are comparing many configurations

Use `normal_long` when:

- the metric depends on internal state
- the metric can be noisy on short windows
- GC behavior matters

## Important Rule

Do not use only one tiny measured slice for every figure.

The intended policy is:

- `short` for overhead figures
- `long` for GC / `WAF` / policy-faithfulness figures

## File Naming Convention

A generated file name looks like:

- `msr_hm_0__warmup.csv`
- `msr_hm_0__normal_short.csv`
- `msr_hm_0__normal_long.csv`

The same naming is used in `fio_iolog/`.

Interpretation:

- prefix before `__`: workload unit name
- suffix after `__`: segment type

## Where To Look Up The Exact Source Trace

Use `manifests/workload_manifest.csv`.

It records:

- tier
- workload unit name
- segment
- source family
- original source path(s)
- generated CSV path
- generated iolog path
- request count
- basic workload statistics

## Recommended Default Workflow

For development:

- use `dev`
- run `warmup + normal_short`

For main paper evaluation:

- use `core`
- run `warmup + normal_short` for overhead figures
- run `warmup + normal_long` for GC and `WAF` figures

For longer internal-policy validation:

- use `long_gc`
- run `warmup + normal_long`

## Summary

Use the workload sets like this:

- `dev` = fast iteration
- `core` = main evaluation
- `long_gc` = long-horizon GC and policy behavior
- `warmup` = precondition only
- `normal_short` = main overhead slice
- `normal_long` = GC / `WAF` / policy-faithfulness slice
