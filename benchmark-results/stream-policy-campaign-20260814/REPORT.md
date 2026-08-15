# Stream-placement benchmark report

Date: 2026-08-14

Each full run used a fresh FEMU process, a 60-second warmup, and a 600-second
measurement. The common workload used four workers, 64 KiB writes, queue depth
32, a 12 GiB working set, and 64 MiB reclaimable logical regions. All runs
completed 600 throughput samples with zero I/O errors.

## Results

| Policy | Frontiers | Full-window MiB/s | Last 300 s MiB/s | Mean latency (us) | p99 latency (us) | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Original block-policy baseline | 1 | 193.15 | 175.62 | 10,294.85 | 267,697 | 0 |
| Independent block control | 1 | 193.49 | 176.00 | 10,274.52 | 266,933 | 0 |
| Independent block policy | 2 | 269.07 | 259.28 | 7,358.69 | 190,319 | 0 |
| Independent block policy | 4 | 725.01 | 724.89 | 2,704.90 | 12,039 | 0 |
| ZNS | Host-managed zones | 867.87 | 867.84 | 2,246.44 | 6,514 | 0 |

The independent one-frontier implementation is within 0.18% of the original
block baseline over the complete window and within 0.22% over the final five
minutes. This validates it as a useful implementation control.

Using the final five minutes as the steady-state comparison, two frontiers are
1.48x baseline, four frontiers are 4.13x baseline, and ZNS is 4.94x baseline.
ZNS remains 1.20x faster than the four-frontier block policy.

## Interpretation

The four-frontier result is valid for this benchmark, but it is an idealized
upper-bound result. One benchmark region and one eSWD are both exactly 64 MiB.
The workload assigns regions to workers by region number modulo four, while the
policy assigns regions to physical frontiers by the same rule. Consequently,
the four-frontier policy can place each logical region in its own eSWD. When
the workload discards that region, the corresponding eSWD can become wholly
invalid instead of requiring live pages from other regions to be migrated.

With one frontier, writes from all four independently reclaimed regions are
interleaved in the same eSWDs. With two frontiers, two region sequences still
share each eSWD. The large tail-latency reductions are consistent with less
valid-page migration: p99 falls from about 268 ms for one frontier to 190 ms
for two, 12 ms for four, and 6.5 ms for ZNS.

The benchmark completed and accounted for 6.96 million writes and 6,796
logical-region reclaims in the four-frontier run. It therefore did not obtain
the high result by dropping writes or avoiding reuse. `region_reclamations` is
a workload reset/discard count, however, not an internal SSD garbage-collection
counter. Direct GC invocation and migration counts are unavailable after the
evaluation-only statistics API was removed, so the migration explanation is
an inference from the policy algorithm, exact region/eSWD alignment, throughput
shape, and latency distribution.

These policies do not implement the NVMe Streams interface and required no
native SSD changes. They derive a known placement group from the LPN, making
the experiment a mechanism study: it shows what this workload can gain when
the policy is given perfect placement knowledge. It does not show that an
ordinary block interface can infer such knowledge for arbitrary workloads.

## Repetition requirement

This campaign contains one full repetition of each policy plus a short smoke
run. The differences are large and the one-frontier controls agree closely,
but publication-quality results should still repeat each full configuration
at least three times in rotated order and report variation.
