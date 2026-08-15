# Steady-State Block and ZNS Campaign

Date: 2026-08-13 through 2026-08-14

## Method

Each case used a freshly started FEMU instance and the rebuilt policy images.
Block cases used 240 or 300 seconds of unmeasured preconditioning followed by
300 seconds of measurement. ZNS controls used 120 seconds of preconditioning
and 300 seconds of measurement because their throughput converged immediately.
Every run completed with zero benchmark errors.

The namespace is 16 GiB, the flash page is 4 KiB, an eSWD/benchmark region is
64 MiB, and the device has 64 LUNs (8 channels by 8 LUNs). Unless a row says
otherwise, the working set is 12 GiB (75%), the request size is 64 KiB, and the
aggregate queue depth is 32.

`Tail MiB/s` is the mean of the final 60 one-second samples. It is more useful
than the complete-window average for cases that were still degrading.

## Results

| Case | Mean MiB/s | Tail MiB/s | IOPS | Mean latency (us) | p99 (us) |
|---|---:|---:|---:|---:|---:|
| Block, 1 stream | 727.29 | 727.15 | 11,636.6 | 2,593 | 7,987 |
| Block, 2 streams | 249.79 | 257.01 | 3,996.7 | 7,907 | 196,643 |
| Block, 4 streams | 189.82 | 184.88 | 3,037.1 | 10,478 | 269,701 |
| Block, 8 streams | 182.67 | 153.45 | 2,922.7 | 10,895 | 280,349 |
| Block, 50% occupancy, 4 streams | 726.90 | 726.69 | 11,630.4 | 2,695 | 9,179 |
| Block, 87.5% occupancy, 4 streams | 191.82 | 176.86 | 3,069.1 | 10,378 | 267,081 |
| Block, 4 KiB, 4 streams | 198.56 | 193.61 | 50,830.9 | 627 | 231 |
| Block, 16 KiB, 4 streams | 187.43 | 188.75 | 11,995.5 | 2,660 | 4,693 |
| Block, 256 KiB, 4 streams | 483.12 | 482.65 | 1,932.5 | 13,996 | 111,651 |
| Block, QD 8, 4 streams | 190.29 | 184.47 | 3,044.6 | 2,618 | 56,139 |
| Block, QD 1, 1 stream | 281.13 | 281.22 | 4,498.1 | 219 | 352 |
| ZNS, 1 stream | 870.82 | 870.52 | 13,933.2 | 2,102 | 2,269 |
| ZNS, 256 KiB, 4 streams | 858.73 | 855.68 | 3,434.9 | 8,920 | 12,238 |

The previously completed ZNS 64 KiB, four-stream run was 877.34 MiB/s and was
flat in its final 300 seconds. It is not duplicated in this campaign directory.

## Main Findings

1. The large ZNS advantage is workload-dependent, not a universal 5x device
   advantage. With one stream, ZNS is only 1.20x faster than block. At 50%
   occupancy and four streams, block also reaches about 727 MiB/s. The 4.6x
   gap appears at 75% occupancy with four interleaved streams.

2. Interleaving is the strongest block-policy stressor. Moving from one to two
   streams drops block throughput by 65.7%. Four and eight streams make the
   tail progressively worse. ZNS is essentially stream-insensitive: one stream
   produced 870.82 MiB/s versus 877.34 MiB/s for the earlier four-stream run.

3. Spare area has a threshold effect. Four-stream block throughput is flat at
   726.90 MiB/s with a 50% working set, but about 185 MiB/s in the tail at 75%.
   Raising occupancy to 87.5% does not create another equally large cliff; once
   migration-heavy GC is active, both cases operate in the same slow regime.

4. The slow regime is bursty GC behavior rather than uniformly slow writes.
   For the 75%, four-stream block case, p50 remains 2.436 ms while p99 reaches
   269.7 ms and one-second throughput has a 25.8% coefficient of variation.
   The 50% case has 9.2 ms p99 and only 0.5% throughput variation.

5. Queue depth is not the bottleneck in the slow four-stream regime. QD 8 and
   QD 32 both produce about 190 MiB/s. QD 32 only raises mean latency because
   more requests wait behind the same GC work. With one stream, QD 32 does help:
   it reaches 727 MiB/s versus 281 MiB/s at QD 1.

6. Requests from 4 through 64 KiB converge near the same byte rate. The 256 KiB
   request is different and reaches 483 MiB/s. It contains 64 flash pages, equal
   to the 64-LUN stripe width, and it also amortizes per-NVMe-event policy and
   background-dispatch work. ZNS does not gain from 256 KiB, so this is specific
   to the block translation/GC path rather than higher raw-flash bandwidth.

## Code Interpretation

The block policy writes every host stream into one global current eSWD. With
multiple logical streams, pages from unrelated regions therefore share physical
eSWDs. Reclaiming one logical region can leave valid pages from the other
streams in those eSWDs, forcing migration. One stream, or sufficiently aligned
reclamation at 50% occupancy, produces much cleaner victims.

The policy selects the eSWD with the fewest valid pages using its WASM-resident
victim heap. GC then scans all 16,384 pages in a 64 MiB eSWD. Each page-status
check crosses the WAMR import boundary; each valid page is migrated through
another imported API call, and mappings are updated in WASM. This is
algorithmically similar to greedy line GC, but its per-page control loop is
materially more expensive than a native FEMU loop.

Background GC is dispatched synchronously after every NVMe request by the
single BBSSD worker. The policy begins background GC below the 25% free-eSWD
watermark and also forces GC in the write action below 5%. A GC action reclaims
one whole eSWD before the worker proceeds. This structure explains the normal
median latency plus very large tail stalls seen in migration-heavy cases.

There are additional native overheads worth measuring later, but they were not
changed in this campaign: request reads allocate and free a temporary native
buffer for every copied page, and migration performs one BBM read/write pair per
page. The current data cannot separate these CPU costs from physical migration
cost because evaluation counters were intentionally removed.

## Limitations and Next Measurements

- `region_reclamations` counts benchmark-level 64 MiB discard/reset operations;
  it is not an internal GC count and must not be interpreted as write amplification.
- Eight streams and 87.5% occupancy were still degrading after preconditioning,
  so their tail rates are better steady-state estimates than their full averages.
- The existing benchmark always reclaims each region immediately before reuse.
  Batched or synchronized reclamation requires a new benchmark option and was
  not tested because this campaign was required not to change native code.
- The highest-value next instrumentation is per-run GC count, valid pages moved,
  physical reads/writes/erases, time spent in WASM, and time spent in BBM. Those
  counters would directly yield write amplification and split algorithmic cost
  from runtime overhead.

