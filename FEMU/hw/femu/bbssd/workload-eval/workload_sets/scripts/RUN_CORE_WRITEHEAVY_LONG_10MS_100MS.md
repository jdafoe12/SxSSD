# Core Writeheavy Long Runs

Note: the workload trace files are not bundled in this compressed artifact. Reviewers should use the VM-provided copy of `~/workload-eval/workload_sets` and prefer the top-level reviewer guide for the full host/guest workflow:

- [REVIEWER_EVALUATION.md](/home/main/Projects/SUBMIT/SxSSD/REVIEWER_EVALUATION.md)

This file lists the exact commands to run the `core_writeheavy` workload set with:

- `--measure long`
- `--cap 10`
- scaled iologs for `12288` MiB
- latency logging enabled with `--log-avg-msec 100`

Run each workload from a fresh FEMU boot if you want clean, comparable results.

## Host Setup

Based on the official FEMU best-practice notes, do this on the host before each run:

1. Set host CPUs to `performance` mode.
2. Start FEMU.
3. Pin FEMU vCPUs/QEMU threads after QEMU is up.

Run these commands on the host:

```bash
cd "$ARTIFACT_ROOT/FEMU/femu-scripts" && sudo ./set_cpu_perf_mode.sh
```

```bash
cd "$ARTIFACT_ROOT/FEMU/build-femu" && \
FEMU_IMAGE_DIR="$FEMU_IMAGE_DIR" \
FEMU_OS_IMAGE="$FEMU_OS_IMAGE" \
FEMU_HOST_RESULTS_DIR="$BASELINE_RESULTS" \
./run-blackbox.sh
```

After the VM is up and `qmp-sock` exists, pin FEMU:

```bash
cd "$ARTIFACT_ROOT/FEMU/build-femu" && ../femu-scripts/pin.sh
```

## VM Setup

Run these commands inside the VM before starting a workload run:

```bash
sudo mkdir -p /mnt/femu-host-results
sudo mount -t 9p -o trans=virtio,version=9p2000.L femu_host_results /mnt/femu-host-results
cd ~/workload-eval/workload_sets
```

Optional verification:

```bash
mount | grep femu_host_results
ls /mnt/femu-host-results
```

## Workload Commands

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit alibaba_01 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit alibaba_08 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit fiu_homes_02 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit fiu_mail_03 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit fiu_web_02 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit msr_mds_0 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit msr_prn_0 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit msr_prxy_0 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit systor_05 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit systor_06 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

```bash
cd ~/workload-eval/workload_sets && sudo python3 scripts/run_workload_set.py core_writeheavy block --target /dev/nvme0n1 --nvme-dev /dev/nvme0 --unit systor_11 --measure long --cap 10 --scaled --ssd-size-mb 12288 --replay-time-scale 100 --repetition-id 0 --build-label general-overhead-eval --log-avg-msec 100
```

## Output Location

After the guest mount is active, results should appear on the host under:

```bash
$BASELINE_RESULTS
```
