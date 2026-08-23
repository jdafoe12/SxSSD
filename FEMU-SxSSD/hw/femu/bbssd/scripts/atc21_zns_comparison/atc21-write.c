/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libaio.h>
#include <linux/blkzoned.h>
#include <linux/fs.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MIB (1024ULL * 1024ULL)
#define LATENCY_BUCKETS 1000001U
#define LATENCY_OVERFLOW_US 1000000U

enum benchmark_mode {
    MODE_BLOCK,
    MODE_ZNS,
};

struct benchmark_config {
    enum benchmark_mode mode;
    const char *device;
    const char *output_dir;
    uint64_t offset;
    uint64_t working_set;
    uint64_t zone_size;
    uint32_t block_size;
    uint32_t streams;
    uint32_t iodepth;
    uint32_t warmup_seconds;
    uint32_t runtime_seconds;
};

struct shared_state {
    struct benchmark_config config;
    int fd;
    uint64_t total_zones;
    uint64_t start_ns;
    uint64_t measure_start_ns;
    uint64_t measure_end_ns;
    atomic_bool stop;
    atomic_uint_fast64_t measured_bytes;
    atomic_uint_fast64_t measured_ios;
    atomic_uint_fast64_t errors;
};

struct io_slot {
    struct iocb iocb;
    void *buffer;
    uint64_t submitted_ns;
    bool active;
};

struct worker_state {
    struct shared_state *shared;
    uint32_t id;
    uint32_t depth;
    io_context_t aio_context;
    struct io_slot *slots;
    struct io_event *events;
    uint64_t *latency_histogram;
    uint64_t latency_samples;
    uint64_t latency_sum_ns;
    uint64_t reclamations;
};

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_until(uint64_t target_ns)
{
    struct timespec target = {
        .tv_sec = (time_t)(target_ns / 1000000000ULL),
        .tv_nsec = (long)(target_ns % 1000000000ULL),
    };

    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &target, NULL) == EINTR) {
    }
}

static void usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage: %s --mode block|zns --device PATH --output-dir DIR\n"
            "          --working-set BYTES --zone-size BYTES [options]\n\n"
            "Options:\n"
            "  --offset BYTES       Working-set start offset (default: 0)\n"
            "  --bs BYTES           Write size (default: 65536)\n"
            "  --streams COUNT      Concurrent sequential regions (default: 4)\n"
            "  --iodepth COUNT      Aggregate queue depth (default: 32)\n"
            "  --warmup SECONDS     Unmeasured warmup (default: 60)\n"
            "  --runtime SECONDS    Measured duration (default: 600)\n",
            program);
}

static uint64_t parse_u64(const char *text, const char *name)
{
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(text, &end, 0);
    if (errno || !end || *end != '\0') {
        fprintf(stderr, "Invalid %s: %s\n", name, text);
        exit(EXIT_FAILURE);
    }
    return (uint64_t)value;
}

static const char *mode_name(enum benchmark_mode mode)
{
    return mode == MODE_ZNS ? "zns" : "block";
}

static int reclaim_range(struct shared_state *shared, uint64_t offset,
                         uint64_t length)
{
    if (shared->config.mode == MODE_BLOCK) {
        uint64_t range[2] = { offset, length };

        return ioctl(shared->fd, BLKDISCARD, &range);
    } else {
        struct blk_zone_range range = {
            .sector = offset / 512,
            .nr_sectors = length / 512,
        };

        return ioctl(shared->fd, BLKRESETZONE, &range);
    }
}

static void record_latency(struct worker_state *worker, uint64_t latency_ns)
{
    uint64_t latency_us = (latency_ns + 999) / 1000;
    uint32_t bucket = latency_us >= LATENCY_OVERFLOW_US
                    ? LATENCY_OVERFLOW_US : (uint32_t)latency_us;

    worker->latency_histogram[bucket]++;
    worker->latency_samples++;
    worker->latency_sum_ns += latency_ns;
}

static struct io_slot *find_free_slot(struct worker_state *worker)
{
    for (uint32_t i = 0; i < worker->depth; i++) {
        if (!worker->slots[i].active) {
            return &worker->slots[i];
        }
    }
    return NULL;
}

static int submit_write(struct worker_state *worker, uint64_t offset)
{
    struct shared_state *shared = worker->shared;
    struct io_slot *slot = find_free_slot(worker);
    struct iocb *requests[1];
    int result;

    if (!slot) {
        errno = EBUSY;
        return -1;
    }

    memset(&slot->iocb, 0, sizeof(slot->iocb));
    io_prep_pwrite(&slot->iocb, shared->fd, slot->buffer,
                   shared->config.block_size, (long long)offset);
    slot->iocb.data = slot;
    slot->submitted_ns = monotonic_ns();
    requests[0] = &slot->iocb;

    do {
        result = io_submit(worker->aio_context, 1, requests);
    } while (result < 0 && result == -EINTR);
    if (result != 1) {
        errno = result < 0 ? -result : EIO;
        return -1;
    }
    slot->active = true;
    return 0;
}

static int reap_completions(struct worker_state *worker, uint32_t minimum,
                            uint32_t outstanding)
{
    struct shared_state *shared = worker->shared;
    struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
    int completed;

    do {
        completed = io_getevents(worker->aio_context, minimum, outstanding,
                                 worker->events, &timeout);
    } while (completed < 0 && completed == -EINTR);

    if (completed < 0) {
        errno = -completed;
        return -1;
    }

    for (int i = 0; i < completed; i++) {
        struct io_slot *slot = worker->events[i].data;
        uint64_t completed_ns = monotonic_ns();

        if (!slot || !slot->active ||
            worker->events[i].res != shared->config.block_size) {
            fprintf(stderr,
                    "Worker %u: write completion failed: res=%" PRId64
                    " res2=%" PRId64 "\n",
                    worker->id, (int64_t)worker->events[i].res,
                    (int64_t)worker->events[i].res2);
            atomic_fetch_add(&shared->errors, 1);
            atomic_store(&shared->stop, true);
            if (slot) {
                slot->active = false;
            }
            continue;
        }

        slot->active = false;
        if (completed_ns >= shared->measure_start_ns &&
            completed_ns < shared->measure_end_ns) {
            atomic_fetch_add(&shared->measured_bytes,
                             shared->config.block_size);
            atomic_fetch_add(&shared->measured_ios, 1);
            record_latency(worker, completed_ns - slot->submitted_ns);
        }
    }

    return completed;
}

static void *worker_main(void *opaque)
{
    struct worker_state *worker = opaque;
    struct shared_state *shared = worker->shared;
    const struct benchmark_config *config = &shared->config;
    uint64_t zone_index = worker->id;
    uint64_t zone_start = config->offset + zone_index * config->zone_size;
    uint64_t next_offset = zone_start;
    uint64_t completed_zones = 0;
    uint64_t zones_per_worker = shared->total_zones / config->streams;
    uint32_t outstanding = 0;

    sleep_until(shared->start_ns);

    while (true) {
        bool stopping = atomic_load(&shared->stop) ||
                        monotonic_ns() >= shared->measure_end_ns;

        while (!stopping && outstanding < worker->depth &&
               next_offset < zone_start + config->zone_size) {
            if (submit_write(worker, next_offset) != 0) {
                fprintf(stderr, "Worker %u: io_submit failed: %s\n",
                        worker->id, strerror(errno));
                atomic_fetch_add(&shared->errors, 1);
                atomic_store(&shared->stop, true);
                stopping = true;
                break;
            }
            next_offset += config->block_size;
            outstanding++;
        }

        if (outstanding) {
            int completed = reap_completions(worker, 1, outstanding);

            if (completed < 0) {
                fprintf(stderr, "Worker %u: io_getevents failed: %s\n",
                        worker->id, strerror(errno));
                atomic_fetch_add(&shared->errors, 1);
                atomic_store(&shared->stop, true);
                break;
            }
            outstanding -= (uint32_t)completed;
            continue;
        }

        if (stopping) {
            break;
        }

        completed_zones++;
        zone_index = (zone_index + config->streams) % shared->total_zones;
        zone_start = config->offset + zone_index * config->zone_size;
        /* A fresh device needs reclamation only after the first complete pass. */
        if (completed_zones >= zones_per_worker &&
            reclaim_range(shared, zone_start, config->zone_size) != 0) {
            fprintf(stderr, "Worker %u: %s failed at offset %" PRIu64
                    ": %s\n", worker->id,
                    config->mode == MODE_ZNS ? "zone reset" : "discard",
                    zone_start, strerror(errno));
            atomic_fetch_add(&shared->errors, 1);
            atomic_store(&shared->stop, true);
            break;
        }
        if (completed_zones >= zones_per_worker &&
            monotonic_ns() >= shared->measure_start_ns &&
            monotonic_ns() < shared->measure_end_ns) {
            worker->reclamations++;
        }
        next_offset = zone_start;
    }

    while (outstanding) {
        int completed = reap_completions(worker, 1, outstanding);

        if (completed <= 0) {
            break;
        }
        outstanding -= (uint32_t)completed;
    }
    return NULL;
}

static uint64_t percentile_us(struct worker_state *workers, uint32_t count,
                              uint64_t total, double percentile)
{
    uint64_t target = (uint64_t)((double)total * percentile + 0.999999);
    uint64_t cumulative = 0;

    if (!total) {
        return 0;
    }
    if (!target) {
        target = 1;
    }

    for (uint32_t bucket = 0; bucket < LATENCY_BUCKETS; bucket++) {
        for (uint32_t worker = 0; worker < count; worker++) {
            cumulative += workers[worker].latency_histogram[bucket];
        }
        if (cumulative >= target) {
            return bucket;
        }
    }
    return LATENCY_OVERFLOW_US;
}

static int write_summary(const struct shared_state *shared,
                         struct worker_state *workers)
{
    const struct benchmark_config *config = &shared->config;
    char path[4096];
    FILE *stream;
    uint64_t latency_samples = 0;
    uint64_t latency_sum_ns = 0;
    uint64_t reclamations = 0;
    uint64_t bytes = atomic_load(&shared->measured_bytes);
    uint64_t ios = atomic_load(&shared->measured_ios);
    uint64_t errors = atomic_load(&shared->errors);

    for (uint32_t i = 0; i < config->streams; i++) {
        latency_samples += workers[i].latency_samples;
        latency_sum_ns += workers[i].latency_sum_ns;
        reclamations += workers[i].reclamations;
    }

    if (snprintf(path, sizeof(path), "%s/summary.json", config->output_dir) >=
        (int)sizeof(path)) {
        return -1;
    }
    stream = fopen(path, "w");
    if (!stream) {
        return -1;
    }

    fprintf(stream,
            "{\n"
            "  \"mode\": \"%s\",\n"
            "  \"device\": \"%s\",\n"
            "  \"offset_bytes\": %" PRIu64 ",\n"
            "  \"working_set_bytes\": %" PRIu64 ",\n"
            "  \"zone_size_bytes\": %" PRIu64 ",\n"
            "  \"total_zones\": %" PRIu64 ",\n"
            "  \"active_streams\": %u,\n"
            "  \"block_size_bytes\": %u,\n"
            "  \"iodepth\": %u,\n"
            "  \"warmup_seconds\": %u,\n"
            "  \"runtime_seconds\": %u,\n"
            "  \"bytes_completed\": %" PRIu64 ",\n"
            "  \"ios_completed\": %" PRIu64 ",\n"
            "  \"throughput_mib_s\": %.6f,\n"
            "  \"iops\": %.6f,\n"
            "  \"write_latency_mean_us\": %.3f,\n"
            "  \"write_latency_p50_us\": %" PRIu64 ",\n"
            "  \"write_latency_p95_us\": %" PRIu64 ",\n"
            "  \"write_latency_p99_us\": %" PRIu64 ",\n"
            "  \"write_latency_p99_9_us\": %" PRIu64 ",\n"
            "  \"region_reclamations\": %" PRIu64 ",\n"
            "  \"errors\": %" PRIu64 "\n"
            "}\n",
            mode_name(config->mode), config->device, config->offset,
            config->working_set, config->zone_size, shared->total_zones,
            config->streams, config->block_size, config->iodepth,
            config->warmup_seconds, config->runtime_seconds, bytes, ios,
            (double)bytes / MIB / config->runtime_seconds,
            (double)ios / config->runtime_seconds,
            latency_samples ? (double)latency_sum_ns / latency_samples / 1000.0 : 0,
            percentile_us(workers, config->streams, latency_samples, 0.50),
            percentile_us(workers, config->streams, latency_samples, 0.95),
            percentile_us(workers, config->streams, latency_samples, 0.99),
            percentile_us(workers, config->streams, latency_samples, 0.999),
            reclamations, errors);
    fclose(stream);
    return 0;
}

static int initialize_worker(struct worker_state *worker,
                             struct shared_state *shared, uint32_t id,
                             uint32_t depth)
{
    worker->shared = shared;
    worker->id = id;
    worker->depth = depth;
    worker->slots = calloc(depth, sizeof(*worker->slots));
    worker->events = calloc(depth, sizeof(*worker->events));
    worker->latency_histogram = calloc(LATENCY_BUCKETS,
                                       sizeof(*worker->latency_histogram));
    if (!worker->slots || !worker->events || !worker->latency_histogram) {
        return -1;
    }
    if (io_setup(depth, &worker->aio_context) != 0) {
        return -1;
    }

    for (uint32_t i = 0; i < depth; i++) {
        if (posix_memalign(&worker->slots[i].buffer, 4096,
                           shared->config.block_size) != 0) {
            return -1;
        }
        memset(worker->slots[i].buffer, (int)(id + 1),
               shared->config.block_size);
    }
    return 0;
}

static void destroy_worker(struct worker_state *worker)
{
    if (worker->aio_context) {
        io_destroy(worker->aio_context);
    }
    if (worker->slots) {
        for (uint32_t i = 0; i < worker->depth; i++) {
            free(worker->slots[i].buffer);
        }
    }
    free(worker->slots);
    free(worker->events);
    free(worker->latency_histogram);
}

int main(int argc, char **argv)
{
    struct benchmark_config config = {
        .block_size = 65536,
        .streams = 4,
        .iodepth = 32,
        .warmup_seconds = 60,
        .runtime_seconds = 600,
    };
    struct shared_state shared = { .fd = -1 };
    struct worker_state *workers = NULL;
    pthread_t *threads = NULL;
    FILE *throughput = NULL;
    uint64_t device_size;
    char throughput_path[4096];
    bool mode_set = false;
    int option;
    int rc = EXIT_FAILURE;
    static const struct option options[] = {
        { "mode", required_argument, NULL, 'm' },
        { "device", required_argument, NULL, 'd' },
        { "output-dir", required_argument, NULL, 'o' },
        { "offset", required_argument, NULL, 1 },
        { "working-set", required_argument, NULL, 2 },
        { "zone-size", required_argument, NULL, 3 },
        { "bs", required_argument, NULL, 4 },
        { "streams", required_argument, NULL, 5 },
        { "iodepth", required_argument, NULL, 6 },
        { "warmup", required_argument, NULL, 7 },
        { "runtime", required_argument, NULL, 8 },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    /* The wrapper pipes output through tee, so make status lines immediate. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    while ((option = getopt_long(argc, argv, "m:d:o:h", options, NULL)) != -1) {
        switch (option) {
        case 'm':
            if (!strcmp(optarg, "block")) {
                config.mode = MODE_BLOCK;
            } else if (!strcmp(optarg, "zns")) {
                config.mode = MODE_ZNS;
            } else {
                usage(stderr, argv[0]);
                return EXIT_FAILURE;
            }
            mode_set = true;
            break;
        case 'd': config.device = optarg; break;
        case 'o': config.output_dir = optarg; break;
        case 1: config.offset = parse_u64(optarg, "offset"); break;
        case 2: config.working_set = parse_u64(optarg, "working set"); break;
        case 3: config.zone_size = parse_u64(optarg, "zone size"); break;
        case 4: config.block_size = parse_u64(optarg, "block size"); break;
        case 5: config.streams = parse_u64(optarg, "streams"); break;
        case 6: config.iodepth = parse_u64(optarg, "iodepth"); break;
        case 7: config.warmup_seconds = parse_u64(optarg, "warmup"); break;
        case 8: config.runtime_seconds = parse_u64(optarg, "runtime"); break;
        case 'h': usage(stdout, argv[0]); return EXIT_SUCCESS;
        default: usage(stderr, argv[0]); return EXIT_FAILURE;
        }
    }

    if (!mode_set || !config.device || !config.output_dir || !config.working_set ||
        !config.zone_size || !config.block_size || !config.streams ||
        !config.iodepth || !config.runtime_seconds ||
        config.working_set % config.zone_size ||
        config.zone_size % config.block_size ||
        config.iodepth % config.streams ||
        config.working_set / config.zone_size < config.streams ||
        (config.working_set / config.zone_size) % config.streams ||
        config.offset % 4096 || config.block_size % 4096) {
        usage(stderr, argv[0]);
        return EXIT_FAILURE;
    }

    shared.config = config;
    shared.total_zones = config.working_set / config.zone_size;
    shared.fd = open(config.device, O_RDWR | O_DIRECT);
    if (shared.fd < 0) {
        perror("open device");
        return EXIT_FAILURE;
    }
    if (ioctl(shared.fd, BLKGETSIZE64, &device_size) != 0) {
        perror("BLKGETSIZE64");
        goto cleanup;
    }
    if (config.offset + config.working_set < config.offset ||
        config.offset + config.working_set > device_size) {
        fprintf(stderr, "Working set exceeds device capacity\n");
        goto cleanup;
    }

    printf("[atc21-write] Using %" PRIu64
           " initially empty regions; reclamation begins on reuse\n",
           shared.total_zones);

    workers = calloc(config.streams, sizeof(*workers));
    threads = calloc(config.streams, sizeof(*threads));
    if (!workers || !threads) {
        fprintf(stderr, "Could not allocate worker state\n");
        goto cleanup;
    }

    for (uint32_t i = 0; i < config.streams; i++) {
        if (initialize_worker(&workers[i], &shared, i,
                              config.iodepth / config.streams) != 0) {
            fprintf(stderr, "Could not initialize worker %u\n", i);
            goto cleanup;
        }
    }

    if (snprintf(throughput_path, sizeof(throughput_path),
                 "%s/throughput.csv", config.output_dir) >=
        (int)sizeof(throughput_path)) {
        fprintf(stderr, "Output path is too long\n");
        goto cleanup;
    }
    throughput = fopen(throughput_path, "w");
    if (!throughput) {
        perror("open throughput.csv");
        goto cleanup;
    }
    fprintf(throughput, "elapsed_seconds,bytes_completed,mib_per_second\n");

    shared.start_ns = monotonic_ns() + 1000000000ULL;
    shared.measure_start_ns = shared.start_ns +
                              (uint64_t)config.warmup_seconds * 1000000000ULL;
    shared.measure_end_ns = shared.measure_start_ns +
                            (uint64_t)config.runtime_seconds * 1000000000ULL;

    for (uint32_t i = 0; i < config.streams; i++) {
        int result = pthread_create(&threads[i], NULL, worker_main, &workers[i]);

        if (result != 0) {
            fprintf(stderr, "pthread_create failed: %s\n", strerror(result));
            goto cleanup;
        }
    }

    printf("[atc21-write] Warmup: %u seconds\n", config.warmup_seconds);
    sleep_until(shared.measure_start_ns);
    printf("[atc21-write] Measuring: %u seconds\n", config.runtime_seconds);

    uint64_t previous_bytes = 0;
    for (uint32_t second = 1; second <= config.runtime_seconds; second++) {
        uint64_t sample_ns = shared.measure_start_ns +
                             (uint64_t)second * 1000000000ULL;
        uint64_t bytes;
        uint64_t delta;

        sleep_until(sample_ns);
        bytes = atomic_load(&shared.measured_bytes);
        delta = bytes - previous_bytes;
        fprintf(throughput, "%u,%" PRIu64 ",%.6f\n", second, delta,
                (double)delta / MIB);
        fflush(throughput);
        previous_bytes = bytes;

        if (atomic_load(&shared.errors)) {
            break;
        }
        if (second % 60 == 0 || second == config.runtime_seconds) {
            printf("[atc21-write] %u/%u seconds: %.2f MiB/s average\n",
                   second, config.runtime_seconds,
                   (double)bytes / MIB / second);
        }
    }

    atomic_store(&shared.stop, true);
    for (uint32_t i = 0; i < config.streams; i++) {
        pthread_join(threads[i], NULL);
        threads[i] = 0;
    }

    if (write_summary(&shared, workers) != 0) {
        perror("write summary");
        goto cleanup;
    }
    printf("[atc21-write] Complete: %.2f MiB/s, errors=%" PRIuFAST64 "\n",
           (double)atomic_load(&shared.measured_bytes) / MIB /
           config.runtime_seconds,
           atomic_load(&shared.errors));
    rc = atomic_load(&shared.errors) ? EXIT_FAILURE : EXIT_SUCCESS;

cleanup:
    atomic_store(&shared.stop, true);
    if (throughput) {
        fclose(throughput);
    }
    if (threads) {
        for (uint32_t i = 0; i < config.streams; i++) {
            if (threads[i]) {
                pthread_join(threads[i], NULL);
            }
        }
    }
    if (workers) {
        for (uint32_t i = 0; i < config.streams; i++) {
            destroy_worker(&workers[i]);
        }
    }
    free(threads);
    free(workers);
    if (shared.fd >= 0) {
        close(shared.fd);
    }
    return rc;
}
