/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Modified for SxSSD by Josh Dafoe.
 * SxSSD modifications: 2025-12-16 through 2026-08-23.
 * Includes code reorganized from the FEMU BBSSD ftl.c implementation.
 */

#include "../nvme.h"
#include "./policy-api.h"
#include "./policy-engine.h"

static void *bbssd_worker(void *opaque);

#ifdef FEMU_EVAL
#define FEMU_STATS_IDLE_TIMEOUT_MS 10000

static uint64_t thread_cpu_time_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint64_t scaled_controller_time_ns(struct ssd *ssd, uint64_t raw_ns)
{
    uint64_t host_mhz = ssd->stats_ctl.host_mhz;
    uint64_t ctrl_mhz = ssd->stats_ctl.ctrl_mhz;

    if (!host_mhz || !ctrl_mhz) {
        return raw_ns;
    }
    return (raw_ns / ctrl_mhz) * host_mhz +
           ((raw_ns % ctrl_mhz) * host_mhz) / ctrl_mhz;
}

static bool ssd_ftl_rings_empty(FemuCtrl *n)
{
    int i;

    for (i = 1; i <= n->nr_pollers; i++) {
        if (n->to_ftl[i] && femu_ring_count(n->to_ftl[i])) {
            return false;
        }
    }
    return true;
}

/* Returns with stats_ctl.lock held at an FTL phase boundary. */
static int ssd_stats_lock_idle(FemuCtrl *n)
{
    struct ssd *ssd = n->ssd;
    struct ssd_stats_control *ctl = &ssd->stats_ctl;

    qemu_mutex_lock(&ctl->lock);
    while (ctl->handler_active || !ssd_ftl_rings_empty(n)) {
        if (!qemu_cond_timedwait(&ctl->idle_cond, &ctl->lock,
                                 FEMU_STATS_IDLE_TIMEOUT_MS)) {
            qemu_mutex_unlock(&ctl->lock);
            return -ETIMEDOUT;
        }
    }
    return 0;
}

static void ssd_stats_handler_begin(struct ssd *ssd)
{
    qemu_mutex_lock(&ssd->stats_ctl.lock);
    ssd->stats_ctl.handler_active = true;
    qemu_mutex_unlock(&ssd->stats_ctl.lock);
}

static void ssd_stats_handler_end(struct ssd *ssd)
{
    qemu_mutex_lock(&ssd->stats_ctl.lock);
    ssd->stats_ctl.handler_active = false;
    qemu_cond_broadcast(&ssd->stats_ctl.idle_cond);
    qemu_mutex_unlock(&ssd->stats_ctl.lock);
}

static void stats_json_u64(FILE *f, const char *name, uint64_t value,
                           bool trailing_comma)
{
    fprintf(f, "  \"%s\": %" PRIu64 "%s\n", name, value,
            trailing_comma ? "," : "");
}

static int ssd_stats_write_json(FemuCtrl *n, uint32_t run_id)
{
    struct ssd *ssd = n->ssd;
    struct ssdparams *spp = &ssd->raw_flash->sp;
    struct ssd_stats *stats = &ssd->stats_ctl.stats;
    const char *dir = getenv(FEMU_STATS_DIR_ENV);
    uint64_t physical_page_reads;
    uint64_t physical_page_programs;
    char *path = NULL;
    char *tmp_path = NULL;
    FILE *f = NULL;
    int fd = -1;
    int ret = -1;

    if (!dir || !*dir || !g_file_test(dir, G_FILE_TEST_IS_DIR)) {
        fprintf(stderr, "[BBSSD] %s must name an existing directory\n",
                FEMU_STATS_DIR_ENV);
        return -EINVAL;
    }

    path = g_strdup_printf("%s/stats_%" PRIu32 ".json", dir, run_id);
    tmp_path = g_strdup_printf("%s/.stats_%" PRIu32 ".XXXXXX", dir, run_id);
    if (g_file_test(path, G_FILE_TEST_EXISTS)) {
        fprintf(stderr, "[BBSSD] refusing to overwrite evaluation statistics %s\n",
                path);
        ret = -EEXIST;
        goto out;
    }
    fd = g_mkstemp(tmp_path);
    if (fd < 0) {
        ret = -errno;
        goto out;
    }
    f = fdopen(fd, "w");
    if (!f) {
        ret = -errno;
        goto out;
    }
    fd = -1;

    physical_page_reads = stats->host_read_page_reads +
                          stats->rmw_read_page_reads + stats->gc_page_reads;
    physical_page_programs = stats->host_write_page_programs +
                             stats->gc_page_programs;

    fprintf(f, "{\n");
    fprintf(f, "  \"schema_version\": \"femu-bbssd-eval-v1\",\n");
    stats_json_u64(f, "run_id", run_id, true);
    stats_json_u64(f, "logical_capacity_bytes", n->ns_size, true);
    stats_json_u64(f, "physical_capacity_bytes",
                   (uint64_t)spp->tt_secs * spp->secsz, true);
    stats_json_u64(f, "sector_size_bytes", spp->secsz, true);
    stats_json_u64(f, "sectors_per_page", spp->secs_per_pg, true);
    stats_json_u64(f, "pages_per_block", spp->pgs_per_blk, true);
    stats_json_u64(f, "blocks_per_plane", spp->blks_per_pl, true);
    stats_json_u64(f, "planes_per_lun", spp->pls_per_lun, true);
    stats_json_u64(f, "luns_per_channel", spp->luns_per_ch, true);
    stats_json_u64(f, "channels", spp->nchs, true);
    stats_json_u64(f, "page_read_latency_ns", spp->pg_rd_lat, true);
    stats_json_u64(f, "page_program_latency_ns", spp->pg_wr_lat, true);
    stats_json_u64(f, "block_erase_latency_ns", spp->blk_er_lat, true);
    stats_json_u64(f, "gc_threshold_percent", n->bb_params.gc_thres_pcent,
                   true);
    stats_json_u64(f, "gc_high_threshold_percent",
                   n->bb_params.gc_thres_pcent_high, true);
    stats_json_u64(f, "host_mhz", ssd->stats_ctl.host_mhz, true);
    stats_json_u64(f, "ctrl_mhz", ssd->stats_ctl.ctrl_mhz, true);
    stats_json_u64(f, "host_read_cmds", stats->host_read_cmds, true);
    stats_json_u64(f, "host_write_cmds", stats->host_write_cmds, true);
    stats_json_u64(f, "host_trim_cmds", stats->host_trim_cmds, true);
    stats_json_u64(f, "host_read_sectors", stats->host_read_sectors, true);
    stats_json_u64(f, "host_write_sectors", stats->host_write_sectors, true);
    stats_json_u64(f, "host_trim_sectors", stats->host_trim_sectors, true);
    stats_json_u64(f, "host_read_page_reads", stats->host_read_page_reads,
                   true);
    stats_json_u64(f, "host_write_page_programs",
                   stats->host_write_page_programs, true);
    stats_json_u64(f, "host_write_page_spans", stats->host_write_page_spans,
                   true);
    stats_json_u64(f, "full_page_write_spans", stats->full_page_write_spans,
                   true);
    stats_json_u64(f, "partial_write_page_spans",
                   stats->partial_write_page_spans, true);
    stats_json_u64(f, "partial_write_unmapped_page_spans",
                   stats->partial_write_unmapped_page_spans, true);
    stats_json_u64(f, "rmw_read_page_reads", stats->rmw_read_page_reads,
                   true);
    stats_json_u64(f, "gc_page_reads", stats->gc_page_reads, true);
    stats_json_u64(f, "gc_page_programs", stats->gc_page_programs, true);
    stats_json_u64(f, "gc_page_copies", stats->gc_page_copies, true);
    stats_json_u64(f, "gc_pages_migrated", stats->gc_pages_migrated, true);
    stats_json_u64(f, "gc_invocations", stats->gc_invocations, true);
    stats_json_u64(f, "foreground_gc_invocations",
                   stats->foreground_gc_invocations, true);
    stats_json_u64(f, "background_gc_invocations",
                   stats->background_gc_invocations, true);
    stats_json_u64(f, "block_erases", stats->block_erases, true);
    stats_json_u64(f, "physical_page_reads", physical_page_reads, true);
    stats_json_u64(f, "physical_page_programs", physical_page_programs, true);
    stats_json_u64(f, "foreground_handler_cpu_ns_raw",
                   stats->foreground_handler_cpu_ns_raw, true);
    stats_json_u64(f, "foreground_handler_cpu_ns_scaled",
                   stats->foreground_handler_cpu_ns_scaled, true);
    stats_json_u64(f, "background_gc_cpu_ns_raw",
                   stats->background_gc_cpu_ns_raw, true);
    stats_json_u64(f, "background_gc_cpu_ns_scaled",
                   stats->background_gc_cpu_ns_scaled, false);
    fprintf(f, "}\n");

    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        ret = -errno;
        goto out;
    }
    if (fclose(f) != 0) {
        f = NULL;
        ret = -errno;
        goto out;
    }
    f = NULL;
    if (g_rename(tmp_path, path) != 0) {
        ret = -errno;
        goto out;
    }
    ret = 0;
out:
    if (f) {
        fclose(f);
    } else if (fd >= 0) {
        close(fd);
    }
    if (ret && tmp_path) {
        g_unlink(tmp_path);
    }
    g_free(tmp_path);
    g_free(path);
    return ret;
}

int ssd_stats_reset(FemuCtrl *n)
{
    struct ssd_stats_control *ctl = &n->ssd->stats_ctl;
    int ret = ssd_stats_lock_idle(n);

    if (ret) {
        return ret;
    }
    memset(&ctl->stats, 0, sizeof(ctl->stats));
    qemu_mutex_unlock(&ctl->lock);
    return 0;
}

int ssd_stats_dump_json(FemuCtrl *n, uint32_t run_id)
{
    struct ssd_stats_control *ctl = &n->ssd->stats_ctl;
    int ret = ssd_stats_lock_idle(n);

    if (ret) {
        return ret;
    }
    ret = ssd_stats_write_json(n, run_id);
    qemu_mutex_unlock(&ctl->lock);
    return ret;
}

static void ssd_stats_note_write_spans(struct ssd *ssd,
                                       const struct NvmeCommandEvent *event)
{
    const uint64_t sectors_per_page = ssd->raw_flash->sp.secs_per_pg;
    uint64_t current_lba;
    uint64_t end_lba;

    if (!sectors_per_page || !event->nsecs ||
        event->lba > UINT64_MAX - event->nsecs) {
        return;
    }
    current_lba = event->lba;
    end_lba = event->lba + event->nsecs;
    while (current_lba < end_lba) {
        uint64_t page_sector = current_lba % sectors_per_page;
        uint64_t sectors = MIN(sectors_per_page - page_sector,
                               end_lba - current_lba);

        ssd->stats_ctl.stats.host_write_page_spans++;
        if (page_sector == 0 && sectors == sectors_per_page) {
            ssd->stats_ctl.stats.full_page_write_spans++;
        } else {
            ssd->stats_ctl.stats.partial_write_page_spans++;
        }
        current_lba += sectors;
    }
}

static void ssd_stats_note_host_command(struct ssd *ssd,
                                        const struct NvmeCommandEvent *event)
{
    int range_idx;

    switch (event->opcode) {
    case NVME_CMD_READ:
        ssd->stats_ctl.stats.host_read_cmds++;
        ssd->stats_ctl.stats.host_read_sectors += event->nsecs;
        break;
    case NVME_CMD_WRITE:
        ssd->stats_ctl.stats.host_write_cmds++;
        ssd->stats_ctl.stats.host_write_sectors += event->nsecs;
        ssd_stats_note_write_spans(ssd, event);
        break;
    case NVME_CMD_DSM:
        ssd->stats_ctl.stats.host_trim_cmds++;
        for (range_idx = 0; event->req &&
             range_idx < event->req->dsm_nr_ranges; range_idx++) {
            ssd->stats_ctl.stats.host_trim_sectors +=
                le32_to_cpu(event->req->dsm_ranges[range_idx].nlb);
        }
        break;
    default:
        break;
    }
}
#endif

static void bbssd_init_lun(struct nand_lun *lun)
{
    lun->next_lun_avail_time = 0;
    lun->busy = false;
    lun->gc_endtime = 0;
}

static void bbssd_init_channel(struct ssd *ssd, struct ssd_channel *channel)
{
    const struct bbm_geom *geometry = ssd->bbm->geom;

    channel->nluns = geometry->luns_per_ch;
    channel->lun = g_malloc0(sizeof(struct nand_lun) * channel->nluns);
    for (int i = 0; i < channel->nluns; i++) {
        bbssd_init_lun(&channel->lun[i]);
    }
    channel->next_ch_avail_time = 0;
    channel->busy = false;
}

static void bbssd_init(FemuCtrl *n)
{
    struct ssd *ssd = n->ssd;
    struct ssdparams *parameters;

    assert(ssd);
    ssd->ctrl = n;

    ssd->raw_flash = g_malloc0(sizeof(*ssd->raw_flash));
    raw_flash_init(ssd->raw_flash, n->mbe, &n->bb_params);

    ssd->bbm = g_malloc0(sizeof(*ssd->bbm));
    bbm_init(ssd->bbm, &n->bb_params, &ssd->raw_flash->sp);

    parameters = &ssd->raw_flash->sp;
    ssd->ch = g_malloc0(sizeof(struct ssd_channel) * parameters->nchs);
    for (int i = 0; i < parameters->nchs; i++) {
        bbssd_init_channel(ssd, &ssd->ch[i]);
    }

    ssd->policy_engine = pe_create(ssd);
    bbm_set_event_notify(ssd->bbm, pe_dispatch_flash_event,
                         ssd->policy_engine);
    bbm_set_pswd_transition_notify(
        ssd->bbm, pe_dispatch_pswd_transition, ssd->policy_engine);
    bbm_set_error_notify(ssd->bbm, pe_dispatch_flash_error,
                         ssd->policy_engine);

    if (pe_bootstrap_meta_interface_policy(ssd->policy_engine, ssd) != 0) {
        fprintf(stderr, "[BBSSD] Failed to bootstrap meta-interface policy\n");
        abort();
    }

#ifdef FEMU_EVAL
    qemu_mutex_init(&ssd->stats_ctl.lock);
    qemu_cond_init(&ssd->stats_ctl.idle_cond);
    ssd->stats_ctl.host_mhz = n->bb_params.host_mhz;
    ssd->stats_ctl.ctrl_mhz = n->bb_params.ctrl_mhz;
#endif

    qemu_thread_create(&ssd->worker_thread, "FEMU-SxSSD-Thread", bbssd_worker,
                       n,
                       QEMU_THREAD_JOINABLE);
}

static void bb_init_ctrl_str(FemuCtrl *n)
{
    static int fsid_vbb = 0;
    const char *vbbssd_mn = "FEMU BlackBox-SSD Controller";
    const char *vbbssd_sn = "vSSD";

    nvme_set_ctrl_name(n, vbbssd_mn, vbbssd_sn, &fsid_vbb);
}

/* bb <=> black-box */
static void bb_init(FemuCtrl *n, Error **errp)
{
    uint32_t i;
    struct ssd *ssd = n->ssd = g_malloc0(sizeof(struct ssd));

    bb_init_ctrl_str(n);

    ssd->dataplane_started_ptr = &n->dataplane_started;
    ssd->ssdname = (char *)n->devname;
    femu_debug("Starting FEMU in Blackbox-SSD mode ...\n");
    bbssd_init(n);

    /*
     * Bootstrap in an unpublished state so policyctl can resolve and publish
     * the final namespace personality before the guest kernel binds a block
     * namespace. The controller remains reachable via /dev/nvmeX.
     */
    n->id_ctrl.nn = cpu_to_le32(0);
    for (i = 0; i < n->num_namespaces; i++) {
        n->namespaces[i].published = false;
    }
}

static uint16_t bb_flip(FemuCtrl *n, NvmeCmd *cmd)
{
    struct ssd *ssd = n->ssd;
    int64_t cdw10 = le64_to_cpu(cmd->cdw10);

    switch (cdw10) {
    case FEMU_ENABLE_GC_DELAY:
        ssd->raw_flash->sp.enable_gc_delay = true;
        femu_log("%s,FEMU GC Delay Emulation [Enabled]!\n", n->devname);
        return NVME_SUCCESS;
    case FEMU_DISABLE_GC_DELAY:
        ssd->raw_flash->sp.enable_gc_delay = false;
        femu_log("%s,FEMU GC Delay Emulation [Disabled]!\n", n->devname);
        return NVME_SUCCESS;
    case FEMU_ENABLE_DELAY_EMU:
        ssd->raw_flash->sp.pg_rd_lat = 40000;     /* 40us NAND read latency */
        ssd->raw_flash->sp.pg_wr_lat = 200000;    /* 200us NAND program latency */
        ssd->raw_flash->sp.blk_er_lat = 2000000;  /* 2ms NAND erase latency */
        ssd->raw_flash->sp.ch_xfer_lat = 0;
        femu_log("%s,FEMU Delay Emulation [Enabled]!\n", n->devname);
        return NVME_SUCCESS;
    case FEMU_DISABLE_DELAY_EMU:
        ssd->raw_flash->sp.pg_rd_lat = 0;
        ssd->raw_flash->sp.pg_wr_lat = 0;
        ssd->raw_flash->sp.blk_er_lat = 0;
        ssd->raw_flash->sp.ch_xfer_lat = 0;
        femu_log("%s,FEMU Delay Emulation [Disabled]!\n", n->devname);
        return NVME_SUCCESS;
    case FEMU_RESET_ACCT:
        n->nr_tt_ios = 0;
        n->nr_tt_late_ios = 0;
        femu_log("%s,Reset tt_late_ios/tt_ios,%lu/%lu\n", n->devname,
                n->nr_tt_late_ios, n->nr_tt_ios);
        return NVME_SUCCESS;
    case FEMU_ENABLE_LOG:
        n->print_log = true;
        femu_log("%s,Log print [Enabled]!\n", n->devname);
        return NVME_SUCCESS;
    case FEMU_DISABLE_LOG:
        n->print_log = false;
        femu_log("%s,Log print [Disabled]!\n", n->devname);
        return NVME_SUCCESS;
#ifdef FEMU_EVAL
    case FEMU_STATS_RESET:
        return ssd_stats_reset(n) == 0 ? NVME_SUCCESS :
                                        NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    case FEMU_STATS_DUMP:
        return ssd_stats_dump_json(n, le32_to_cpu(cmd->cdw11)) == 0 ?
                   NVME_SUCCESS : NVME_INTERNAL_DEV_ERROR | NVME_DNR;
#endif
    default:
        printf("FEMU:%s,Not implemented flip cmd (%lu)\n", n->devname, cdw10);
        return NVME_SUCCESS;
    }
}

static uint16_t bb_nvme_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeRequest *req)
{
    return nvme_rw(n, ns, cmd, req);
}

static uint16_t bb_custom_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                               NvmeRequest *req)
{
    /* Minimal parsing - just enough to route to FTL thread */
    /* Policy hook will handle all command-specific logic */
    /* Preserve the complete command for policy dispatch. */
    req->cmd = *cmd;  /* Copy entire command for CDW10-CDW15 access */
    req->slba = 0;    /* Custom commands may not use SLBA */
    req->nlb = 0;     /* Custom commands may not use NLB */
    req->is_write = 0; /* Policy determines data direction */
    req->status = NVME_SUCCESS;

    /* If command has data transfer, map PRP/SGL */
    /* For now, assume no automatic buffer mapping - policy uses buffer API */
    /* Policies can use copy_request_data/write_request_data for data access */

    return NVME_SUCCESS;
}

static uint16_t bb_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                          NvmeRequest *req)
{
    struct ssd *ssd = n->ssd;

    if (ns && !ns->published) {
        if (ssd && ssd->policy_engine &&
            pe_has_nvme_hook(ssd->policy_engine, cmd->opcode)) {
            return bb_custom_cmd(n, ns, cmd, req);
        }
        return NVME_INVALID_NSID | NVME_DNR;
    }

    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        return bb_nvme_rw(n, ns, cmd, req);
    default:
        /* Check if policy has registered a handler for this opcode */
        if (ssd && ssd->policy_engine &&
            pe_has_nvme_hook(ssd->policy_engine, cmd->opcode)) {
            /* Policy will handle this - parse as generic command */
            return bb_custom_cmd(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static uint16_t bb_admin_cmd(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    struct ssd *ssd = n->ssd;

    (void)cqe;

    switch (cmd->opcode) {
    case NVME_ADM_CMD_FEMU_FLIP:
        return bb_flip(n, cmd);
    default:
        if (ssd && ssd->policy_engine &&
            pe_has_admin_hook(ssd->policy_engine, cmd->opcode)) {
            struct NvmeCommandEvent event = {
                .opcode = cmd->opcode,
                .is_admin = true,
                .req = NULL,
                .cmd = cmd,
                .cqe = cqe,
                .ctrl = n,
                .status = NVME_SUCCESS,
            };

            pe_dispatch_admin_cmd(ssd->policy_engine, ssd, &event);
            return event.status;
        }
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void *bbssd_worker(void *opaque)
{
    FemuCtrl *n = opaque;
    struct ssd *ssd = n->ssd;
    NvmeRequest *request = NULL;

    while (!*ssd->dataplane_started_ptr) {
        usleep(100000);
    }

    ssd->to_ftl = n->to_ftl;
    ssd->to_poller = n->to_poller;

    while (true) {
        for (int i = 1; i <= n->nr_pollers; i++) {
            struct NvmeCommandEvent event;
            uint64_t latency;
            int rc;
#ifdef FEMU_EVAL
            uint64_t cpu_t0;
            uint64_t cpu_t1;
            uint64_t raw_cpu_ns;
            uint64_t scaled_cpu_ns;
            uint64_t background_t0;
            uint64_t background_t1;
            uint64_t partial_spans_before;
            uint64_t rmw_reads_before;
            uint64_t gc_invocations_before;
#endif

            if (!ssd->to_ftl[i] || !femu_ring_count(ssd->to_ftl[i])) {
                continue;
            }

#ifdef FEMU_EVAL
            ssd_stats_handler_begin(ssd);
#endif
            rc = femu_ring_dequeue(ssd->to_ftl[i], (void *)&request, 1);
            assert(rc == 1);
            assert(request);

#ifdef FEMU_EVAL
            cpu_t0 = thread_cpu_time_ns();
#endif
            policy_event_from_nvme_request(ssd, request, &event);
#ifdef FEMU_EVAL
            partial_spans_before = ssd->stats_ctl.stats.partial_write_page_spans;
            rmw_reads_before = ssd->stats_ctl.stats.rmw_read_page_reads;
            ssd_stats_note_host_command(ssd, &event);
#endif
            latency = pe_dispatch_nvme_cmd(ssd->policy_engine, ssd, &event);
#ifdef FEMU_EVAL
            if (event.opcode == NVME_CMD_WRITE) {
                uint64_t partial_spans =
                    ssd->stats_ctl.stats.partial_write_page_spans -
                    partial_spans_before;
                uint64_t rmw_reads = ssd->stats_ctl.stats.rmw_read_page_reads -
                                     rmw_reads_before;

                if (rmw_reads <= partial_spans) {
                    ssd->stats_ctl.stats.partial_write_unmapped_page_spans +=
                        partial_spans - rmw_reads;
                }
            }
            cpu_t1 = thread_cpu_time_ns();
            raw_cpu_ns = cpu_t1 - cpu_t0;
            scaled_cpu_ns = scaled_controller_time_ns(ssd, raw_cpu_ns);
            ssd->stats_ctl.stats.foreground_handler_cpu_ns_raw += raw_cpu_ns;
            ssd->stats_ctl.stats.foreground_handler_cpu_ns_scaled +=
                scaled_cpu_ns;
            latency += scaled_cpu_ns;
#endif
            request->status = event.status;
            request->reqlat = latency;
            request->expire_time += latency;

            rc = femu_ring_enqueue(ssd->to_poller[i], (void *)&request, 1);
            if (rc != 1) {
                fprintf(stderr, "[BBSSD] to_poller enqueue failed\n");
            }

#ifdef FEMU_EVAL
            gc_invocations_before = ssd->stats_ctl.stats.gc_invocations;
            background_t0 = thread_cpu_time_ns();
#endif
            pe_dispatch_background_event(ssd->policy_engine, ssd);
#ifdef FEMU_EVAL
            background_t1 = thread_cpu_time_ns();
            if (ssd->stats_ctl.stats.gc_invocations != gc_invocations_before) {
                raw_cpu_ns = background_t1 - background_t0;
                ssd->stats_ctl.stats.background_gc_cpu_ns_raw += raw_cpu_ns;
                ssd->stats_ctl.stats.background_gc_cpu_ns_scaled +=
                    scaled_controller_time_ns(ssd, raw_cpu_ns);
            }
            ssd_stats_handler_end(ssd);
#endif
        }
    }

    return NULL;
}

int nvme_register_bbssd(FemuCtrl *n)
{
    n->ext_ops = (FemuExtCtrlOps) {
        .state            = NULL,
        .init             = bb_init,
        .exit             = NULL,
        .rw_check_req     = NULL,
        .admin_cmd        = bb_admin_cmd,
        .io_cmd           = bb_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}
