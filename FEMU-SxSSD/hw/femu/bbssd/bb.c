#include "../nvme.h"
#include "./policy-api.h"
#include "./policy-engine.h"

static void *bbssd_worker(void *opaque);

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
    raw_flash_set_pswd_transition_notify(
        ssd->raw_flash, pe_dispatch_pswd_transition, ssd->policy_engine);

    if (pe_bootstrap_meta_interface_policy(ssd->policy_engine, ssd) != 0) {
        fprintf(stderr, "[BBSSD] Failed to bootstrap meta-interface policy\n");
        abort();
    }

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

static void bb_flip(FemuCtrl *n, NvmeCmd *cmd)
{
    struct ssd *ssd = n->ssd;
    int64_t cdw10 = le64_to_cpu(cmd->cdw10);

    switch (cdw10) {
    case FEMU_ENABLE_GC_DELAY:
        ssd->raw_flash->sp.enable_gc_delay = true;
        femu_log("%s,FEMU GC Delay Emulation [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_GC_DELAY:
        ssd->raw_flash->sp.enable_gc_delay = false;
        femu_log("%s,FEMU GC Delay Emulation [Disabled]!\n", n->devname);
        break;
    case FEMU_ENABLE_DELAY_EMU:
        ssd->raw_flash->sp.pg_rd_lat = 40000;     /* 40us NAND read latency */
        ssd->raw_flash->sp.pg_wr_lat = 200000;    /* 200us NAND program latency */
        ssd->raw_flash->sp.blk_er_lat = 2000000;  /* 2ms NAND erase latency */
        ssd->raw_flash->sp.ch_xfer_lat = 0;
        femu_log("%s,FEMU Delay Emulation [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_DELAY_EMU:
        ssd->raw_flash->sp.pg_rd_lat = 0;
        ssd->raw_flash->sp.pg_wr_lat = 0;
        ssd->raw_flash->sp.blk_er_lat = 0;
        ssd->raw_flash->sp.ch_xfer_lat = 0;
        femu_log("%s,FEMU Delay Emulation [Disabled]!\n", n->devname);
        break;
    case FEMU_RESET_ACCT:
        n->nr_tt_ios = 0;
        n->nr_tt_late_ios = 0;
        femu_log("%s,Reset tt_late_ios/tt_ios,%lu/%lu\n", n->devname,
                n->nr_tt_late_ios, n->nr_tt_ios);
        break;
    case FEMU_ENABLE_LOG:
        n->print_log = true;
        femu_log("%s,Log print [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_LOG:
        n->print_log = false;
        femu_log("%s,Log print [Disabled]!\n", n->devname);
        break;
    default:
        printf("FEMU:%s,Not implemented flip cmd (%lu)\n", n->devname, cdw10);
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
        bb_flip(n, cmd);
        return NVME_SUCCESS;
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

            if (!ssd->to_ftl[i] || !femu_ring_count(ssd->to_ftl[i])) {
                continue;
            }

            rc = femu_ring_dequeue(ssd->to_ftl[i], (void *)&request, 1);
            assert(rc == 1);
            assert(request);

            policy_event_from_nvme_request(ssd, request, &event);
            latency = pe_dispatch_nvme_cmd(ssd->policy_engine, ssd, &event);
            request->status = event.status;
            request->reqlat = latency;
            request->expire_time += latency;

            rc = femu_ring_enqueue(ssd->to_poller[i], (void *)&request, 1);
            if (rc != 1) {
                fprintf(stderr, "[BBSSD] to_poller enqueue failed\n");
            }

            pe_dispatch_background_event(ssd->policy_engine, ssd);
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
