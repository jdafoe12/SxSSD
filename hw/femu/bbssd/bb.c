#include "../nvme.h"
#include "./ftl.h"
#include "./policy-engine.h"

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
    struct ssd *ssd = n->ssd = g_malloc0(sizeof(struct ssd));

    bb_init_ctrl_str(n);

    ssd->dataplane_started_ptr = &n->dataplane_started;
    ssd->ssdname = (char *)n->devname;
    femu_debug("Starting FEMU in Blackbox-SSD mode ...\n");
    ssd_init(n);
}

static void bb_flip(FemuCtrl *n, NvmeCmd *cmd)
{
    struct ssd *ssd = n->ssd;
    int64_t cdw10 = le64_to_cpu(cmd->cdw10);

    switch (cdw10) {
    case FEMU_ENABLE_GC_DELAY:
        ssd->fb->sp.enable_gc_delay = true;
        femu_log("%s,FEMU GC Delay Emulation [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_GC_DELAY:
        ssd->fb->sp.enable_gc_delay = false;
        femu_log("%s,FEMU GC Delay Emulation [Disabled]!\n", n->devname);
        break;
    case FEMU_ENABLE_DELAY_EMU:
        ssd->fb->sp.pg_rd_lat = 40000;     /* 40us NAND read latency */
        ssd->fb->sp.pg_wr_lat = 200000;    /* 200us NAND program latency */
        ssd->fb->sp.blk_er_lat = 2000000;  /* 2ms NAND erase latency */
        ssd->fb->sp.ch_xfer_lat = 0;
        femu_log("%s,FEMU Delay Emulation [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_DELAY_EMU:
        ssd->fb->sp.pg_rd_lat = 0;
        ssd->fb->sp.pg_wr_lat = 0;
        ssd->fb->sp.blk_er_lat = 0;
        ssd->fb->sp.ch_xfer_lat = 0;
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
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint32_t phase = le32_to_cpu(cmd->cdw10);
    
    /* Store opcode in request for ftl_fill_nvme_event() */
    req->cmd = *cmd;  /* Copy entire command for CDW10-CDW15 access */
    req->slba = 0;    /* Custom commands may not use SLBA */
    req->nlb = 0;     /* Custom commands may not use NLB */
    req->is_write = 0; /* Policy determines data direction */
    req->status = NVME_SUCCESS;

    printf("FEMU: bb_custom_cmd opcode=0x%02x phase=%u prp1=0x%llx prp2=0x%llx\n",
           cmd->opcode, phase,
           (unsigned long long)prp1,
           (unsigned long long)prp2);
    
    /* If command has data transfer, map PRP/SGL */
    /* For now, assume no automatic buffer mapping - policy uses buffer API */
    /* Policies can use copy_request_data/write_request_data for data access */
    
    return NVME_SUCCESS;
}

static uint16_t bb_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                          NvmeRequest *req)
{
    struct ssd *ssd = n->ssd;
    
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

static uint16_t bb_admin_cmd(FemuCtrl *n, NvmeCmd *cmd)
{
    switch (cmd->opcode) {
    case NVME_ADM_CMD_FEMU_FLIP:
        bb_flip(n, cmd);
        return NVME_SUCCESS;
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
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
