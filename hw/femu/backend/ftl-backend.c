#include "./ftl-backend.h"
#include <assert.h>
#include <string.h>

int ftl_backend_init(struct FtlBackend *fb, SsdDramBackend *mbe, const BbCtrlParams *bbp)
{
    if (!fb || !bbp) {
        return -1;
    }

    fb->mbe = mbe;

    struct ssdparams *spp = &fb->sp;

    /* base geometry */
    spp->secsz       = bbp->secsz;
    spp->secs_per_pg = bbp->secs_per_pg;
    spp->pgs_per_blk = bbp->pgs_per_blk;
    spp->blks_per_pl = bbp->blks_per_pl;
    spp->pls_per_lun = bbp->pls_per_lun;
    spp->luns_per_ch = bbp->luns_per_ch;
    spp->nchs        = bbp->nchs;

    /* timing */
    spp->pg_rd_lat   = bbp->pg_rd_lat;
    spp->pg_wr_lat   = bbp->pg_wr_lat;
    spp->blk_er_lat  = bbp->blk_er_lat;
    spp->ch_xfer_lat = bbp->ch_xfer_lat;

    /* GC configuration */
    spp->gc_thres_pcent = bbp->gc_thres_pcent / 100.0;
    spp->gc_thres_pcent_high = bbp->gc_thres_pcent_high / 100.0;
    spp->enable_gc_delay = true;

    /* derived geometry */
    spp->secs_per_blk = spp->secs_per_pg * spp->pgs_per_blk;
    spp->secs_per_pl  = spp->secs_per_blk * spp->blks_per_pl;
    spp->secs_per_lun = spp->secs_per_pl * spp->pls_per_lun;
    spp->secs_per_ch  = spp->secs_per_lun * spp->luns_per_ch;
    spp->tt_secs      = spp->secs_per_ch * spp->nchs;

    spp->pgs_per_pl  = spp->pgs_per_blk * spp->blks_per_pl;
    spp->pgs_per_lun = spp->pgs_per_pl * spp->pls_per_lun;
    spp->pgs_per_ch  = spp->pgs_per_lun * spp->luns_per_ch;
    spp->tt_pgs      = spp->pgs_per_ch * spp->nchs;

    spp->blks_per_lun = spp->blks_per_pl * spp->pls_per_lun;
    spp->blks_per_ch  = spp->blks_per_lun * spp->luns_per_ch;
    spp->tt_blks      = spp->blks_per_ch * spp->nchs;

    spp->pls_per_ch = spp->pls_per_lun * spp->luns_per_ch;
    spp->tt_pls     = spp->pls_per_ch * spp->nchs;
    spp->tt_luns    = spp->luns_per_ch * spp->nchs;

    /* line-level derived counts (kept consistent with ftl.c helpers) */
    spp->blks_per_line = spp->tt_luns;
    spp->pgs_per_line  = spp->blks_per_line * spp->pgs_per_blk;
    spp->secs_per_line = spp->pgs_per_line * spp->secs_per_pg;
    spp->tt_lines      = spp->blks_per_lun;

    /* GC thresholds (based on physical geometry) */
    spp->gc_thres_lines = (int)((1.0 - spp->gc_thres_pcent) * spp->tt_lines);
    spp->gc_thres_lines_high = (int)((1.0 - spp->gc_thres_pcent_high) * spp->tt_lines);

    fb->erase_cnt = g_malloc0(sizeof(int) * spp->tt_blks);

    /* initialize timing metadata (per-LUN/channel availability & GC end times) */
    fb->bt.lun_next_avail = g_malloc0(sizeof(uint64_t) * spp->tt_luns);
    fb->bt.ch_next_avail  = g_malloc0(sizeof(uint64_t) * spp->nchs);

    return 0;
}

static inline uint32_t lun_index(const struct ssdparams *spp,
                                 const struct ppa *ppa)
{
    return ppa->g.ch * spp->luns_per_ch + ppa->g.lun;
}

static inline uint32_t ch_index(const struct ppa *ppa)
{
    return ppa->g.ch;
}

/* Timing-only scheduler using backend metadata (no FTL structs). */
static uint64_t ssd_advance_status(struct FtlBackend *fb, const struct ppa *ppa,
                                   struct FtlBackendEvent *event)
{
    const struct ssdparams *spp = &fb->sp;
    uint32_t lidx = lun_index(spp, ppa);
    uint32_t cidx = ch_index(ppa);
    uint64_t cmd_stime = event && event->stime ? event->stime
                                     : qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    uint64_t nand_stime;
    uint64_t lat = 0;

    switch (event ? event->cmd : FTL_BACKEND_EVENT_READ) {
    case FTL_BACKEND_EVENT_READ:
        nand_stime = fb->bt.lun_next_avail[lidx] < cmd_stime ?
                     cmd_stime : fb->bt.lun_next_avail[lidx];
        fb->bt.lun_next_avail[lidx] = nand_stime + spp->pg_rd_lat;
        lat = fb->bt.lun_next_avail[lidx] - cmd_stime;
        break;

    case FTL_BACKEND_EVENT_WRITE:
        nand_stime = fb->bt.lun_next_avail[lidx] < cmd_stime ?
                     cmd_stime : fb->bt.lun_next_avail[lidx];
        fb->bt.lun_next_avail[lidx] = nand_stime + spp->pg_wr_lat;
        lat = fb->bt.lun_next_avail[lidx] - cmd_stime;
        break;

    case FTL_BACKEND_EVENT_ERASE:
        nand_stime = fb->bt.lun_next_avail[lidx] < cmd_stime ?
                     cmd_stime : fb->bt.lun_next_avail[lidx];
        fb->bt.lun_next_avail[lidx] = nand_stime + spp->blk_er_lat;
        lat = fb->bt.lun_next_avail[lidx] - cmd_stime;
        break;

    default:
        femu_err("Unsupported backend command: 0x%x\n",
                event ? event->cmd : -1);
        break;
    }

    //if (event) {
    //    event->lat = lat;
    //}

    /* Optionally track channel GC/end if you later model channel contention. */
    (void)cidx;
    return lat;
}


static uint64_t ppa2pgidx(const struct ssdparams *spp, const struct ppa *ppa)
{
    assert(spp);
    assert(ppa);
    assert(ppa->g.ch  < (uint64_t)spp->nchs);
    assert(ppa->g.lun < (uint64_t)spp->luns_per_ch);
    assert(ppa->g.pl  < (uint64_t)spp->pls_per_lun);
    assert(ppa->g.blk < (uint64_t)spp->blks_per_pl);
    assert(ppa->g.pg  < (uint64_t)spp->pgs_per_blk);

    const uint64_t pgidx = ppa->g.ch  * (uint64_t)spp->pgs_per_ch  +
                           ppa->g.lun * (uint64_t)spp->pgs_per_lun +
                           ppa->g.pl  * (uint64_t)spp->pgs_per_pl  +
                           ppa->g.blk * (uint64_t)spp->pgs_per_blk +
                           ppa->g.pg;

    assert(pgidx < (uint64_t)spp->tt_pgs);
    return pgidx;
}

static uint64_t pba2blkidx(const struct ssdparams *spp, const struct pba *pba)
{
    assert(spp);
    assert(pba);
    assert(pba->g.ch  < (uint64_t)spp->nchs);
    assert(pba->g.lun < (uint64_t)spp->luns_per_ch);
    assert(pba->g.pl  < (uint64_t)spp->pls_per_lun);
    assert(pba->g.blk < (uint64_t)spp->blks_per_pl);

    const uint64_t blkidx = pba->g.ch  * (uint64_t)spp->blks_per_ch  +
                            pba->g.lun * (uint64_t)spp->blks_per_lun +
                            pba->g.pl  * (uint64_t)spp->blks_per_pl  +
                            pba->g.blk;

    assert(blkidx < (uint64_t)spp->tt_blks);
    return blkidx;
}

static uint64_t *build_offset_list(const struct ssdparams *spp, struct ppa *ppa_list, uint64_t ppa_count,
                                   uint64_t page_size)
{
    if (!spp || !ppa_list || !ppa_count) {
        return NULL;
    }

    uint64_t *offset_list = g_malloc0(sizeof(uint64_t) * ppa_count);
    for (uint64_t i = 0; i < ppa_count; ++i) {
        offset_list[i] = ppa2pgidx(spp, &ppa_list[i]) * page_size;
    }

    return offset_list;
}

static uint64_t calc_first_page_offset(NvmeRequest *req, uint64_t page_size)
{
    if (!req || !req->ns || !page_size) {
        return 0;
    }

    NvmeNamespace *ns = req->ns;
    uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    uint8_t lbads = ns->id_ns.lbaf[lba_index].lbads;
    uint64_t secsz = 1ULL << lbads;

    if (!secsz) {
        return 0;
    }

    uint64_t secs_per_pg = page_size / secsz;
    if (!secs_per_pg) {
        return 0;
    }

    uint64_t sector_offset = req->slba % secs_per_pg;
    return sector_offset * secsz;
}

static int get_read_status(struct FtlBackend *fb, struct ppa page_addr)
{
    return 0; // zero is success. other number is ecc error count.
}

static int get_write_status(struct FtlBackend *fb, struct ppa page_addr)
{
    return 0; // zero is success. other number is failure.
}

static int get_erase_status(struct FtlBackend *fb, struct pba block_addr)
{
    return 0; // zero is success. other number is failure.
}

static void fill_read_event(struct FtlBackend *fb, struct FtlBackendEvent *event, struct ppa *ppa_list, uint64_t count, int lat)
{
    event->cmd = FTL_BACKEND_EVENT_READ;
    event->count = count;
    /* Ownership: upper layer allocates/frees status_list. Backend only fills it. */
    if (event->status_list) {
        for (uint64_t i = 0; i < count; ++i) {
            event->status_list[i] = get_read_status(fb, ppa_list[i]);
        }
    }
    event->lat = lat;
}

static void fill_write_event(struct FtlBackend *fb, struct FtlBackendEvent *event, struct ppa *ppa_list, uint64_t count, int lat)
{
    event->cmd = FTL_BACKEND_EVENT_WRITE;
    event->count = count;
    /* Ownership: upper layer allocates/frees status_list. Backend only fills it. */
    if (event->status_list) {
        for (uint64_t i = 0; i < count; ++i) {
            event->status_list[i] = get_write_status(fb, ppa_list[i]);
        }
    }
    event->lat = lat;
}

static void fill_erase_event(struct FtlBackend *fb, struct FtlBackendEvent *event, struct pba *pba, uint64_t count, int lat)
{
    const struct ssdparams *spp = &fb->sp;
    event->cmd = FTL_BACKEND_EVENT_ERASE;
    event->count = count;
    /* Ownership: upper layer allocates/frees status_list. Backend only fills it. */
    for (uint64_t i = 0; i < count; ++i) {
        const int st = get_erase_status(fb, pba[i]);
        const uint64_t blkidx = pba2blkidx(spp, &pba[i]);

        if (event->status_list) {
            event->status_list[i] = st;
        }

        /* Update persistent physical erase counters on successful erase. */
        if (st == 0 && fb->erase_cnt) {
            fb->erase_cnt[blkidx]++;
        }
    }
    event->lat = lat;
}

int ftl_backend_get_erase_cnt(const struct FtlBackend *fb, const struct pba *pba)
{
    if (!fb || !pba || !fb->erase_cnt) {
        return -1;
    }

    const struct ssdparams *spp = &fb->sp;
    if (pba->g.ch  >= (uint64_t)spp->nchs ||
        pba->g.lun >= (uint64_t)spp->luns_per_ch ||
        pba->g.pl  >= (uint64_t)spp->pls_per_lun ||
        pba->g.blk >= (uint64_t)spp->blks_per_pl) {
        return -1;
    }

    const uint64_t blkidx =
        (uint64_t)pba->g.ch  * (uint64_t)spp->blks_per_ch +
        (uint64_t)pba->g.lun * (uint64_t)spp->blks_per_lun +
        (uint64_t)pba->g.pl  * (uint64_t)spp->blks_per_pl +
        (uint64_t)pba->g.blk;

    if (blkidx >= (uint64_t)spp->tt_blks) {
        return -1;
    }

    return fb->erase_cnt[blkidx];
}

static int ftl_backend_latency(struct FtlBackend *fb, struct ppa *ppa_list,
                               uint64_t ppa_count, struct FtlBackendEvent *event)
{
    if (!fb || !ppa_list || !ppa_count) {
        return 0;
    }

    int max_lat = 0;
    for (uint64_t i = 0; i < ppa_count; ++i) {
        int lat = (int)ssd_advance_status(fb, &ppa_list[i], event);
        if (lat > max_lat) {
            max_lat = lat;
        }
    }
    return max_lat;
}

int ftl_backend_read(struct FtlBackend *fb, NvmeRequest *req, struct ppa *ppa_list,
                     uint64_t ppa_count, uint64_t page_size,
                     struct FtlBackendEvent *event)
{
    if (!fb || !fb->mbe || !req || !ppa_list || !ppa_count || !page_size) {
        return 0;
    }

    uint64_t *offset_list = build_offset_list(&fb->sp, ppa_list, ppa_count, page_size);
    uint64_t first_page_off = calc_first_page_offset(req, page_size);

    if (!offset_list) {
        qemu_sglist_destroy(&req->qsg);
        return 0;
    }

    backend_rw(fb->mbe, &req->qsg, offset_list, ppa_count, false, page_size,
               first_page_off);

    int lat = ftl_backend_latency(fb, ppa_list, ppa_count, event);
    if (event) {
        fill_read_event(fb, event, ppa_list, ppa_count, lat);
    }
    g_free(offset_list);

    return 0;
}

int ftl_backend_write(struct FtlBackend *fb, NvmeRequest *req, struct ppa *ppa_list,
                      uint64_t ppa_count, uint64_t page_size,
                      struct FtlBackendEvent *event)
{
    if (!fb || !fb->mbe || !req || !ppa_list || !ppa_count || !page_size) {
        return 0;
    }

    uint64_t *offset_list = build_offset_list(&fb->sp, ppa_list, ppa_count, page_size);
    uint64_t first_page_off = calc_first_page_offset(req, page_size);

    if (!offset_list) {
        qemu_sglist_destroy(&req->qsg);
        return 0;
    }

    backend_rw(fb->mbe, &req->qsg, offset_list, ppa_count, true, page_size,
               first_page_off);

    int lat = ftl_backend_latency(fb, ppa_list, ppa_count, event);
    if (event) {
        fill_write_event(fb, event, ppa_list, ppa_count, lat);
    }
    g_free(offset_list);
    return 0;
}

// Raw operations

int ftl_backend_raw_read(struct FtlBackend *fb, uint8_t *buffer, struct ppa *ppa_list,
                         uint64_t ppa_count, uint64_t page_size,
                         struct FtlBackendEvent *event)
{
    if (!fb || !fb->mbe || !buffer || !ppa_list || !ppa_count || !page_size) {
        return 0;
    }

    uint64_t *offset_list = build_offset_list(&fb->sp, ppa_list, ppa_count, page_size);
    if (!offset_list) {
        return 0;
    }
    for (uint64_t i = 0; i < ppa_count; ++i) {
        memcpy(buffer + i * page_size, fb->mbe->backend_memory + offset_list[i],
               page_size);
    }

    int lat = ftl_backend_latency(fb, ppa_list, ppa_count, event);
    if (event) {
        fill_read_event(fb, event, ppa_list, ppa_count, lat);
    }
    g_free(offset_list);

    return 0;
}

int ftl_backend_raw_write(struct FtlBackend *fb, uint8_t *buffer, struct ppa *ppa_list,
                          uint64_t ppa_count, uint64_t page_size,
                          struct FtlBackendEvent *event)
{
    if (!fb || !fb->mbe || !buffer || !ppa_list || !ppa_count || !page_size) {
        return 0;
    }

    uint64_t *offset_list = build_offset_list(&fb->sp, ppa_list, ppa_count, page_size);
    if (!offset_list) {
        return 0;
    }
    for (uint64_t i = 0; i < ppa_count; ++i) {
        memcpy(fb->mbe->backend_memory + offset_list[i], buffer + i * page_size,
               page_size);
    }

    int lat = ftl_backend_latency(fb, ppa_list, ppa_count, event);
    if (event) {
        fill_write_event(fb, event, ppa_list, ppa_count, lat);
    }
    g_free(offset_list);

    return 0;
}

// Note: this is the raw operation. The FTL will handle relevant metadata updates.
int ftl_backend_raw_erase(struct FtlBackend *fb, struct pba *pba_list,
                          uint64_t block_count, struct FtlBackendEvent *event)
{
    if (!fb || !fb->mbe || !pba_list || !block_count) {
        return 0;
    }

    const struct ssdparams *spp = &fb->sp;
    uint64_t bytes_per_block =
        (uint64_t)spp->secsz * spp->secs_per_pg * spp->pgs_per_blk;

    for (uint64_t i = 0; i < block_count; ++i) {
        uint64_t blkidx = pba2blkidx(spp, &pba_list[i]);
        memset(fb->mbe->backend_memory + blkidx * bytes_per_block, 0xFF,
               bytes_per_block);
    }

    /* Coarse timing: treat each block as one erase event at (ch,lun). */
    int max_lat = 0;
    for (uint64_t i = 0; i < block_count; ++i) {
        struct ppa ppa = {0};
        ppa.g.ch  = pba_list[i].g.ch;
        ppa.g.lun = pba_list[i].g.lun;
        ppa.g.pl  = pba_list[i].g.pl;
        ppa.g.blk = pba_list[i].g.blk;
        int lat = (int)ssd_advance_status(fb, &ppa, event);
        if (lat > max_lat) {
            max_lat = lat;
        }
    }

    if (event) {
        fill_erase_event(fb, event, pba_list, block_count, max_lat);
    }

    return 0;
}
// TODO: a few existing problems. pba usage in advance_status.
// the correct passing of fb throughout the project/layers needs to be addressed
// need to add the lat parameter to fill event functions


/* OOB management */
int ftl_backend_register_oob_policy(struct FtlBackend *fb, 
                                     const char *policy_name,
                                     size_t required_size,
                                     int *policy_handle_out)
{
    
    if (fb->oob_policy_count >= MAX_OOB_POLICIES) {
        return -1;  /* too many policies */
    }

    if (fb->oob_used_per_page + required_size > fb->oob_size_per_page) {
        return -2;  /* OOB space exhausted */
    }
    
    int handle = fb->oob_policy_count;
    struct OobPolicyRegistration *reg = &fb->oob_policies[handle];
    
    reg->policy_name = strdup(policy_name);
    reg->required_size = required_size;
    reg->offset = fb->oob_used_per_page;  /* assign next available offset */
    reg->active = true;
    
    fb->oob_used_per_page += required_size;
    fb->oob_policy_count++;
    
    *policy_handle_out = handle;
    return 0;
}

void* ftl_backend_get_oob_for_policy(struct FtlBackend *fb, 
                                      struct ppa *ppa,
                                      int policy_handle)
{
    if (policy_handle < 0 || policy_handle >= fb->oob_policy_count) {
        return NULL;
    }
    
    struct OobPolicyRegistration *reg = &fb->oob_policies[policy_handle];
    if (!reg->active) {
        return NULL;
    }
    
    uint64_t page_idx = ppa2pgidx(&fb->sp, ppa);
    size_t base = page_idx * fb->oob_size_per_page;
    
    return &fb->oob_buf[base + reg->offset];
}