#include "./ftl-backend.h"
#include <assert.h>
#include <string.h>

int ftl_backend_init(FtlBackend *fb, const BbCtrlParams *bbp)
{
    if (!fb || !bbp) {
        return -1;
    }

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
static uint64_t ssd_advance_status(FtlBackend *fb, const struct ppa *ppa,
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
        ftl_err("Unsupported backend command: 0x%x\n",
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


uint64_t ppa2pgidx(const struct ssdparams *spp, const struct ppa *ppa)
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

uint64_t pba2blkidx(const struct ssdparams *spp, const struct pba *pba)
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

static uint64_t *build_offset_list(struct ppa *ppa_list, uint64_t ppa_count,
                                   uint64_t page_size)
{
    if (!ppa_list || !ppa_count) {
        return NULL;
    }

    uint64_t *offset_list = g_malloc0(sizeof(uint64_t) * ppa_count);
    for (uint64_t i = 0; i < ppa_count; ++i) {
        offset_list[i] = ppa2pgidx(ppa_list[i]) * page_size;
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

static int get_read_status(FtlBackend *fb, struct ppa page_addr)
{
    return 0; // zero is success. other number is ecc error count.
}

static int get_write_status(FtlBackend *fb, struct ppa page_addr)
{
    return 0; // zero is success. other number is failure.
}

static int get_erase_status(FtlBackend *fb, struct pba block_addr)
{
    return 0; // zero is success. other number is failure.
}

static void fill_read_event(FtlBackend *fb, struct FtlBackendEvent *event, struct ppa *ppa_list, uint64_t count, int lat)
{
    event->type = FTL_BACKEND_EVENT_READ;
    event->count = count;
    event->status_list = g_malloc0(sizeof(int) * count);
    for (uint64_t i = 0; i < count; ++i) {
        event->status_list[i] = get_read_status(fb, ppa_list[i]);
    }
    event->lat = lat;
}

static void fill_write_event(FtlBackend *fb, struct FtlBackendEvent *event, struct ppa *ppa_list, uint64_t count, int lat)
{
    event->type = FTL_BACKEND_EVENT_WRITE;
    event->count = count;
    event->status_list = g_malloc0(sizeof(int) * count);
    for (uint64_t i = 0; i < count; ++i) {
        event->status_list[i] = get_write_status(fb, offset_list[i]);
    }
    event->lat = lat;
}

static void fill_erase_event(FtlBackend *fb, struct FtlBackendEvent *event, struct pba *pba, uint64_t count, int lat)
{
    event->type = FTL_BACKEND_EVENT_ERASE;
    event->count = count;
    event->status_list = g_malloc0(sizeof(int) * count);
    for (uint64_t i = 0; i < count; ++i) {
        event->status_list[i] = get_erase_status(fb, pba[i]);
    }
    event->lat = lat;
}

int ftl_backend_read(SsdDramBackend *mbe, NvmeRequest *req, struct ppa *ppa_list,
                     uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event)
{
    uint64_t *offset_list = build_offset_list(ppn_list, lpn_count, page_size);
    uint64_t first_page_off = calc_first_page_offset(req, page_size);

    if (!offset_list) {
        qemu_sglist_destroy(&req->qsg);
        return 0;
    }

    backend_rw(mbe, &req->qsg, offset_list, lpn_count, false, page_size,
               first_page_off);
    
    int lat = ssd_advance_status(fb, ppa, event);
    fill_read_event(fb, event, offset_list, lpn_count, lat);
    g_free(offset_list);

    return 0;
}

int ftl_backend_write(SsdDramBackend *mbe, NvmeRequest *req, struct ppa *ppa_list,
                      uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event)
{
    uint64_t *offset_list = build_offset_list(ppa_list, ppa_count, page_size);
    uint64_t first_page_off = calc_first_page_offset(req, page_size);

    if (!offset_list) {
        qemu_sglist_destroy(&req->qsg);
        return 0;
    }

    backend_rw(mbe, &req->qsg, offset_list, ppa_count, true, page_size,
               first_page_off);

    int lat = ssd_advance_status(fb, ppa, event);
    fill_write_event(fb, event, offset_list, ppa_count, lat);
    g_free(offset_list);
    return 0;
}

// Raw operations

int ftl_backend_raw_read(SsdDramBackend *mbe, uint8_t *buffer, struct ppa *ppa_list,
                         uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event)
{
    if (!buffer || !ppa_list || !ppa_count || !page_size) {
        return 0;
    }

    uint64_t *offset_list = build_offset_list(ppa_list, ppa_count, page_size);
    if (!offset_list) {
        return 0;
    }
    for (uint64_t i = 0; i < ppa_count; ++i) {
        memcpy(buffer + i * page_size, mbe->logical_space + offset_list[i], page_size);
    }

    int lat = ssd_advance_status(fb, ppa, event);
    fill_read_event(fb, event, offset_list, ppa_count, lat);
    g_free(offset_list);


    return 0;
}

int ftl_backend_raw_write(SsdDramBackend *mbe, uint8_t *buffer, struct ppa *ppa_list,
                          uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event)
{
    if (!buffer || !ppa_list || !ppa_count || !page_size) {
        return 0;
    }

    uint64_t *offset_list = build_offset_list(ppn_list, ppa_count, page_size);
    if (!offset_list) {
        return 0;
    }
    for (uint64_t i = 0; i < ppa_count; ++i) {
        memcpy(mbe->logical_space + offset_list[i], buffer + i * page_size, page_size);
    }

    int lat = ssd_advance_status(fb, ppa, event);
    fill_write_event(fb, event, offset_list, ppa_count, lat);
    g_free(offset_list);

    return 0;
}

// Note: this is the raw operation. The FTL will handle relevant metadata updates.
int ftl_backend_raw_erase(SsdDramBackend *mbe, struct pba *pb, uint64_t block_size, struct FtlBackendEvent *event)
{
    if (!pba || !block_size) {
        return 0;
    }

    for (uint64_t i = 0; i < block_size; ++i) {
        // Erasure sets the block to all 1s.
        memset(mbe->logical_space + pba[i] * block_size, 0xFF, block_size); 
    }

    int lat = ssd_advance_status(fb, pba, event); 
    fill_erase_event(fb, event, pba, block_size, lat);
    g_free(offset_list);
    return 0;
}
// TODO: a few existing problems. pba usage in advance_status.
// the correct passing of fb throughout the project/layers needs to be addressed
// need to add the lat parameter to fill event functions
