#include "ftl.h"
#include "../backend/bbssd-backend.h"
#include <errno.h>
#include <string.h>

//#define FEMU_DEBUG_FTL

static void *ftl_thread(void *arg);

void ssd_stats_reset(struct ssd *ssd)
{
    memset(&ssd->stats, 0, sizeof(ssd->stats));
}

void ssd_stats_dump_json(struct ssd *ssd, uint32_t run_id)
{
    const char *dir = getenv(FEMU_STATS_DIR_ENV);
    char path[512];
    FILE *f;

    if (!dir || !*dir) {
        printf("FEMU: ssd_stats_dump_json: %s not set, skipping dump\n",
               FEMU_STATS_DIR_ENV);
        return;
    }

    snprintf(path, sizeof(path), "%s/stats_%u.json", dir, run_id);
    f = fopen(path, "w");
    if (!f) {
        printf("FEMU: ssd_stats_dump_json: failed to open %s: %s\n",
               path, strerror(errno));
        return;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"run_id\": %u,\n", run_id);
    fprintf(f, "  \"host_read_cmds\": %lu,\n",      ssd->stats.host_read_cmds);
    fprintf(f, "  \"host_write_cmds\": %lu,\n",     ssd->stats.host_write_cmds);
    fprintf(f, "  \"host_trim_cmds\": %lu,\n",      ssd->stats.host_trim_cmds);
    fprintf(f, "  \"host_read_sectors\": %lu,\n",   ssd->stats.host_read_sectors);
    fprintf(f, "  \"host_write_sectors\": %lu,\n",  ssd->stats.host_write_sectors);
    fprintf(f, "  \"host_trim_sectors\": %lu,\n",   ssd->stats.host_trim_sectors);
    fprintf(f, "  \"phys_page_reads\": %lu,\n",     ssd->stats.phys_page_reads);
    fprintf(f, "  \"phys_page_programs\": %lu,\n",  ssd->stats.phys_page_programs);
    fprintf(f, "  \"block_erases\": %lu,\n",        ssd->stats.block_erases);
    fprintf(f, "  \"gc_invocations\": %lu,\n",      ssd->stats.gc_invocations);
    fprintf(f, "  \"gc_pages_migrated\": %lu,\n",   ssd->stats.gc_pages_migrated);
    fprintf(f, "  \"foreground_gc_count\": %lu,\n", ssd->stats.foreground_gc_count);
    fprintf(f, "  \"background_gc_count\": %lu,\n", ssd->stats.background_gc_count);
    fprintf(f, "  \"gc_time_ns\": %lu,\n",          ssd->stats.gc_time_ns);
    fprintf(f, "  \"policy_dispatch_time_ns\": %lu,\n", ssd->stats.policy_dispatch_time_ns);
    fprintf(f, "  \"bytes_copied\": %lu\n",         ssd->stats.bytes_copied);
    fprintf(f, "}\n");

    fclose(f);
    printf("FEMU: stats dumped to %s\n", path);
}

static inline bool should_gc(struct ssd *ssd)
{
    return (ssd->lm.free_line_cnt <= ssd->sp.gc_thres_lines);
}

static inline bool should_gc_high(struct ssd *ssd)
{
    return (ssd->lm.free_line_cnt <= ssd->sp.gc_thres_lines_high);
}

static inline struct ppa get_maptbl_ent(struct ssd *ssd, uint64_t lpn)
{
    return ssd->maptbl[lpn];
}

static inline void set_maptbl_ent(struct ssd *ssd, uint64_t lpn, struct ppa *ppa)
{
    ftl_assert(lpn < ssd->sp.tt_pgs);
    ssd->maptbl[lpn] = *ppa;
}

static uint64_t ppa2pgidx(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t pgidx;

    pgidx = ppa->g.ch  * spp->pgs_per_ch  + \
            ppa->g.lun * spp->pgs_per_lun + \
            ppa->g.pl  * spp->pgs_per_pl  + \
            ppa->g.blk * spp->pgs_per_blk + \
            ppa->g.pg;

    ftl_assert(pgidx < spp->tt_pgs);

    return pgidx;
}

static uint32_t build_request_spans(struct ssd *ssd, uint64_t slba, uint32_t nsecs,
                                    BbssdBackendSpan *spans,
                                    struct ppa *ppas, bool *mapped)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t req_end = slba + nsecs;
    uint64_t start_lpn = slba / spp->secs_per_pg;
    uint64_t end_lpn = (req_end - 1) / spp->secs_per_pg;
    uint64_t page_size = (uint64_t)spp->secsz * spp->secs_per_pg;
    uint32_t nr_spans = 0;

    for (uint64_t lpn = start_lpn; lpn <= end_lpn; lpn++) {
        uint64_t page_start = lpn * spp->secs_per_pg;
        uint64_t chunk_start = MAX(slba, page_start);
        uint64_t chunk_end = MIN(req_end, page_start + spp->secs_per_pg);
        uint64_t page_sec_off = chunk_start - page_start;
        BbssdBackendSpan *span = &spans[nr_spans];

        span->len = (chunk_end - chunk_start) * spp->secsz;
        span->page_offset = page_sec_off * spp->secsz;
        span->mapped = mapped[nr_spans];
        span->offset = 0;
        if (span->mapped) {
            span->offset = ppa2pgidx(ssd, &ppas[nr_spans]) * page_size;
        }

        nr_spans++;
    }

    return nr_spans;
}

static int bbssd_rw_one(QEMUSGList *qsg, int *sg_cur_index,
                        dma_addr_t *sg_cur_byte, void *buf,
                        uint32_t len, DMADirection dir)
{
    uint8_t *ptr = buf;

    while (len > 0) {
        dma_addr_t cur_addr;
        dma_addr_t cur_len;
        dma_addr_t sg_avail;

        if (*sg_cur_index >= qsg->nsg) {
            return -EINVAL;
        }

        cur_addr = qsg->sg[*sg_cur_index].base + *sg_cur_byte;
        sg_avail = qsg->sg[*sg_cur_index].len - *sg_cur_byte;
        cur_len = MIN((dma_addr_t)len, sg_avail);

        if (dma_memory_rw(qsg->as, cur_addr, ptr, cur_len, dir,
                          MEMTXATTRS_UNSPECIFIED)) {
            return -EIO;
        }

        *sg_cur_byte += cur_len;
        if (*sg_cur_byte == qsg->sg[*sg_cur_index].len) {
            *sg_cur_byte = 0;
            (*sg_cur_index)++;
        }

        ptr += cur_len;
        len -= cur_len;
    }

    return 0;
}

static inline uint64_t get_rmap_ent(struct ssd *ssd, struct ppa *ppa)
{
    uint64_t pgidx = ppa2pgidx(ssd, ppa);

    return ssd->rmap[pgidx];
}

/* set rmap[page_no(ppa)] -> lpn */
static inline void set_rmap_ent(struct ssd *ssd, uint64_t lpn, struct ppa *ppa)
{
    uint64_t pgidx = ppa2pgidx(ssd, ppa);

    ssd->rmap[pgidx] = lpn;
}

static inline int victim_line_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return (next > curr);
}

static inline pqueue_pri_t victim_line_get_pri(void *a)
{
    return ((struct line *)a)->vpc;
}

static inline void victim_line_set_pri(void *a, pqueue_pri_t pri)
{
    ((struct line *)a)->vpc = pri;
}

static inline size_t victim_line_get_pos(void *a)
{
    return ((struct line *)a)->pos;
}

static inline void victim_line_set_pos(void *a, size_t pos)
{
    ((struct line *)a)->pos = pos;
}

static void ssd_init_lines(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    struct line *line;

    lm->tt_lines = spp->blks_per_pl;
    ftl_assert(lm->tt_lines == spp->tt_lines);
    lm->lines = g_malloc0(sizeof(struct line) * lm->tt_lines);

    QTAILQ_INIT(&lm->free_line_list);
    lm->victim_line_pq = pqueue_init(spp->tt_lines, victim_line_cmp_pri,
            victim_line_get_pri, victim_line_set_pri,
            victim_line_get_pos, victim_line_set_pos);
    QTAILQ_INIT(&lm->full_line_list);

    lm->free_line_cnt = 0;
    for (int i = 0; i < lm->tt_lines; i++) {
        line = &lm->lines[i];
        line->id = i;
        line->ipc = 0;
        line->vpc = 0;
        line->pos = 0;
        /* initialize all the lines as free lines */
        QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
        lm->free_line_cnt++;
    }

    ftl_assert(lm->free_line_cnt == lm->tt_lines);
    lm->victim_line_cnt = 0;
    lm->full_line_cnt = 0;
}

static void ssd_init_write_pointer(struct ssd *ssd)
{
    struct write_pointer *wpp = &ssd->wp;
    struct line_mgmt *lm = &ssd->lm;
    struct line *curline = NULL;

    curline = QTAILQ_FIRST(&lm->free_line_list);
    QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
    lm->free_line_cnt--;

    /* wpp->curline is always our next-to-write super-block */
    wpp->curline = curline;
    wpp->ch = 0;
    wpp->lun = 0;
    wpp->pg = 0;
    wpp->blk = 0;
    wpp->pl = 0;
}

static inline void check_addr(int a, int max)
{
    ftl_assert(a >= 0 && a < max);
}

static struct line *get_next_free_line(struct ssd *ssd)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *curline = NULL;

    curline = QTAILQ_FIRST(&lm->free_line_list);
    if (!curline) {
        ftl_err("No free lines left in [%s] !!!!\n", ssd->ssdname);
        return NULL;
    }

    QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
    lm->free_line_cnt--;
    return curline;
}

static void ssd_advance_write_pointer(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    struct write_pointer *wpp = &ssd->wp;
    struct line_mgmt *lm = &ssd->lm;

    check_addr(wpp->ch, spp->nchs);
    wpp->ch++;
    if (wpp->ch == spp->nchs) {
        wpp->ch = 0;
        check_addr(wpp->lun, spp->luns_per_ch);
        wpp->lun++;
        /* in this case, we should go to next lun */
        if (wpp->lun == spp->luns_per_ch) {
            wpp->lun = 0;
            /* go to next page in the block */
            check_addr(wpp->pg, spp->pgs_per_blk);
            wpp->pg++;
            if (wpp->pg == spp->pgs_per_blk) {
                wpp->pg = 0;
                /* move current line to {victim,full} line list */
                if (wpp->curline->vpc == spp->pgs_per_line) {
                    /* all pgs are still valid, move to full line list */
                    ftl_assert(wpp->curline->ipc == 0);
                    QTAILQ_INSERT_TAIL(&lm->full_line_list, wpp->curline, entry);
                    lm->full_line_cnt++;
                } else {
                    ftl_assert(wpp->curline->vpc >= 0 && wpp->curline->vpc < spp->pgs_per_line);
                    /* there must be some invalid pages in this line */
                    ftl_assert(wpp->curline->ipc > 0);
                    pqueue_insert(lm->victim_line_pq, wpp->curline);
                    lm->victim_line_cnt++;
                }
                /* current line is used up, pick another empty line */
                check_addr(wpp->blk, spp->blks_per_pl);
                wpp->curline = NULL;
                wpp->curline = get_next_free_line(ssd);
                if (!wpp->curline) {
                    /* TODO */
                    abort();
                }
                wpp->blk = wpp->curline->id;
                check_addr(wpp->blk, spp->blks_per_pl);
                /* make sure we are starting from page 0 in the super block */
                ftl_assert(wpp->pg == 0);
                ftl_assert(wpp->lun == 0);
                ftl_assert(wpp->ch == 0);
                /* TODO: assume # of pl_per_lun is 1, fix later */
                ftl_assert(wpp->pl == 0);
            }
        }
    }
}

static struct ppa get_new_page(struct ssd *ssd)
{
    struct write_pointer *wpp = &ssd->wp;
    struct ppa ppa;
    ppa.ppa = 0;
    ppa.g.ch = wpp->ch;
    ppa.g.lun = wpp->lun;
    ppa.g.pg = wpp->pg;
    ppa.g.blk = wpp->blk;
    ppa.g.pl = wpp->pl;
    ftl_assert(ppa.g.pl == 0);

    return ppa;
}

static void check_params(struct ssdparams *spp)
{
    /*
     * we are using a general write pointer increment method now, no need to
     * force luns_per_ch and nchs to be power of 2
     */

    //ftl_assert(is_power_of_2(spp->luns_per_ch));
    //ftl_assert(is_power_of_2(spp->nchs));
}

static void ssd_init_params(struct ssdparams *spp, FemuCtrl *n)
{
    spp->secsz = n->bb_params.secsz; // 512
    spp->secs_per_pg = n->bb_params.secs_per_pg; // 8
    spp->pgs_per_blk = n->bb_params.pgs_per_blk; //256
    spp->blks_per_pl = n->bb_params.blks_per_pl; /* 256 16GB */
    spp->pls_per_lun = n->bb_params.pls_per_lun; // 1
    spp->luns_per_ch = n->bb_params.luns_per_ch; // 8
    spp->nchs = n->bb_params.nchs; // 8

    spp->pg_rd_lat = n->bb_params.pg_rd_lat;
    spp->pg_wr_lat = n->bb_params.pg_wr_lat;
    spp->blk_er_lat = n->bb_params.blk_er_lat;
    spp->ch_xfer_lat = n->bb_params.ch_xfer_lat;

    /* calculated values */
    spp->secs_per_blk = spp->secs_per_pg * spp->pgs_per_blk;
    spp->secs_per_pl = spp->secs_per_blk * spp->blks_per_pl;
    spp->secs_per_lun = spp->secs_per_pl * spp->pls_per_lun;
    spp->secs_per_ch = spp->secs_per_lun * spp->luns_per_ch;
    spp->tt_secs = spp->secs_per_ch * spp->nchs;

    spp->pgs_per_pl = spp->pgs_per_blk * spp->blks_per_pl;
    spp->pgs_per_lun = spp->pgs_per_pl * spp->pls_per_lun;
    spp->pgs_per_ch = spp->pgs_per_lun * spp->luns_per_ch;
    spp->tt_pgs = spp->pgs_per_ch * spp->nchs;

    spp->blks_per_lun = spp->blks_per_pl * spp->pls_per_lun;
    spp->blks_per_ch = spp->blks_per_lun * spp->luns_per_ch;
    spp->tt_blks = spp->blks_per_ch * spp->nchs;

    spp->pls_per_ch =  spp->pls_per_lun * spp->luns_per_ch;
    spp->tt_pls = spp->pls_per_ch * spp->nchs;

    spp->tt_luns = spp->luns_per_ch * spp->nchs;

    /* line is special, put it at the end */
    spp->blks_per_line = spp->tt_luns; /* TODO: to fix under multiplanes */
    spp->pgs_per_line = spp->blks_per_line * spp->pgs_per_blk;
    spp->secs_per_line = spp->pgs_per_line * spp->secs_per_pg;
    spp->tt_lines = spp->blks_per_lun; /* TODO: to fix under multiplanes */

    spp->gc_thres_pcent = n->bb_params.gc_thres_pcent/100.0;
    spp->gc_thres_lines = (int)((1 - spp->gc_thres_pcent) * spp->tt_lines);
    spp->gc_thres_pcent_high = n->bb_params.gc_thres_pcent_high/100.0;
    spp->gc_thres_lines_high = (int)((1 - spp->gc_thres_pcent_high) * spp->tt_lines);
    spp->enable_gc_delay = true;


    check_params(spp);
}

static void ssd_init_nand_page(struct nand_page *pg, struct ssdparams *spp)
{
    pg->nsecs = spp->secs_per_pg;
    pg->sec = g_malloc0(sizeof(nand_sec_status_t) * pg->nsecs);
    for (int i = 0; i < pg->nsecs; i++) {
        pg->sec[i] = SEC_FREE;
    }
    pg->status = PG_FREE;
}

static void ssd_init_nand_blk(struct nand_block *blk, struct ssdparams *spp)
{
    blk->npgs = spp->pgs_per_blk;
    blk->pg = g_malloc0(sizeof(struct nand_page) * blk->npgs);
    for (int i = 0; i < blk->npgs; i++) {
        ssd_init_nand_page(&blk->pg[i], spp);
    }
    blk->ipc = 0;
    blk->vpc = 0;
    blk->erase_cnt = 0;
    blk->wp = 0;
}

static void ssd_init_nand_plane(struct nand_plane *pl, struct ssdparams *spp)
{
    pl->nblks = spp->blks_per_pl;
    pl->blk = g_malloc0(sizeof(struct nand_block) * pl->nblks);
    for (int i = 0; i < pl->nblks; i++) {
        ssd_init_nand_blk(&pl->blk[i], spp);
    }
}

static void ssd_init_nand_lun(struct nand_lun *lun, struct ssdparams *spp)
{
    lun->npls = spp->pls_per_lun;
    lun->pl = g_malloc0(sizeof(struct nand_plane) * lun->npls);
    for (int i = 0; i < lun->npls; i++) {
        ssd_init_nand_plane(&lun->pl[i], spp);
    }
    lun->next_lun_avail_time = 0;
    lun->busy = false;
}

static void ssd_init_ch(struct ssd_channel *ch, struct ssdparams *spp)
{
    ch->nluns = spp->luns_per_ch;
    ch->lun = g_malloc0(sizeof(struct nand_lun) * ch->nluns);
    for (int i = 0; i < ch->nluns; i++) {
        ssd_init_nand_lun(&ch->lun[i], spp);
    }
    ch->next_ch_avail_time = 0;
    ch->busy = 0;
}

static void ssd_init_maptbl(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;

    ssd->maptbl = g_malloc0(sizeof(struct ppa) * spp->tt_pgs);
    for (int i = 0; i < spp->tt_pgs; i++) {
        ssd->maptbl[i].ppa = UNMAPPED_PPA;
    }
}

static void ssd_init_rmap(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;

    ssd->rmap = g_malloc0(sizeof(uint64_t) * spp->tt_pgs);
    for (int i = 0; i < spp->tt_pgs; i++) {
        ssd->rmap[i] = INVALID_LPN;
    }
}

void ssd_init(FemuCtrl *n)
{
    struct ssd *ssd = n->ssd;
    struct ssdparams *spp = &ssd->sp;

    ftl_assert(ssd);

    ssd_init_params(spp, n);
    ssd->mbe = n->mbe;

    /* initialize ssd internal layout architecture */
    ssd->ch = g_malloc0(sizeof(struct ssd_channel) * spp->nchs);
    for (int i = 0; i < spp->nchs; i++) {
        ssd_init_ch(&ssd->ch[i], spp);
    }

    /* initialize maptbl */
    ssd_init_maptbl(ssd);

    /* initialize rmap */
    ssd_init_rmap(ssd);

    /* initialize all the lines */
    ssd_init_lines(ssd);

    /* initialize write pointer, this is how we allocate new pages for writes */
    ssd_init_write_pointer(ssd);

    ftl_assert(n->bb_params.host_mhz > 0);
    ftl_assert(n->bb_params.ctrl_mhz > 0);
    ssd->cpu_scale_factor = (double)n->bb_params.host_mhz /
                            n->bb_params.ctrl_mhz;
    ssd_stats_reset(ssd);

    qemu_thread_create(&ssd->ftl_thread, "FEMU-FTL-Thread", ftl_thread, n,
                       QEMU_THREAD_JOINABLE);
}

static inline bool valid_ppa(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    int ch = ppa->g.ch;
    int lun = ppa->g.lun;
    int pl = ppa->g.pl;
    int blk = ppa->g.blk;
    int pg = ppa->g.pg;
    int sec = ppa->g.sec;

    if (ch >= 0 && ch < spp->nchs && lun >= 0 && lun < spp->luns_per_ch && pl >=
        0 && pl < spp->pls_per_lun && blk >= 0 && blk < spp->blks_per_pl && pg
        >= 0 && pg < spp->pgs_per_blk && sec >= 0 && sec < spp->secs_per_pg)
        return true;

    return false;
}

static inline bool valid_lpn(struct ssd *ssd, uint64_t lpn)
{
    return (lpn < ssd->sp.tt_pgs);
}

static inline bool mapped_ppa(struct ppa *ppa)
{
    return !(ppa->ppa == UNMAPPED_PPA);
}

static inline struct ssd_channel *get_ch(struct ssd *ssd, struct ppa *ppa)
{
    return &(ssd->ch[ppa->g.ch]);
}

static inline struct nand_lun *get_lun(struct ssd *ssd, struct ppa *ppa)
{
    struct ssd_channel *ch = get_ch(ssd, ppa);
    return &(ch->lun[ppa->g.lun]);
}

static inline struct nand_plane *get_pl(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_lun *lun = get_lun(ssd, ppa);
    return &(lun->pl[ppa->g.pl]);
}

static inline struct nand_block *get_blk(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_plane *pl = get_pl(ssd, ppa);
    return &(pl->blk[ppa->g.blk]);
}

static inline struct line *get_line(struct ssd *ssd, struct ppa *ppa)
{
    return &(ssd->lm.lines[ppa->g.blk]);
}

static inline struct nand_page *get_pg(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_block *blk = get_blk(ssd, ppa);
    return &(blk->pg[ppa->g.pg]);
}

static uint64_t ssd_advance_status(struct ssd *ssd, struct ppa *ppa, struct
        nand_cmd *ncmd)
{
    int c = ncmd->cmd;
    uint64_t cmd_stime = (ncmd->stime == 0) ? \
        qemu_clock_get_ns(QEMU_CLOCK_REALTIME) : ncmd->stime;
    uint64_t nand_stime;
    struct ssdparams *spp = &ssd->sp;
    struct nand_lun *lun = get_lun(ssd, ppa);
    uint64_t lat = 0;

    switch (c) {
    case NAND_READ:
        /* read: perform NAND cmd first */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat;
        lat = lun->next_lun_avail_time - cmd_stime;
#if 0
        lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat;

        /* read: then data transfer through channel */
        chnl_stime = (ch->next_ch_avail_time < lun->next_lun_avail_time) ? \
            lun->next_lun_avail_time : ch->next_ch_avail_time;
        ch->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

        lat = ch->next_ch_avail_time - cmd_stime;
#endif
        break;

    case NAND_WRITE:
        /* write: transfer data through channel first */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        if (ncmd->type == USER_IO) {
            lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
        } else {
            lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
        }
        lat = lun->next_lun_avail_time - cmd_stime;

#if 0
        chnl_stime = (ch->next_ch_avail_time < cmd_stime) ? cmd_stime : \
                     ch->next_ch_avail_time;
        ch->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

        /* write: then do NAND program */
        nand_stime = (lun->next_lun_avail_time < ch->next_ch_avail_time) ? \
            ch->next_ch_avail_time : lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;

        lat = lun->next_lun_avail_time - cmd_stime;
#endif
        break;

    case NAND_ERASE:
        /* erase: only need to advance NAND status */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->blk_er_lat;

        lat = lun->next_lun_avail_time - cmd_stime;
        break;

    default:
        ftl_err("Unsupported NAND command: 0x%x\n", c);
    }

    return lat;
}

/* update SSD status about one page from PG_VALID -> PG_INVALID */
static void mark_page_invalid(struct ssd *ssd, struct ppa *ppa)
{
    struct line_mgmt *lm = &ssd->lm;
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    bool was_full_line = false;
    struct line *line;

    /* update corresponding page status */
    pg = get_pg(ssd, ppa);
    ftl_assert(pg->status == PG_VALID);
    pg->status = PG_INVALID;

    /* update corresponding block status */
    blk = get_blk(ssd, ppa);
    ftl_assert(blk->ipc >= 0 && blk->ipc < spp->pgs_per_blk);
    blk->ipc++;
    ftl_assert(blk->vpc > 0 && blk->vpc <= spp->pgs_per_blk);
    blk->vpc--;

    /* update corresponding line status */
    line = get_line(ssd, ppa);
    ftl_assert(line->ipc >= 0 && line->ipc < spp->pgs_per_line);
    if (line->vpc == spp->pgs_per_line) {
        ftl_assert(line->ipc == 0);
        was_full_line = true;
    }
    line->ipc++;
    ftl_assert(line->vpc > 0 && line->vpc <= spp->pgs_per_line);
    /* Adjust the position of the victime line in the pq under over-writes */
    if (line->pos) {
        /* Note that line->vpc will be updated by this call */
        pqueue_change_priority(lm->victim_line_pq, line->vpc - 1, line);
    } else {
        line->vpc--;
    }

    if (was_full_line) {
        /* move line: "full" -> "victim" */
        QTAILQ_REMOVE(&lm->full_line_list, line, entry);
        lm->full_line_cnt--;
        pqueue_insert(lm->victim_line_pq, line);
        lm->victim_line_cnt++;
    }
}

static void mark_page_valid(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    struct line *line;

    /* update page status */
    pg = get_pg(ssd, ppa);
    ftl_assert(pg->status == PG_FREE);
    pg->status = PG_VALID;

    /* update corresponding block status */
    blk = get_blk(ssd, ppa);
    ftl_assert(blk->vpc >= 0 && blk->vpc < ssd->sp.pgs_per_blk);
    blk->vpc++;

    /* update corresponding line status */
    line = get_line(ssd, ppa);
    ftl_assert(line->vpc >= 0 && line->vpc < ssd->sp.pgs_per_line);
    line->vpc++;
}

static void mark_block_free(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = get_blk(ssd, ppa);
    struct nand_page *pg = NULL;

    for (int i = 0; i < spp->pgs_per_blk; i++) {
        /* reset page status */
        pg = &blk->pg[i];
        ftl_assert(pg->nsecs == spp->secs_per_pg);
        pg->status = PG_FREE;
    }

    /* reset block status */
    ftl_assert(blk->npgs == spp->pgs_per_blk);
    blk->ipc = 0;
    blk->vpc = 0;
    blk->erase_cnt++;
    ssd->stats.block_erases++;
}

static void gc_read_page(struct ssd *ssd, struct ppa *ppa)
{
    ssd->stats.phys_page_reads++;
    /* advance ssd status, we don't care about how long it takes */
    if (ssd->sp.enable_gc_delay) {
        struct nand_cmd gcr;
        gcr.type = GC_IO;
        gcr.cmd = NAND_READ;
        gcr.stime = 0;
        ssd_advance_status(ssd, ppa, &gcr);
    }
}

/* move valid page data (already in DRAM) from victim line to a new page */
static uint64_t gc_write_page(struct ssd *ssd, struct ppa *old_ppa)
{
    struct ppa new_ppa;
    struct nand_lun *new_lun;
    uint64_t lpn = get_rmap_ent(ssd, old_ppa);

    ftl_assert(valid_lpn(ssd, lpn));
    new_ppa = get_new_page(ssd);
    /* update maptbl */
    set_maptbl_ent(ssd, lpn, &new_ppa);
    /* update rmap */
    set_rmap_ent(ssd, lpn, &new_ppa);

    mark_page_valid(ssd, &new_ppa);
    ssd->stats.phys_page_programs++;
    ssd->stats.gc_pages_migrated++;

    /* need to advance the write pointer here */
    ssd_advance_write_pointer(ssd);

    if (ssd->sp.enable_gc_delay) {
        struct nand_cmd gcw;
        gcw.type = GC_IO;
        gcw.cmd = NAND_WRITE;
        gcw.stime = 0;
        ssd_advance_status(ssd, &new_ppa, &gcw);
    }

    /* advance per-ch gc_endtime as well */
#if 0
    new_ch = get_ch(ssd, &new_ppa);
    new_ch->gc_endtime = new_ch->next_ch_avail_time;
#endif

    new_lun = get_lun(ssd, &new_ppa);
    new_lun->gc_endtime = new_lun->next_lun_avail_time;

    return 0;
}

static struct line *select_victim_line(struct ssd *ssd, bool force)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *victim_line = NULL;

    victim_line = pqueue_peek(lm->victim_line_pq);
    if (!victim_line) {
        return NULL;
    }

    if (!force && victim_line->ipc < ssd->sp.pgs_per_line / 8) {
        return NULL;
    }

    pqueue_pop(lm->victim_line_pq);
    victim_line->pos = 0;
    lm->victim_line_cnt--;
    /* victim_line is a danggling node now */
    return victim_line;
}

/* here ppa identifies the block we want to clean */
static void clean_one_block(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_page *pg_iter = NULL;
    int cnt = 0;

    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
        ppa->g.pg = pg;
        pg_iter = get_pg(ssd, ppa);
        /* there shouldn't be any free page in victim blocks */
        ftl_assert(pg_iter->status != PG_FREE);
        if (pg_iter->status == PG_VALID) {
            gc_read_page(ssd, ppa);
            /* delay the maptbl update until "write" happens */
            gc_write_page(ssd, ppa);
            cnt++;
        }
    }

    ftl_assert(get_blk(ssd, ppa)->vpc == cnt);
}

static void mark_line_free(struct ssd *ssd, struct ppa *ppa)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *line = get_line(ssd, ppa);
    line->ipc = 0;
    line->vpc = 0;
    /* move this line to free line list */
    QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
    lm->free_line_cnt++;
}

static int do_gc(struct ssd *ssd, bool force)
{
    struct line *victim_line = NULL;
    struct ssdparams *spp = &ssd->sp;
    struct nand_lun *lunp;
    struct ppa ppa;
    int ch, lun;
    uint64_t gc_t0, gc_t1;

    ssd->stats.gc_invocations++;
    if (force) {
        ssd->stats.foreground_gc_count++;
    } else {
        ssd->stats.background_gc_count++;
    }
    ssd->stats.gc_active = true;
    gc_t0 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    victim_line = select_victim_line(ssd, force);
    if (!victim_line) {
        ssd->stats.gc_active = false;
        return -1;
    }

    ppa.g.blk = victim_line->id;
    fprintf(stderr,
            "[GC] victim_eswd=%d valid=%d invalid=%d total=%d valid%%=%.1f invalid%%=%.1f free_cnt=%d victim_cnt=%d full_cnt=%d\n",
            ppa.g.blk, victim_line->vpc, victim_line->ipc, spp->pgs_per_line,
            (100.0 * victim_line->vpc) / spp->pgs_per_line,
            (100.0 * victim_line->ipc) / spp->pgs_per_line,
            ssd->lm.free_line_cnt, ssd->lm.victim_line_cnt,
            ssd->lm.full_line_cnt);

    /* copy back valid data */
    for (ch = 0; ch < spp->nchs; ch++) {
        for (lun = 0; lun < spp->luns_per_ch; lun++) {
            ppa.g.ch = ch;
            ppa.g.lun = lun;
            ppa.g.pl = 0;
            lunp = get_lun(ssd, &ppa);
            clean_one_block(ssd, &ppa);
            mark_block_free(ssd, &ppa);

            if (spp->enable_gc_delay) {
                struct nand_cmd gce;
                gce.type = GC_IO;
                gce.cmd = NAND_ERASE;
                gce.stime = 0;
                ssd_advance_status(ssd, &ppa, &gce);
            }

            lunp->gc_endtime = lunp->next_lun_avail_time;
        }
    }

    /* update line status */
    mark_line_free(ssd, &ppa);
    gc_t1 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    ssd->stats.gc_time_ns += (gc_t1 - gc_t0);
    ssd->stats.gc_active = false;

    return 0;
}

static uint64_t ssd_read(struct ssd *ssd, NvmeRequest *req)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t lba = req->slba;
    int nsecs = req->nlb;
    struct ppa ppa;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + nsecs - 1) / spp->secs_per_pg;
    uint64_t lpn;
    uint64_t sublat, maxlat = 0;
    uint32_t nr_pages = end_lpn - start_lpn + 1;
    struct ppa *read_ppas = g_new0(struct ppa, nr_pages);
    uint64_t *page_idxs = g_new0(uint64_t, nr_pages);
    bool *mapped = g_new0(bool, nr_pages);
    BbssdBackendSpan *spans = g_new0(BbssdBackendSpan, nr_pages);
    uint8_t *temp_buf = g_malloc0((uint64_t)nsecs * spp->secsz);
    uint8_t *page_bufs = g_malloc0((uint64_t)nr_pages * spp->secsz * spp->secs_per_pg);
    uint32_t nr_spans;
    uint32_t page_idx = 0;
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("start_lpn=%"PRIu64",tt_pgs=%d\n", start_lpn, ssd->sp.tt_pgs);
    }

    /* normal IO read path */
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        ppa = get_maptbl_ent(ssd, lpn);
        read_ppas[page_idx] = ppa;
        if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
            page_idx++;
            continue;
        }

        mapped[page_idx] = true;
        page_idxs[page_idx] = ppa2pgidx(ssd, &ppa);
        struct nand_cmd srd;
        srd.type = USER_IO;
        srd.cmd = NAND_READ;
        srd.stime = req->stime;
        ssd->stats.phys_page_reads++;
        sublat = ssd_advance_status(ssd, &ppa, &srd);
        maxlat = (sublat > maxlat) ? sublat : maxlat;
        page_idx++;
    }

    nr_spans = build_request_spans(ssd, lba, nsecs, spans, read_ppas, mapped);
    bbssd_backend_read_pages(ssd->mbe, page_bufs, page_idxs, mapped, nr_pages,
                             spp->secsz * spp->secs_per_pg);
    for (uint32_t i = 0, temp_off = 0; i < nr_spans; i++) {
        if (!spans[i].len) {
            continue;
        }
        memcpy(temp_buf + temp_off,
               page_bufs + (uint64_t)i * spp->secsz * spp->secs_per_pg +
               spans[i].page_offset,
               spans[i].len);
        temp_off += spans[i].len;
    }
    bbssd_rw_one(&req->qsg, &sg_cur_index, &sg_cur_byte, temp_buf,
                 (uint64_t)nsecs * spp->secsz, DMA_DIRECTION_FROM_DEVICE);

    g_free(page_bufs);
    g_free(temp_buf);
    g_free(spans);
    g_free(mapped);
    g_free(page_idxs);
    g_free(read_ppas);

    return maxlat;
}

static uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req)
{
    uint64_t lba = req->slba;
    struct ssdparams *spp = &ssd->sp;
    int len = req->nlb;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + len - 1) / spp->secs_per_pg;
    struct ppa ppa;
    uint64_t lpn;
    uint64_t curlat = 0, maxlat = 0;
    int r;
    uint32_t nr_pages = end_lpn - start_lpn + 1;
    struct ppa *write_ppas = g_new0(struct ppa, nr_pages);
    uint64_t *page_idxs = g_new0(uint64_t, nr_pages);
    bool *mapped = g_new0(bool, nr_pages);
    BbssdBackendSpan *spans = g_new0(BbssdBackendSpan, nr_pages);
    uint8_t *temp_buf = g_malloc0((uint64_t)len * spp->secsz);
    uint8_t *page_bufs = g_malloc0((uint64_t)nr_pages * spp->secsz * spp->secs_per_pg);
    uint32_t nr_spans;
    uint32_t page_idx = 0;
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;

    ssd->stats.bytes_copied += (uint64_t)len * spp->secsz;

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("start_lpn=%"PRIu64",tt_pgs=%d\n", start_lpn, ssd->sp.tt_pgs);
    }

    while (should_gc_high(ssd)) {
        /* perform GC here until !should_gc(ssd) */
        r = do_gc(ssd, true);
        if (r == -1)
            break;
    }

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        ppa = get_maptbl_ent(ssd, lpn);
        if (mapped_ppa(&ppa)) {
            /* update old page information first */
            mark_page_invalid(ssd, &ppa);
            set_rmap_ent(ssd, INVALID_LPN, &ppa);
        }

        /* new write */
        ppa = get_new_page(ssd);
        /* update maptbl */
        set_maptbl_ent(ssd, lpn, &ppa);
        /* update rmap */
        set_rmap_ent(ssd, lpn, &ppa);

        mark_page_valid(ssd, &ppa);
        ssd->stats.phys_page_programs++;
        write_ppas[page_idx] = ppa;
        page_idxs[page_idx] = ppa2pgidx(ssd, &ppa);
        mapped[page_idx] = true;

        /* need to advance the write pointer here */
        ssd_advance_write_pointer(ssd);

        struct nand_cmd swr;
        swr.type = USER_IO;
        swr.cmd = NAND_WRITE;
        swr.stime = req->stime;
        /* get latency statistics */
        curlat = ssd_advance_status(ssd, &ppa, &swr);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
        page_idx++;
    }

    nr_spans = build_request_spans(ssd, lba, len, spans, write_ppas, mapped);
    bbssd_rw_one(&req->qsg, &sg_cur_index, &sg_cur_byte, temp_buf,
                 (uint64_t)len * spp->secsz, DMA_DIRECTION_TO_DEVICE);
    for (uint32_t i = 0, temp_off = 0; i < nr_spans; i++) {
        uint8_t *page = page_bufs + (uint64_t)i * spp->secsz * spp->secs_per_pg;

        if (!spans[i].len) {
            continue;
        }
        memset(page, 0, spp->secsz * spp->secs_per_pg);
        memcpy(page + spans[i].page_offset, temp_buf + temp_off, spans[i].len);
        temp_off += spans[i].len;
    }
    bbssd_backend_write_pages(ssd->mbe, page_bufs, page_idxs, nr_pages,
                              spp->secsz * spp->secs_per_pg);

    g_free(page_bufs);
    g_free(temp_buf);
    g_free(spans);
    g_free(mapped);
    g_free(page_idxs);
    g_free(write_ppas);

    return maxlat;
}

static uint64_t ssd_trim(struct ssd *ssd, NvmeRequest *req)
{
    struct ssdparams *spp = &ssd->sp;
    NvmeDsmRange *ranges = req->dsm_ranges;
    int nr_ranges = req->dsm_nr_ranges;
    // uint32_t attributes = req->dsm_attributes;
    
    int total_trimmed_pages = 0;
    int total_already_invalid = 0;
    int total_out_of_bounds = 0;
    
    if (!ranges || nr_ranges <= 0) {
        printf("TRIM: Invalid ranges or count\n");
        return 0;
    }
    
    // printf("TRIM: Processing %d ranges (attributes=0x%x)\n", nr_ranges, attributes);
    
    for (int range_idx = 0; range_idx < nr_ranges; range_idx++) {
        uint64_t slba = le64_to_cpu(ranges[range_idx].slba);
        uint32_t nlb = le32_to_cpu(ranges[range_idx].nlb);
        // uint32_t cattr = le32_to_cpu(ranges[range_idx].cattr);
        
        uint64_t start_lpn = slba / spp->secs_per_pg;
        uint64_t end_lpn = (slba + nlb - 1) / spp->secs_per_pg;
        uint64_t lpn;
        struct ppa ppa;
        int trimmed_pages = 0;
        int already_invalid = 0;

        // ftl_debug("TRIM Range %d: LBA %lu + %u sectors, LPN range %lu-%lu (%lu pages), cattr=0x%x\n", 
        //        range_idx, slba, nlb, start_lpn, end_lpn, end_lpn - start_lpn + 1, cattr);

        // Boundary check
        if (end_lpn >= spp->tt_pgs) {
            ftl_err("TRIM: Range %d exceeds FTL capacity - end_lpn=%lu, tt_pgs=%d\n", 
                   range_idx, end_lpn, spp->tt_pgs);
            total_out_of_bounds++;
            continue;  // Skip this range, continue with others
        }

        // Process each LPN in this range
        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            ppa = get_maptbl_ent(ssd, lpn);
            
            // Skip already unmapped/invalid pages
            if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
                already_invalid++;
                continue;
            }

            // Invalidate the existing mapped page
            mark_page_invalid(ssd, &ppa);
            
            // Clear reverse mapping
            set_rmap_ent(ssd, INVALID_LPN, &ppa);
            
            // Set mapping table entry as unmapped
            ppa.ppa = UNMAPPED_PPA;
            set_maptbl_ent(ssd, lpn, &ppa);
            
            trimmed_pages++;
        }
        
        total_trimmed_pages += trimmed_pages;
        total_already_invalid += already_invalid;
        
        // ftl_debug("TRIM Range %d: %d pages trimmed, %d already invalid\n", 
        //        range_idx, trimmed_pages, already_invalid);
    }

    // ftl_debug("TRIM: Completed - %d pages trimmed, %d already invalid, %d out of bounds across %d ranges\n", 
    //        total_trimmed_pages, total_already_invalid, total_out_of_bounds, nr_ranges);

    // Free the ranges array
    g_free(ranges);
    req->dsm_ranges = NULL;
    req->dsm_nr_ranges = 0;
    req->dsm_attributes = 0;

    return 0;  // Assume TRIM operations have no NAND latency
}

static void *ftl_thread(void *arg)
{
    FemuCtrl *n = (FemuCtrl *)arg;
    struct ssd *ssd = n->ssd;
    NvmeRequest *req = NULL;
    uint64_t lat = 0;
    int rc;
    int i;

    while (!*(ssd->dataplane_started_ptr)) {
        usleep(100000);
    }

    /* FIXME: not safe, to handle ->to_ftl and ->to_poller gracefully */
    ssd->to_ftl = n->to_ftl;
    ssd->to_poller = n->to_poller;

    while (1) {
        for (i = 1; i <= n->nr_pollers; i++) {
            if (!ssd->to_ftl[i] || !femu_ring_count(ssd->to_ftl[i]))
                continue;

            rc = femu_ring_dequeue(ssd->to_ftl[i], (void *)&req, 1);
            if (rc != 1) {
                printf("FEMU: FTL to_ftl dequeue failed\n");
            }

            ftl_assert(req);
            {
                uint64_t cpu_t0 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
                uint64_t cpu_t1;
                uint64_t cpu_overhead_ns;

                switch (req->cmd.opcode) {
                case NVME_CMD_WRITE:
                    ssd->stats.host_write_cmds++;
                    ssd->stats.host_write_sectors += req->nlb;
                    lat = ssd_write(ssd, req);
                    break;
                case NVME_CMD_READ:
                    ssd->stats.host_read_cmds++;
                    ssd->stats.host_read_sectors += req->nlb;
                    lat = ssd_read(ssd, req);
                    break;
                case NVME_CMD_DSM:
                    if (req->dsm_ranges && req->dsm_nr_ranges > 0) {
                        int range_idx;

                        ssd->stats.host_trim_cmds++;
                        for (range_idx = 0; range_idx < req->dsm_nr_ranges; range_idx++) {
                            ssd->stats.host_trim_sectors +=
                                le32_to_cpu(req->dsm_ranges[range_idx].nlb);
                        }
                        lat = ssd_trim(ssd, req);
                    } else {
                        lat = 0;
                    }
                    break;
                default:
                    lat = 0;
                    break;
                }

                cpu_t1 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
                ssd->stats.policy_dispatch_time_ns += (cpu_t1 - cpu_t0);
                cpu_overhead_ns = (uint64_t)((cpu_t1 - cpu_t0) *
                                             ssd->cpu_scale_factor);
                lat += cpu_overhead_ns;
            }

            req->reqlat = lat;
            req->expire_time += lat;

            rc = femu_ring_enqueue(ssd->to_poller[i], (void *)&req, 1);
            if (rc != 1) {
                ftl_err("FTL to_poller enqueue failed\n");
            }

            /* clean one line if needed (in the background) */
            if (should_gc(ssd)) {
                do_gc(ssd, false);
            }
        }
    }

    return NULL;
}
