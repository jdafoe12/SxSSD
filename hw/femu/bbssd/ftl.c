#include "ftl.h"
#include "bbm.h"
//#include "../backend/ftl-backend.h"

//#define FEMU_DEBUG_FTL

static void *ftl_thread(void *arg);

static inline bool should_gc(struct ssd *ssd)
{
    return (ssd->lm.free_line_cnt <= ssd->fb->sp.gc_thres_lines);
}

static inline bool should_gc_high(struct ssd *ssd)
{
    return (ssd->lm.free_line_cnt <= ssd->fb->sp.gc_thres_lines_high);
}

static inline PseudoPpa get_maptbl_ent(struct ssd *ssd, uint64_t lpn)
{
    return ssd->maptbl[lpn];
}

static inline void set_maptbl_ent(struct ssd *ssd, uint64_t lpn, PseudoPpa *ppa)
{
    ftl_assert(lpn < ssd->bbm->geom->tt_pgs_log);
    ssd->maptbl[lpn] = *ppa;
}

static uint64_t pseudo_ppa2pgidx(struct ssd *ssd, PseudoPpa *ppa)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    uint64_t pgidx;

    pgidx = ppa->g.ch  * geom->pgs_per_ch  + \
            ppa->g.lun * geom->pgs_per_lun + \
            ppa->g.pl  * geom->pgs_per_pl  + \
            ppa->g.blk * geom->pgs_per_blk + \
            ppa->g.pg;

    ftl_assert(pgidx < geom->tt_pgs_log);

    return pgidx;
}

static inline uint64_t get_rmap_ent(struct ssd *ssd, PseudoPpa *ppa)
{
    uint64_t pgidx = pseudo_ppa2pgidx(ssd, ppa);

    return ssd->rmap[pgidx];
}

/* set rmap[page_no(ppa)] -> lpn */
static inline void set_rmap_ent(struct ssd *ssd, uint64_t lpn, PseudoPpa *ppa)
{
    uint64_t pgidx = pseudo_ppa2pgidx(ssd, ppa);

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
    const struct bbm_geom *geom = ssd->bbm->geom;
    struct line_mgmt *lm = &ssd->lm;
    struct line *line;

    lm->tt_lines = geom->blks_per_pl_log;
    ftl_assert(lm->tt_lines == geom->tt_lines);
    lm->lines = g_malloc0(sizeof(struct line) * lm->tt_lines);

    QTAILQ_INIT(&lm->free_line_list);
    lm->victim_line_pq = pqueue_init(geom->tt_lines, victim_line_cmp_pri,
                                     victim_line_get_pri, victim_line_set_pri,
                                     victim_line_get_pos, victim_line_set_pos);
    QTAILQ_INIT(&lm->full_line_list);

    lm->free_line_cnt = 0;
    for (int i = 0; i < geom->tt_lines; i++) {
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
    const struct bbm_geom *geom = ssd->bbm->geom;
    struct write_pointer *wpp = &ssd->wp;
    struct line_mgmt *lm = &ssd->lm;

    check_addr(wpp->ch, geom->nchs);
    wpp->ch++;
    if (wpp->ch == geom->nchs) {
        wpp->ch = 0;
        check_addr(wpp->lun, geom->luns_per_ch);
        wpp->lun++;
        /* in this case, we should go to next lun */
        if (wpp->lun == geom->luns_per_ch) {
            wpp->lun = 0;
            /* go to next page in the block */
            check_addr(wpp->pg, geom->pgs_per_blk);
            wpp->pg++;
            if (wpp->pg == geom->pgs_per_blk) {
                wpp->pg = 0;
                /* move current line to {victim,full} line list */
                if (wpp->curline->vpc == geom->pgs_per_line) {
                    /* all pgs are still valid, move to full line list */
                    ftl_assert(wpp->curline->ipc == 0);
                    QTAILQ_INSERT_TAIL(&lm->full_line_list, wpp->curline, entry);
                    lm->full_line_cnt++;
                } else {
                    ftl_assert(wpp->curline->vpc >= 0 && wpp->curline->vpc < geom->pgs_per_line);
                    /* there must be some invalid pages in this line */
                    ftl_assert(wpp->curline->ipc > 0);
                    pqueue_insert(lm->victim_line_pq, wpp->curline);
                    lm->victim_line_cnt++;
                }
                /* current line is used up, pick another empty line */
                check_addr(wpp->blk, geom->blks_per_pl_log);
                wpp->curline = NULL;
                wpp->curline = get_next_free_line(ssd);
                if (!wpp->curline) {
                    /* TODO */
                    abort();
                }
                wpp->blk = wpp->curline->id;
                check_addr(wpp->blk, geom->blks_per_pl_log);
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

static PseudoPpa get_new_page(struct ssd *ssd)
{
    struct write_pointer *wpp = &ssd->wp;
    PseudoPpa ppa;
    ppa.g.ch = wpp->ch;
    ppa.g.lun = wpp->lun;
    ppa.g.pl = wpp->pl;
    ppa.g.blk = wpp->blk;
    ppa.g.pg = wpp->pg;
    ftl_assert(ppa.g.pl == 0);

    return ppa;
}

/* Commented out - no longer needed with refactored backend
static void check_params(struct ssdparams *spp)
{
    // we are using a general write pointer increment method now, no need to
    // force luns_per_ch and nchs to be power of 2
    //ftl_assert(is_power_of_2(spp->luns_per_ch));
    //ftl_assert(is_power_of_2(spp->nchs));
}
*/

// static void ssd_init_params(struct ssdparams *spp, FemuCtrl *n)
// {
//     const BbCtrlParams *bbp = &n->bb_params;
//     spp->secsz = bbp->secsz; // 512
//     spp->secs_per_pg = bbp->secs_per_pg; // 8
//     spp->pgs_per_blk = bbp->pgs_per_blk; //256

//     int blks_per_pl_phys = bbp->blks_per_pl; /* physical blocks per plane */
//     int reserved_blks = (blks_per_pl_phys * bbp->op_pct) / 100;
//     if (reserved_blks >= blks_per_pl_phys && blks_per_pl_phys > 0) {
//         reserved_blks = blks_per_pl_phys - 1; /* keep at least one logical block */
//     }
//     int blks_per_pl_log = blks_per_pl_phys - reserved_blks;

//     spp->blks_per_pl = blks_per_pl_log; /* logical blocks per plane */
//     spp->pls_per_lun = bbp->pls_per_lun; // 1
//     spp->luns_per_ch = bbp->luns_per_ch; // 8
//     spp->nchs = bbp->nchs; // 8

//     spp->pg_rd_lat = bbp->pg_rd_lat;
//     spp->pg_wr_lat = bbp->pg_wr_lat;
//     spp->blk_er_lat = bbp->blk_er_lat;
//     spp->ch_xfer_lat = bbp->ch_xfer_lat;

//     /* calculated values */
//     spp->secs_per_blk = spp->secs_per_pg * spp->pgs_per_blk;
//     spp->secs_per_pl = spp->secs_per_blk * spp->blks_per_pl;
//     spp->secs_per_lun = spp->secs_per_pl * spp->pls_per_lun;
//     spp->secs_per_ch = spp->secs_per_lun * spp->luns_per_ch;
//     spp->tt_secs = spp->secs_per_ch * spp->nchs;

//     spp->pgs_per_pl = spp->pgs_per_blk * spp->blks_per_pl;
//     spp->pgs_per_lun = spp->pgs_per_pl * spp->pls_per_lun;
//     spp->pgs_per_ch = spp->pgs_per_lun * spp->luns_per_ch;
//     spp->tt_pgs = spp->pgs_per_ch * spp->nchs;

//     spp->blks_per_lun = spp->blks_per_pl * spp->pls_per_lun; /* logical */
//     spp->blks_per_ch = spp->blks_per_lun * spp->luns_per_ch;
//     spp->tt_blks = spp->blks_per_ch * spp->nchs;

//     spp->pls_per_ch =  spp->pls_per_lun * spp->luns_per_ch;
//     spp->tt_pls = spp->pls_per_ch * spp->nchs;

//     spp->tt_luns = spp->luns_per_ch * spp->nchs;

//     /* line is special, put it at the end */
//     spp->blks_per_line = spp->tt_luns; /* TODO: to fix under multiplanes */
//     spp->pgs_per_line = spp->blks_per_line * spp->pgs_per_blk;
//     spp->secs_per_line = spp->pgs_per_line * spp->secs_per_pg;
//     spp->tt_lines = spp->blks_per_lun; /* TODO: to fix under multiplanes */

//     spp->gc_thres_pcent = n->bb_params.gc_thres_pcent/100.0;
//     spp->gc_thres_lines = (int)((1 - spp->gc_thres_pcent) * spp->tt_lines);
//     spp->gc_thres_pcent_high = n->bb_params.gc_thres_pcent_high/100.0;
//     spp->gc_thres_lines_high = (int)((1 - spp->gc_thres_pcent_high) * spp->tt_lines);
//     spp->enable_gc_delay = true;


//     check_params(spp);
// }

static void ssd_init_nand_page(struct nand_page *pg, const struct bbm_geom *geom)
{
    pg->nsecs = geom->secs_per_pg;
    pg->sec = g_malloc0(sizeof(nand_sec_status_t) * pg->nsecs);
    for (int i = 0; i < pg->nsecs; i++) {
        pg->sec[i] = SEC_FREE;
    }
    pg->status = PG_FREE;
}

static void ssd_init_nand_blk(struct nand_block *blk, const struct bbm_geom *geom)
{
    blk->npgs = geom->pgs_per_blk;
    blk->pg = g_malloc0(sizeof(struct nand_page) * blk->npgs);
    for (int i = 0; i < blk->npgs; i++) {
        ssd_init_nand_page(&blk->pg[i], geom);
    }
    blk->ipc = 0;
    blk->vpc = 0;
 //   blk->erase_cnt = 0;
    blk->wp = 0;
}

static void ssd_init_nand_plane(struct ssd *ssd, struct nand_plane *pl)
{
    /* BBSSD: model only the logical block address space (exclude OP/reserved). */
    const struct bbm_geom *geom = ssd->bbm->geom;
    pl->nblks = geom->blks_per_pl_log;
    pl->blk = g_malloc0(sizeof(struct nand_block) * pl->nblks);
    for (int i = 0; i < pl->nblks; i++) {
        ssd_init_nand_blk(&pl->blk[i], geom);
    }
}

static void ssd_init_nand_lun(struct ssd *ssd, struct nand_lun *lun)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    lun->npls = geom->pls_per_lun;
    lun->pl = g_malloc0(sizeof(struct nand_plane) * lun->npls);
    for (int i = 0; i < lun->npls; i++) {
        ssd_init_nand_plane(ssd, &lun->pl[i]);
    }
    lun->next_lun_avail_time = 0;
    lun->busy = false;
}

static void ssd_init_ch(struct ssd *ssd, struct ssd_channel *ch)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    ch->nluns = geom->luns_per_ch;
    ch->lun = g_malloc0(sizeof(struct nand_lun) * ch->nluns);
    for (int i = 0; i < ch->nluns; i++) {
        ssd_init_nand_lun(ssd, &ch->lun[i]);
    }
    ch->next_ch_avail_time = 0;
    ch->busy = 0;
}

static void ssd_init_maptbl(struct ssd *ssd)
{
    struct bbm_geom *geom = ssd->bbm->geom;

    ssd->maptbl = g_malloc0(sizeof(PseudoPpa) * geom->tt_pgs_log);
    for (int i = 0; i < geom->tt_pgs_log; i++) {
        ssd->maptbl[i].ppa = UNMAPPED_PPA; // The mapping table is fairly simple. Just a list of ppa, indexed by lpn.
    }
}

static void ssd_init_rmap(struct ssd *ssd)
{
    const struct bbm_geom *geom = ssd->bbm->geom;

    ssd->rmap = g_malloc0(sizeof(uint64_t) * geom->tt_pgs_log);
    for (int i = 0; i < geom->tt_pgs_log; i++) {
        ssd->rmap[i] = INVALID_LPN;
    }
}

/* TODO: I think this does not belong in ftl.c? */
void ssd_init(FemuCtrl *n)
{
    struct ssd *ssd = n->ssd;
    struct ssdparams *spp = &ssd->fb->sp;

    ftl_assert(ssd);

    /* Initialize backend timing/error model */
    if (!ssd->fb) {
        ssd->fb = g_malloc0(sizeof(struct FtlBackend));
    }
    ftl_backend_init(ssd->fb, n->mbe, &n->bb_params); /* Note that fb is part of ssd. 
                                                * Additionally, ssdParams is part of fb and thus hidden from the higher
                                                * ftl layers. 
                                                * */
    if (!ssd->bbm) {
        ssd->bbm = g_malloc0(sizeof(*ssd->bbm));
    }
    bbm_init(ssd->bbm, &n->bb_params, &ssd->fb->sp);

   // ssd_init_params(spp, n); // removed becuase it is handled in the backend. The ssdParams are relevant to hardware geometry. 

    /* initialize ssd pseudophysical internal layout architecture */
    ssd->ch = g_malloc0(sizeof(struct ssd_channel) * spp->nchs);
    for (int i = 0; i < spp->nchs; i++) {
        ssd_init_ch(ssd, &ssd->ch[i]); 
    }

    /* initialize pseudophysical maptbl */
    ssd_init_maptbl(ssd); 

    /* initialize pseudophysical rmap */
    ssd_init_rmap(ssd); 

    /* initialize all the pseudophysical lines */
    ssd_init_lines(ssd); 

    /* initialize write pointer, this is how we allocate new pages for writes */
    ssd_init_write_pointer(ssd); 

    qemu_thread_create(&ssd->ftl_thread, "FEMU-FTL-Thread", ftl_thread, n,
                       QEMU_THREAD_JOINABLE);
}

// Checks that the ppa is in range. 
static inline bool valid_ppa(struct ssd *ssd, PseudoPpa *ppa)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    int ch = ppa->g.ch;
    int lun = ppa->g.lun;
    int pl = ppa->g.pl;
    int blk = ppa->g.blk;
    int pg = ppa->g.pg;
    int sec = ppa->g.sec;

    if (ch >= 0 && ch < geom->nchs && lun >= 0 && lun < geom->luns_per_ch && pl >=
        0 && pl < geom->pls_per_lun && blk >= 0 && blk < geom->blks_per_pl_log && pg
        >= 0 && pg < geom->pgs_per_blk && sec >= 0 && sec < geom->secs_per_pg)
        return true;

    return false;
}

static inline bool valid_lpn(struct ssd *ssd, uint64_t lpn)
{
    return (lpn < ssd->bbm->geom->tt_pgs_log);
}

static inline bool mapped_ppa(PseudoPpa *ppa)
{
    return !(ppa->ppa == UNMAPPED_PPA);
}

static inline struct ssd_channel *get_ch(struct ssd *ssd, PseudoPpa *ppa)
{
    return &(ssd->ch[ppa->g.ch]);
}

static inline struct nand_lun *get_lun(struct ssd *ssd, PseudoPpa *ppa)
{
    struct ssd_channel *ch = get_ch(ssd, ppa);
    return &(ch->lun[ppa->g.lun]);
}

static inline struct nand_plane *get_pl(struct ssd *ssd, PseudoPpa *ppa)
{
    struct nand_lun *lun = get_lun(ssd, ppa);
    return &(lun->pl[ppa->g.pl]);
}

static inline struct nand_block *get_blk(struct ssd *ssd, PseudoPpa *ppa)
{
    struct nand_plane *pl = get_pl(ssd, ppa);
    return &(pl->blk[ppa->g.blk]);
}

static inline struct line *get_line(struct ssd *ssd, PseudoPpa *ppa)
{
    return &(ssd->lm.lines[ppa->g.blk]);
}

static inline struct nand_page *get_pg(struct ssd *ssd, PseudoPpa *ppa)
{
    struct nand_block *blk = get_blk(ssd, ppa);
    return &(blk->pg[ppa->g.pg]);
}


// This is purely timing simulation, given a nand command 
// static uint64_t ssd_advance_status(struct ssd *ssd, PseudoPpa *ppa, struct
//         nand_cmd *ncmd)
// {
//     int c = ncmd->cmd;
//     uint64_t cmd_stime = (ncmd->stime == 0) ?
//         qemu_clock_get_ns(QEMU_CLOCK_REALTIME) : ncmd->stime;
//     uint64_t nand_stime;
//     struct ssdparams *spp = &ssd->sp;
//     struct nand_lun *lun = get_lun(ssd, ppa);
//     uint64_t lat = 0;

//     switch (c) {
//     case NAND_READ:
//         /* read: perform NAND cmd first */
//         nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime :
//                      lun->next_lun_avail_time; // This is where parallelism is introduced. We can access different luns at the same time,
//                                                // but a given lun has a time delay to perform the operation
//         lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat; // the lun is now busy
//         lat = lun->next_lun_avail_time - cmd_stime;
// #if 0
//         lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat;

//         /* read: then data transfer through channel */
//         chnl_stime = (ch->next_ch_avail_time < lun->next_lun_avail_time) ?
//             lun->next_lun_avail_time : ch->next_ch_avail_time;
//         ch->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

//         lat = ch->next_ch_avail_time - cmd_stime;
// #endif
//         break;

//     case NAND_WRITE:
//         /* write: transfer data through channel first */
//         nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime :
//                      lun->next_lun_avail_time;
//         if (ncmd->type == USER_IO) {
//             lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
//         } else {
//             lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
//         }
//         lat = lun->next_lun_avail_time - cmd_stime;

// #if 0
//         chnl_stime = (ch->next_ch_avail_time < cmd_stime) ? cmd_stime :
//                      ch->next_ch_avail_time;
//         ch->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

//         /* write: then do NAND program */
//         nand_stime = (lun->next_lun_avail_time < ch->next_ch_avail_time) ?
//             ch->next_ch_avail_time : lun->next_lun_avail_time;
//         lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;

//         lat = lun->next_lun_avail_time - cmd_stime;
// #endif
//         break;

//     case NAND_ERASE:
//         /* erase: only need to advance NAND status */
//         nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime :
//                      lun->next_lun_avail_time;
//         lun->next_lun_avail_time = nand_stime + spp->blk_er_lat;

//         lat = lun->next_lun_avail_time - cmd_stime;
//         break;

//     default:
//         ftl_err("Unsupported NAND command: 0x%x\n", c);
//     }

//     return lat;
// }

/* update SSD status about one page from PG_VALID -> PG_INVALID */
/* Josh: These are completely metadata updates. Part of "mapping" */
static void mark_page_invalid(struct ssd *ssd, PseudoPpa *ppa)
{
    struct line_mgmt *lm = &ssd->lm;
    const struct bbm_geom *geom = ssd->bbm->geom;
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
    ftl_assert(blk->ipc >= 0 && blk->ipc < geom->pgs_per_blk);
    blk->ipc++;
    ftl_assert(blk->vpc > 0 && blk->vpc <= geom->pgs_per_blk);
    blk->vpc--;

    /* update corresponding line status */
    line = get_line(ssd, ppa);
    ftl_assert(line->ipc >= 0 && line->ipc < geom->pgs_per_line);
    if (line->vpc == geom->pgs_per_line) {
        ftl_assert(line->ipc == 0);
        was_full_line = true;
    }
    line->ipc++;
    ftl_assert(line->vpc > 0 && line->vpc <= geom->pgs_per_line);
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

/* Josh: These are completely metadata updates. Part of "mapping" */
static void mark_page_valid(struct ssd *ssd, PseudoPpa *ppa)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    struct line *line;

    /* update page status */
    pg = get_pg(ssd, ppa);
    ftl_assert(pg->status == PG_FREE);
    pg->status = PG_VALID;

    /* update corresponding block status */
    blk = get_blk(ssd, ppa);
    ftl_assert(blk->vpc >= 0 && blk->vpc < geom->pgs_per_blk);
    blk->vpc++;

    /* update corresponding line status */
    line = get_line(ssd, ppa);
    ftl_assert(line->vpc >= 0 && line->vpc < geom->pgs_per_line);
    line->vpc++;
    
    /* Suppress unused variable warning when FEMU_DEBUG_FTL is disabled */
    (void)geom;
}

/* Josh: Note: the calling of this function should be a policy level decision.*/
/* Of course, it is needed as a subfunction for many policies. */
static void mark_block_free(struct ssd *ssd, PseudoPpa *ppa)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    struct nand_block *blk = get_blk(ssd, ppa);
    struct nand_page *pg = NULL;

    for (int i = 0; i < geom->pgs_per_blk; i++) {
        /* reset page status */
        pg = &blk->pg[i];
        ftl_assert(pg->nsecs == geom->secs_per_pg);
        pg->status = PG_FREE;
    }

    /* reset block status */
    ftl_assert(blk->npgs == geom->pgs_per_blk);
    blk->ipc = 0;
    blk->vpc = 0;
  //  blk->erase_cnt++; /* TODO: This is taken care of in the backend.  =*/
}

/* TODO: Again this can be ignored for now because it is policy level, but this really does nothing. 
 * Other than simulate timing, which is handled in the backend now anyways. */
static void gc_read_page(struct ssd *ssd, PseudoPpa *ppa)
{
    /* Read page for GC operation */
    if (ssd->fb->sp.enable_gc_delay) {
        struct FtlBackendEvent event;
        event.cmd = FTL_BACKEND_EVENT_READ;
        event.type = POLICY_IO;
        event.count = 1;
        event.status_list = NULL;
        event.stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        event.lat = 0;

        uint64_t page_size = ssd->fb->sp.secs_per_pg * ssd->fb->sp.secsz;
        /* We don't actually need the data in a buffer for GC, just simulate timing */
        bbm_raw_read(ssd->fb, ssd->bbm, NULL, ppa, 1, page_size, &event);
    }
}

/* move valid page data (already in DRAM) from victim line to a new page */
static uint64_t gc_write_page(struct ssd *ssd, PseudoPpa *old_ppa)
{
    PseudoPpa new_ppa;
    struct nand_lun *new_lun;
    uint64_t lpn = get_rmap_ent(ssd, old_ppa);

    ftl_assert(valid_lpn(ssd, lpn));
    new_ppa = get_new_page(ssd);
    /* update maptbl */
    set_maptbl_ent(ssd, lpn, &new_ppa);
    /* update rmap */
    set_rmap_ent(ssd, lpn, &new_ppa);

    mark_page_valid(ssd, &new_ppa);

    /* need to advance the write pointer here */
    ssd_advance_write_pointer(ssd);

    /* Write page for GC operation */
    if (ssd->fb->sp.enable_gc_delay) {
        struct FtlBackendEvent event;
        event.cmd = FTL_BACKEND_EVENT_WRITE;
        event.type = POLICY_IO;
        event.count = 1;
        event.status_list = NULL;
        event.stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        event.lat = 0;

        uint64_t page_size = ssd->fb->sp.secs_per_pg * ssd->fb->sp.secsz;
        /* We don't actually need to provide data buffer for GC write, just simulate timing */
        bbm_raw_write(ssd->fb, ssd->bbm, NULL, &new_ppa, 1, page_size, &event);

        /* advance per-ch gc_endtime as well */
        new_lun = get_lun(ssd, &new_ppa);
        new_lun->gc_endtime = new_lun->next_lun_avail_time;
    }

    return 0;
}

static struct line *select_victim_line(struct ssd *ssd, bool force)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    struct line_mgmt *lm = &ssd->lm;
    struct line *victim_line = NULL;

    victim_line = pqueue_peek(lm->victim_line_pq);
    if (!victim_line) {
        return NULL;
    }

    if (!force && victim_line->ipc < geom->pgs_per_line / 8) {
        return NULL;
    }

    pqueue_pop(lm->victim_line_pq);
    victim_line->pos = 0;
    lm->victim_line_cnt--;

    /* victim_line is a danggling node now */
    return victim_line;
}

/* here ppa identifies the block we want to clean */
static void clean_one_block(struct ssd *ssd, PseudoPpa *ppa)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    struct nand_page *pg_iter = NULL;
    int cnt = 0;

    for (int pg = 0; pg < geom->pgs_per_blk; pg++) {
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

static void mark_line_free(struct ssd *ssd, PseudoPpa *ppa)
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
    const struct bbm_geom *geom = ssd->bbm->geom;
    struct ssdparams *spp = &ssd->fb->sp;
    struct nand_lun *lunp;
    PseudoPpa ppa;
    int ch, lun;

    victim_line = select_victim_line(ssd, force);
    if (!victim_line) {
        return -1;
    }

    ppa.g.blk = victim_line->id;
    ftl_debug("GC-ing line:%d,ipc=%d,victim=%d,full=%d,free=%d\n", ppa.g.blk,
              victim_line->ipc, ssd->lm.victim_line_cnt, ssd->lm.full_line_cnt,
              ssd->lm.free_line_cnt);

    /* copy back valid data */
    for (ch = 0; ch < geom->nchs; ch++) {
        for (lun = 0; lun < geom->luns_per_ch; lun++) {
            ppa.g.ch = ch;
            ppa.g.lun = lun;
            ppa.g.pl = 0;
            lunp = get_lun(ssd, &ppa);
            clean_one_block(ssd, &ppa);
            mark_block_free(ssd, &ppa);

            /* Erase block for GC operation */
            if (spp->enable_gc_delay) {
                struct FtlBackendEvent event;
                event.cmd = FTL_BACKEND_EVENT_ERASE;
                event.type = POLICY_IO;
                event.count = 1;
                event.status_list = NULL;
                event.stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
                event.lat = 0;

                /* Convert PseudoPpa to PseudoPba for erase (block-level operation) */
                PseudoPba ppba;
                ppba.g.ch = ppa.g.ch;
                ppba.g.lun = ppa.g.lun;
                ppba.g.pl = ppa.g.pl;
                ppba.g.blk = ppa.g.blk;

                bbm_raw_erase(ssd->fb, ssd->bbm, &ppba, 1, &event);

                lunp->gc_endtime = lunp->next_lun_avail_time;
            }
        }
    }

    /* update line status */
    mark_line_free(ssd, &ppa);

    return 0;
}

static uint64_t ssd_read(struct ssd *ssd, NvmeRequest *req)
{
    struct ssdparams *spp = &ssd->fb->sp; 
    const struct bbm_geom *geom = ssd->bbm->geom;
    uint64_t lba = req->slba;
    int nsecs = req->nlb;
    PseudoPpa ppa;
    uint64_t start_lpn = lba / geom->secs_per_pg;
    uint64_t end_lpn = (lba + nsecs - 1) / geom->secs_per_pg;
    uint64_t lpn_cnt = end_lpn - start_lpn + 1;
    uint64_t lpn;

    if (end_lpn >= geom->tt_pgs_log) {
        ftl_err("start_lpn=%"PRIu64",tt_pgs=%"PRIu64"\n", start_lpn, (uint64_t)geom->tt_pgs_log);
    }

    PseudoPpa *ppa_list = g_malloc0(sizeof(PseudoPpa) * lpn_cnt);
    int ppa_idx = 0;
    /* normal IO read path */
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        ppa = get_maptbl_ent(ssd, lpn);
        if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
            //printf("%s,lpn(%" PRId64 ") not mapped to valid ppa\n", ssd->ssdname, lpn);
            //printf("Invalid ppa,ch:%d,lun:%d,blk:%d,pl:%d,pg:%d,sec:%d\n",
            //ppa.g.ch, ppa.g.lun, ppa.g.blk, ppa.g.pl, ppa.g.pg, ppa.g.sec);
            continue;
        }

        ppa_list[ppa_idx++] = ppa;
    }

    /* Create backend event to track latency */
    struct FtlBackendEvent event;
    event.cmd = FTL_BACKEND_EVENT_READ;
    event.type = USER_IO;
    event.count = ppa_idx;
    event.status_list = NULL;  /* Can be allocated if error tracking is needed */
    event.stime = req->stime;
    event.lat = 0;

    uint64_t page_size = spp->secs_per_pg * spp->secsz;
    bbm_read(ssd->fb, ssd->bbm, req, ppa_list, ppa_idx, page_size, &event);
    g_free(ppa_list);

    return event.lat;
}

static uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req)
{
    uint64_t lba = req->slba;
    const struct bbm_geom *geom = ssd->bbm->geom;
    const struct ssdparams *spp = &ssd->fb->sp;
    int len = req->nlb;
    uint64_t start_lpn = lba / spp->secs_per_pg; // so LBA is a sector number? (it seems that sector is a logical concept?)
    uint64_t end_lpn = (lba + len - 1) / spp->secs_per_pg;
    uint64_t lpn_cnt = end_lpn - start_lpn + 1;
    PseudoPpa ppa;
    uint64_t lpn;
    int r;


    PseudoPpa *ppa_list = g_malloc0(sizeof(PseudoPpa) * lpn_cnt);
    int ppa_idx = 0;
    if (end_lpn >= geom->tt_pgs_log) { /* tt_pgs is the total number of pages in the FTL
                                   * however, we should use the logical geometry here not the physical geometry. */
        ftl_err("start_lpn=%"PRIu64",tt_pgs=%"PRIu64"\n", start_lpn, (uint64_t)geom->tt_pgs_log);
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

        ppa_list[ppa_idx++] = ppa;

        /* need to advance the write pointer here */
        ssd_advance_write_pointer(ssd);
    }

    /* Create backend event to track latency */
    struct FtlBackendEvent event;
    event.cmd = FTL_BACKEND_EVENT_WRITE;
    event.type = USER_IO;
    event.count = ppa_idx;
    event.status_list = NULL;  /* Can be allocated if error tracking is needed */
    event.stime = req->stime;
    event.lat = 0;

    /* Call backend to move data. */
    uint64_t page_size = (uint64_t)spp->secs_per_pg * spp->secsz;
    bbm_write(ssd->fb, ssd->bbm, req, ppa_list, ppa_idx, page_size, &event);
    g_free(ppa_list);

    return event.lat;
}

static uint64_t ssd_trim(struct ssd *ssd, NvmeRequest *req)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
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
        
        uint64_t start_lpn = slba / geom->secs_per_pg;
        uint64_t end_lpn = (slba + nlb - 1) / geom->secs_per_pg;
        uint64_t lpn;
        PseudoPpa ppa;
        int trimmed_pages = 0;
        int already_invalid = 0;

        // ftl_debug("TRIM Range %d: LBA %lu + %u sectors, LPN range %lu-%lu (%lu pages), cattr=0x%x\n", 
        //        range_idx, slba, nlb, start_lpn, end_lpn, end_lpn - start_lpn + 1, cattr);

        // Boundary check
        if (end_lpn >= geom->tt_pgs_log) {
            ftl_err("TRIM: Range %d exceeds FTL capacity - end_lpn=%"PRIu64", tt_pgs=%"PRIu64"\n", 
                   range_idx, end_lpn, (uint64_t)geom->tt_pgs_log);
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
            switch (req->cmd.opcode) {
            case NVME_CMD_WRITE:
                lat = ssd_write(ssd, req);
                break;
            case NVME_CMD_READ:
                lat = ssd_read(ssd, req);
                break;
            case NVME_CMD_DSM:
                if (req->dsm_ranges && req->dsm_nr_ranges > 0) {
                    lat = ssd_trim(ssd, req);
                }
                break;
            default:
                //ftl_err("FTL received unkown request type, ERROR\n");
                ;
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
