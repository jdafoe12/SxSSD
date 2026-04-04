#include "ftl.h"
#include "bbm.h"
#include "policy-engine.h"
#include "eswd-config.h"
#include "eswd-layout.h"
#include "meta-interface-policy.h"
#include <errno.h>
#include <string.h>
//#include "../backend/ftl-backend.h"

//#define FEMU_DEBUG_FTL

static void *ftl_thread(void *arg);

static inline uint32_t eswd_lbas_per_page(struct ssd *ssd)
{
    return ssd->bbm->geom->secs_per_pg;
}

static inline uint32_t eswd_lba_size(struct ssd *ssd)
{
    return ssd->bbm->geom->secsz;
}

static inline uint64_t eswd_page_size_bytes(struct ssd *ssd)
{
    return (uint64_t)eswd_lbas_per_page(ssd) * eswd_lba_size(ssd);
}

static inline uint64_t eswd_capacity_lbas(struct ssd *ssd)
{
    return (uint64_t)ssd->eswd_layout.pgs_per_eswd * eswd_lbas_per_page(ssd);
}

static inline uint64_t eswd_start_lba(struct ssd *ssd, uint32_t eswd_id)
{
    return (uint64_t)eswd_id * eswd_capacity_lbas(ssd);
}

static inline uint64_t eswd_end_lba(struct ssd *ssd, uint32_t eswd_id)
{
    return eswd_start_lba(ssd, eswd_id) + eswd_capacity_lbas(ssd);
}

static inline void eswd_clear_stage(struct ssd *ssd, struct eswd *e)
{
    if (e->staged_page_buf) {
        memset(e->staged_page_buf, 0, (size_t)eswd_page_size_bytes(ssd));
    }
    e->staged_page_lba = INVALID_LPN;
    e->staged_valid_lbas = 0;
}

static uint64_t eswd_flush_staged_page(struct ssd *ssd, uint32_t eswd_id,
                                       struct eswd *e, int64_t stime_ns)
{
    struct BbmEvent event = {0};
    PseudoPpa ppa;
    uint64_t page_size;

    if (!e || e->staged_valid_lbas == 0) {
        return 0;
    }
    if (e->wp_page_index >= ssd->eswd_layout.pgs_per_eswd) {
        return 0;
    }
    if (eswd_id_to_ppa_wrapper(ssd, eswd_id, e->wp_page_index, &ppa) != 0) {
        return 0;
    }

    page_size = eswd_page_size_bytes(ssd);
    event.cmd = BBM_EVENT_WRITE;
    event.type = BBM_EVENT_POLICY_IO;
    event.count = 1;
    event.stime = stime_ns;
    bbm_raw_write(ssd->fb, ssd->bbm, e->staged_page_buf, &ppa, 1, page_size, &event);
    mark_page_valid(ssd, &ppa);
    e->wp_page_index++;
    eswd_clear_stage(ssd, e);
    return (uint64_t)event.lat;
}

static uint32_t eswd_stage_offset_lbas(struct ssd *ssd, const struct eswd *e,
                                       uint64_t slba)
{
    (void)ssd;
    return (uint32_t)(slba - e->staged_page_lba);
}

/* ======================================================== */
/* FTL API functions for FTL policies to access NVMe request data */
/* ======================================================== */

uint64_t ftl_get_request_buffer_size(NvmeRequest *req)
{
    if (!req) {
        return 0;
    }

    uint64_t total_size = 0;
    QEMUSGList *qsg = &req->qsg;

    for (int i = 0; i < qsg->nsg; i++) {
        total_size += qsg->sg[i].len;
    }

    return total_size;
}

uint8_t *ftl_copy_request_data(NvmeRequest *req, uint64_t offset, 
                                uint64_t length, uint64_t *out_size)
{
    if (!req || !out_size) {
        return NULL;
    }

    QEMUSGList *qsg = &req->qsg;
    if (qsg->nsg == 0) {
        *out_size = 0;
        return NULL;
    }

    /* Calculate total available data */
    uint64_t total_size = ftl_get_request_buffer_size(req);
    
    if (offset >= total_size) {
        *out_size = 0;
        return NULL;
    }

    /* Determine how much to copy */
    uint64_t available = total_size - offset;
    uint64_t to_copy = (length == 0 || length > available) ? available : length;

    /* Allocate destination buffer */
    uint8_t *buffer = g_malloc(to_copy);
    if (!buffer) {
        *out_size = 0;
        return NULL;
    }

    /* Copy data from scatter-gather list */
    uint64_t copied = 0;
    uint64_t sg_offset = 0;
    int sg_index = 0;

    /* Skip to the starting offset */
    uint64_t skip_remaining = offset;
    while (sg_index < qsg->nsg && skip_remaining > 0) {
        if (skip_remaining >= qsg->sg[sg_index].len) {
            skip_remaining -= qsg->sg[sg_index].len;
            sg_index++;
        } else {
            sg_offset = skip_remaining;
            skip_remaining = 0;
        }
    }

    /* Copy the data */
    while (sg_index < qsg->nsg && copied < to_copy) {
        dma_addr_t cur_addr = qsg->sg[sg_index].base + sg_offset;
        uint64_t sg_remaining = qsg->sg[sg_index].len - sg_offset;
        uint64_t chunk = (to_copy - copied < sg_remaining) ? 
                         (to_copy - copied) : sg_remaining;

        /* Use DMA memory read to copy from guest memory */
        if (dma_memory_read(qsg->as, cur_addr, buffer + copied, chunk, 
                           MEMTXATTRS_UNSPECIFIED)) {
            ftl_err("dma_memory_read error in ftl_copy_request_data\n");
            g_free(buffer);
            *out_size = 0;
            return NULL;
        }

        copied += chunk;
        sg_offset = 0;  /* After first chunk, start from beginning of next SG entry */
        sg_index++;
    }

    *out_size = copied;
    return buffer;
}

uint64_t ftl_write_request_data(NvmeRequest *req, const uint8_t *buffer,
                                 uint64_t offset, uint64_t length)
{
    if (!req || !buffer || length == 0) {
        return 0;
    }

    QEMUSGList *qsg = &req->qsg;
    if (qsg->nsg == 0) {
        return 0;
    }

    /* Calculate total available space */
    uint64_t total_size = ftl_get_request_buffer_size(req);
    
    if (offset >= total_size) {
        return 0;
    }

    /* Determine how much to write */
    uint64_t available = total_size - offset;
    uint64_t to_write = (length > available) ? available : length;

    /* Write data to scatter-gather list */
    uint64_t written = 0;
    uint64_t sg_offset = 0;
    int sg_index = 0;

    /* Skip to the starting offset */
    uint64_t skip_remaining = offset;
    while (sg_index < qsg->nsg && skip_remaining > 0) {
        if (skip_remaining >= qsg->sg[sg_index].len) {
            skip_remaining -= qsg->sg[sg_index].len;
            sg_index++;
        } else {
            sg_offset = skip_remaining;
            skip_remaining = 0;
        }
    }

    /* Write the data */
    while (sg_index < qsg->nsg && written < to_write) {
        dma_addr_t cur_addr = qsg->sg[sg_index].base + sg_offset;
        uint64_t sg_remaining = qsg->sg[sg_index].len - sg_offset;
        uint64_t chunk = (to_write - written < sg_remaining) ? 
                         (to_write - written) : sg_remaining;

        /* Use DMA memory write to copy to guest memory */
        if (dma_memory_write(qsg->as, cur_addr, buffer + written, chunk, 
                            MEMTXATTRS_UNSPECIFIED)) {
            ftl_err("dma_memory_write error in ftl_write_request_data\n");
            return written;  /* Return partial write count */
        }

        written += chunk;
        sg_offset = 0;  /* After first chunk, start from beginning of next SG entry */
        sg_index++;
    }

    return written;
}

const NvmeDsmRange *ftl_get_dsm_ranges(NvmeRequest *req, int *nr_ranges)
{
    if (nr_ranges) {
        *nr_ranges = req ? req->dsm_nr_ranges : 0;
    }
    return req ? req->dsm_ranges : NULL;
}

uint16_t ftl_read_cmd_buffer(struct NvmeCommandEvent *event, void *dst,
                             uint32_t length)
{
    FemuCtrl *n;
    NvmeCmd *cmd;

    if (!event || !dst || length == 0) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    n = event->ctrl;
    cmd = event->cmd;
    if (!n || !cmd) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (dma_write_prp(n, dst, length,
                      le64_to_cpu(cmd->dptr.prp1),
                      le64_to_cpu(cmd->dptr.prp2)) != NVME_SUCCESS) {
        return NVME_DATA_TRAS_ERROR | NVME_DNR;
    }

    return NVME_SUCCESS;
}

uint16_t ftl_write_cmd_buffer(struct NvmeCommandEvent *event, const void *src,
                              uint32_t length)
{
    FemuCtrl *n;
    NvmeCmd *cmd;

    if (!event || !src || length == 0) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    n = event->ctrl;
    cmd = event->cmd;
    if (!n || !cmd) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (dma_read_prp(n, (uint8_t *)src, length,
                     le64_to_cpu(cmd->dptr.prp1),
                     le64_to_cpu(cmd->dptr.prp2)) != NVME_SUCCESS) {
        return NVME_DATA_TRAS_ERROR | NVME_DNR;
    }

    return NVME_SUCCESS;
}

void ftl_set_completion_result_u64(struct NvmeCommandEvent *event,
                                   uint64_t value)
{
    NvmeRequest *req;

    if (!event) {
        return;
    }

    req = event->req;
    if (!req) {
        return;
    }

    req->cqe.res64 = value;
}

int ftl_get_gc_thres_lines(struct ssd *ssd)
{
    return (ssd && ssd->fb) ? ssd->fb->sp.gc_thres_lines : 0;
}

int ftl_get_gc_thres_lines_high(struct ssd *ssd)
{
    return (ssd && ssd->fb) ? ssd->fb->sp.gc_thres_lines_high : 0;
}

int ftl_get_page_status(struct ssd *ssd, const PseudoPpa *ppa)
{
    if (!ssd || !ssd->bbm || !ppa) {
        return -1;
    }
    return bbm_get_page_status(ssd->fb, ssd->bbm, ppa);
}

/* ======================================================== */
/* FTL API functions for FTL policies to interact with NVMe event hooks */
/* ======================================================== */

int ftl_register_nvme_hook(struct ssd *ssd, uint8_t opcode,
                           NvmeHookCondition condition,
                           NvmeHookCallback callback,
                           void *context)
{
    if (!ssd || !callback || !ssd->policy_engine) {
        return -1;
    }
    return pe_register_nvme_hook(ssd->policy_engine, opcode, condition, callback, context);
}

int ftl_unregister_nvme_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_unregister_nvme_hook(ssd->policy_engine, hook_handle);
}

int ftl_inactivate_nvme_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_inactivate_nvme_hook(ssd->policy_engine, hook_handle);
}

int ftl_reactivate_nvme_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_reactivate_nvme_hook(ssd->policy_engine, hook_handle);
}

int ftl_register_admin_hook(struct ssd *ssd, uint8_t opcode,
                            NvmeHookCondition condition,
                            NvmeHookCallback callback,
                            void *context)
{
    if (!ssd || !callback || !ssd->policy_engine) {
        return -1;
    }
    return pe_register_admin_hook(ssd->policy_engine, opcode, condition, callback, context);
}

int ftl_unregister_admin_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_unregister_admin_hook(ssd->policy_engine, hook_handle);
}

int ftl_inactivate_admin_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_inactivate_admin_hook(ssd->policy_engine, hook_handle);
}

int ftl_reactivate_admin_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_reactivate_admin_hook(ssd->policy_engine, hook_handle);
}

/* ======================================================== */
/* FTL API functions for FTL policies to interact with background event hooks */
/* ======================================================== */

int ftl_register_background_hook(struct ssd *ssd, BackgroundHookCondition condition,
                                 BackgroundHookCallback callback, void *context)
{
    if (!ssd || !callback || !ssd->policy_engine) {
        return -1;
    }
    return pe_register_background_hook(ssd->policy_engine, condition, callback, context);
}

int ftl_unregister_background_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_unregister_background_hook(ssd->policy_engine, hook_handle);
}

int ftl_inactivate_background_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_inactivate_background_hook(ssd->policy_engine, hook_handle);
}

int ftl_reactivate_background_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_reactivate_background_hook(ssd->policy_engine, hook_handle);
}

/* ======================================================== */
/* FTL API functions for FTL policies to interact with backend fail status event hooks */
/* ======================================================== */
static int ftl_register_backend_hook(struct ssd *ssd, BackendEventHookCondition condition,
                                     BackendEventHookCallback callback, void *context)
{
    if (!ssd || !callback || !ssd->policy_engine) {
        return -1;
    }
    return pe_register_backend_hook(ssd->policy_engine, condition, callback, context);
}

static int ftl_unregister_backend_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_unregister_backend_hook(ssd->policy_engine, hook_handle);
}

static int ftl_inactivate_backend_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_inactivate_backend_hook(ssd->policy_engine, hook_handle);
}

static int ftl_reactivate_backend_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_reactivate_backend_hook(ssd->policy_engine, hook_handle);
}

/* ======================================================== */
/* FTL API functions for FTL policies to interact with pSWD transition event hooks */
/* ======================================================== */
static int ftl_register_pswd_transition_hook(struct ssd *ssd, PswdTransitionHookCondition condition,
                                            PswdTransitionHookCallback callback, void *context)
{
    if (!ssd || !callback || !ssd->policy_engine) {
        return -1;
    }
    return pe_register_pswd_transition_hook(ssd->policy_engine, condition, callback, context);
}

static int ftl_unregister_pswd_transition_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_unregister_pswd_transition_hook(ssd->policy_engine, hook_handle);
}

static int ftl_inactivate_pswd_transition_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_inactivate_pswd_transition_hook(ssd->policy_engine, hook_handle);
}

static int ftl_reactivate_pswd_transition_hook(struct ssd *ssd, int hook_handle)
{
    if (!ssd || !ssd->policy_engine) {
        return -1;
    }
    return pe_reactivate_pswd_transition_hook(ssd->policy_engine, hook_handle);
}

void ftl_fill_nvme_event(struct ssd *ssd, NvmeRequest *req, struct NvmeCommandEvent *event)
{
    if (!ssd || !req || !event) {
        return;
    }
    const struct bbm_geom *geom = ssd->bbm->geom;

    event->opcode = req->cmd.opcode;
    event->is_admin = false;
    event->lba = req->slba;
    event->nsecs = req->nlb;
    event->start_lpn = req->slba / geom->secs_per_pg;
    event->end_lpn = (req->slba + req->nlb - 1) / geom->secs_per_pg;
    event->lpn_cnt = event->end_lpn - event->start_lpn + 1;
    event->req = req;
    event->cmd = &req->cmd;
    event->ctrl = req->sq ? req->sq->ctrl : NULL;
    event->stime = req->stime;
    event->lat = 0;
    event->status = NVME_SUCCESS;
}

void ftl_fill_admin_nvme_event(struct ssd *ssd, FemuCtrl *n, NvmeCmd *cmd,
                               struct NvmeCommandEvent *event)
{
    if (!ssd || !n || !cmd || !event) {
        return;
    }

    memset(event, 0, sizeof(*event));
    event->opcode = cmd->opcode;
    event->is_admin = true;
    event->req = NULL;
    event->cmd = cmd;
    event->ctrl = n;
    event->status = NVME_SUCCESS;
}

/*
 * Perform a user read through BBM: resolve LPNs to PPAs via the policy callback,
 * then call BBM read (pseudo→physical, backend I/O, event dispatch).
 * event is used for LPN range, req, stime; lat is set on return.
 */
uint64_t ftl_read_user_request(struct ssd *ssd, struct NvmeCommandEvent *event,
                               ReadPpaResolver resolve_ppa, void *resolve_ctx)
{
    if (!ssd || !event || !event->req || !resolve_ppa) {
        return 0;
    }
    const struct ssdparams *spp = &ssd->fb->sp;
    uint64_t page_size = (uint64_t)spp->secs_per_pg * spp->secsz;
    uint64_t start_lpn = event->start_lpn;
    uint64_t end_lpn = event->end_lpn;

    PseudoPpa *ppa_list = g_malloc0(sizeof(PseudoPpa) * event->lpn_cnt);
    int ppa_idx = 0;
    for (uint64_t lpn = start_lpn; lpn <= end_lpn; lpn++) {
        PseudoPpa ppa;
        if (resolve_ppa(resolve_ctx, ssd, lpn, &ppa)) {
            ppa_list[ppa_idx++] = ppa;
        }
    }

    if (ppa_idx == 0) {
        g_free(ppa_list);
        event->lat = 0;
        return 0;
    }

    struct BbmEvent bbm_ev = {
        .cmd = BBM_EVENT_READ,
        .type = BBM_EVENT_USER_IO,
        .count = (uint32_t)ppa_idx,
        .status_list = g_malloc0(sizeof(int) * (size_t)ppa_idx),
        .stime = (int64_t)event->stime,
        .lat = 0,
    };

    bbm_read(ssd->fb, ssd->bbm, event->req, ppa_list,
             (uint64_t)ppa_idx, page_size, &bbm_ev);

    event->lat = (uint64_t)bbm_ev.lat;
    g_free(bbm_ev.status_list);
    g_free(ppa_list);
    return (uint64_t)bbm_ev.lat;
}

/*
 * Perform a user write through BBM: call BBM write (pseudo→physical, backend I/O,
 * event dispatch) for the policy-supplied PPA list. Policy owns ppa_list and may free
 * it after return. Returns latency.
 */
uint64_t ftl_write_user_request(struct ssd *ssd, NvmeRequest *req,
                                PseudoPpa *ppa_list, uint64_t ppa_cnt)
{
    if (!ssd || !req || !ppa_list || ppa_cnt == 0) {
        return 0;
    }
    const struct ssdparams *spp = &ssd->fb->sp;
    uint64_t page_size = (uint64_t)spp->secs_per_pg * spp->secsz;

    struct BbmEvent bbm_ev = {
        .cmd = BBM_EVENT_WRITE,
        .type = BBM_EVENT_USER_IO,
        .count = (uint32_t)ppa_cnt,
        .status_list = g_malloc0(sizeof(int) * (size_t)ppa_cnt),
        .stime = (int64_t)req->stime,
        .lat = 0,
    };

    bbm_write(ssd->fb, ssd->bbm, req, ppa_list, ppa_cnt, page_size, &bbm_ev);

    g_free(bbm_ev.status_list);
    return (uint64_t)bbm_ev.lat;
}

/* ======================================================== */


uint64_t get_total_logical_pages(struct ssd *ssd)
{
    return ssd->bbm->geom->tt_pgs_log;
}

const struct bbm_geom *get_bbm_geom(struct ssd *ssd)
{
    return (ssd && ssd->bbm) ? ssd->bbm->geom : NULL;
}

const struct eswd_layout *get_eswd_layout(struct ssd *ssd)
{
    return ssd ? &ssd->eswd_layout : NULL;
}


uint64_t ppa_to_pgidx(struct ssd *ssd, PseudoPpa *ppa)
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

/* ======================================================== 
 * --- eSWD: configuration. This is to set eswd size and striping level. Should be called by policy_init for 
 * exactly one policy.
 * ======================================================== */
void set_eswd_config(struct ssd *ssd, const struct eswd_config *config)
{
    if (!ssd || !config || !ssd->bbm || !ssd->bbm->geom) {
        return;
    }
    if (ssd->eswd_layout_finalized) {
        ftl_err("[FTL] set_eswd_config: layout already finalized\n");
        return;
    }
    const struct bbm_geom *geom = ssd->bbm->geom;
    if (!eswd_config_valid(config, geom->nchs, geom->luns_per_ch,
                           geom->pls_per_lun, geom->blks_per_lun_log)) {
        ftl_err("[FTL] set_eswd_config: invalid config for geometry\n");
        return;
    }
    ssd->eswd_config = *config;
    ssd->eswd_config_set = true;
}

static void ssd_init_eswds(struct ssd *ssd)
{
    const struct eswd_layout *layout = &ssd->eswd_layout;
    uint32_t tt = layout->tt_eswds;
    uint64_t page_size = eswd_page_size_bytes(ssd);

    ssd->tt_eswds = tt;
    ssd->eswds = g_malloc0(sizeof(struct eswd) * tt);
    for (uint32_t i = 0; i < tt; i++) {
        ssd->eswds[i].id = i;
        ssd->eswds[i].ipc = 0;
        ssd->eswds[i].vpc = 0;
        ssd->eswds[i].wp_page_index = 0;
        ssd->eswds[i].wp_lba = eswd_start_lba(ssd, i);
        ssd->eswds[i].staged_page_lba = INVALID_LPN;
        ssd->eswds[i].staged_valid_lbas = 0;
        ssd->eswds[i].staged_page_buf = g_malloc0((size_t)page_size);
    }
}

int finalize_ftl_init(struct ssd *ssd)
{
    const struct bbm_geom *geom;

    if (!ssd || !ssd->bbm || !ssd->bbm->geom) {
        return -1;
    }
    if (ssd->eswd_layout_finalized) {
        return 0;
    }
    if (!ssd->eswd_config_set) {
        ftl_err("[FTL] finalize_ftl_init: eSWD config has not been set\n");
        return -1;
    }

    geom = ssd->bbm->geom;
    if (eswd_layout_compute(&ssd->eswd_layout, &ssd->eswd_config, geom) != 0) {
        fprintf(stderr, "[FTL] Failed to compute eSWD layout\n");
        return -1;
    }

    ssd->eswd_layout_finalized = true;
    ssd_init_eswds(ssd);
    return 0;
}

/* --- eSWD: lookup --- Definitely mechanism level! */
struct eswd *get_eswd(struct ssd *ssd, PseudoPpa *ppa)
{
    uint32_t eswd_id;
    uint32_t page_index; /* Need to provide this - eswd_ppa_to_page requires it */
    if (eswd_ppa_to_page(&ssd->eswd_layout, ssd->bbm->geom, ppa, &eswd_id, &page_index) != 0) {
        return NULL;
    }
    if (eswd_id >= ssd->tt_eswds) {
        return NULL;
    }
    return &ssd->eswds[eswd_id];
}

/* --- eSWD: state updates (validity, free) --- Seems like this is part mechanism level and part policy level? */
/* Backend validity via BBM; FTL updates eSWD vpc/ipc and policy victim list. */
void mark_page_invalid(struct ssd *ssd, PseudoPpa *ppa)
{
    struct eswd *e = get_eswd(ssd, ppa);

    bbm_mark_page_invalid(ssd->fb, ssd->bbm, ppa);
    if (!e) {
        ftl_err("BUG: mark_page_invalid: get_eswd returned NULL for ppa (ch=%d,lun=%d,pl=%d,blk=%d,pg=%d)\n",
                ppa->g.ch, ppa->g.lun, ppa->g.pl, ppa->g.blk, ppa->g.pg);
        return;
    }

    /* Mechanism-level: update eSWD vpc/ipc. Policy handles its own full/victim lists. */
    ftl_assert(e->ipc >= 0 && e->ipc < (int)ssd->eswd_layout.pgs_per_eswd);
    ftl_assert(e->vpc > 0 && e->vpc <= (int)ssd->eswd_layout.pgs_per_eswd);
    e->ipc++;
    e->vpc--;
}

/* Backend validity via BBM; FTL updates eSWD vpc. This is mechanism level for sure */
void mark_page_valid(struct ssd *ssd, PseudoPpa *ppa)
{
    struct eswd *e = get_eswd(ssd, ppa);

    bbm_mark_page_valid(ssd->fb, ssd->bbm, ppa);
    if (!e) {
        ftl_err("BUG: mark_page_valid: get_eswd returned NULL for ppa (ch=%d,lun=%d,pl=%d,blk=%d,pg=%d)\n",
                ppa->g.ch, ppa->g.lun, ppa->g.pl, ppa->g.blk, ppa->g.pg);
        return;
    }
    ftl_assert(e->vpc >= 0 && e->vpc < (int)ssd->eswd_layout.pgs_per_eswd);
    e->vpc++;
}

/* ======================================================== 
 * --- Mechanism API: eSWD query and state operations ---
 * These expose eSWD primitives to policies without making policy decisions.
 * ======================================================== */

struct eswd *get_eswd_by_id(struct ssd *ssd, uint32_t eswd_id)
{
    if (eswd_id >= ssd->tt_eswds) {
        return NULL;
    }
    return &ssd->eswds[eswd_id];
}

struct eswd *get_eswd_by_ppa(struct ssd *ssd, PseudoPpa *ppa)
{
    return get_eswd(ssd, ppa);
}

void get_eswd_vpc_ipc(struct ssd *ssd, uint32_t eswd_id, int *vpc, int *ipc)
{
    if (eswd_id >= ssd->tt_eswds) {
        if (vpc) *vpc = 0;
        if (ipc) *ipc = 0;
        return;
    }
    struct eswd *e = &ssd->eswds[eswd_id];
    if (vpc) *vpc = e->vpc;
    if (ipc) *ipc = e->ipc;
}

uint32_t get_eswd_wp_index(struct ssd *ssd, uint32_t eswd_id)
{
    if (eswd_id >= ssd->tt_eswds) {
        return 0;
    }
    return ssd->eswds[eswd_id].wp_page_index;
}

uint32_t get_total_eswds(struct ssd *ssd)
{
    return ssd->tt_eswds;
}

void eswd_set_vpc_ipc(struct ssd *ssd, uint32_t eswd_id, int vpc, int ipc)
{
    if (eswd_id >= ssd->tt_eswds) {
        return;
    }
    struct eswd *e = &ssd->eswds[eswd_id];
    e->vpc = vpc;
    e->ipc = ipc;
}

void eswd_increment_wp(struct ssd *ssd, uint32_t eswd_id)
{
    if (eswd_id >= ssd->tt_eswds) {
        return;
    }
    ssd->eswds[eswd_id].wp_page_index++;
    ssd->eswds[eswd_id].wp_lba += eswd_lbas_per_page(ssd);
}

void eswd_reset(struct ssd *ssd, uint32_t eswd_id)
{
    if (eswd_id >= ssd->tt_eswds) {
        return;
    }
    struct eswd *e = &ssd->eswds[eswd_id];
    e->ipc = 0;
    e->vpc = 0;
    e->wp_page_index = 0;
    e->wp_lba = eswd_start_lba(ssd, eswd_id);
    eswd_clear_stage(ssd, e);
}

uint64_t eswd_get_wp_lba(struct ssd *ssd, uint32_t eswd_id)
{
    if (eswd_id >= ssd->tt_eswds) {
        return 0;
    }
    return ssd->eswds[eswd_id].wp_lba;
}

uint16_t eswd_check_seq_write(struct ssd *ssd, uint32_t eswd_id,
                              uint64_t slba, uint32_t nlb)
{
    struct eswd *e;
    uint64_t end_lba;

    if (!ssd || eswd_id >= ssd->tt_eswds) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (nlb == 0) {
        return NVME_SUCCESS;
    }

    e = &ssd->eswds[eswd_id];
    end_lba = eswd_end_lba(ssd, eswd_id);
    if (slba != e->wp_lba) {
        return NVME_ZONE_INVALID_WRITE | NVME_DNR;
    }
    if (UINT64_MAX - slba < nlb || slba + nlb > end_lba) {
        return NVME_ZONE_BOUNDARY_ERROR | NVME_DNR;
    }
    return NVME_SUCCESS;
}

uint16_t eswd_check_read_range(struct ssd *ssd, uint32_t eswd_id,
                               uint64_t slba, uint32_t nlb)
{
    if (!ssd || eswd_id >= ssd->tt_eswds) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (nlb == 0) {
        return NVME_SUCCESS;
    }
    if (slba < eswd_start_lba(ssd, eswd_id)) {
        return NVME_LBA_RANGE | NVME_DNR;
    }
    if (UINT64_MAX - slba < nlb || slba + nlb > eswd_end_lba(ssd, eswd_id)) {
        return NVME_ZONE_BOUNDARY_ERROR | NVME_DNR;
    }
    return NVME_SUCCESS;
}

uint64_t eswd_write_lbas(struct ssd *ssd, NvmeRequest *req,
                         uint32_t eswd_id, uint64_t slba, uint32_t nlb,
                         int64_t stime_ns)
{
    struct eswd *e;
    uint8_t *req_data;
    uint64_t req_size = 0;
    uint64_t page_size;
    uint32_t lba_size;
    uint32_t page_lbas;
    uint64_t lat = 0;
    uint64_t data_off = 0;
    uint64_t cur_lba = slba;
    uint32_t remaining = nlb;

    if (!ssd || eswd_id >= ssd->tt_eswds || !req) {
        return 0;
    }
    if (eswd_check_seq_write(ssd, eswd_id, slba, nlb) != NVME_SUCCESS) {
        return 0;
    }

    e = &ssd->eswds[eswd_id];
    lba_size = eswd_lba_size(ssd);
    page_lbas = eswd_lbas_per_page(ssd);
    page_size = eswd_page_size_bytes(ssd);
    req_data = ftl_copy_request_data(req, 0, (uint64_t)nlb * lba_size, &req_size);
    if (!req_data || req_size < (uint64_t)nlb * lba_size) {
        g_free(req_data);
        return 0;
    }

    while (remaining > 0) {
        uint32_t stage_off_lbas;
        uint32_t copy_lbas;
        uint64_t copy_bytes;

        if (e->staged_valid_lbas == 0) {
            e->staged_page_lba = cur_lba - (cur_lba % page_lbas);
        }

        stage_off_lbas = eswd_stage_offset_lbas(ssd, e, cur_lba);
        copy_lbas = page_lbas - stage_off_lbas;
        if (copy_lbas > remaining) {
            copy_lbas = remaining;
        }
        copy_bytes = (uint64_t)copy_lbas * lba_size;
        memcpy(e->staged_page_buf + (size_t)stage_off_lbas * lba_size,
               req_data + data_off, (size_t)copy_bytes);

        data_off += copy_bytes;
        cur_lba += copy_lbas;
        remaining -= copy_lbas;
        e->staged_valid_lbas = stage_off_lbas + copy_lbas;
        e->wp_lba += copy_lbas;

        if (e->staged_valid_lbas == page_lbas) {
            lat += eswd_flush_staged_page(ssd, eswd_id, e, stime_ns);
            if (page_size == 0) {
                break;
            }
        }
    }

    g_free(req_data);
    return lat;
}

uint64_t eswd_read_lbas(struct ssd *ssd, NvmeRequest *req,
                        uint32_t eswd_id, uint64_t slba, uint32_t nlb,
                        int64_t stime_ns)
{
    struct eswd *e;
    uint8_t *out;
    uint8_t *page_buf;
    uint64_t page_size;
    uint32_t lba_size;
    uint32_t page_lbas;
    uint64_t total_bytes;
    uint64_t lat = 0;
    uint64_t out_off = 0;
    uint64_t cur_lba = slba;
    uint32_t remaining = nlb;

    if (!ssd || eswd_id >= ssd->tt_eswds || !req) {
        return 0;
    }
    if (eswd_check_read_range(ssd, eswd_id, slba, nlb) != NVME_SUCCESS) {
        return 0;
    }

    e = &ssd->eswds[eswd_id];
    lba_size = eswd_lba_size(ssd);
    page_lbas = eswd_lbas_per_page(ssd);
    page_size = eswd_page_size_bytes(ssd);
    total_bytes = (uint64_t)nlb * lba_size;
    out = g_malloc0((size_t)total_bytes);
    page_buf = g_malloc0((size_t)page_size);
    if (!out || !page_buf) {
        g_free(out);
        g_free(page_buf);
        return 0;
    }

    while (remaining > 0) {
        uint64_t page_lba = cur_lba - (cur_lba % page_lbas);
        uint32_t page_off_lbas = (uint32_t)(cur_lba - page_lba);
        uint32_t chunk_lbas = page_lbas - page_off_lbas;
        uint64_t copy_bytes;
        uint32_t page_index;

        if (chunk_lbas > remaining) {
            chunk_lbas = remaining;
        }
        copy_bytes = (uint64_t)chunk_lbas * lba_size;
        page_index = (uint32_t)((page_lba - eswd_start_lba(ssd, eswd_id)) / page_lbas);

        memset(page_buf, 0, (size_t)page_size);
        if (page_index < e->wp_page_index) {
            struct BbmEvent event = {0};
            PseudoPpa ppa;

            if (eswd_id_to_ppa_wrapper(ssd, eswd_id, page_index, &ppa) == 0) {
                event.cmd = BBM_EVENT_READ;
                event.type = BBM_EVENT_POLICY_IO;
                event.count = 1;
                event.stime = stime_ns;
                bbm_raw_read(ssd->fb, ssd->bbm, page_buf, &ppa, 1, page_size, &event);
                lat += (uint64_t)event.lat;
            }
        }

        if (e->staged_valid_lbas > 0 && e->staged_page_lba == page_lba) {
            memcpy(page_buf, e->staged_page_buf,
                   (size_t)e->staged_valid_lbas * lba_size);
        }

        memcpy(out + out_off, page_buf + (size_t)page_off_lbas * lba_size,
               (size_t)copy_bytes);
        out_off += copy_bytes;
        cur_lba += chunk_lbas;
        remaining -= chunk_lbas;
    }

    (void)ftl_write_request_data(req, out, 0, total_bytes);
    g_free(out);
    g_free(page_buf);
    return lat;
}

uint64_t read_page_buffer(struct ssd *ssd, const PseudoPpa *ppa,
                          uint8_t *buffer, int64_t stime_ns)
{
    struct BbmEvent event = {0};
    uint64_t page_size;
    PseudoPpa local;

    if (!ssd || !ppa || !buffer) {
        return 0;
    }
    local = *ppa;
    if (!valid_ppa(ssd, &local)) {
        return 0;
    }

    page_size = eswd_page_size_bytes(ssd);
    event.cmd = BBM_EVENT_READ;
    event.type = BBM_EVENT_POLICY_IO;
    event.count = 1;
    event.stime = stime_ns;
    bbm_raw_read(ssd->fb, ssd->bbm, buffer, &local, 1, page_size, &event);
    return (uint64_t)event.lat;
}

uint64_t commit_page_to_eswd(struct ssd *ssd, uint32_t eswd_id,
                             const uint8_t *buffer, PseudoPpa *out_ppa,
                             int64_t stime_ns)
{
    struct BbmEvent event = {0};
    struct eswd *e;
    PseudoPpa ppa;
    uint64_t page_size;

    if (!ssd || eswd_id >= ssd->tt_eswds || !buffer) {
        return 0;
    }
    e = &ssd->eswds[eswd_id];
    if (e->wp_page_index >= ssd->eswd_layout.pgs_per_eswd) {
        return 0;
    }
    if (eswd_id_to_ppa_wrapper(ssd, eswd_id, e->wp_page_index, &ppa) != 0) {
        return 0;
    }

    page_size = eswd_page_size_bytes(ssd);
    event.cmd = BBM_EVENT_WRITE;
    event.type = BBM_EVENT_POLICY_IO;
    event.count = 1;
    event.stime = stime_ns;
    bbm_raw_write(ssd->fb, ssd->bbm, (uint8_t *)buffer, &ppa, 1, page_size, &event);
    mark_page_valid(ssd, &ppa);
    e->wp_page_index++;
    e->wp_lba += eswd_lbas_per_page(ssd);
    if (out_ppa) {
        *out_ppa = ppa;
    }
    return (uint64_t)event.lat;
}

/* eSWD layout query wrappers */
int eswd_id_to_ppa_wrapper(struct ssd *ssd, uint32_t eswd_id, uint32_t page_index, PseudoPpa *ppa)
{
    return eswd_page_to_ppa(&ssd->eswd_layout, ssd->bbm->geom, eswd_id, page_index, ppa);
}

int ppa_to_eswd_id_wrapper(struct ssd *ssd, const PseudoPpa *ppa, uint32_t *eswd_id, uint32_t *page_index)
{
    return eswd_ppa_to_page(&ssd->eswd_layout, ssd->bbm->geom, ppa, eswd_id, page_index);
}

int eswd_block_to_ppa_wrapper(struct ssd *ssd, uint32_t eswd_id, uint32_t block_index, PseudoPpa *ppa)
{
    return eswd_block_to_ppa(&ssd->eswd_layout, ssd->bbm->geom, eswd_id, block_index, ppa);
}

int ftl_eswd_advance_wp_to_end(struct ssd *ssd, uint32_t eswd_id)
{
    if (!ssd || eswd_id >= ssd->tt_eswds) {
        return -1;
    }
    ssd->eswds[eswd_id].wp_lba = eswd_end_lba(ssd, eswd_id);
    return 0;
}

uint64_t ftl_eswd_erase_physical(struct ssd *ssd, uint32_t eswd_id, int64_t stime_ns)
{
    const struct eswd_layout *layout;
    uint64_t maxlat = 0;
    struct BbmEvent bbm_ev = {0};

    if (!ssd || !ssd->fb || !ssd->bbm || eswd_id >= ssd->tt_eswds) {
        return 0;
    }
    layout = &ssd->eswd_layout;
    bbm_ev.cmd = BBM_EVENT_ERASE;
    bbm_ev.type = BBM_EVENT_POLICY_IO;
    bbm_ev.stime = stime_ns;
    if (layout->blks_per_eswd > 0) {
        bbm_ev.status_list = g_malloc0(sizeof(int) * (size_t)layout->blks_per_eswd);
    }

    for (uint32_t blk = 0; blk < layout->blks_per_eswd; blk++) {
        PseudoPpa ppa;
        PseudoPba pba;

        if (eswd_block_to_ppa_wrapper(ssd, eswd_id, blk, &ppa) != 0) {
            continue;
        }
        mark_block_free(ssd, &ppa);
        pba.g.ch = ppa.g.ch;
        pba.g.lun = ppa.g.lun;
        pba.g.pl = ppa.g.pl;
        pba.g.blk = ppa.g.blk;
        bbm_raw_erase(ssd->fb, ssd->bbm, &pba, 1, &bbm_ev);
        if ((uint64_t)bbm_ev.lat > maxlat) {
            maxlat = (uint64_t)bbm_ev.lat;
        }
    }

    g_free(bbm_ev.status_list);
    return maxlat;
}

/* ======================================================== 
 * --- Mechanism API: eSWD Migration ---
 * Mechanism performs the actual page copy; policy decides validity and updates mapping.
 * ======================================================== */

int migrate_eswd_pages(struct ssd *ssd,
                       uint32_t src_eswd_id,
                       uint32_t dst_eswd_id,
                       MigrationValidityCallback is_valid,
                       MigrationResultCallback on_migrated,
                       void *context,
                       struct FtlMigrationCallbacks *callbacks,
                       void *policy_ctx)
{
    assert(ssd);
    assert(src_eswd_id < ssd->tt_eswds);
    assert(dst_eswd_id < ssd->tt_eswds);
    assert(is_valid);
    assert(on_migrated);
    assert(context);
    
    const struct eswd_layout *layout = &ssd->eswd_layout;
    const struct bbm_geom *geom = ssd->bbm->geom;
    struct eswd *src_eswd = get_eswd_by_id(ssd, src_eswd_id);
    struct eswd *dst_eswd = get_eswd_by_id(ssd, dst_eswd_id);
    int migrated_count = 0;

    if (!src_eswd || !dst_eswd || !is_valid) {
        return -1;
    }

    if (src_eswd_id == dst_eswd_id) {
        ftl_err("BUG: migrate from eSWD %u to itself\n", src_eswd_id);
    }

    /* Iterate through all pages in source eSWD */
    for (uint32_t page_idx = 0; page_idx < layout->pgs_per_eswd; page_idx++) {
        PseudoPpa src_ppa, dst_ppa;
        
        /* Get source PPA */
        if (eswd_page_to_ppa(layout, geom, src_eswd_id, page_idx, &src_ppa) != 0) {
            continue;
        }
        
        /* Ask policy if this page should be migrated */
        if (!is_valid(src_eswd_id, page_idx, &src_ppa, context)) {
            continue;
        }
        
        /* Destination full: ask policy to switch to next eSWD (no wp increment) */
        if (dst_eswd->wp_page_index >= layout->pgs_per_eswd) {
            if (callbacks && callbacks->on_destination_full && policy_ctx) {
                uint32_t new_dest_id = 0;
                int rc = callbacks->on_destination_full(policy_ctx, dst_eswd_id, &new_dest_id);
                if (rc < 0) {
                    ftl_err("Migration failed: destination full and on_destination_full returned %d\n", rc);
                    return -1;
                }
                dst_eswd_id = new_dest_id;
                dst_eswd = get_eswd_by_id(ssd, dst_eswd_id);
                if (!dst_eswd) {
                    ftl_err("Migration failed: invalid new destination %u\n", dst_eswd_id);
                    return -1;
                }
            } else {
                ftl_err("Migration failed: dst_eswd %u wp_index %u invalid (no on_destination_full)\n",
                        dst_eswd_id, dst_eswd->wp_page_index);
                return -1;
            }
        }
        
        /* Get destination PPA (at current wp_index of dst_eswd) */
        if (eswd_page_to_ppa(layout, geom, dst_eswd_id, dst_eswd->wp_page_index, &dst_ppa) != 0) {
            ftl_err("Migration failed: dst_eswd %u wp_index %u invalid\n", 
                    dst_eswd_id, dst_eswd->wp_page_index);
            return -1;
        }
        
        /* Perform the actual migration (read + write) with timing simulation */

        struct BbmEvent read_event, write_event;
        uint64_t page_size = ssd->fb->sp.secs_per_pg * ssd->fb->sp.secsz;
            
        /* Read from source */
        read_event.cmd = BBM_EVENT_READ;
        read_event.type = BBM_EVENT_POLICY_IO;
        read_event.count = 1;
        read_event.status_list = NULL;
        read_event.stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        read_event.lat = 0;
        bbm_raw_read(ssd->fb, ssd->bbm, NULL, &src_ppa, 1, page_size, &read_event);
            
        /* Write to destination */
        write_event.cmd = BBM_EVENT_WRITE;
        write_event.type = BBM_EVENT_POLICY_IO;
        write_event.count = 1;
        write_event.status_list = NULL;
        write_event.stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        write_event.lat = 0;
        bbm_raw_write(ssd->fb, ssd->bbm, NULL, &dst_ppa, 1, page_size, &write_event);
            
        /* Update LUN gc_endtime */
        struct nand_lun *dst_lun = get_lun(ssd, &dst_ppa);
        dst_lun->gc_endtime = dst_lun->next_lun_avail_time;
        
        
        /* Update eSWD vpc/ipc (mechanism owns this) */
        src_eswd->vpc--;
        src_eswd->ipc++;
        dst_eswd->vpc++;
        
        /* Update backend validity (mechanism owns this) */
        bbm_mark_page_invalid(ssd->fb, ssd->bbm, &src_ppa);
        bbm_mark_page_valid(ssd->fb, ssd->bbm, &dst_ppa);
        
        /* Advance destination write pointer */
        dst_eswd->wp_page_index++;
        
        /* Notify policy of migration (policy updates maptbl) */
        if (on_migrated) {
            /* Policy needs to look up LPN via its rmap and update maptbl */
            on_migrated(0, &src_ppa, &dst_ppa, context);
        }
        
        migrated_count++;
    }

    /* After migrating valid pages, erase the source eSWD blocks (mechanism completes the migration) */
    const struct ssdparams *spp = &ssd->fb->sp;
    
    for (uint32_t block_idx = 0; block_idx < layout->blks_per_eswd; block_idx++) {
        PseudoPpa ppa;
        if (eswd_block_to_ppa(layout, ssd->bbm->geom, src_eswd_id, block_idx, &ppa) != 0) {
            continue;
        }
        
        /* Mark block as free in backend */
        bbm_mark_block_free(ssd->fb, ssd->bbm, &ppa);
        
        /* Simulate erase latency (critical for accurate GC performance) */
        if (spp->enable_gc_delay) {
            struct BbmEvent event;
            event.cmd = BBM_EVENT_ERASE;
            event.type = BBM_EVENT_POLICY_IO;
            event.count = 1;
            event.status_list = NULL;
            event.stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
            event.lat = 0;
            
            PseudoPba ppba;
            ppba.g.ch = ppa.g.ch;
            ppba.g.lun = ppa.g.lun;
            ppba.g.pl = ppa.g.pl;
            ppba.g.blk = ppa.g.blk;
            
            bbm_raw_erase(ssd->fb, ssd->bbm, &ppba, 1, &event);
            
            /* Update LUN gc_endtime */
            struct nand_lun *src_lun = get_lun(ssd, &ppa);
            src_lun->gc_endtime = src_lun->next_lun_avail_time;
        }
    }

    return migrated_count;
}

/* ============================================================================
 * GENERIC MIGRATION FRAMEWORK
 * ============================================================================
 * High-level orchestration for data migration operations (GC, wear leveling, 
 * compaction, refresh, etc.). Uses callbacks to remain policy-agnostic while
 * coordinating the complete migration workflow.
 */


int ftl_run_migration(struct ssd *ssd,
                      struct FtlMigrationCallbacks *callbacks,
                      void *policy_ctx,
                      bool force)
{
    assert(callbacks);
    assert(policy_ctx);
    assert(ssd);
    
    /* Validate required callbacks */
    if (!callbacks->select_victim || !callbacks->get_destination) {
        ftl_err("ftl_run_migration: missing required callbacks\n");
        return -EINVAL;
    }
    
    /* Check if migration is needed (optional callback) */
    if (callbacks->should_migrate && !callbacks->should_migrate(policy_ctx, force)) {
        return 0;  /* Migration not needed */
    }
    
    /* Select victim eSWD */
    uint32_t victim_eswd_id = 0;
    int rc = callbacks->select_victim(policy_ctx, force, &victim_eswd_id);
    if (rc < 0) {
        /* No suitable victim */
        if (callbacks->on_failed) {
            callbacks->on_failed(policy_ctx, ~0U, rc);
        }
        return -1;
    }
    
    /* Get destination for data migration */
    uint32_t dest_eswd_id = 0;
    rc = callbacks->get_destination(policy_ctx, &dest_eswd_id);
    if (rc < 0) {
        /* No destination available */
        if (callbacks->on_failed) {
            callbacks->on_failed(policy_ctx, victim_eswd_id, rc);
        }
        return -1;
    }
    
    
    int pages_moved = migrate_eswd_pages(ssd, victim_eswd_id, dest_eswd_id,
                                        callbacks->is_page_valid,
                                        callbacks->on_page_migrated,
                                        policy_ctx,
                                        callbacks,
                                        policy_ctx);
    
    if (pages_moved < 0) {
        if (callbacks->on_failed) {
            callbacks->on_failed(policy_ctx, victim_eswd_id, pages_moved);
        }
        return -1;
    }
    
    if (callbacks->on_complete) {
        callbacks->on_complete(policy_ctx, victim_eswd_id, pages_moved);
    }
    return pages_moved;
}

/**
 * ftl_run_migration_loop - Execute multiple migration cycles
 * @ssd: SSD device
 * @callbacks: Migration callback structure
 * @policy_ctx: Policy-specific context
 * @force: Force migration even if thresholds not met
 * @max_iterations: Maximum number of iterations (0 = unlimited)
 * 
 * Runs migration cycles until should_migrate returns false or max_iterations reached.
 * 
 * Returns: Total pages moved on success, negative on error
 */
int ftl_run_migration_loop(struct ssd *ssd,
                           struct FtlMigrationCallbacks *callbacks,
                           void *policy_ctx,
                           bool force,
                           int max_iterations)
{
    assert(ssd);
    assert(callbacks);
    assert(policy_ctx);
    
    int total_pages_moved = 0;
    int iterations = 0;
    
    /* Run migration until should_migrate returns false or max iterations reached */
    while (max_iterations == 0 || iterations < max_iterations) {
        /* Check if migration is still needed */
        if (callbacks->should_migrate && !callbacks->should_migrate(policy_ctx, force)) {
            break;
        }
        
        /* Run one migration cycle */
        int pages_moved = ftl_run_migration(ssd, callbacks, policy_ctx, force);
        if (pages_moved < 0) {
            /* Migration failed - stop loop */
            ftl_err("ftl_run_migration_loop: Migration failed\n");
            return (total_pages_moved > 0) ? total_pages_moved : -1;
        }
        
        total_pages_moved += pages_moved;
        iterations++;
        
        /* If no pages were moved, stop to avoid infinite loop */
        if (pages_moved == 0) {
            break;
        }
    }
    
    return total_pages_moved;
}

/* ======================================================== 
 * --- Mechanism API: eSWD Remapping ---
 * Allow policy to remap eSWDs to different physical blocks for wear leveling.
 * ======================================================== */

int remap_eswd_to_physical(struct ssd *ssd,
                           uint32_t eswd_id,
                           uint8_t target_ch,
                           uint8_t target_lun,
                           uint8_t target_pl,
                           uint16_t target_blk_start)
{
    /* TODO: This requires coordination with BBM layer.
     * For now, return not implemented. This would allow policies to:
     * - Move eSWDs to different planes for wear leveling
     * - Remap eSWDs away from bad blocks
     * The mechanism validates the target is in valid range and updates the mapping.
     */
    (void)ssd;
    (void)eswd_id;
    (void)target_ch;
    (void)target_lun;
    (void)target_pl;
    (void)target_blk_start;
    
    ftl_err("remap_eswd_to_physical not yet implemented\n");
    return -1;
}

/* ======================================================== */
/* SSD init and address validation / accessors              */
/* ======================================================== */

static void ssd_init_nand_lun(struct ssd *ssd, struct nand_lun *lun)
{
    (void)ssd;
    lun->next_lun_avail_time = 0;
    lun->busy = false;
    lun->gc_endtime = 0;
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

static void *ftl_dup_payload(const void *src, size_t len)
{
    void *dst;

    if (!src || len == 0) {
        return NULL;
    }

    dst = g_malloc0(len);
    memcpy(dst, src, len);
    return dst;
}

static uint32_t ftl_count_published_namespaces(FemuCtrl *n)
{
    uint32_t i;
    uint32_t count = 0;

    if (!n || !n->namespaces) {
        return 0;
    }

    for (i = 0; i < n->num_namespaces; i++) {
        if (n->namespaces[i].published) {
            count++;
        }
    }

    return count;
}

int configure_namespace_personality(struct ssd *ssd,
                                    const struct NamespacePersonalityConfig *config)
{
    FemuCtrl *n;
    NvmeNamespace *ns;
    void *ns_csi_copy = NULL;
    void *ctrl_csi_copy = NULL;

    if (!ssd || !ssd->ctrl || !config) {
        return -1;
    }

    n = ssd->ctrl;
    if (!n->namespaces || n->num_namespaces == 0) {
        return -1;
    }
    ns = &n->namespaces[0];
    if (!ns) {
        return -1;
    }

    if (config->ns_csi_data_len && !config->ns_csi_data) {
        return -1;
    }
    if (config->ctrl_csi_data_len && !config->ctrl_csi_data) {
        return -1;
    }

    ns_csi_copy = ftl_dup_payload(config->ns_csi_data, config->ns_csi_data_len);
    ctrl_csi_copy = ftl_dup_payload(config->ctrl_csi_data, config->ctrl_csi_data_len);

    g_free(n->id_ns_csi);
    g_free(n->id_ctrl_csi);

    n->csi = config->csi;
    n->id_ns_csi = ns_csi_copy;
    n->id_ns_csi_len = config->ns_csi_data_len;
    n->id_ctrl_csi = ctrl_csi_copy;
    n->id_ctrl_csi_len = config->ctrl_csi_data_len;

    /* Preserve the legacy zoned pointer for existing identify paths that still
     * special-case CSI_ZONED while keeping the installed payload generic. */
    n->id_ns_zoned = (config->csi == NVME_CSI_ZONED) ? (NvmeIdNsZoned *)n->id_ns_csi : NULL;

    ns->id_ns.nsze = cpu_to_le64(config->nsze);
    ns->id_ns.ncap = cpu_to_le64(config->ncap);
    ns->id_ns.nuse = cpu_to_le64(config->nuse);
    ns->id_ns.noiob = config->noiob;
    ns->published = true;
    n->id_ctrl.nn = cpu_to_le32(ftl_count_published_namespaces(n));

    return 0;
}


void ssd_init(FemuCtrl *n)
{
    struct ssd *ssd = n->ssd;
   // struct ssdparams *spp = &ssd->fb->sp;

    ftl_assert(ssd);
    ssd->ctrl = n;

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
    struct ssdparams *spp = &ssd->fb->sp;

   // ssd_init_params(spp, n); // removed becuase it is handled in the backend. The ssdParams are relevant to hardware geometry. 

    /* initialize ssd pseudophysical internal layout architecture */
    ssd->ch = g_malloc0(sizeof(struct ssd_channel) * spp->nchs);
    for (int i = 0; i < spp->nchs; i++) {
        ssd_init_ch(ssd, &ssd->ch[i]); 
    }

    /* Create policy engine (holds FTL, backend, pSWD hook arrays) and wire to BBM and backend */
    ssd->policy_engine = pe_create();
    bbm_set_policy_engine(ssd->bbm, ssd->policy_engine);
    pe_set_bbm(ssd->policy_engine, ssd->bbm);
    ftl_backend_set_pswd_transition_notify(ssd->fb, pe_dispatch_pswd_transition, ssd->policy_engine);

    /* Initialize FTL Policy API (mechanism primitives only) */
    ssd->policy_api = g_malloc0(sizeof(struct FtlPolicyAPI));
    ssd->policy_api->version = 1;
    
    /* eSWD query operations (mechanism exposes eSWD state) */
    ssd->policy_api->get_eswd_by_id = get_eswd_by_id;
    ssd->policy_api->get_eswd_by_ppa = get_eswd_by_ppa;
    ssd->policy_api->get_eswd_vpc_ipc = get_eswd_vpc_ipc;
    ssd->policy_api->get_eswd_wp_index = get_eswd_wp_index;
    ssd->policy_api->get_total_eswds = get_total_eswds;
    ssd->policy_api->get_total_logical_pages = get_total_logical_pages;
    ssd->policy_api->get_bbm_geom = get_bbm_geom;
    ssd->policy_api->get_eswd_layout = get_eswd_layout;
    
    /* eSWD state modification (mechanism updates eSWD struct) */
    ssd->policy_api->eswd_set_vpc_ipc = eswd_set_vpc_ipc;
    ssd->policy_api->eswd_increment_wp = eswd_increment_wp;
    ssd->policy_api->eswd_reset = eswd_reset;
    ssd->policy_api->eswd_get_wp_lba = eswd_get_wp_lba;
    ssd->policy_api->eswd_check_seq_write = eswd_check_seq_write;
    ssd->policy_api->eswd_check_read_range = eswd_check_read_range;
    ssd->policy_api->eswd_write_lbas = eswd_write_lbas;
    ssd->policy_api->eswd_read_lbas = eswd_read_lbas;
    ssd->policy_api->read_page_buffer = read_page_buffer;
    ssd->policy_api->commit_page_to_eswd = commit_page_to_eswd;
    ssd->policy_api->eswd_advance_wp_to_end = ftl_eswd_advance_wp_to_end;
    ssd->policy_api->eswd_erase_physical = ftl_eswd_erase_physical;

    /* eSWD layout query (mechanism owns layout) */
    ssd->policy_api->eswd_id_to_ppa = eswd_id_to_ppa_wrapper;
    ssd->policy_api->ppa_to_eswd_id = ppa_to_eswd_id_wrapper;
    ssd->policy_api->eswd_block_to_ppa = eswd_block_to_ppa_wrapper;
    
    /* Migration and remapping API (mechanism provides) */
    ssd->policy_api->migrate_eswd_pages = migrate_eswd_pages;
    ssd->policy_api->run_migration = ftl_run_migration;
    ssd->policy_api->remap_eswd_to_physical = remap_eswd_to_physical;
    
    /* Validity tracking (mechanism updates backend) */
    ssd->policy_api->mark_page_valid = mark_page_valid;
    ssd->policy_api->mark_page_invalid = mark_page_invalid;
    ssd->policy_api->mark_block_free = mark_block_free;
    
    /* Address validation (mechanism checks geometry) */
    ssd->policy_api->valid_ppa = valid_ppa;
    ssd->policy_api->mapped_ppa = mapped_ppa;
    ssd->policy_api->ppa_to_pgidx = ppa_to_pgidx;
    
    /* Hardware accessors (mechanism provides) */
    ssd->policy_api->get_lun = get_lun;
    ssd->policy_api->get_ch = get_ch;
    
    /* Buffer helpers (mechanism provides) */
    ssd->policy_api->get_request_buffer_size = ftl_get_request_buffer_size;
    ssd->policy_api->copy_request_data = ftl_copy_request_data;
    ssd->policy_api->write_request_data = ftl_write_request_data;
    ssd->policy_api->get_dsm_ranges = ftl_get_dsm_ranges;
    ssd->policy_api->read_cmd_buffer = ftl_read_cmd_buffer;
    ssd->policy_api->write_cmd_buffer = ftl_write_cmd_buffer;
    ssd->policy_api->set_completion_result_u64 = ftl_set_completion_result_u64;
    ssd->policy_api->get_gc_thres_lines = ftl_get_gc_thres_lines;
    ssd->policy_api->get_gc_thres_lines_high = ftl_get_gc_thres_lines_high;
    ssd->policy_api->get_page_status = ftl_get_page_status;

    /* Hook registration (mechanism provides event system) */
    ssd->policy_api->register_nvme_hook = ftl_register_nvme_hook;
    ssd->policy_api->unregister_nvme_hook = ftl_unregister_nvme_hook;
    ssd->policy_api->inactivate_nvme_hook = ftl_inactivate_nvme_hook;
    ssd->policy_api->reactivate_nvme_hook = ftl_reactivate_nvme_hook;
    ssd->policy_api->register_admin_hook = ftl_register_admin_hook;
    ssd->policy_api->unregister_admin_hook = ftl_unregister_admin_hook;
    ssd->policy_api->inactivate_admin_hook = ftl_inactivate_admin_hook;
    ssd->policy_api->reactivate_admin_hook = ftl_reactivate_admin_hook;
    ssd->policy_api->register_backend_hook = ftl_register_backend_hook;
    ssd->policy_api->unregister_backend_hook = ftl_unregister_backend_hook;
    ssd->policy_api->inactivate_backend_hook = ftl_inactivate_backend_hook;
    ssd->policy_api->reactivate_backend_hook = ftl_reactivate_backend_hook;
    ssd->policy_api->register_pswd_transition_hook = ftl_register_pswd_transition_hook;
    ssd->policy_api->unregister_pswd_transition_hook = ftl_unregister_pswd_transition_hook;
    ssd->policy_api->inactivate_pswd_transition_hook = ftl_inactivate_pswd_transition_hook;
    ssd->policy_api->reactivate_pswd_transition_hook = ftl_reactivate_pswd_transition_hook;
    ssd->policy_api->register_background_hook = ftl_register_background_hook;
    ssd->policy_api->unregister_background_hook = ftl_unregister_background_hook;
    ssd->policy_api->inactivate_background_hook = ftl_inactivate_background_hook;
    ssd->policy_api->reactivate_background_hook = ftl_reactivate_background_hook;

    /* eSWD config (policy sets at init) */
    ssd->policy_api->set_eswd_config = set_eswd_config;
    ssd->policy_api->finalize_ftl_init = finalize_ftl_init;
    ssd->policy_api->configure_namespace_personality = configure_namespace_personality;

    /* User read through BBM (mechanism builds PPA list via policy resolver and calls BBM) */
    ssd->policy_api->read_user_request = ftl_read_user_request;
    ssd->policy_api->write_user_request = ftl_write_user_request;

    /* BBM policy-visible pass-through intentionally disabled. */

    if (m_interface_policy_init(ssd) != 0) {
        fprintf(stderr, "[FTL] Failed to initialize meta interface policy\n");
    }

    qemu_thread_create(&ssd->ftl_thread, "FEMU-FTL-Thread", ftl_thread, n,
                       QEMU_THREAD_JOINABLE);
}

/* --- Address validation and channel/LUN accessors --- */
/* Check that the PPA is in range. BBM indexes by (ch, lun, blk) with blk < blks_per_lun_log. */
bool valid_ppa(struct ssd *ssd, PseudoPpa *ppa)
{
    const struct bbm_geom *geom = ssd->bbm->geom;
    int ch = ppa->g.ch;
    int lun = ppa->g.lun;
    int pl = ppa->g.pl;
    int blk = ppa->g.blk;
    int pg = ppa->g.pg;
    int sec = ppa->g.sec;

    if (ch >= 0 && ch < (int)geom->nchs && lun >= 0 && lun < (int)geom->luns_per_ch &&
        pl >= 0 && pl < (int)geom->pls_per_lun && blk >= 0 && blk < (int)geom->blks_per_lun_log &&
        pg >= 0 && pg < (int)geom->pgs_per_blk && sec >= 0 && sec < (int)geom->secs_per_pg)
        return true;

    return false;
}

bool valid_lpn(struct ssd *ssd, uint64_t lpn)
{
    return (lpn < ssd->bbm->geom->tt_pgs_log);
}

bool mapped_ppa(PseudoPpa *ppa)
{
    return !(ppa->ppa == UNMAPPED_PPA);
}

struct ssd_channel *get_ch(struct ssd *ssd, PseudoPpa *ppa)
{
    return &(ssd->ch[ppa->g.ch]);
}

struct nand_lun *get_lun(struct ssd *ssd, PseudoPpa *ppa)
{
    struct ssd_channel *ch = get_ch(ssd, ppa);
    return &(ch->lun[ppa->g.lun]);
}

/* Backend clears per-block validity; policy calls this after cleaning a block (e.g. in migration). */
void mark_block_free(struct ssd *ssd, PseudoPpa *ppa)
{
    bbm_mark_block_free(ssd->fb, ssd->bbm, ppa);
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
            ftl_assert(rc == 1);
            ftl_assert(req);
            {
                struct NvmeCommandEvent nvme_event;
                ftl_fill_nvme_event(ssd, req, &nvme_event);
                lat = pe_dispatch_nvme_cmd(ssd->policy_engine, ssd, &nvme_event);
            }

            req->reqlat = lat;
            req->expire_time += lat;

            rc = femu_ring_enqueue(ssd->to_poller[i], (void *)&req, 1);
            if (rc != 1) {
                ftl_err("FTL to_poller enqueue failed\n");
            }

            /* Background event: policy engine runs registered hooks (e.g. if should_gc do_gc) */
            pe_dispatch_background_event(ssd->policy_engine, ssd);
        }
    }

    return NULL;
}
