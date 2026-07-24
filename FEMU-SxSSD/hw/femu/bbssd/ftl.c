#include "ftl.h"
#include "device-signing.h"
#include "bbm.h"
#include "policy-engine.h"
#include "eswd-config.h"
#include "eswd-layout.h"
#include "qemu/timer.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
//#include "../backend/ftl-backend.h"

//#define FEMU_DEBUG_FTL

static void *ftl_thread(void *arg);

typedef void (*FtlInternalPpaCommit)(void *context, struct ssd *ssd,
                                     uint64_t lpn,
                                     const PseudoPpa *new_ppa);
typedef void (*FtlInternalOobFill)(void *context, struct ssd *ssd,
                                   uint64_t lpn, void *oob_buffer,
                                   uint32_t oob_length);


// LBA is the OS/NVMe view of the logical address space. Each LBA is a "sector"
// PBA is the physical address space.
// LPN is the logical page number.
// PPN is the physical page number.

static inline uint32_t eswd_lbas_per_page(struct ssd *ssd)
{
    return ssd->bbm->geom->secs_per_pg;
}

static inline uint32_t eswd_lba_size(struct ssd *ssd)
{
    return ssd->bbm->geom->secsz; // Sector size in bytes.
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

static inline uint64_t ftl_now_ns(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

static bool ftl_get_oob_range(struct ssd *ssd, int oob_handle,
                              size_t *offset_out, size_t *len_out)
{
    if (!ssd || !ssd->fb || oob_handle < 0) {
        return false;
    }
    return ftl_backend_get_oob_policy_info(ssd->fb, oob_handle,
                                           offset_out, len_out) == 0;
}

/*
 * Private physical-write primitive: program one or more page-sized buffers to the
 * given PseudoPpas via bbm_raw_write, then mark the pages valid.
 */

 // TODO: look over this in details. Is this what we want? is it general enouph?
 // Also, what is the purpose of each write function? even, of each function in this file?
static uint64_t ftl_write_pages_raw(struct ssd *ssd, const uint8_t *buffer,
                                    PseudoPpa *ppas, uint32_t page_count,
                                    int oob_handle,
                                    FtlInternalOobFill fill_oob,
                                    void *oob_ctx,
                                    uint64_t start_lpn,
                                    int64_t stime_ns)
{
    struct BbmEvent event = {0};
    uint64_t page_size = eswd_page_size_bytes(ssd);
    uint8_t *oob_pages = NULL;
    size_t oob_offset = 0;
    size_t oob_len = 0;
    if (!ssd || !buffer || !ppas || page_count == 0) {
        return 0;
    }

    if (fill_oob && ftl_get_oob_range(ssd, oob_handle, &oob_offset, &oob_len) &&
        oob_len > 0) {
        oob_pages = g_malloc0((size_t)page_count * oob_len);
        if (!oob_pages) {
            return 0;
        }
        for (uint32_t i = 0; i < page_count; i++) {
            fill_oob(oob_ctx, ssd, start_lpn + i, oob_pages + ((size_t)i * oob_len),
                     (uint32_t)oob_len);
        }
    }

    event.cmd = BBM_EVENT_WRITE;
    event.type = BBM_EVENT_POLICY_IO;
    event.count = page_count;
    event.stime = stime_ns;
    bbm_raw_write(ssd->fb, ssd->bbm, (uint8_t *)buffer, ppas, page_count,
                  page_size, oob_pages, oob_offset, oob_len, &event);
    g_free(oob_pages);
    for (uint32_t i = 0; i < page_count; i++) {
        mark_page_valid(ssd, &ppas[i]);
    }
    ssd->stats.phys_page_programs += page_count;
    return (uint64_t)event.lat;
}

static uint64_t ftl_write_direct_pages(struct ssd *ssd, uint32_t eswd_id,
                                       const uint8_t *buffer, uint32_t page_count,
                                       uint64_t start_lpn,
                                       int oob_handle,
                                       FtlInternalOobFill fill_oob,
                                       void *oob_ctx,
                                       FtlInternalPpaCommit on_page_commit,
                                       void *commit_ctx,
                                       PseudoPpa *ppa_out,
                                       int64_t stime_ns)
{
    struct eswd *e;
    PseudoPpa *ppas;
    uint32_t pages_until_end;
    uint64_t lat;
    if (!ssd || eswd_id >= ssd->tt_eswds || !buffer || !page_count) {
        return 0;
    }
    e = &ssd->eswds[eswd_id];
    pages_until_end = ssd->eswd_layout.pgs_per_eswd - e->wp_page_index;
    if (page_count > pages_until_end) {
        page_count = pages_until_end;
    }
    if (!page_count) {
        return 0;
    }

    ppas = g_malloc0(sizeof(*ppas) * page_count);
    if (!ppas) {
        return 0;
    }
    for (uint32_t i = 0; i < page_count; i++) {
        if (eswd_id_to_ppa_wrapper(ssd, eswd_id, e->wp_page_index + i, &ppas[i]) != 0) {
            page_count = i;
            break;
        }
    }
    if (!page_count) {
        g_free(ppas);
        return 0;
    }

    lat = ftl_write_pages_raw(ssd, buffer, ppas, page_count, oob_handle,
                              fill_oob, oob_ctx, start_lpn, stime_ns);
    for (uint32_t i = 0; i < page_count; i++) {
        uint64_t lpn = start_lpn + i;

        if (ppa_out) {
            *ppa_out = ppas[i];
        }
        if (on_page_commit) {
            on_page_commit(commit_ctx, ssd, lpn, &ppas[i]);
        }
        eswd_increment_wp(ssd, eswd_id);
    }
    g_free(ppas);
    return lat;
}

struct ftl_fixed_oob_context {
    const uint8_t *data;
    uint32_t length;
};

static void ftl_copy_fixed_oob(void *opaque, struct ssd *ssd, uint64_t lpn,
                               void *oob_buffer, uint32_t oob_length)
{
    const struct ftl_fixed_oob_context *context = opaque;

    (void)ssd;
    (void)lpn;
    if (context && context->data && context->length == oob_length) {
        memcpy(oob_buffer, context->data, oob_length);
    }
}

int ftl_policy_page_append(struct ssd *ssd, uint32_t eswd_id,
                           const uint8_t *page_data, int oob_handle,
                           const uint8_t *oob_data, uint32_t oob_length,
                           PseudoPpa *ppa_out, uint64_t *latency_out,
                           int64_t stime_ns)
{
    struct ftl_fixed_oob_context oob_context = {
        .data = oob_data,
        .length = oob_length,
    };
    struct eswd *eswd;
    uint64_t latency;

    if (!ssd || !page_data || !ppa_out || !latency_out ||
        eswd_id >= ssd->tt_eswds ||
        (oob_length != 0 && (!oob_data || oob_handle < 0))) {
        return -1;
    }
    eswd = &ssd->eswds[eswd_id];
    if (eswd->wp_page_index >= ssd->eswd_layout.pgs_per_eswd) {
        return -1;
    }
    ppa_out->ppa = INVALID_PPA;
    latency = ftl_write_direct_pages(
        ssd, eswd_id, page_data, 1,
        eswd->wp_lba / eswd_lbas_per_page(ssd), oob_handle,
        oob_length ? ftl_copy_fixed_oob : NULL,
        oob_length ? &oob_context : NULL, NULL, NULL, ppa_out, stime_ns);
    if (ppa_out->ppa == INVALID_PPA) {
        return -1;
    }
    *latency_out = latency;
    return 0;
}

int ftl_policy_page_read(struct ssd *ssd, const PseudoPpa *ppa,
                         uint8_t *page_data, int oob_handle, void *oob_data,
                         int64_t stime_ns, uint64_t *latency_out)
{
    if (!ssd || !ppa || !page_data || !latency_out ||
        !valid_ppa(ssd, (PseudoPpa *)ppa)) {
        return -1;
    }
    *latency_out = read_page_buffer(ssd, ppa, page_data, oob_handle, oob_data,
                                    stime_ns);
    ssd->stats.phys_page_reads++;
    return 0;
}

static uint64_t ftl_flush_staged_page(struct ssd *ssd, uint32_t eswd_id,
                                      struct eswd *e, uint64_t page_lpn,
                                      PseudoPpa *ppa_out,
                                      int64_t stime_ns)
{
    PseudoPpa ppa;
    uint64_t lat;

    if (!ssd || !e || e->staged_valid_lbas != eswd_lbas_per_page(ssd)) {
        return 0;
    }
    if (eswd_id_to_ppa_wrapper(ssd, eswd_id, e->wp_page_index, &ppa) != 0) {
        return 0;
    }

    lat = ftl_write_pages_raw(ssd, e->staged_page_buf, &ppa, 1, -1,
                              NULL, NULL, page_lpn, stime_ns);
    eswd_increment_wp(ssd, eswd_id);
    e->staged_valid_lbas = 0;
    if (ppa_out) {
        *ppa_out = ppa;
    }
    return lat;
}

uint64_t ftl_write_seq_lbas(struct ssd *ssd, uint32_t eswd_id,
                            uint64_t slba, const uint8_t *buf, uint32_t nlb,
                            PseudoPpa *ppa_out, int64_t stime_ns)
{
    uint32_t lbas_per_page;
    uint32_t lba_size;
    uint64_t page_size;
    uint64_t max_lat = 0;
    uint32_t remaining;
    uint64_t cur_lba;
    uint64_t data_off;
    struct eswd *e;

    if (!ssd || eswd_id >= ssd->tt_eswds || !buf || nlb == 0) {
        return 0;
    }

    lbas_per_page = eswd_lbas_per_page(ssd);
    lba_size = eswd_lba_size(ssd);
    page_size = eswd_page_size_bytes(ssd);
    remaining = nlb;
    cur_lba = slba;
    data_off = 0;
    e = &ssd->eswds[eswd_id];

    while (remaining > 0) {
        uint64_t page_lba = cur_lba - (cur_lba % lbas_per_page);
        uint64_t page_lpn = page_lba / lbas_per_page;
        uint32_t page_off = (uint32_t)(cur_lba - page_lba);
        uint32_t chunk_lbas = lbas_per_page - page_off;
        bool full_page;

        if (chunk_lbas > remaining) {
            chunk_lbas = remaining;
        }
        full_page = (page_off == 0 && chunk_lbas == lbas_per_page);

        if (e->staged_valid_lbas == 0 && full_page) {
            uint32_t pages_until_end = ssd->eswd_layout.pgs_per_eswd - e->wp_page_index;
            uint32_t direct_pages = remaining / lbas_per_page;
            uint64_t lat;

            if (direct_pages > pages_until_end) {
                direct_pages = pages_until_end;
            }
            if (direct_pages > 0) {
                lat = ftl_write_direct_pages(ssd, eswd_id,
                                             buf + data_off, direct_pages,
                                             page_lpn, -1, NULL, NULL,
                                             NULL, NULL, ppa_out, stime_ns);
                if (lat > max_lat) {
                    max_lat = lat;
                }
                cur_lba += (uint64_t)direct_pages * lbas_per_page;
                remaining -= direct_pages * lbas_per_page;
                data_off += (uint64_t)direct_pages * page_size;
                continue;
            }
        }

        {
            uint64_t lat;

            if (e->staged_valid_lbas == 0) {
                e->staged_page_lba = page_lba;
                memset(e->staged_page_buf, 0, (size_t)page_size);
            }

            memcpy(e->staged_page_buf + (size_t)page_off * lba_size,
                   buf + data_off,
                   (size_t)chunk_lbas * lba_size);
            e->staged_valid_lbas = page_off + chunk_lbas;

            lat = ftl_flush_staged_page(ssd, eswd_id, e, page_lpn,
                                        ppa_out, stime_ns);
            if (lat > max_lat) {
                max_lat = lat;
            }
        }

        cur_lba += chunk_lbas;
        remaining -= chunk_lbas;
        data_off += (uint64_t)chunk_lbas * lba_size;
    }

    return max_lat;
}

/*
 * Staged-aware page read for policies.
 *
 * If the requested page_lba is currently held in the eSWD's staging buffer,
 * copies staged data into buf_out (no flash latency). Otherwise resolves the
 * PseudoPpa for the committed page and reads from flash via read_page_buffer.
 */
uint64_t ftl_read_eswd_page(struct ssd *ssd, uint32_t eswd_id,
                            uint64_t page_lba, uint8_t *buf_out,
                            int64_t stime_ns)
{
    uint32_t lbas_per_page;
    uint64_t page_size;
    struct eswd *e;

    if (!ssd || eswd_id >= ssd->tt_eswds || !buf_out) {
        return 0;
    }
    e = &ssd->eswds[eswd_id];
    lbas_per_page = eswd_lbas_per_page(ssd);
    page_size     = eswd_page_size_bytes(ssd);

    if (e->staged_valid_lbas > 0 && e->staged_page_lba == page_lba) {
        memset(buf_out, 0, page_size);
        memcpy(buf_out, e->staged_page_buf,
               (size_t)e->staged_valid_lbas * eswd_lba_size(ssd));
        return 0;
    }

    /* Page is on flash: compute page_index and read it */
    uint64_t start = eswd_start_lba(ssd, eswd_id);
    if (page_lba < start) {
        return 0;
    }
    uint32_t page_index = (uint32_t)((page_lba - start) / lbas_per_page);
    PseudoPpa ppa;
    if (eswd_id_to_ppa_wrapper(ssd, eswd_id, page_index, &ppa) != 0) {
        return 0;
    }
    ssd->stats.phys_page_reads++;
    return read_page_buffer(ssd, &ppa, buf_out, -1, NULL, stime_ns);
}

/*
 * Returns the effective (host-visible) write pointer for the given eSWD,
 * including any partially-staged LBAs not yet flushed to flash.
 */
uint64_t ftl_eswd_get_effective_wp_lba(struct ssd *ssd, uint32_t eswd_id)
{
    struct eswd *e;

    if (!ssd || eswd_id >= ssd->tt_eswds) {
        return 0;
    }
    e = &ssd->eswds[eswd_id];
    if (e->staged_valid_lbas > 0) {
        return e->staged_page_lba + e->staged_valid_lbas;
    }
    return e->wp_lba;
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

#define FTL_MAX_COMMAND_TRANSFER_BYTES (1024U * 1024U)

static int ftl_command_data_transfer(struct NvmeCommandEvent *event,
                                     bool write_to_host,
                                     uint32_t command_offset, void *buffer,
                                     uint32_t length)
{
    uint8_t *temporary;
    uint64_t total;
    uint16_t status;
    int rc = -EIO;

    if (!event || !buffer || length == 0 ||
        command_offset > FTL_MAX_COMMAND_TRANSFER_BYTES ||
        length > FTL_MAX_COMMAND_TRANSFER_BYTES - command_offset) {
        return -EINVAL;
    }
    total = command_offset + length;
    temporary = g_try_malloc0(total);
    if (!temporary) {
        return -ENOMEM;
    }
    if (write_to_host) {
        if (command_offset != 0) {
            status = ftl_read_cmd_buffer(event, temporary, total);
            if (status != NVME_SUCCESS) {
                goto cleanup;
            }
        }
        memcpy(temporary + command_offset, buffer, length);
        status = ftl_write_cmd_buffer(event, temporary, total);
    } else {
        status = ftl_read_cmd_buffer(event, temporary, total);
        if (status == NVME_SUCCESS) {
            memcpy(buffer, temporary + command_offset, length);
        }
    }
    if (status == NVME_SUCCESS) {
        rc = 0;
    }

cleanup:
    OPENSSL_cleanse(temporary, total);
    g_free(temporary);
    return rc;
}

int ftl_command_data_read(struct NvmeCommandEvent *event,
                          uint32_t command_offset, void *destination,
                          uint32_t length)
{
    return ftl_command_data_transfer(event, false, command_offset, destination,
                                     length);
}

int ftl_command_data_write(struct NvmeCommandEvent *event,
                           uint32_t command_offset, const void *source,
                           uint32_t length)
{
    return ftl_command_data_transfer(event, true, command_offset,
                                     (void *)source, length);
}

void ftl_set_completion_result_u64(struct NvmeCommandEvent *event,
                                   uint64_t value)
{
    NvmeRequest *req;

    if (!event) {
        return;
    }

    req = event->req;
    if (req) {
        req->cqe.res64 = cpu_to_le64(value);
    } else if (event->cqe) {
        event->cqe->res64 = cpu_to_le64(value);
    }
}

int ftl_get_page_status(struct ssd *ssd, const PseudoPpa *ppa)
{
    if (!ssd || !ssd->bbm || !ppa) {
        return -1;
    }
    return bbm_get_page_status(ssd->fb, ssd->bbm, ppa);
}

int ftl_register_oob_region(struct ssd *ssd, const char *name,
                            uint32_t size, int *handle_out)
{
    if (!ssd || !ssd->fb || !name || !handle_out || size == 0) {
        return -1;
    }
    return ftl_backend_register_oob_policy(ssd->fb, name, size, handle_out);
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
    event->cqe = &req->cqe;
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

/* ======================================================== */


uint64_t get_total_logical_pages(struct ssd *ssd)
{
    return ssd->bbm->geom->tt_pgs_log;
}

uint64_t get_advertised_nsze_lbas(struct ssd *ssd)
{
    return (ssd && ssd->ctrl) ? (ssd->ctrl->ns_size / 512) : 0;
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
        ssd->eswds[i].staged_page_buf = g_malloc0(page_size);
        ssd->eswds[i].staged_page_lba = eswd_start_lba(ssd, i);
        ssd->eswds[i].staged_valid_lbas = 0;
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
 * These expose eSWD primitives to policies.
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
    if (e->staged_page_buf) {
        memset(e->staged_page_buf, 0, eswd_page_size_bytes(ssd));
    }
    e->staged_page_lba = eswd_start_lba(ssd, eswd_id);
    e->staged_valid_lbas = 0;
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
    uint64_t end_lba;

    if (!ssd || eswd_id >= ssd->tt_eswds) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (nlb == 0) {
        return NVME_SUCCESS;
    }

    end_lba = eswd_end_lba(ssd, eswd_id);
    if (slba != ftl_eswd_get_effective_wp_lba(ssd, eswd_id)) {
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

uint64_t read_page_buffer(struct ssd *ssd, const PseudoPpa *ppa,
                          uint8_t *buffer,
                          int oob_handle, void *oob_buf,
                          int64_t stime_ns)
{
    struct BbmEvent event = {0};
    uint64_t page_size;
    PseudoPpa local;
    size_t oob_offset = 0;
    size_t oob_len = 0;

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
    if (!oob_buf || !ftl_get_oob_range(ssd, oob_handle, &oob_offset, &oob_len)) {
        oob_buf = NULL;
        oob_offset = 0;
        oob_len = 0;
    }
    bbm_raw_read(ssd->fb, ssd->bbm, buffer, &local, 1, page_size,
                 oob_buf, oob_offset, oob_len, &event);
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
    if (layout->blks_per_eswd >
        UINT64_MAX - ssd->stats.block_erases) {
        ssd->stats.block_erases = UINT64_MAX;
    } else {
        ssd->stats.block_erases += layout->blks_per_eswd;
    }
    return maxlat;
}

/* ======================================================== 
 * --- Mechanism API: eSWD Migration ---
 * Mechanism performs the actual page copy; policy decides validity and updates mapping.
 * ======================================================== */

int ftl_policy_page_migrate(struct ssd *ssd, const PseudoPpa *source,
                            uint32_t destination_eswd_id,
                            PseudoPpa *destination_out,
                            uint64_t *latency_out)
{
    struct eswd *source_eswd;
    struct eswd *destination_eswd;
    struct BbmEvent read_event = {0};
    struct BbmEvent write_event = {0};
    PseudoPpa source_copy;
    uint8_t *page_buffer = NULL;
    uint8_t *oob_buffer = NULL;
    uint64_t page_size;
    size_t oob_size;
    int rc = -1;

    if (!ssd || !source || !destination_out || !latency_out ||
        destination_eswd_id >= ssd->tt_eswds) {
        return -1;
    }
    source_copy = *source;
    if (!valid_ppa(ssd, &source_copy) ||
        ftl_get_page_status(ssd, &source_copy) != PG_VALID) {
        return -1;
    }
    source_eswd = get_eswd(ssd, &source_copy);
    destination_eswd = get_eswd_by_id(ssd, destination_eswd_id);
    if (!source_eswd || !destination_eswd ||
        source_eswd == destination_eswd ||
        destination_eswd->wp_page_index >=
            ssd->eswd_layout.pgs_per_eswd ||
        eswd_id_to_ppa_wrapper(ssd, destination_eswd_id,
                               destination_eswd->wp_page_index,
                               destination_out) != 0) {
        return -1;
    }

    page_size = eswd_page_size_bytes(ssd);
    oob_size = ssd->fb->oob_size_per_page;
    page_buffer = g_try_malloc0(page_size);
    oob_buffer = oob_size ? g_try_malloc0(oob_size) : NULL;
    if (!page_buffer || (oob_size && !oob_buffer)) {
        goto cleanup;
    }

    read_event.cmd = BBM_EVENT_READ;
    read_event.type = BBM_EVENT_POLICY_IO;
    read_event.count = 1;
    bbm_raw_read(ssd->fb, ssd->bbm, page_buffer, &source_copy, 1,
                 page_size, oob_buffer, 0, oob_size, &read_event);

    write_event.cmd = BBM_EVENT_WRITE;
    write_event.type = BBM_EVENT_POLICY_IO;
    write_event.count = 1;
    bbm_raw_write(ssd->fb, ssd->bbm, page_buffer, destination_out, 1,
                  page_size, oob_buffer, 0, oob_size, &write_event);

    bbm_mark_page_invalid(ssd->fb, ssd->bbm, &source_copy);
    bbm_mark_page_valid(ssd->fb, ssd->bbm, destination_out);
    source_eswd->vpc--;
    source_eswd->ipc++;
    destination_eswd->vpc++;
    eswd_increment_wp(ssd, destination_eswd_id);
    ssd->stats.phys_page_reads++;
    ssd->stats.phys_page_programs++;
    *latency_out = MAX((uint64_t)read_event.lat,
                       (uint64_t)write_event.lat);
    rc = 0;

cleanup:
    g_free(page_buffer);
    g_free(oob_buffer);
    return rc;
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

    ftl_assert(ssd);
    ssd->ctrl = n;

    /* Initialize backend timing/error model */
    if (!ssd->fb) {
        ssd->fb = g_malloc0(sizeof(struct FtlBackend));
    }
    ftl_backend_init(ssd->fb, n->mbe, &n->bb_params);
    if (!ssd->bbm) {
        ssd->bbm = g_malloc0(sizeof(*ssd->bbm));
    }
    bbm_init(ssd->bbm, &n->bb_params, &ssd->fb->sp);
    struct ssdparams *spp = &ssd->fb->sp;

    /* initialize ssd pseudophysical internal layout architecture */
    ssd->ch = g_malloc0(sizeof(struct ssd_channel) * spp->nchs);
    for (int i = 0; i < spp->nchs; i++) {
        ssd_init_ch(ssd, &ssd->ch[i]); 
    }

    /* Create the common runtime used by installed and built-in policies. */
    ssd->policy_engine = pe_create(ssd);
    bbm_set_policy_engine(ssd->bbm, ssd->policy_engine);
    ftl_backend_set_pswd_transition_notify(
        ssd->fb, pe_dispatch_pswd_transition, ssd->policy_engine);

    if (pe_bootstrap_meta_interface_policy(ssd->policy_engine, ssd) != 0) {
        fprintf(stderr, "[FTL] Failed to bootstrap meta-interface policy\n");
        abort();
    }

    ftl_assert(n->bb_params.host_mhz > 0);
    ftl_assert(n->bb_params.ctrl_mhz > 0);
    ssd->cpu_scale_factor =
        (double)n->bb_params.host_mhz / n->bb_params.ctrl_mhz;

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
    fprintf(f, "  \"block_erases\": %lu,\n",         ssd->stats.block_erases);
    fprintf(f, "  \"gc_invocations\": %lu,\n",       ssd->stats.gc_invocations);
    fprintf(f, "  \"gc_pages_migrated\": %lu,\n",    ssd->stats.gc_pages_migrated);
    fprintf(f, "  \"foreground_gc_count\": %lu,\n",  ssd->stats.foreground_gc_count);
    fprintf(f, "  \"background_gc_count\": %lu,\n",  ssd->stats.background_gc_count);
    fprintf(f, "  \"gc_time_ns\": %lu,\n",            ssd->stats.gc_time_ns);
    fprintf(f, "  \"policy_dispatch_time_ns\": %lu,\n", ssd->stats.policy_dispatch_time_ns);
    fprintf(f, "  \"bytes_copied\": %lu\n",          ssd->stats.bytes_copied);
    fprintf(f, "}\n");

    fclose(f);
    printf("FEMU: stats dumped to %s\n", path);
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
                uint64_t cpu_t0;
                uint64_t cpu_t1;
                uint64_t cpu_overhead_ns;

                ftl_fill_nvme_event(ssd, req, &nvme_event);

                /* Host I/O counters */
                switch (nvme_event.opcode) {
                case NVME_CMD_READ:
                    ssd->stats.host_read_cmds++;
                    ssd->stats.host_read_sectors += nvme_event.nsecs;
                    break;
                case NVME_CMD_WRITE:
                    ssd->stats.host_write_cmds++;
                    ssd->stats.host_write_sectors += nvme_event.nsecs;
                    break;
                case NVME_CMD_DSM:
                    ssd->stats.host_trim_cmds++;
                    ssd->stats.host_trim_sectors += nvme_event.nsecs;
                    break;
                default:
                    break;
                }

                cpu_t0 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
                lat = pe_dispatch_nvme_cmd(ssd->policy_engine, ssd, &nvme_event);
                cpu_t1 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
                cpu_overhead_ns = (uint64_t)((cpu_t1 - cpu_t0) *
                                             ssd->cpu_scale_factor);
                ssd->stats.policy_dispatch_time_ns += (cpu_t1 - cpu_t0);
                lat += cpu_overhead_ns;
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
