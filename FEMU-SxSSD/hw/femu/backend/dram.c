#include "../nvme.h"

/* Coperd: FEMU Memory Backend (mbe) for emulated SSD */

int init_dram_backend(SsdDramBackend **mbe, int64_t nbytes)
{
    SsdDramBackend *b = *mbe = g_malloc0(sizeof(SsdDramBackend));

    b->size = nbytes;
    b->backend_memory = g_malloc0(nbytes);

    if (mlock(b->backend_memory, nbytes) == -1) {
        femu_err("Failed to pin the memory backend to the host DRAM: %s (errno=%d)\n",
                 strerror(errno), errno);
        femu_err("Attempted to lock %" PRId64 " bytes. Check ulimit -l and available memory.\n",
                 nbytes);
        g_free(b->backend_memory);
        abort();
    }

    return 0;
}

void free_dram_backend(SsdDramBackend *b)
{
    if (b->backend_memory) {
        munlock(b->backend_memory, b->size);
        g_free(b->backend_memory);
    }
}

/* Josh: The extra parameters are relevant to BBSSD mode only. */
int backend_rw(SsdDramBackend *b, QEMUSGList *qsg, uint64_t *lbal,
               uint64_t lbal_cnt, bool is_write, uint64_t page_size,
               uint64_t first_page_off)
{
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    dma_addr_t cur_addr, cur_len;
    void *mb = b->backend_memory;

    DMADirection dir = DMA_DIRECTION_FROM_DEVICE;

    if (is_write) {
        dir = DMA_DIRECTION_TO_DEVICE;
    }

    if (b->femu_mode == FEMU_BBSSD_MODE) {
        uint64_t page_idx = 0;
        uint64_t page_consumed = 0;
        uint64_t page_oft = lbal ? lbal[0] : 0;

        if (!lbal || !lbal_cnt || !page_size) {
            femu_err("Invalid parameters for BBSSD backend_rw\n");
            goto out;
        }
        if (first_page_off >= page_size) {
            femu_err("first_page_off (%" PRIu64 ") >= page_size (%" PRIu64 ")\n",
                     first_page_off, page_size);
            goto out;
        }
        page_consumed = first_page_off;

        while (sg_cur_index < qsg->nsg && page_idx < lbal_cnt) {
            cur_addr = qsg->sg[sg_cur_index].base + sg_cur_byte;
            uint64_t sg_remaining =
                qsg->sg[sg_cur_index].len - sg_cur_byte;
            uint64_t page_remaining = page_size - page_consumed;
            uint64_t chunk = MIN(sg_remaining, page_remaining);

            if (!chunk) {
                /* either SG entry exhausted or we finished the page */
                if (sg_remaining == 0) {
                    sg_cur_byte = 0;
                    ++sg_cur_index;
                    continue;
                }

                if (page_remaining == 0) {
                    page_consumed = 0;
                    ++page_idx;
                    if (page_idx < lbal_cnt) {
                        page_oft = lbal[page_idx];
                    }
                    continue;
                }

                break;
            }
            if (dma_memory_rw(qsg->as, cur_addr,
                              mb + page_oft + page_consumed, chunk, dir,
                              MEMTXATTRS_UNSPECIFIED)) {
                femu_err("dma_memory_rw error\n");
            }

            sg_cur_byte += chunk;
            if (sg_cur_byte == qsg->sg[sg_cur_index].len) {
                sg_cur_byte = 0;
                ++sg_cur_index;
            }

            page_consumed += chunk;
            if (page_consumed == page_size) {
                page_consumed = 0;
                ++page_idx;
                if (page_idx < lbal_cnt) {
                    page_oft = lbal[page_idx];
                }
            }
        }

        goto out;
    }

    uint64_t mb_oft = lbal[0];
    while (sg_cur_index < qsg->nsg) {
        cur_addr = qsg->sg[sg_cur_index].base + sg_cur_byte;
        cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;
        if (dma_memory_rw(qsg->as, cur_addr, mb + mb_oft, cur_len, dir, MEMTXATTRS_UNSPECIFIED)) {
            femu_err("dma_memory_rw error\n");
        }

        sg_cur_byte += cur_len;
        if (sg_cur_byte == qsg->sg[sg_cur_index].len) {
            sg_cur_byte = 0;
            ++sg_cur_index;
        }

        if (b->femu_mode == FEMU_OCSSD_MODE) {
            mb_oft = lbal[sg_cur_index];
        } else if (b->femu_mode == FEMU_NOSSD_MODE ||
                   b->femu_mode == FEMU_ZNSSD_MODE) {
            mb_oft += cur_len;
        } else {
            assert(0);
        }
    }

out:
    qemu_sglist_destroy(qsg);

    return 0;
}

/* Copy len bytes from qsg at byte offset start_off into buf. Does not destroy qsg. */
int backend_sglist_read(QEMUSGList *qsg, uint8_t *buf, uint64_t len, uint64_t start_off)
{
    if (!qsg || !buf || qsg->nsg == 0 || len == 0) {
        return -1;
    }

    uint64_t copied = 0;
    uint64_t sg_byte = 0;
    int sg_idx = 0;

    /* Skip to start_off */
    while (sg_idx < qsg->nsg && start_off > 0) {
        uint64_t seg_len = qsg->sg[sg_idx].len;
        if (start_off >= seg_len) {
            start_off -= seg_len;
            sg_idx++;
        } else {
            sg_byte = start_off;
            start_off = 0;
            break;
        }
    }

    while (sg_idx < qsg->nsg && copied < len) {
        dma_addr_t cur_addr = qsg->sg[sg_idx].base + sg_byte;
        uint64_t sg_remaining = qsg->sg[sg_idx].len - sg_byte;
        uint64_t to_copy = len - copied;
        if (to_copy > sg_remaining) {
            to_copy = sg_remaining;
        }

        if (dma_memory_read(qsg->as, cur_addr, buf + copied, to_copy,
                            MEMTXATTRS_UNSPECIFIED)) {
            return -1;
        }
        copied += to_copy;
        sg_byte += to_copy;
        if (sg_byte >= qsg->sg[sg_idx].len) {
            sg_byte = 0;
            sg_idx++;
        }
    }

    return (copied == len) ? 0 : -1;
}
