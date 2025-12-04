#include "../nvme.h"

/* Coperd: FEMU Memory Backend (mbe) for emulated SSD */

int init_dram_backend(SsdDramBackend **mbe, int64_t nbytes)
{
    SsdDramBackend *b = *mbe = g_malloc0(sizeof(SsdDramBackend));

    b->size = nbytes;
    b->logical_space = g_malloc0(nbytes);

    if (mlock(b->logical_space, nbytes) == -1) {
        femu_err("Failed to pin the memory backend to the host DRAM\n");
        g_free(b->logical_space);
        abort();
    }

    return 0;
}

void free_dram_backend(SsdDramBackend *b)
{
    if (b->logical_space) {
        munlock(b->logical_space, b->size);
        g_free(b->logical_space);
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
    void *mb = b->logical_space;

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
