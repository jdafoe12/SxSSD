#include "./ftl-backend.h"

static uint64_t *build_offset_list(uint64_t *lpn_list, uint64_t lpn_count,
                                   uint64_t page_size)
{
    if (!lpn_list || !lpn_count) {
        return NULL;
    }

    uint64_t *offset_list = g_malloc0(sizeof(uint64_t) * lpn_count);
    for (uint64_t i = 0; i < lpn_count; ++i) {
        offset_list[i] = lpn_list[i] * page_size;
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

int ftl_backend_read(SsdDramBackend *mbe, NvmeRequest *req, uint64_t *lpn_list,
                     uint64_t lpn_count, uint64_t page_size)
{
    uint64_t *offset_list = build_offset_list(lpn_list, lpn_count, page_size);
    uint64_t first_page_off = calc_first_page_offset(req, page_size);

    if (!offset_list) {
        qemu_sglist_destroy(&req->qsg);
        return 0;
    }

    backend_rw(mbe, &req->qsg, offset_list, lpn_count, false, page_size,
               first_page_off);
    g_free(offset_list);

    return 0;
}

int ftl_backend_write(SsdDramBackend *mbe, NvmeRequest *req, uint64_t *lpn_list,
                      uint64_t lpn_count, uint64_t page_size)
{
    uint64_t *offset_list = build_offset_list(lpn_list, lpn_count, page_size);
    uint64_t first_page_off = calc_first_page_offset(req, page_size);

    if (!offset_list) {
        qemu_sglist_destroy(&req->qsg);
        return 0;
    }

    backend_rw(mbe, &req->qsg, offset_list, lpn_count, true, page_size,
               first_page_off);
    g_free(offset_list);

    return 0;
}

// Raw operations

int ftl_backend_raw_read(SsdDramBackend *mbe, uint8_t *buffer, uint64_t *ppn_list,
                         uint64_t ppn_count, uint64_t page_size)
{
    if (!buffer || !ppn_list || !ppn_count || !page_size) {
        return 0;
    }

    uint64_t *offset_list = build_offset_list(ppn_list, ppn_count, page_size);
    if (!offset_list) {
        return 0;
    }
    for (uint64_t i = 0; i < ppn_count; ++i) {
        memcpy(buffer + i * page_size, mbe->logical_space + offset_list[i], page_size);
    }
    g_free(offset_list);


    return 0;
}

int ftl_backend_raw_write(SsdDramBackend *mbe, uint8_t *buffer, uint64_t *ppn_list,
                          uint64_t ppn_count, uint64_t page_size)
{
    if (!buffer || !ppn_list || !ppn_count || !page_size) {
        return 0;
    }

    uint64_t *offset_list = build_offset_list(ppn_list, ppn_count, page_size);
    if (!offset_list) {
        return 0;
    }
    for (uint64_t i = 0; i < ppn_count; ++i) {
        memcpy(mbe->logical_space + offset_list[i], buffer + i * page_size, page_size);
    }
    g_free(offset_list);

    return 0;
}

// Note: this is the raw operation. The FTL will handle relevant metadata updates.
int ftl_backend_raw_erase(SsdDramBackend *mbe, uint64_t *pbn, uint64_t block_size)
{
    if (!pbn || !block_size) {
        return 0;
    }

    for (uint64_t i = 0; i < block_size; ++i) {
        // Erasure sets the block to all 1s.
        memset(mbe->logical_space + pbn[i] * block_size, 0xFF, block_size); 
    }
    return 0;
}
