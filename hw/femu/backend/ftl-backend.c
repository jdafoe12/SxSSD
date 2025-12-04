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

