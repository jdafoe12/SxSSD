/*
 * Modified for SxSSD by Josh Dafoe.
 * SxSSD modifications: 2025-12-04 through 2026-08-23.
 */

#include "qemu/osdep.h"
#include "hw/qdev-properties.h"

#include "./nvme.h"

#define NVME_SPEC_VER (0x00010400)

static void nvme_clear_ctrl(FemuCtrl *n, bool shutdown)
{
    int i;

    /* Coperd: pause nvme poller at earliest convenience */
    n->dataplane_started = false;

    if (shutdown) {
        femu_debug("shutting down NVMe Controller ...\n");
    } else {
        femu_debug("disabling NVMe Controller ...\n");
    }

    if (shutdown) {
        femu_debug("%s,clear_guest_notifier\n", __func__);
        nvme_clear_virq(n);
    }

    for (i = 0; i <= n->nr_io_queues; i++) {
        if (n->sq[i] != NULL) {
            nvme_free_sq(n->sq[i], n);
        }
    }
    for (i = 0; i <= n->nr_io_queues; i++) {
        if (n->cq[i] != NULL) {
            nvme_free_cq(n->cq[i], n);
        }
    }

    n->bar.cc = 0;
    n->features.temp_thresh = 0x14d;
    n->temp_warn_issued = 0;
    n->dbs_addr = 0;
    n->dbs_addr_hva = 0;
    n->eis_addr = 0;
    n->eis_addr_hva = 0;
}

static int nvme_start_ctrl(FemuCtrl *n)
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (n->cq[0] || n->sq[0] || !n->bar.asq || !n->bar.acq ||
        n->bar.asq & (page_size - 1) || n->bar.acq & (page_size - 1) ||
        NVME_CC_MPS(n->bar.cc) < NVME_CAP_MPSMIN(n->bar.cap) ||
        NVME_CC_MPS(n->bar.cc) > NVME_CAP_MPSMAX(n->bar.cap) ||
        NVME_CC_IOCQES(n->bar.cc) < NVME_CTRL_CQES_MIN(n->id_ctrl.cqes) ||
        NVME_CC_IOCQES(n->bar.cc) > NVME_CTRL_CQES_MAX(n->id_ctrl.cqes) ||
        NVME_CC_IOSQES(n->bar.cc) < NVME_CTRL_SQES_MIN(n->id_ctrl.sqes) ||
        NVME_CC_IOSQES(n->bar.cc) > NVME_CTRL_SQES_MAX(n->id_ctrl.sqes) ||
        !NVME_AQA_ASQS(n->bar.aqa) || NVME_AQA_ASQS(n->bar.aqa) > 4095 ||
        !NVME_AQA_ACQS(n->bar.aqa) || NVME_AQA_ACQS(n->bar.aqa) > 4095) {
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = 1 << n->page_bits;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);
    n->cqe_size = 1 << NVME_CC_IOCQES(n->bar.cc);
    n->sqe_size = 1 << NVME_CC_IOSQES(n->bar.cc);

    nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0, NVME_AQA_ACQS(n->bar.aqa) +
                 1, 1, 1);
    nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0, NVME_AQA_ASQS(n->bar.aqa) +
                 1, NVME_Q_PRIO_HIGH, 1);

    /* Currently only used by FEMU ZNS extension */
    if (n->ext_ops.start_ctrl) {
        n->ext_ops.start_ctrl(n);
    }

    return 0;
}

static void nvme_write_bar(FemuCtrl *n, hwaddr offset, uint64_t data, unsigned size)
{
    switch (offset) {
    case 0xc:
        n->bar.intms |= data & 0xffffffff;
        n->bar.intmc = n->bar.intms;
        break;
    case 0x10:
        n->bar.intms &= ~(data & 0xffffffff);
        n->bar.intmc = n->bar.intms;
        break;
    case 0x14:
        /* If first sending data, then sending enable bit */
        if (!NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc) &&
                !NVME_CC_SHN(data) && !NVME_CC_SHN(n->bar.cc))
        {
            n->bar.cc = data;
        }

        if (NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc)) {
            n->bar.cc = data;
            if (nvme_start_ctrl(n)) {
                n->bar.csts = NVME_CSTS_FAILED;
            } else {
                n->bar.csts = NVME_CSTS_READY;
            }
        } else if (!NVME_CC_EN(data) && NVME_CC_EN(n->bar.cc)) {
            nvme_clear_ctrl(n, false);
            n->bar.csts &= ~NVME_CSTS_READY;
        }
        if (NVME_CC_SHN(data) && !(NVME_CC_SHN(n->bar.cc))) {
            nvme_clear_ctrl(n, true);
            n->bar.cc = data;
            n->bar.csts |= NVME_CSTS_SHST_COMPLETE;
        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(n->bar.cc)) {
            n->bar.csts &= ~NVME_CSTS_SHST_COMPLETE;
            n->bar.cc = data;
        }
        break;
    case 0x24:
        n->bar.aqa = data & 0xffffffff;
        break;
    case 0x28:
        n->bar.asq = data;
        break;
    case 0x2c:
        n->bar.asq |= data << 32;
        break;
    case 0x30:
        n->bar.acq = data;
        break;
    case 0x34:
        n->bar.acq |= data << 32;
        break;
    default:
        break;
    }
}

static uint64_t nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    uint8_t *ptr = (uint8_t *)&n->bar;
    uint64_t val = 0;

    if (addr < sizeof(n->bar)) {
        memcpy(&val, ptr + addr, size);
    }

    return val;
}

static void nvme_process_db_admin(FemuCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
        NvmeCQueue *cq;

        qid = ((addr - (0x1000 + (1 << (2 + n->db_stride)))) >> (3 +
                                                                 n->db_stride));
        if (nvme_check_cqid(n, qid)) {
            return;
        }

        cq = n->cq[qid];
        if (new_val >= cq->size) {
            return;
        }

        cq->head = new_val;

        if (cq->tail != cq->head) {
            nvme_isr_notify_admin(cq);
        }
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            return;
        }
        sq = n->sq[qid];
        if (new_val >= sq->size) {
            return;
        }

        sq->tail = new_val;
        nvme_process_sq_admin(sq);
    }
}

static void nvme_process_db_io(FemuCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (n->dataplane_started) {
        return;
    }

    if (addr & ((1 << (2 + n->db_stride)) - 1)) {
        return;
    }

    if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
        NvmeCQueue *cq;

        qid = ((addr - (0x1000 + (1 << (2 + n->db_stride)))) >> (3 +
                                                                 n->db_stride));
        if (nvme_check_cqid(n, qid)) {
            return;
        }

        cq = n->cq[qid];
        if (new_val >= cq->size) {
            return;
        }

        if (!cq->db_addr) {
            cq->head = new_val;
        }

        if (cq->tail != cq->head) {
            nvme_isr_notify_io(cq);
        }
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            return;
        }
        sq = n->sq[qid];
        if (new_val >= sq->size) {
            return;
        }

        if (!sq->db_addr) {
            sq->tail = new_val;
        }
    }
}

static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    if (addr < sizeof(n->bar)) {
        nvme_write_bar(n, addr, data, size);
    } else if (addr >= 0x1000 && addr < 0x1008) {
        nvme_process_db_admin(n, addr, data);
    } else {
        nvme_process_db_io(n, addr, data);
    }
}

static void nvme_cmb_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;

    memcpy(&n->cmbuf[addr], &data, size);
}

static uint64_t nvme_cmb_read(void *opaque, hwaddr addr, unsigned size)
{
    uint64_t val;
    FemuCtrl *n = (FemuCtrl *)opaque;

    memcpy(&val, &n->cmbuf[addr], size);

    return val;
}

static const MemoryRegionOps nvme_cmb_ops = {
    .read = nvme_cmb_read,
    .write = nvme_cmb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static const MemoryRegionOps nvme_mmio_ops = {
    .read = nvme_mmio_read,
    .write = nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static int nvme_check_constraints(FemuCtrl *n, Error **errp)
{
    if (n->num_namespaces == 0 || n->num_namespaces > NVME_MAX_NUM_NAMESPACES) {
        error_setg(errp, "Invalid number of namespaces: %u (must be 1-%u)",
                   n->num_namespaces, NVME_MAX_NUM_NAMESPACES);
        return -1;
    }
    if (n->nr_io_queues < 1 || n->nr_io_queues > NVME_MAX_QS) {
        error_setg(errp, "Invalid number of IO queues: %u (must be 1-%u)",
                   n->nr_io_queues, NVME_MAX_QS);
        return -1;
    }
    if (n->db_stride > NVME_MAX_STRIDE) {
        error_setg(errp, "Invalid doorbell stride: %u (max %u)",
                   n->db_stride, NVME_MAX_STRIDE);
        return -1;
    }
    if (n->max_q_ents < 1) {
        error_setg(errp, "Invalid max queue entries: %u (must be >= 1)",
                   n->max_q_ents);
        return -1;
    }
    if (n->max_sqes > NVME_MAX_QUEUE_ES || n->max_cqes > NVME_MAX_QUEUE_ES ||
        n->max_sqes < NVME_MIN_SQUEUE_ES || n->max_cqes < NVME_MIN_CQUEUE_ES) {
        error_setg(errp, "Invalid queue entry sizes: sqes=%u (min %u, max %u), cqes=%u (min %u, max %u)",
                   n->max_sqes, NVME_MIN_SQUEUE_ES, NVME_MAX_QUEUE_ES,
                   n->max_cqes, NVME_MIN_CQUEUE_ES, NVME_MAX_QUEUE_ES);
        return -1;
    }
    if (n->vwc > 1 || n->intc > 1 || n->cqr > 1 || n->extended > 1) {
        error_setg(errp, "Invalid boolean flags: vwc=%u, intc=%u, cqr=%u, extended=%u (must be 0 or 1)",
                   n->vwc, n->intc, n->cqr, n->extended);
        return -1;
    }
    if (n->nlbaf > 16) {
        error_setg(errp, "Invalid number of LBA formats: %u (max 16)", n->nlbaf);
        return -1;
    }
    if (n->lba_index >= n->nlbaf) {
        error_setg(errp, "Invalid LBA index: %u (must be < %u)", n->lba_index, n->nlbaf);
        return -1;
    }
    if (n->meta && !n->mc) {
        error_setg(errp, "Metadata size specified but metadata capabilities not set");
        return -1;
    }
    if (n->extended && !(NVME_ID_NS_MC_EXTENDED(n->mc))) {
        error_setg(errp, "Extended format requested but not supported in metadata capabilities");
        return -1;
    }
    if (!n->extended && n->meta && !(NVME_ID_NS_MC_SEPARATE(n->mc))) {
        error_setg(errp, "Separate metadata requested but not supported in metadata capabilities");
        return -1;
    }
    if (n->dps && n->meta < 8) {
        error_setg(errp, "Data protection requires metadata size >= 8, got %u", n->meta);
        return -1;
    }
    if (n->dps && ((n->dps & DPS_FIRST_EIGHT) &&
                   !NVME_ID_NS_DPC_FIRST_EIGHT(n->dpc))) {
        error_setg(errp, "Data protection first 8 bytes requested but not supported");
        return -1;
    }
    if (n->dps && !(n->dps & DPS_FIRST_EIGHT) &&
        !NVME_ID_NS_DPC_LAST_EIGHT(n->dpc)) {
        error_setg(errp, "Data protection last 8 bytes requested but not supported");
        return -1;
    }
    if (n->dps & DPS_TYPE_MASK && !((n->dpc & NVME_ID_NS_DPC_TYPE_MASK) &
                                    (1 << ((n->dps & DPS_TYPE_MASK) - 1)))) {
        error_setg(errp, "Data protection type not supported");
        return -1;
    }
    if (n->mpsmax > 0xf || n->mpsmax > n->mpsmin) {
        error_setg(errp, "Invalid memory page size: mpsmax=%u, mpsmin=%u", n->mpsmax, n->mpsmin);
        return -1;
    }
    if (n->oacs & ~(NVME_OACS_FORMAT)) {
        error_setg(errp, "Unsupported optional admin command support: 0x%x", n->oacs);
        return -1;
    }
    if (n->oncs & ~(NVME_ONCS_COMPARE | NVME_ONCS_WRITE_UNCORR |
                    NVME_ONCS_DSM | NVME_ONCS_WRITE_ZEROS)) {
        error_setg(errp, "Unsupported optional NVM command support: 0x%x", n->oncs);
        return -1;
    }

    return 0;
}

static void nvme_ns_init_identify(FemuCtrl *n, NvmeIdNs *id_ns)
{
    int npdg;
    int i;

    /* NSFEAT Bit 3: Support the Deallocated or Unwritten Logical Block error */
    id_ns->nsfeat        |= (0x4 | 0x10);
    id_ns->nlbaf         = n->nlbaf - 1;
    id_ns->flbas         = n->lba_index | (n->extended << 4);
    id_ns->mc            = n->mc;
    id_ns->dpc           = n->dpc;
    id_ns->dps           = n->dps;
    id_ns->dlfeat        = 0x9;
    id_ns->lbaf[0].lbads = 9;
    id_ns->lbaf[0].ms    = 0;

    npdg = 1;
    id_ns->npda = id_ns->npdg = npdg - 1;

    for (i = 0; i < n->nlbaf; i++) {
        id_ns->lbaf[i].lbads = BDRV_SECTOR_BITS + i;
        id_ns->lbaf[i].ms    = cpu_to_le16(n->meta);
    }
}

static int nvme_init_namespace(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    NvmeIdNs *id_ns = &ns->id_ns;
    uint64_t num_blks;
    int lba_index;

    nvme_ns_init_identify(n, id_ns);

    lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    num_blks = n->ns_size / ((1 << id_ns->lbaf[lba_index].lbads));
    /* Set nsze to the logical capacity, measured in LBAs rather than bytes. 
     * This is used to check that requests from above are within the logical capacity. */
    id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(num_blks);

    n->csi = NVME_CSI_NVM;
    ns->ctrl = n;
    ns->ns_blks = ns_blks(ns, lba_index);
    ns->util = bitmap_new(num_blks);
    ns->uncorrectable = bitmap_new(num_blks);
    ns->published = true;

    return 0;
}

static int nvme_init_namespaces(FemuCtrl *n, Error **errp)
{
    int i;

    /* FIXME: FEMU only supports 1 namesapce now */
    assert(n->num_namespaces == 1);

    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        ns->size = n->ns_size;
        ns->start_block = i * n->ns_size >> BDRV_SECTOR_BITS;
        ns->id = i + 1;

        if (nvme_init_namespace(n, ns, errp)) {
            return 1;
        }
    }

    return 0;
}

static void nvme_init_ctrl(FemuCtrl *n)
{
    NvmeIdCtrl *id = &n->id_ctrl;
    uint8_t *pci_conf = n->parent_obj.config;
    char *subnqn;
    int i;

    id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
    id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));

    id->rab          = 6;
    id->ieee[0]      = 0x00;
    id->ieee[1]      = 0x02;
    id->ieee[2]      = 0xb3;
    id->cmic         = 0;
    id->mdts         = n->mdts;
    id->ver          = 0x00010300;
    /* TODO: NVME_OACS_NS_MGMT */
    id->oacs         = cpu_to_le16(n->oacs | NVME_OACS_DBBUF);
    id->acl          = n->acl;
    id->aerl         = n->aerl;
    id->frmw         = 7 << 1 | 1;
    id->lpa          = NVME_LPA_NS_SMART | NVME_LPA_CSE | NVME_LPA_EXTENDED;
    id->elpe         = n->elpe;
    id->npss         = 0;
    id->sqes         = (n->max_sqes << 4) | 0x6;
    id->cqes         = (n->max_cqes << 4) | 0x4;
    id->nn           = cpu_to_le32(n->num_namespaces);
    id->oncs         = cpu_to_le16(n->oncs);
    subnqn           = g_strdup_printf("nqn.2019-08.org.qemu:%s", n->serial);
    strpadcpy((char *)id->subnqn, sizeof(id->subnqn), subnqn, '\0');
    id->fuses        = cpu_to_le16(0);
    id->fna          = 0;
    id->vwc          = n->vwc;
    id->awun         = cpu_to_le16(0);
    id->awupf        = cpu_to_le16(0);
    id->psd[0].mp    = cpu_to_le16(0x9c4);
    id->psd[0].enlat = cpu_to_le32(0x10);
    id->psd[0].exlat = cpu_to_le32(0x4);

    n->features.arbitration     = 0x1f0f0706;
    n->features.power_mgmt      = 0;
    n->features.temp_thresh     = 0x14d;
    n->features.err_rec         = 0;
    n->features.volatile_wc     = n->vwc;
    n->features.nr_io_queues   = ((n->nr_io_queues - 1) | ((n->nr_io_queues -
                                                              1) << 16));
    n->features.int_coalescing  = n->intc_thresh | (n->intc_time << 8);
    n->features.write_atomicity = 0;
    n->features.async_config    = 0x0;
    n->features.sw_prog_marker  = 0;

    for (i = 0; i <= n->nr_io_queues; i++) {
        n->features.int_vector_config[i] = i | (n->intc << 16);
    }

    n->bar.cap = 0;
    NVME_CAP_SET_MQES(n->bar.cap, n->max_q_ents);
    NVME_CAP_SET_CQR(n->bar.cap, n->cqr);
    NVME_CAP_SET_AMS(n->bar.cap, 1);
    NVME_CAP_SET_TO(n->bar.cap, 0xf);
    NVME_CAP_SET_DSTRD(n->bar.cap, n->db_stride);
    NVME_CAP_SET_NSSRS(n->bar.cap, 0);
    NVME_CAP_SET_CSS(n->bar.cap, 1);
    NVME_CAP_SET_CSS(n->bar.cap, NVME_CAP_CSS_CSI_SUPP);
    NVME_CAP_SET_CSS(n->bar.cap, NVME_CAP_CSS_ADMIN_ONLY);

    NVME_CAP_SET_MPSMIN(n->bar.cap, n->mpsmin);
    NVME_CAP_SET_MPSMAX(n->bar.cap, n->mpsmax);

    n->bar.vs = NVME_SPEC_VER;
    n->bar.intmc = n->bar.intms = 0;
    n->temperature = NVME_TEMPERATURE;
}

static void nvme_init_cmb(FemuCtrl *n)
{
    n->bar.cmbloc = n->cmbloc;
    n->bar.cmbsz  = n->cmbsz;

    n->cmbuf = g_malloc0(NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
    memory_region_init_io(&n->ctrl_mem, OBJECT(n), &nvme_cmb_ops, n, "nvme-cmb",
                          NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
    pci_register_bar(&n->parent_obj, NVME_CMBLOC_BIR(n->bar.cmbloc),
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64, &n->ctrl_mem);
}

static void nvme_init_pci(FemuCtrl *n)
{
    uint8_t *pci_conf = n->parent_obj.config;

    pci_conf[PCI_INTERRUPT_PIN] = 1;
    /* Coperd: QEMU-OCSSD(0x1d1d,0x1f1f), QEMU-NVMe(0x8086,0x5845) */
    pci_config_set_prog_interface(pci_conf, 0x2);
    pci_config_set_vendor_id(pci_conf, n->vid);
    pci_config_set_device_id(pci_conf, n->did);
    pci_config_set_class(pci_conf, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(&n->parent_obj, 0x80);

    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n, "nvme",
                          n->reg_size);
    pci_register_bar(&n->parent_obj, 0, PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64, &n->iomem);
    if (msix_init_exclusive_bar(&n->parent_obj, n->nr_io_queues + 1, 4, NULL)) {
        return;
    }
    msi_init(&n->parent_obj, 0x50, 32, true, false, NULL);

    if (n->cmbsz) {
        nvme_init_cmb(n);
    }
}

static int nvme_register_extensions(FemuCtrl *n)
{
    if (OCSSD(n)) {
        switch (n->lver) {
        case OCSSD12:
            nvme_register_ocssd12(n);
            break;
        case OCSSD20:
            nvme_register_ocssd20(n);
            break;
        default:
            break;
        }
    } else if (NOSSD(n)) {
        nvme_register_nossd(n);
    } else if (BBSSD(n)) {
        nvme_register_bbssd(n);
    } else if (ZNSSD(n)) {
        nvme_register_znssd(n);
    } else {
        /* TODO: For future extensions */
    }

    return 0;
}

static int64_t bbssd_physical_bytes(const BbCtrlParams *bbp)
{
    uint64_t blks_per_pl_phys = bbp->blks_per_pl;

    if (bbp->op_pct > 0 && bbp->op_pct < 100) {
        uint64_t denom = (uint64_t)(100 - bbp->op_pct);
        blks_per_pl_phys = ((uint64_t)bbp->blks_per_pl * 100 + denom - 1) / denom;
    }

    /* Physical capacity includes the extra OP blocks added on top of the exposed geometry. */
    uint64_t blks_per_lun_phys = blks_per_pl_phys * bbp->pls_per_lun;
    uint64_t total_blks_phys = blks_per_lun_phys * bbp->luns_per_ch * bbp->nchs;
    return (int64_t)bbp->secsz * bbp->secs_per_pg * bbp->pgs_per_blk *
           total_blks_phys;
}

static void femu_realize(PCIDevice *pci_dev, Error **errp)
{
    FemuCtrl *n = FEMU(pci_dev);
    int64_t bs_size; /* BACKEND STORAGE SIZE!
                      * This is the physical 
                      * capacity in bytes. */
    int64_t ls_size; /* LOGICAL STORAGE SIZE!
                      * This is the logical
                      * capacity in bytes. */

    /* Force output to stderr immediately to diagnose silent failures */
    fprintf(stderr, "[FEMU] Starting device realization (mode=%d)\n", n->femu_mode);
    fflush(stderr);

    femu_debug("FEMU: Starting device realization (mode=%d)\n", n->femu_mode);

    nvme_check_size();

    if (nvme_check_constraints(n, errp)) {
        fprintf(stderr, "[FEMU] ERROR: Constraint check failed\n");
        fflush(stderr);
        femu_err("FEMU: Constraint check failed\n");
        return;
    }

    //fprintf(stderr, "[FEMU] Constraint check passed\n");
    fflush(stderr);
    femu_debug("FEMU: Constraint check passed\n");

    
    bs_size = ((int64_t)n->memsz) * 1024 * 1024;
    ls_size = ((int64_t)n->memsz) * 1024 * 1024;
    /* In BBSSD mode, keep the larger physical backend from geometry/OP,
     * but advertise the configured namespace size just like regular FEMU.
     */
    if (BBSSD(n)) {
        const BbCtrlParams *bbp = &n->bb_params;
        bs_size = bbssd_physical_bytes(bbp);
    }

    /* There are problems with this call. The backend should 
     * occupy the physical capacity of the SSD, not the logical
     * capacity!
     */
    fprintf(stderr, "[FEMU] Allocating backend memory: %" PRId64 " bytes\n", bs_size);
    fflush(stderr);
    init_dram_backend(&n->mbe, bs_size);
    fprintf(stderr, "[FEMU] Backend memory allocated successfully\n");
    fflush(stderr); 
    n->mbe->femu_mode = n->femu_mode;

    n->completed = 0;
    n->start_time = time(NULL);
    n->reg_size = pow2ceil(0x1004 + 2 * (n->nr_io_queues + 1) * 4);
    /* n->ns_size is the advertised namespace size in bytes. */
    n->ns_size = ls_size / (uint64_t)n->num_namespaces;

    /* Coperd: [1..nr_io_queues] are used as IO queues */
    n->sq = g_malloc0(sizeof(*n->sq) * (n->nr_io_queues + 1));
    n->cq = g_malloc0(sizeof(*n->cq) * (n->nr_io_queues + 1));
    n->namespaces = g_malloc0(sizeof(*n->namespaces) * n->num_namespaces);
    n->elpes = g_malloc0(sizeof(*n->elpes) * (n->elpe + 1));
    n->aer_reqs = g_malloc0(sizeof(*n->aer_reqs) * (n->aerl + 1));
    n->features.int_vector_config = g_malloc0(sizeof(*n->features.int_vector_config) * (n->nr_io_queues + 1));

    //fprintf(stderr, "[FEMU] Initializing PCI...\n");
   // fflush(stderr);
    nvme_init_pci(n);
   // fprintf(stderr, "[FEMU] Initializing controller...\n");
   // fflush(stderr);
    nvme_init_ctrl(n);
    //fprintf(stderr, "[FEMU] Initializing namespaces...\n");
   // fflush(stderr);
    nvme_init_namespaces(n, errp);
    if (*errp) {
        fprintf(stderr, "[FEMU] ERROR: Namespace initialization failed\n");
        fflush(stderr);
        return;
    }
   // fprintf(stderr, "[FEMU] Namespace initialization completed\n");
    //fflush(stderr);

    /* This call registers the appropriate extension (e.g. BBSSD, ZNS, etc.) */
   // fprintf(stderr, "[FEMU] Registering extensions...\n");
  //  fflush(stderr);
    nvme_register_extensions(n); 

    /* This call initializes the extension (e.g. BBSSD, ZNS, etc.) 
     * in the case of BBSSD, it calls the bb_init function. */
    if (n->ext_ops.init) {
      //  fprintf(stderr, "[FEMU] Initializing extension (mode=%d)...\n", n->femu_mode);
      //  fflush(stderr);
        n->ext_ops.init(n, errp);
     //   if (*errp) {
     //       fprintf(stderr, "[FEMU] ERROR: Extension initialization failed\n");
    //        fflush(stderr);
    //        return;
    //    }
     //   fprintf(stderr, "[FEMU] Extension initialization completed\n");
    //    fflush(stderr);
    }
    
   // fprintf(stderr, "[FEMU] Device realization completed successfully\n");
   // fflush(stderr);
}

static void nvme_destroy_poller(FemuCtrl *n)
{
    int i;
    femu_debug("Destroying NVMe poller !!\n");

    for (i = 1; i <= n->nr_pollers; i++) {
        qemu_thread_join(&n->poller[i]);
    }

    for (i = 1; i <= n->nr_pollers; i++) {
        pqueue_free(n->pq[i]);
        femu_ring_free(n->to_poller[i]);
        femu_ring_free(n->to_ftl[i]);
    }

    g_free(n->should_isr);
}

static void femu_exit(PCIDevice *pci_dev)
{
    FemuCtrl *n = FEMU(pci_dev);

    femu_debug("femu_exit starting!\n");

    if (n->ext_ops.exit) {
        n->ext_ops.exit(n);
    }

    nvme_clear_ctrl(n, true);
    nvme_destroy_poller(n);
    free_dram_backend(n->mbe);

    g_free(n->namespaces);
    g_free(n->features.int_vector_config);
    g_free(n->aer_reqs);
    g_free(n->elpes);
    g_free(n->cq);
    g_free(n->sq);
    msix_uninit_exclusive_bar(pci_dev);
    memory_region_unref(&n->iomem);
    if (n->cmbsz) {
        memory_region_unref(&n->ctrl_mem);
    }
}

static const Property femu_props[] = {
    //DEFINE_BLOCK_PROPERTIES(FemuCtrl, blkconf),
    DEFINE_PROP_STRING("serial", FemuCtrl, serial),
    DEFINE_PROP_UINT32("devsz_mb", FemuCtrl, memsz, 1024), /* in MB */
    DEFINE_PROP_UINT32("namespaces", FemuCtrl, num_namespaces, 1),
    DEFINE_PROP_UINT32("queues", FemuCtrl, nr_io_queues, 8),
    DEFINE_PROP_UINT32("entries", FemuCtrl, max_q_ents, 0x7ff),
    DEFINE_PROP_UINT8("multipoller_enabled", FemuCtrl, multipoller_enabled, 0),
    DEFINE_PROP_UINT8("max_cqes", FemuCtrl, max_cqes, 0x4),
    DEFINE_PROP_UINT8("max_sqes", FemuCtrl, max_sqes, 0x6),
    DEFINE_PROP_UINT8("stride", FemuCtrl, db_stride, 0),
    DEFINE_PROP_UINT8("aerl", FemuCtrl, aerl, 3),
    DEFINE_PROP_UINT8("acl", FemuCtrl, acl, 3),
    DEFINE_PROP_UINT8("elpe", FemuCtrl, elpe, 3),
    DEFINE_PROP_UINT8("mdts", FemuCtrl, mdts, 10),
    DEFINE_PROP_UINT8("cqr", FemuCtrl, cqr, 1),
    DEFINE_PROP_UINT8("vwc", FemuCtrl, vwc, 0),
    DEFINE_PROP_UINT8("intc", FemuCtrl, intc, 0),
    DEFINE_PROP_UINT8("intc_thresh", FemuCtrl, intc_thresh, 0),
    DEFINE_PROP_UINT8("intc_time", FemuCtrl, intc_time, 0),
    DEFINE_PROP_UINT8("ms", FemuCtrl, ms, 16),
    DEFINE_PROP_UINT8("ms_max", FemuCtrl, ms_max, 64),
    DEFINE_PROP_UINT8("dlfeat", FemuCtrl, dlfeat, 1),
    DEFINE_PROP_UINT8("mpsmin", FemuCtrl, mpsmin, 0),
    DEFINE_PROP_UINT8("mpsmax", FemuCtrl, mpsmax, 0),
    DEFINE_PROP_UINT8("nlbaf", FemuCtrl, nlbaf, 5),
    DEFINE_PROP_UINT8("lba_index", FemuCtrl, lba_index, 0),
    DEFINE_PROP_UINT8("extended", FemuCtrl, extended, 0),
    DEFINE_PROP_UINT8("dpc", FemuCtrl, dpc, 0),
    DEFINE_PROP_UINT8("dps", FemuCtrl, dps, 0),
    DEFINE_PROP_UINT8("mc", FemuCtrl, mc, 0),
    DEFINE_PROP_UINT8("meta", FemuCtrl, meta, 0),
    DEFINE_PROP_UINT32("cmbsz", FemuCtrl, cmbsz, 0),
    DEFINE_PROP_UINT32("cmbloc", FemuCtrl, cmbloc, 0),
    DEFINE_PROP_UINT16("oacs", FemuCtrl, oacs, NVME_OACS_FORMAT),
    DEFINE_PROP_UINT16("oncs", FemuCtrl, oncs, NVME_ONCS_DSM),
    DEFINE_PROP_UINT16("vid", FemuCtrl, vid, 0x1d1d),
    DEFINE_PROP_UINT16("did", FemuCtrl, did, 0x1f1f),
    DEFINE_PROP_UINT8("femu_mode", FemuCtrl, femu_mode, FEMU_NOSSD_MODE),
    DEFINE_PROP_UINT8("flash_type", FemuCtrl, flash_type, MLC),
    DEFINE_PROP_UINT8("lver", FemuCtrl, lver, 0x2),
    DEFINE_PROP_UINT16("lsec_size", FemuCtrl, oc_params.sec_size, 4096),
    DEFINE_PROP_UINT8("lsecs_per_pg", FemuCtrl, oc_params.secs_per_pg, 4),
    DEFINE_PROP_UINT16("lpgs_per_blk", FemuCtrl, oc_params.pgs_per_blk, 512),
    DEFINE_PROP_UINT8("lmax_sec_per_rq", FemuCtrl, oc_params.max_sec_per_rq, 64),
    DEFINE_PROP_UINT8("lnum_ch", FemuCtrl, oc_params.num_ch, 2),
    DEFINE_PROP_UINT8("lnum_lun", FemuCtrl, oc_params.num_lun, 8),
    DEFINE_PROP_UINT8("lnum_pln", FemuCtrl, oc_params.num_pln, 2),
    DEFINE_PROP_UINT16("lmetasize", FemuCtrl, oc_params.sos, 16),
    DEFINE_PROP_UINT8("zns_num_ch", FemuCtrl, zns_params.zns_num_ch, 2),
    DEFINE_PROP_UINT8("zns_num_lun", FemuCtrl, zns_params.zns_num_lun, 4),
    DEFINE_PROP_UINT8("zns_num_plane", FemuCtrl, zns_params.zns_num_plane, 2),
    DEFINE_PROP_UINT8("zns_num_blk", FemuCtrl, zns_params.zns_num_blk, 32),
    DEFINE_PROP_INT32("zns_flash_type", FemuCtrl, zns_params.zns_flash_type, QLC),
    DEFINE_PROP_INT32("secsz", FemuCtrl, bb_params.secsz, 512),
    DEFINE_PROP_INT32("secs_per_pg", FemuCtrl, bb_params.secs_per_pg, 8),
    DEFINE_PROP_INT32("pgs_per_blk", FemuCtrl, bb_params.pgs_per_blk, 256),
    DEFINE_PROP_INT32("blks_per_pl", FemuCtrl, bb_params.blks_per_pl, 256),
    DEFINE_PROP_INT32("pls_per_lun", FemuCtrl, bb_params.pls_per_lun, 1),
    DEFINE_PROP_INT32("luns_per_ch", FemuCtrl, bb_params.luns_per_ch, 8),
    DEFINE_PROP_INT32("nchs", FemuCtrl, bb_params.nchs, 8),
    DEFINE_PROP_INT32("pg_rd_lat", FemuCtrl, bb_params.pg_rd_lat, 40000),
    DEFINE_PROP_INT32("pg_wr_lat", FemuCtrl, bb_params.pg_wr_lat, 200000),
    DEFINE_PROP_INT32("blk_er_lat", FemuCtrl, bb_params.blk_er_lat, 2000000),
    DEFINE_PROP_INT32("ch_xfer_lat", FemuCtrl, bb_params.ch_xfer_lat, 0),
    DEFINE_PROP_INT32("gc_thres_pcent", FemuCtrl, bb_params.gc_thres_pcent, 75),
    DEFINE_PROP_INT32("gc_thres_pcent_high", FemuCtrl, bb_params.gc_thres_pcent_high, 95),
    DEFINE_PROP_INT32("op_pct", FemuCtrl, bb_params.op_pct, 7),
                                                                // Logical capacity = physical minus OP; backend and BBM use physical for storage.
};

static const VMStateDescription femu_vmstate = {
    .name = "femu",
    .unmigratable = 1,
};

static void femu_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->realize = femu_realize;
    pc->exit = femu_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0x5845;
    pc->revision = 2;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "FEMU Non-Volatile Memory Express";
    device_class_set_props(dc, femu_props);
    dc->vmsd = &femu_vmstate;
}

static const TypeInfo femu_info = {
    .name          = "femu",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(FemuCtrl),
    .class_init    = femu_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    },
};

static void femu_register_types(void)
{
    type_register_static(&femu_info);
}

type_init(femu_register_types)
