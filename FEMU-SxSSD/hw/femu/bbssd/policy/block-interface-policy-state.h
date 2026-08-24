/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef BLOCK_INTERFACE_POLICY_STATE_H
#define BLOCK_INTERFACE_POLICY_STATE_H

#include "femu_policy.h"
#include "inc/pqueue.h"
#include "inc/qtailq.h"

struct flashguard_oob;

struct eswd_free_node {
    uint32_t eswd_id;
    QTAILQ_ENTRY(eswd_free_node) entry;
};

struct eswd_full_node {
    uint32_t eswd_id;
    QTAILQ_ENTRY(eswd_full_node) entry;
};

struct eswd_victim_node {
    struct eswd *eswd;
    size_t pos;
};

struct block_policy_context {
    PseudoPpa *maptbl;
    uint64_t *rmap;
    uint64_t tt_pgs_log;
    uint64_t tt_pgs_phys;
    uint8_t *read_bitmap;
    uint8_t *retained_bitmap;
    uint64_t *retention_timestamps;
    struct flashguard_oob *oob_shadow;
    uint64_t retention_window_ns;
    int flashguard_oob_handle;
    uint32_t cur_eswd_id;
    uint32_t secs_per_pg;
    uint32_t secsz;
    uint64_t page_size;
    pqueue_t *victim_pq;
    QTAILQ_HEAD(free_eswd_list, eswd_free_node) free_list;
    QTAILQ_HEAD(full_eswd_list, eswd_full_node) full_list;
    struct eswd_free_node *free_pool;
    struct eswd_victim_node *victim_nodes;
    struct eswd_full_node *full_pool;
    int free_cnt;
    int victim_cnt;
    int full_cnt;
    int gc_thres_eswds;       /* free_cnt low watermark: trigger background GC  */
    int gc_thres_eswds_high;  /* free_cnt urgent watermark: GC before every write */
    struct FtlPolicyAPI *api;
    struct ssd *ssd;
};

#endif /* BLOCK_INTERFACE_POLICY_STATE_H */
