#ifndef BLOCK_INTERFACE_POLICY_BUFFERED_STATE_H
#define BLOCK_INTERFACE_POLICY_BUFFERED_STATE_H

#include "femu_policy.h"
#include "inc/pqueue.h"
#include "inc/qtailq.h"

struct buffered_eswd_free_node {
    uint32_t eswd_id;
    QTAILQ_ENTRY(buffered_eswd_free_node) entry;
};

struct buffered_eswd_full_node {
    uint32_t eswd_id;
    QTAILQ_ENTRY(buffered_eswd_full_node) entry;
};

struct buffered_eswd_victim_node {
    struct eswd *eswd;
    size_t pos;
};

struct buffered_block_policy_context {
    PseudoPpa *maptbl;
    uint64_t *rmap;
    uint64_t tt_pgs_log;
    uint32_t cur_eswd_id;
    uint32_t secs_per_pg;
    uint32_t secsz;
    uint64_t page_size;
    pqueue_t *victim_pq;
    QTAILQ_HEAD(buffered_free_eswd_list, buffered_eswd_free_node) free_list;
    QTAILQ_HEAD(buffered_full_eswd_list, buffered_eswd_full_node) full_list;
    struct buffered_eswd_free_node *free_pool;
    struct buffered_eswd_victim_node *victim_nodes;
    struct buffered_eswd_full_node *full_pool;
    int free_cnt;
    int victim_cnt;
    int full_cnt;
    struct FtlPolicyAPI *api;
    struct ssd *ssd;
};

#endif
