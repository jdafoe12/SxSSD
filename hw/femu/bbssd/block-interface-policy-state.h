#ifndef BLOCK_INTERFACE_POLICY_STATE_H
#define BLOCK_INTERFACE_POLICY_STATE_H

#include "ftl.h"
#include "../inc/pqueue.h"
#include <sys/queue.h>

/*
 * Block interface policy context
 * 
 * This structure contains all policy-level state for the block interface:
 * - LPN → PPA mapping table (policy owns address translation)
 * - Allocation state (current write eSWD)
 * - Victim/free/full queues (policy owns GC decisions)
 * 
 * Mechanism provides eSWD primitives, migration, and validity tracking.
 * Policy uses these to implement block-level I/O with GC.
 */

/* Queue node types (same as ftl.c eswd_policy_ctx, now policy-owned) */
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
    /* LPN → PPA mapping (policy-owned address translation layer) */
    PseudoPpa *maptbl;
    /* PPA → LPN reverse map (indexed by ppa_to_pgidx(ppa), O(1) lookup) */
    uint64_t *rmap;
    uint64_t tt_pgs_log;
    
    /* Allocation state (policy decides which eSWD to use) */
    uint32_t cur_eswd_id;
    
    /* Victim/free/full queues (policy owns GC victim selection) */
    pqueue_t *victim_pq;
    QTAILQ_HEAD(free_eswd_list, eswd_free_node) free_list;
    QTAILQ_HEAD(full_eswd_list, eswd_full_node) full_list;
    struct eswd_free_node *free_pool;
    struct eswd_victim_node *victim_nodes;
    struct eswd_full_node *full_pool;
    int free_cnt;
    int victim_cnt;
    int full_cnt;
    
    /* Cached API pointer for convenience */
    struct FtlPolicyAPI *api;
    struct ssd *ssd;
};

#endif /* BLOCK_INTERFACE_POLICY_STATE_H */
