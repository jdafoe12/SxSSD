/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef BLOCK_INTERFACE_POLICY_H
#define BLOCK_INTERFACE_POLICY_H

#include "femu_policy.h"
#include "block-interface-policy-state.h"

#define FLASHGUARD_DEFAULT_RETENTION_NS (20ULL * 24ULL * 60ULL * 60ULL * 1000000000ULL)
#define FLASHGUARD_OOB_F_RETAINED       (1U << 0)
#define NVME_ADM_CMD_FLASHGUARD_LIST    0xe0
#define NVME_ADM_CMD_FLASHGUARD_READ    0xe1
#define FLASHGUARD_LIST_MAX_ENTRIES     128U

struct flashguard_oob {
    uint64_t lpn;
    uint64_t prev_ppa_raw;
    uint64_t retention_ts_ns;
    uint32_t flags;
    uint32_t reserved;
};

struct flashguard_list_entry {
    uint64_t ppa_raw;
    uint64_t lpn;
    uint64_t prev_ppa_raw;
    uint64_t retention_ts_ns;
    uint32_t flags;
    uint32_t reserved;
};

struct flashguard_list_response {
    uint32_t version;
    uint32_t total_retained;
    uint32_t returned_entries;
    uint32_t next_index;
    struct flashguard_list_entry entries[];
};

struct flashguard_read_request {
    uint64_t ppa_raw;
};

struct flashguard_read_response {
    uint32_t version;
    uint32_t data_len;
    uint64_t ppa_raw;
    uint64_t lpn;
    uint64_t prev_ppa_raw;
    uint64_t retention_ts_ns;
    uint32_t flags;
    uint32_t reserved;
    uint8_t data[];
};

#endif
