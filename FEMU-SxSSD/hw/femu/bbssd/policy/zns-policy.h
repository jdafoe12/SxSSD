#ifndef SXS_ZNS_WASM_POLICY_H
#define SXS_ZNS_WASM_POLICY_H

#include "policy-wasm-abi.h"

#define ZNS_ZONE_TYPE_SEQ_WRITE 0x02U
#define ZNS_ZA_FINISHED_BY_CONTROLLER 0x01U

#define ZNS_REPORT 0U
#define ZNS_REPORT_EXTENDED 1U

#define ZNS_REPORT_ALL 0U
#define ZNS_REPORT_EMPTY 1U
#define ZNS_REPORT_IMPLICITLY_OPEN 2U
#define ZNS_REPORT_EXPLICITLY_OPEN 3U
#define ZNS_REPORT_CLOSED 4U
#define ZNS_REPORT_FULL 5U
#define ZNS_REPORT_READ_ONLY 6U
#define ZNS_REPORT_OFFLINE 7U

#define ZNS_ACTION_CLOSE 0x01U
#define ZNS_ACTION_FINISH 0x02U
#define ZNS_ACTION_OPEN 0x03U
#define ZNS_ACTION_RESET 0x04U

#define ZNS_STATE_EMPTY 0x01U
#define ZNS_STATE_IMPLICITLY_OPEN 0x02U
#define ZNS_STATE_EXPLICITLY_OPEN 0x03U
#define ZNS_STATE_CLOSED 0x04U
#define ZNS_STATE_READ_ONLY 0x0dU
#define ZNS_STATE_FULL 0x0eU
#define ZNS_STATE_OFFLINE 0x0fU

struct __attribute__((packed)) zns_report_header {
    sxs_u64 zone_count;
    sxs_u8 reserved[56];
};

struct __attribute__((packed)) zns_report_descriptor {
    sxs_u8 type;
    sxs_u8 state;
    sxs_u8 attributes;
    sxs_u8 reserved3[5];
    sxs_u64 capacity;
    sxs_u64 start_lba;
    sxs_u64 write_pointer;
    sxs_u8 reserved32[32];
};

struct zns_zone_state {
    sxs_u32 eswd_id;
    sxs_u8 state;
    sxs_u8 attributes;
    sxs_u16 reserved;
    sxs_u64 start_lba;
    sxs_u64 capacity;
    sxs_u64 write_pointer; /* Logical ZNS write pointer visible to the host. */
    sxs_u64 data_end_lba;  /* First LBA after host-written data. */
};

struct zns_policy_state {
    sxs_u32 zone_count;
    sxs_u32 sectors_per_page;
    sxs_u32 sector_size;
    sxs_u32 max_open_zones;
    sxs_u32 max_active_zones;
    sxs_u32 open_zones;
    sxs_u32 active_zones;
    sxs_u32 cross_zone_read;
    sxs_u64 zone_size_lbas;
};

#endif /* SXS_ZNS_WASM_POLICY_H */
