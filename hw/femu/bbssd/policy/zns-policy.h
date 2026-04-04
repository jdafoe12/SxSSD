#ifndef ZNS_POLICY_H
#define ZNS_POLICY_H

#include "femu_policy.h"

#ifndef QEMU_PACKED
#define QEMU_PACKED __attribute__((packed))
#endif

#define ZNS_POLICY_ZONE_TYPE_SEQ_WRITE 0x02

enum zns_policy_zone_attr {
    ZNS_POLICY_ZA_FINISHED_BY_CTLR = 1 << 0,
};

enum zns_policy_zone_receive_action {
    ZNS_POLICY_ZONE_REPORT = 0,
    ZNS_POLICY_ZONE_REPORT_EXTENDED = 1,
};

enum zns_policy_zone_report_type {
    ZNS_POLICY_ZONE_REPORT_ALL = 0,
    ZNS_POLICY_ZONE_REPORT_EMPTY = 1,
    ZNS_POLICY_ZONE_REPORT_IMPLICITLY_OPEN = 2,
    ZNS_POLICY_ZONE_REPORT_EXPLICITLY_OPEN = 3,
    ZNS_POLICY_ZONE_REPORT_CLOSED = 4,
    ZNS_POLICY_ZONE_REPORT_FULL = 5,
    ZNS_POLICY_ZONE_REPORT_READ_ONLY = 6,
    ZNS_POLICY_ZONE_REPORT_OFFLINE = 7,
};

enum zns_policy_zone_send_action {
    ZNS_POLICY_ZONE_ACTION_CLOSE = 0x01,
    ZNS_POLICY_ZONE_ACTION_FINISH = 0x02,
    ZNS_POLICY_ZONE_ACTION_OPEN = 0x03,
    ZNS_POLICY_ZONE_ACTION_RESET = 0x04,
};

enum zns_policy_zone_state {
    ZNS_POLICY_ZONE_STATE_EMPTY = 0x01,
    ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN = 0x02,
    ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN = 0x03,
    ZNS_POLICY_ZONE_STATE_CLOSED = 0x04,
    ZNS_POLICY_ZONE_STATE_READ_ONLY = 0x0D,
    ZNS_POLICY_ZONE_STATE_FULL = 0x0E,
    ZNS_POLICY_ZONE_STATE_OFFLINE = 0x0F,
};

typedef struct QEMU_PACKED ZnsPolicyZoneReportHeader {
    uint64_t nr_zones;
    uint8_t rsvd[56];
} ZnsPolicyZoneReportHeader;

typedef struct QEMU_PACKED ZnsPolicyZoneDescr {
    uint8_t zt;
    uint8_t zs;
    uint8_t za;
    uint8_t rsvd3[5];
    uint64_t zcap;
    uint64_t zslba;
    uint64_t wp;
    uint8_t rsvd32[32];
} ZnsPolicyZoneDescr;

typedef struct QEMU_PACKED ZnsPolicyLbafe {
    uint64_t zsze;
    uint8_t zdes;
    uint8_t rsvd9[7];
} ZnsPolicyLbafe;

typedef struct QEMU_PACKED ZnsPolicyIdNsZoned {
    uint16_t zoc;
    uint16_t ozcs;
    uint32_t mar;
    uint32_t mor;
    uint32_t rrl;
    uint32_t frl;
    uint8_t rsvd20[2796];
    ZnsPolicyLbafe lbafe[16];
    uint8_t rsvd3072[768];
    uint8_t vs[256];
} ZnsPolicyIdNsZoned;

typedef struct QEMU_PACKED ZnsPolicyIdCtrlZoned {
    uint8_t zasl;
    uint8_t rsvd1[4095];
} ZnsPolicyIdCtrlZoned;

struct zns_policy_zone {
    uint32_t eswd_id;
    uint8_t state;
    uint8_t attr;
    uint64_t zslba;
    uint64_t zcap;
};

struct zns_policy_context {
    struct ssd *ssd;
    struct FtlPolicyAPI *api;
    const struct bbm_geom *geom;
    const struct eswd_layout *layout;
    struct zns_policy_zone *zones;
    uint32_t zone_count;
    uint32_t lbas_per_page;
    uint32_t lbasz;
    uint64_t zone_size_lbas;
    uint64_t zone_capacity_lbas;
    uint32_t max_open_zones;
    uint32_t max_active_zones;
    bool cross_zone_read;
    uint32_t nr_open_zones;
    uint32_t nr_active_zones;
};

#endif
