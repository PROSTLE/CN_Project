/* Types shared by the XDP program and the user-space agent. */
#ifndef GLASSWALL_COMMON_H
#define GLASSWALL_COMMON_H

#include <linux/types.h>
#include "config_gen.h" /* generated from config/glasswall.yaml */

enum gw_action { GW_PASS = 0, GW_DROP = 1, GW_RATE_LIMIT = 2 };
enum gw_rule_mode { GW_MODE_ENFORCE = 0, GW_MODE_LOG_ONLY = 1 };
enum gw_op { GW_OP_GT = 0, GW_OP_GE = 1, GW_OP_LT = 2, GW_OP_LE = 3 };

/* Kernel-realizable features; ids mirror config/features.yaml. */
enum gw_feat {
	GW_F_SRC_PKTS = 0,
	GW_F_SRC_SYN_RATIO_PM = 1,
	GW_F_SRC_RST_RATIO_PM = 2,
	GW_F_SRC_MEAN_SIZE = 3,
	GW_F_SRC_DPORTS = 4,
	GW_F_SRC_DSTS = 5,
	GW_F_SRC_PPS = 6,
	GW_F_SRC_SYN_COUNT = 7,
	GW_F_COUNT = 8,
};

/* Which table produced the verdict for a packet. */
enum gw_vsrc { GW_V_NONE = 0, GW_V_FLOW = 1, GW_V_SRC = 2, GW_V_PREFIX = 3, GW_V_RULE = 4 };

/* Counter slots in the stats array. */
enum gw_stat {
	GW_S_TOTAL = 0, GW_S_PASS, GW_S_SAFETY, GW_S_DROP_FLOW, GW_S_DROP_SRC,
	GW_S_DROP_PREFIX, GW_S_DROP_RULE, GW_S_RATE_DROP, GW_S_RB_FULL,
	GW_S_EMITTED, GW_S_NON_IP, GW_S_MAX
};

/* Flow key oriented client -> server. */
struct gw_flow_key {
	__u32 cli;
	__u32 srv;
	__u16 cport;
	__u16 sport;
	__u8 proto;
	__u8 pad[3];
};

struct gw_flow_state {
	__u64 first_ns;
	__u64 last_ns;
	__u32 pkts;
	__u32 pad;
};

struct gw_src_stats {
	__u64 win_start_ns;
	__u64 pkts;
	__u64 bytes;
	__u64 syn;
	__u64 rst;
	__u64 n_ports;
	__u64 n_hosts;
	__u64 port_bm[GW_PORT_BM_WORDS];
	__u64 host_bm[GW_HOST_BM_WORDS];
};

struct gw_verdict {
	__u32 action;
	__u32 rate_pps;
	__u32 burst;
	__u32 tag; /* decision id low bits / rule id, for tracing */
	__u64 expires_ns; /* 0 = no expiry */
};

struct gw_pred {
	__u32 feat;
	__u32 op;
	__u64 thresh;
};

struct gw_rule {
	__u32 used;
	__u32 mode;
	__u32 action;
	__u32 rule_id;
	__u32 n_pred;
	__u32 rate_pps;
	__u32 burst;
	__u32 pad;
	__u64 expires_ns;
	struct gw_pred p[GW_MAX_PRED];
};

struct gw_rule_hit {
	__u64 matched;
	__u64 dropped;
};

struct gw_tb_key {
	__u32 kind; /* 1 = source, 2 = flow */
	__u32 pad;
	struct gw_flow_key fk;
};

struct gw_tb_state {
	__u64 milli_tokens;
	__u64 last_ns;
};

struct gw_cfg {
	__u64 window_ns;
	__u64 pps_min_elapsed_ns;
	__u32 seq_len;
	__u32 server_ifindex;
};

struct gw_lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

struct gw_pkt_event {
	__u64 ts_ns;
	struct gw_flow_key fk;
	__u32 ifindex;
	__u32 pkt_idx;
	__u16 len;
	__u8 dir; /* 0 client->server, 1 server->client */
	__u8 tcp_flags;
	__u32 vsrc;
	__u32 action;
	__u32 rule_id; /* enforcing rule hit */
	__u32 canary_rule_id; /* log-only rule that would have matched */
	__u64 feat[GW_F_COUNT]; /* kernel feature snapshot for the client */
};

#endif
