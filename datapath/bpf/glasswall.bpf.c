// SPDX-License-Identifier: GPL-2.0
/* GLASSWALL in-kernel datapath (XDP).
 *
 * Per packet: safety allow-list -> per-source window counters -> enforcement
 * table lookup (flow verdict, source verdict, LPM prefix list, compiled rule
 * array selected by an active index) -> PASS / DROP / RATE-LIMIT.
 * The first seq_len packets of every flow (plus FIN/RST packets) are emitted
 * to a ring buffer with a snapshot of the kernel-realizable features.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "glasswall_common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gw_cfg);
} cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u16);
	__type(value, __u8);
} safety_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} safety_ips SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, GW_FLOW_MAP_ENTRIES);
	__type(key, struct gw_flow_key);
	__type(value, struct gw_flow_state);
} flow_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, GW_SRC_MAP_ENTRIES);
	__type(key, __u32);
	__type(value, struct gw_src_stats);
} src_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, GW_VERDICT_MAP_ENTRIES);
	__type(key, struct gw_flow_key);
	__type(value, struct gw_verdict);
} flow_verdict SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, GW_VERDICT_MAP_ENTRIES);
	__type(key, __u32);
	__type(value, struct gw_verdict);
} src_verdict SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct gw_lpm_key);
	__type(value, struct gw_verdict);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} prefix_list SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, GW_MAX_RULES);
	__type(key, __u32);
	__type(value, struct gw_rule);
} rules_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, GW_MAX_RULES);
	__type(key, __u32);
	__type(value, struct gw_rule);
} rules_b SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} rules_active SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct gw_rule_hit);
} rule_hits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, GW_VERDICT_MAP_ENTRIES);
	__type(key, struct gw_tb_key);
	__type(value, struct gw_tb_state);
} token_bucket SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, GW_S_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, GW_RINGBUF_BYTES);
} events SEC(".maps");

static __always_inline void stat_inc(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);
	if (v)
		*v += 1;
}

static __always_inline __u32 hash32(__u32 x)
{
	x ^= x >> 16;
	x *= 0x7feb352d;
	x ^= x >> 15;
	x *= 0x846ca68b;
	x ^= x >> 16;
	return x;
}

static __always_inline void src_features(struct gw_src_stats *s, __u64 now,
					 struct gw_cfg *c, __u64 *f)
{
	__u64 pkts = s->pkts;
	__u64 elapsed = now - s->win_start_ns;

	if (elapsed < c->pps_min_elapsed_ns)
		elapsed = c->pps_min_elapsed_ns;
	f[GW_F_SRC_PKTS] = pkts;
	f[GW_F_SRC_SYN_RATIO_PM] = pkts ? (s->syn * 1000) / pkts : 0;
	f[GW_F_SRC_RST_RATIO_PM] = pkts ? (s->rst * 1000) / pkts : 0;
	f[GW_F_SRC_MEAN_SIZE] = pkts ? s->bytes / pkts : 0;
	f[GW_F_SRC_DPORTS] = s->n_ports;
	f[GW_F_SRC_DSTS] = s->n_hosts;
	f[GW_F_SRC_PPS] = elapsed ? (pkts * 1000000000ULL) / elapsed : 0;
	f[GW_F_SRC_SYN_COUNT] = s->syn;
}

static __always_inline int pred_ok(struct gw_pred *p, __u64 *f)
{
	__u64 v;
	__u32 id = p->feat;

	if (id >= GW_F_COUNT)
		return 0;
	v = f[id & (GW_F_COUNT - 1)];
	switch (p->op) {
	case GW_OP_GT: return v > p->thresh;
	case GW_OP_GE: return v >= p->thresh;
	case GW_OP_LT: return v < p->thresh;
	case GW_OP_LE: return v <= p->thresh;
	}
	return 0;
}

/* Returns 1 if packet is within budget, 0 if it must be dropped. */
static __always_inline int token_ok(struct gw_tb_key *k, struct gw_verdict *v, __u64 now)
{
	struct gw_tb_state *st = bpf_map_lookup_elem(&token_bucket, k);
	__u64 cap = (__u64)v->burst * 1000;

	if (!st) {
		struct gw_tb_state ns = { .milli_tokens = cap > 1000 ? cap - 1000 : 0, .last_ns = now };
		bpf_map_update_elem(&token_bucket, k, &ns, BPF_ANY);
		return 1;
	}
	__u64 refill = ((now - st->last_ns) * v->rate_pps) / 1000000;
	__u64 tok = st->milli_tokens + refill;
	if (tok > cap)
		tok = cap;
	st->last_ns = now;
	if (tok < 1000) {
		st->milli_tokens = tok;
		return 0;
	}
	st->milli_tokens = tok - 1000;
	return 1;
}

/* Evaluate the compiled rule array. Log-only (canary) rules only count.
 * Returns 1 when an enforcing rule matched and fills *out. */
static __always_inline int eval_rules(void *rmap, __u64 *feat, __u64 now,
				      struct gw_verdict *out, __u32 *rule_id, __u32 *canary_id)
{
	for (__u32 i = 0; i < GW_MAX_RULES; i++) {
		__u32 key = i;
		struct gw_rule *r = bpf_map_lookup_elem(rmap, &key);
		if (!r || !r->used)
			continue;
		if (r->expires_ns && r->expires_ns <= now)
			continue;
		int ok = r->n_pred > 0;
		for (__u32 j = 0; j < GW_MAX_PRED; j++) {
			if (j >= r->n_pred)
				break;
			if (!pred_ok(&r->p[j], feat)) {
				ok = 0;
				break;
			}
		}
		if (!ok)
			continue;
		__u32 rid = r->rule_id;
		struct gw_rule_hit *h = bpf_map_lookup_elem(&rule_hits, &rid);
		if (!h) {
			struct gw_rule_hit nh = {};
			bpf_map_update_elem(&rule_hits, &rid, &nh, BPF_NOEXIST);
			h = bpf_map_lookup_elem(&rule_hits, &rid);
		}
		if (h)
			__sync_fetch_and_add(&h->matched, 1);
		if (r->mode == GW_MODE_LOG_ONLY) {
			if (!*canary_id)
				*canary_id = rid;
			continue;
		}
		if (h && r->action == GW_DROP)
			__sync_fetch_and_add(&h->dropped, 1);
		out->action = r->action;
		out->rate_pps = r->rate_pps;
		out->burst = r->burst;
		*rule_id = rid;
		return 1;
	}
	return 0;
}

static __always_inline void emit(struct xdp_md *ctx, struct gw_flow_key *fk, __u64 now, __u32 pkt_idx,
				 __u16 len, __u8 dir, __u8 flags, __u32 vsrc, __u32 action, __u32 rule_id,
				 __u32 canary_id, __u64 *feat)
{
	struct gw_pkt_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(GW_S_RB_FULL);
		return;
	}
	e->ts_ns = now;
	e->fk = *fk;
	e->ifindex = ctx->ingress_ifindex;
	e->pkt_idx = pkt_idx;
	e->len = len;
	e->dir = dir;
	e->tcp_flags = flags;
	e->vsrc = vsrc;
	e->action = action;
	e->rule_id = rule_id;
	e->canary_rule_id = canary_id;
	for (int k = 0; k < GW_F_COUNT; k++)
		e->feat[k] = feat[k];
	bpf_ringbuf_submit(e, 0);
	stat_inc(GW_S_EMITTED);
}

static __always_inline int live(struct gw_verdict *v, __u64 now)
{
	return v && (v->expires_ns == 0 || v->expires_ns > now);
}

SEC("xdp")
int glasswall_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	__u64 now = bpf_ktime_get_ns();
	__u32 zero = 0;

	stat_inc(GW_S_TOTAL);
	struct gw_cfg *c = bpf_map_lookup_elem(&cfg, &zero);
	if (!c)
		return XDP_PASS;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		stat_inc(GW_S_NON_IP);
		return XDP_PASS;
	}
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > end)
		return XDP_PASS;
	__u32 ihl = ip->ihl * 4;
	if (ihl < sizeof(*ip))
		return XDP_PASS;

	__u16 sport = 0, dport = 0;
	__u8 flags = 0;
	void *l4 = (void *)ip + ihl;
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *th = l4;
		if ((void *)(th + 1) > end)
			return XDP_PASS;
		sport = bpf_ntohs(th->source);
		dport = bpf_ntohs(th->dest);
		flags = ((__u8 *)th)[13];
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *uh = l4;
		if ((void *)(uh + 1) > end)
			return XDP_PASS;
		sport = bpf_ntohs(uh->source);
		dport = bpf_ntohs(uh->dest);
	}

	/* 0) safety allow-list: never dropped, checked before anything else */
	if (bpf_map_lookup_elem(&safety_ports, &sport) || bpf_map_lookup_elem(&safety_ports, &dport) ||
	    bpf_map_lookup_elem(&safety_ips, &ip->saddr) || bpf_map_lookup_elem(&safety_ips, &ip->daddr)) {
		stat_inc(GW_S_SAFETY);
		return XDP_PASS;
	}

	__u8 dir = ctx->ingress_ifindex == c->server_ifindex ? 1 : 0;
	struct gw_flow_key fk = {};
	fk.proto = ip->protocol;
	if (dir == 0) {
		fk.cli = ip->saddr; fk.srv = ip->daddr; fk.cport = sport; fk.sport = dport;
	} else {
		fk.cli = ip->daddr; fk.srv = ip->saddr; fk.cport = dport; fk.sport = sport;
	}
	__u16 len = bpf_ntohs(ip->tot_len);

	/* per-flow packet index */
	__u32 pkt_idx = 0;
	struct gw_flow_state *fs = bpf_map_lookup_elem(&flow_state, &fk);
	if (fs) {
		fs->pkts += 1;
		fs->last_ns = now;
		pkt_idx = fs->pkts - 1;
	} else {
		struct gw_flow_state nfs = { .first_ns = now, .last_ns = now, .pkts = 1 };
		bpf_map_update_elem(&flow_state, &fk, &nfs, BPF_ANY);
	}

	/* per-source rolling window, client-originated packets only */
	__u64 feat[GW_F_COUNT] = {};
	struct gw_src_stats *ss = bpf_map_lookup_elem(&src_stats, &fk.cli);
	if (!ss) {
		struct gw_src_stats nss = {};
		nss.win_start_ns = now;
		bpf_map_update_elem(&src_stats, &fk.cli, &nss, BPF_NOEXIST);
		ss = bpf_map_lookup_elem(&src_stats, &fk.cli);
	}
	if (ss) {
		if (now - ss->win_start_ns > c->window_ns) {
			__builtin_memset(ss, 0, sizeof(*ss));
			ss->win_start_ns = now;
		}
		if (dir == 0) {
			ss->pkts += 1;
			ss->bytes += len;
			if ((flags & 0x02) && !(flags & 0x10))
				ss->syn += 1;
			if (flags & 0x04)
				ss->rst += 1;
			__u32 pb = hash32(dport) % (GW_PORT_BM_WORDS * 64);
			__u32 pw = (pb / 64) & (GW_PORT_BM_WORDS - 1);
			__u64 pm = 1ULL << (pb % 64);
			if (!(ss->port_bm[pw] & pm)) {
				ss->port_bm[pw] |= pm;
				ss->n_ports += 1;
			}
			__u32 hb = hash32(ip->daddr) % (GW_HOST_BM_WORDS * 64);
			__u32 hw = (hb / 64) & (GW_HOST_BM_WORDS - 1);
			__u64 hm = 1ULL << (hb % 64);
			if (!(ss->host_bm[hw] & hm)) {
				ss->host_bm[hw] |= hm;
				ss->n_hosts += 1;
			}
		}
		src_features(ss, now, c, feat);
	}

	/* enforcement table: flow -> source -> prefix -> rules */
	__u32 vsrc = GW_V_NONE, action = GW_PASS, rule_id = 0, canary_id = 0;
	struct gw_verdict *v = bpf_map_lookup_elem(&flow_verdict, &fk);
	struct gw_tb_key tbk = {};
	struct gw_verdict rv = {};
	if (live(v, now)) {
		vsrc = GW_V_FLOW;
		tbk.kind = 2;
		tbk.fk = fk;
	} else {
		v = bpf_map_lookup_elem(&src_verdict, &fk.cli);
		if (live(v, now)) {
			vsrc = GW_V_SRC;
			tbk.kind = 1;
			tbk.fk.cli = fk.cli;
		} else {
			struct gw_lpm_key lk = { .prefixlen = 32, .addr = fk.cli };
			v = bpf_map_lookup_elem(&prefix_list, &lk);
			if (live(v, now)) {
				vsrc = GW_V_PREFIX;
				tbk.kind = 1;
				tbk.fk.cli = fk.cli;
			} else {
				v = 0;
			}
		}
	}

	if (!v && dir == 0) {
		__u32 *ai = bpf_map_lookup_elem(&rules_active, &zero);
		int hit;
		/* two call sites so each map lookup has a constant map pointer */
		if (ai && *ai == 1)
			hit = eval_rules(&rules_b, feat, now, &rv, &rule_id, &canary_id);
		else
			hit = eval_rules(&rules_a, feat, now, &rv, &rule_id, &canary_id);
		if (hit) {
			v = &rv;
			vsrc = GW_V_RULE;
			tbk.kind = 1;
			tbk.fk.cli = fk.cli;
		}
	}

	if (v) {
		action = v->action;
		if (action == GW_DROP) {
			stat_inc(vsrc == GW_V_FLOW ? GW_S_DROP_FLOW :
				 vsrc == GW_V_SRC ? GW_S_DROP_SRC :
				 vsrc == GW_V_PREFIX ? GW_S_DROP_PREFIX : GW_S_DROP_RULE);
			/* rule drops are reported (first seq_len packets of the flow) so the
			 * brain can monitor what each compiled rule drops (FP monitor) */
			if (vsrc == GW_V_RULE && pkt_idx < c->seq_len)
				emit(ctx, &fk, now, pkt_idx, len, dir, flags, vsrc, action, rule_id, canary_id, feat);
			return XDP_DROP;
		}
		if (action == GW_RATE_LIMIT && dir == 0 && !token_ok(&tbk, v, now)) {
			stat_inc(GW_S_RATE_DROP);
			return XDP_DROP;
		}
	}
	stat_inc(GW_S_PASS);

	/* telemetry: first seq_len packets of each flow, plus FIN/RST */
	if (pkt_idx < c->seq_len || (flags & 0x05))
		emit(ctx, &fk, now, pkt_idx, len, dir, flags, vsrc, action, rule_id, canary_id, feat);
	return XDP_PASS;
}
