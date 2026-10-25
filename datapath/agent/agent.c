/* GLASSWALL datapath agent (C + libbpf).
 *
 * - loads glasswall.bpf.o, configures it, attaches XDP (generic/skb mode)
 *   to every lab interface of the gateway namespace;
 * - streams ring-buffer packet events as text lines to the brain over a
 *   Unix socket (events socket);
 * - serves enforcement commands on a second Unix socket (control socket);
 * - reaps expired verdict entries.
 *
 * Event line:  P ts cli srv cport sport proto ifindex idx len dir flags vsrc
 *              action rule canary f0..f7
 * Control commands (one per line, reply "OK <latency_us> ..." or "ERR msg"):
 *   HELLO | STATS | SV ip action rate burst ttl_ms tag | DSV ip
 *   FV cli srv cport sport proto action rate burst ttl_ms tag | DFV ...5-tuple
 *   PFX cidr action ttl_ms | DPFX cidr
 *   RCLR | RS slot rule_id mode action rate burst ttl_ms n f op th ...
 *   FLIP | ACTIVE | RH rule_id | NOW
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../bpf/glasswall_common.h"

#define MAX_IFACES 8
#define LINE_MAX_LEN 1024

static volatile sig_atomic_t stop;
static char conf_ifaces[256], conf_server[32], conf_events[128], conf_ctl[128];
static char conf_safety_ports[256], conf_safety_ips[512], conf_realizable[512];
static unsigned long long conf_window_ns, conf_pps_min_ns;
static unsigned conf_seq_len, conf_reaper_ms;

static int ifidx[MAX_IFACES], n_if;
static int fd_cfg, fd_sp, fd_sip, fd_fv, fd_sv, fd_pfx, fd_ra, fd_rb, fd_ract, fd_hits, fd_stats;
static int ev_listen = -1, ev_client = -1, ctl_listen = -1, ctl_client = -1;
static char evbuf[1 << 20];
static size_t evlen;
static unsigned long long ev_dropped;

static void on_sig(int s) { (void)s; stop = 1; }

static unsigned long long mono_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts); /* same clock as bpf_ktime_get_ns */
	return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void load_conf(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[1024];
	if (!f) { perror("agent.conf"); exit(1); }
	while (fgets(line, sizeof(line), f)) {
		char *eq = strchr(line, '=');
		if (!eq) continue;
		*eq = 0;
		char *v = eq + 1;
		v[strcspn(v, "\r\n")] = 0;
		if (!strcmp(line, "ifaces")) snprintf(conf_ifaces, sizeof(conf_ifaces), "%s", v);
		else if (!strcmp(line, "server_iface")) snprintf(conf_server, sizeof(conf_server), "%s", v);
		else if (!strcmp(line, "events_sock")) snprintf(conf_events, sizeof(conf_events), "%s", v);
		else if (!strcmp(line, "ctl_sock")) snprintf(conf_ctl, sizeof(conf_ctl), "%s", v);
		else if (!strcmp(line, "safety_ports")) snprintf(conf_safety_ports, sizeof(conf_safety_ports), "%s", v);
		else if (!strcmp(line, "safety_ips")) snprintf(conf_safety_ips, sizeof(conf_safety_ips), "%s", v);
		else if (!strcmp(line, "realizable")) snprintf(conf_realizable, sizeof(conf_realizable), "%s", v);
		else if (!strcmp(line, "window_ns")) conf_window_ns = strtoull(v, 0, 10);
		else if (!strcmp(line, "pps_min_elapsed_ns")) conf_pps_min_ns = strtoull(v, 0, 10);
		else if (!strcmp(line, "seq_len")) conf_seq_len = strtoul(v, 0, 10);
		else if (!strcmp(line, "reaper_ms")) conf_reaper_ms = strtoul(v, 0, 10);
	}
	fclose(f);
	if (!conf_ifaces[0] || !conf_server[0] || !conf_events[0] || !conf_ctl[0] || !conf_seq_len ||
	    !conf_window_ns || !conf_reaper_ms) {
		fprintf(stderr, "agent.conf incomplete\n");
		exit(1);
	}
}

static int listen_unix(const char *path)
{
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	snprintf(a.sun_path, sizeof(a.sun_path), "%s", path);
	unlink(path);
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) || listen(fd, 4)) {
		perror(path);
		exit(1);
	}
	chmod(path, 0660);
	fcntl(fd, F_SETFL, O_NONBLOCK);
	return fd;
}

static void ev_flush(void)
{
	if (ev_client < 0) { evlen = 0; return; }
	size_t off = 0;
	while (off < evlen) {
		ssize_t n = send(ev_client, evbuf + off, evlen - off, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR) continue;
			close(ev_client);
			ev_client = -1;
			break;
		}
		off += n;
	}
	evlen = 0;
}

static int on_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	const struct gw_pkt_event *e = data;
	if (sz < sizeof(*e)) return 0;
	if (ev_client < 0) { ev_dropped++; return 0; }
	if (evlen + 512 > sizeof(evbuf)) ev_flush();
	char cli[16], srv[16];
	inet_ntop(AF_INET, &e->fk.cli, cli, sizeof(cli));
	inet_ntop(AF_INET, &e->fk.srv, srv, sizeof(srv));
	int n = snprintf(evbuf + evlen, sizeof(evbuf) - evlen,
			 "P %llu %s %s %u %u %u %u %u %u %u %u %u %u %u %u",
			 (unsigned long long)e->ts_ns, cli, srv, e->fk.cport, e->fk.sport, e->fk.proto,
			 e->ifindex, e->pkt_idx, e->len, e->dir, e->tcp_flags, e->vsrc, e->action,
			 e->rule_id, e->canary_rule_id);
	evlen += n;
	for (int k = 0; k < GW_F_COUNT; k++)
		evlen += snprintf(evbuf + evlen, sizeof(evbuf) - evlen, " %llu", (unsigned long long)e->feat[k]);
	evbuf[evlen++] = '\n';
	return 0;
}

static int parse_ip(const char *s, __u32 *out) { return inet_pton(AF_INET, s, out) == 1 ? 0 : -1; }

static __u64 expiry(long ttl_ms) { return ttl_ms > 0 ? mono_ns() + (unsigned long long)ttl_ms * 1000000ULL : 0; }

static int is_safety_ip(__u32 ip)
{
	__u8 v;
	return bpf_map_lookup_elem(fd_sip, &ip, &v) == 0;
}

static int is_safety_port(__u16 p)
{
	__u8 v;
	return bpf_map_lookup_elem(fd_sp, &p, &v) == 0;
}

static int active_index(void)
{
	__u32 z = 0, a = 0;
	bpf_map_lookup_elem(fd_ract, &z, &a);
	return (int)a;
}

static void handle_cmd(char *line, char *reply, size_t rlen)
{
	unsigned long long t0 = mono_ns();
	char *tok[64];
	int n = 0;
	for (char *p = strtok(line, " \t\r\n"); p && n < 64; p = strtok(0, " \t\r\n"))
		tok[n++] = p;
	if (n == 0) { snprintf(reply, rlen, "ERR empty"); return; }
	int rc = 0;
	char extra[768] = "";

	if (!strcmp(tok[0], "HELLO")) {
		snprintf(extra, sizeof(extra), "path=xdp_generic ifaces=%s realizable=%s max_rules=%d max_pred=%d",
			 conf_ifaces, conf_realizable, GW_MAX_RULES, GW_MAX_PRED);
	} else if (!strcmp(tok[0], "NOW")) {
		snprintf(extra, sizeof(extra), "%llu", mono_ns());
	} else if (!strcmp(tok[0], "STATS")) {
		int ncpu = libbpf_num_possible_cpus();
		__u64 *vals = calloc(ncpu, sizeof(__u64));
		size_t off = 0;
		for (__u32 s = 0; s < GW_S_MAX; s++) {
			__u64 sum = 0;
			if (bpf_map_lookup_elem(fd_stats, &s, vals) == 0)
				for (int c = 0; c < ncpu; c++) sum += vals[c];
			off += snprintf(extra + off, sizeof(extra) - off, "%llu ", (unsigned long long)sum);
		}
		snprintf(extra + off, sizeof(extra) - off, "ev_dropped=%llu active=%d", ev_dropped, active_index());
		free(vals);
	} else if (!strcmp(tok[0], "SV") && n == 7) {
		__u32 ip;
		struct gw_verdict v = {0};
		if (parse_ip(tok[1], &ip)) rc = -EINVAL;
		else if (is_safety_ip(ip)) rc = -EPERM;
		else {
			v.action = atoi(tok[2]); v.rate_pps = atoi(tok[3]); v.burst = atoi(tok[4]);
			v.expires_ns = expiry(atol(tok[5])); v.tag = strtoul(tok[6], 0, 10);
			rc = bpf_map_update_elem(fd_sv, &ip, &v, BPF_ANY);
		}
	} else if (!strcmp(tok[0], "DSV") && n == 2) {
		__u32 ip;
		rc = parse_ip(tok[1], &ip) ? -EINVAL : bpf_map_delete_elem(fd_sv, &ip);
	} else if ((!strcmp(tok[0], "FV") && n == 11) || (!strcmp(tok[0], "DFV") && n == 6)) {
		struct gw_flow_key k = {0};
		if (parse_ip(tok[1], &k.cli) || parse_ip(tok[2], &k.srv)) rc = -EINVAL;
		else {
			k.cport = atoi(tok[3]); k.sport = atoi(tok[4]); k.proto = atoi(tok[5]);
			if (tok[0][0] == 'D') rc = bpf_map_delete_elem(fd_fv, &k);
			else if (is_safety_ip(k.cli) || is_safety_ip(k.srv) || is_safety_port(k.cport) ||
				 is_safety_port(k.sport)) rc = -EPERM;
			else {
				struct gw_verdict v = {0};
				v.action = atoi(tok[6]); v.rate_pps = atoi(tok[7]); v.burst = atoi(tok[8]);
				v.expires_ns = expiry(atol(tok[9])); v.tag = strtoul(tok[10], 0, 10);
				rc = bpf_map_update_elem(fd_fv, &k, &v, BPF_ANY);
			}
		}
	} else if ((!strcmp(tok[0], "PFX") && n == 4) || (!strcmp(tok[0], "DPFX") && n == 2)) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%s", tok[1]);
		char *slash = strchr(buf, '/');
		struct gw_lpm_key k = { .prefixlen = 32 };
		if (slash) { *slash = 0; k.prefixlen = atoi(slash + 1); }
		if (parse_ip(buf, &k.addr) || k.prefixlen > 32) rc = -EINVAL;
		else if (tok[0][0] == 'D') rc = bpf_map_delete_elem(fd_pfx, &k);
		else {
			struct gw_verdict v = {0};
			v.action = atoi(tok[2]);
			v.expires_ns = expiry(atol(tok[3]));
			rc = bpf_map_update_elem(fd_pfx, &k, &v, BPF_ANY);
		}
	} else if (!strcmp(tok[0], "RCLR")) {
		/* clear the INACTIVE array only; the datapath never sees it until FLIP */
		int fd = active_index() == 1 ? fd_ra : fd_rb;
		struct gw_rule r = {0};
		for (__u32 i = 0; i < GW_MAX_RULES && !rc; i++)
			rc = bpf_map_update_elem(fd, &i, &r, BPF_ANY);
	} else if (!strcmp(tok[0], "RS") && n >= 9) {
		struct gw_rule r = {0};
		__u32 slot = atoi(tok[1]);
		r.used = 1; r.rule_id = strtoul(tok[2], 0, 10); r.mode = atoi(tok[3]); r.action = atoi(tok[4]);
		r.rate_pps = atoi(tok[5]); r.burst = atoi(tok[6]); r.expires_ns = expiry(atol(tok[7]));
		r.n_pred = atoi(tok[8]);
		if (slot >= GW_MAX_RULES || r.n_pred == 0 || r.n_pred > GW_MAX_PRED || n != 9 + 3 * (int)r.n_pred)
			rc = -EINVAL;
		for (__u32 j = 0; !rc && j < r.n_pred; j++) {
			r.p[j].feat = atoi(tok[9 + 3 * j]);
			r.p[j].op = atoi(tok[10 + 3 * j]);
			r.p[j].thresh = strtoull(tok[11 + 3 * j], 0, 10);
			if (r.p[j].feat >= GW_F_COUNT || r.p[j].op > GW_OP_LE) rc = -EINVAL;
		}
		if (!rc) {
			int fd = active_index() == 1 ? fd_ra : fd_rb;
			rc = bpf_map_update_elem(fd, &slot, &r, BPF_ANY);
		}
	} else if (!strcmp(tok[0], "FLIP")) {
		/* RCU-style: one map update switches the active rule array */
		__u32 z = 0, next = active_index() == 1 ? 0 : 1;
		rc = bpf_map_update_elem(fd_ract, &z, &next, BPF_ANY);
		snprintf(extra, sizeof(extra), "active=%u", next);
	} else if (!strcmp(tok[0], "ACTIVE")) {
		snprintf(extra, sizeof(extra), "%d", active_index());
	} else if (!strcmp(tok[0], "RH") && n == 2) {
		__u32 id = strtoul(tok[1], 0, 10);
		struct gw_rule_hit h = {0};
		bpf_map_lookup_elem(fd_hits, &id, &h);
		snprintf(extra, sizeof(extra), "%llu %llu", (unsigned long long)h.matched, (unsigned long long)h.dropped);
	} else {
		snprintf(reply, rlen, "ERR unknown-or-bad-args %s", tok[0]);
		return;
	}
	unsigned long long us = (mono_ns() - t0) / 1000;
	if (rc) snprintf(reply, rlen, "ERR %s", rc == -EPERM ? "safety-allowlist" : strerror(rc < 0 ? -rc : rc));
	else snprintf(reply, rlen, "OK %llu %s", us, extra);
}

static void reap(void)
{
	__u64 now = mono_ns();
	struct gw_flow_key fk, nfk;
	struct gw_verdict v;
	void *prev = NULL;
	while (bpf_map_get_next_key(fd_fv, prev, &nfk) == 0) {
		fk = nfk;
		if (bpf_map_lookup_elem(fd_fv, &fk, &v) == 0 && v.expires_ns && v.expires_ns <= now) {
			bpf_map_delete_elem(fd_fv, &fk);
			prev = NULL; /* restart iteration after delete */
			continue;
		}
		prev = &fk;
	}
	__u32 ip, nip;
	prev = NULL;
	while (bpf_map_get_next_key(fd_sv, prev, &nip) == 0) {
		ip = nip;
		if (bpf_map_lookup_elem(fd_sv, &ip, &v) == 0 && v.expires_ns && v.expires_ns <= now) {
			char s[16];
			inet_ntop(AF_INET, &ip, s, sizeof(s));
			bpf_map_delete_elem(fd_sv, &ip);
			if (ev_client >= 0)
				evlen += snprintf(evbuf + evlen, sizeof(evbuf) - evlen, "X src %s\n", s);
			prev = NULL;
			continue;
		}
		prev = &ip;
	}
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s glasswall.bpf.o agent.conf\n", argv[0]);
		return 1;
	}
	load_conf(argv[2]);
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "failed to open/load %s\n", argv[1]);
		return 1;
	}
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "glasswall_xdp");
	int pfd = bpf_program__fd(prog);
#define MAPFD(name) bpf_object__find_map_fd_by_name(obj, name)
	fd_cfg = MAPFD("cfg"); fd_sp = MAPFD("safety_ports"); fd_sip = MAPFD("safety_ips");
	fd_fv = MAPFD("flow_verdict"); fd_sv = MAPFD("src_verdict"); fd_pfx = MAPFD("prefix_list");
	fd_ra = MAPFD("rules_a"); fd_rb = MAPFD("rules_b"); fd_ract = MAPFD("rules_active");
	fd_hits = MAPFD("rule_hits"); fd_stats = MAPFD("stats");

	int server_if = if_nametoindex(conf_server);
	if (!server_if) { fprintf(stderr, "server iface %s not found\n", conf_server); return 1; }
	struct gw_cfg c = { .window_ns = conf_window_ns, .pps_min_elapsed_ns = conf_pps_min_ns,
			    .seq_len = conf_seq_len, .server_ifindex = server_if };
	__u32 zero = 0;
	bpf_map_update_elem(fd_cfg, &zero, &c, BPF_ANY);

	__u8 one = 1;
	char tmp[512];
	snprintf(tmp, sizeof(tmp), "%s", conf_safety_ports);
	for (char *p = strtok(tmp, ","); p; p = strtok(0, ",")) {
		__u16 port = atoi(p);
		bpf_map_update_elem(fd_sp, &port, &one, BPF_ANY);
	}
	snprintf(tmp, sizeof(tmp), "%s", conf_safety_ips);
	for (char *p = strtok(tmp, ","); p; p = strtok(0, ",")) {
		__u32 ip;
		if (!parse_ip(p, &ip)) bpf_map_update_elem(fd_sip, &ip, &one, BPF_ANY);
	}

	snprintf(tmp, sizeof(tmp), "%s", conf_ifaces);
	for (char *p = strtok(tmp, ","); p && n_if < MAX_IFACES; p = strtok(0, ",")) {
		int idx = if_nametoindex(p);
		if (!idx) { fprintf(stderr, "iface %s not found\n", p); return 1; }
		int err = bpf_xdp_attach(idx, pfd, XDP_FLAGS_SKB_MODE, NULL);
		if (err) {
			fprintf(stderr, "xdp generic attach on %s failed: %s\n", p, strerror(-err));
			return 2;
		}
		ifidx[n_if++] = idx;
		fprintf(stderr, "attached xdpgeneric on %s (ifindex %d)\n", p, idx);
	}

	struct ring_buffer *rb = ring_buffer__new(MAPFD("events"), on_event, NULL, NULL);
	ev_listen = listen_unix(conf_events);
	ctl_listen = listen_unix(conf_ctl);
	fprintf(stderr, "agent ready: events=%s ctl=%s\n", conf_events, conf_ctl);

	unsigned long long last_reap = mono_ns();
	char ctlbuf[8192];
	size_t ctllen = 0;
	while (!stop) {
		ring_buffer__poll(rb, 20);
		ev_flush();

		int fd = accept(ev_listen, NULL, NULL);
		if (fd >= 0) {
			if (ev_client >= 0) close(ev_client);
			ev_client = fd;
		}
		fd = accept(ctl_listen, NULL, NULL);
		if (fd >= 0) {
			if (ctl_client >= 0) close(ctl_client);
			ctl_client = fd;
			fcntl(ctl_client, F_SETFL, O_NONBLOCK);
			ctllen = 0;
		}
		if (ctl_client >= 0) {
			ssize_t r = recv(ctl_client, ctlbuf + ctllen, sizeof(ctlbuf) - ctllen - 1, 0);
			if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
				close(ctl_client);
				ctl_client = -1;
			} else if (r > 0) {
				ctllen += r;
				ctlbuf[ctllen] = 0;
				char *nl;
				while ((nl = memchr(ctlbuf, '\n', ctllen))) {
					*nl = 0;
					char reply[1024];
					handle_cmd(ctlbuf, reply, sizeof(reply));
					size_t rl = strlen(reply);
					reply[rl++] = '\n';
					send(ctl_client, reply, rl, MSG_NOSIGNAL);
					size_t used = nl - ctlbuf + 1;
					memmove(ctlbuf, ctlbuf + used, ctllen - used);
					ctllen -= used;
				}
				if (ctllen >= sizeof(ctlbuf) - 1) ctllen = 0;
			}
		}
		if (mono_ns() - last_reap > (unsigned long long)conf_reaper_ms * 1000000ULL) {
			reap();
			last_reap = mono_ns();
		}
	}
	for (int i = 0; i < n_if; i++)
		bpf_xdp_detach(ifidx[i], XDP_FLAGS_SKB_MODE, NULL);
	ring_buffer__free(rb);
	bpf_object__close(obj);
	unlink(conf_events);
	unlink(conf_ctl);
	fprintf(stderr, "agent stopped, XDP detached\n");
	return 0;
}
