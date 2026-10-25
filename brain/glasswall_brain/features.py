"""Shared feature extractor (online == offline).

FlowTable consumes datapath packet records (dp.Pkt) in stream order and emits
Snapshots at the configured checkpoints (8/16/32 packets) and at flow end
(FIN/RST + linger, or idle timeout). The brain feeds it live agent events; the
dataset builder feeds it recorded event files - same code, same order, same
vectors. Time is event time (kernel monotonic ns) so replay is deterministic.

Identity fields (IPs, ports) are kept only in Snapshot.meta and never enter
the model vector (see tests/test_features.py).
"""
from __future__ import annotations

import bisect
import hashlib
from dataclasses import dataclass, field

import numpy as np

from .config import cfg, features_cfg, model_feature_names, sequence_channels
from .dp import Pkt

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
SCHEMA_VERSION = hashlib.sha256(str(features_cfg()).encode()).hexdigest()[:12]
FEATS = model_feature_names()
FIDX = {n: i for i, n in enumerate(FEATS)}
SEQ_CH = sequence_channels()
SEQ_LEN = cfg()["datapath"]["seq_len_n"]
KFEAT_NAMES = [k["name"] for k in sorted(features_cfg()["kernel_features"], key=lambda k: k["id"])]


@dataclass(slots=True)
class Snapshot:
    flow_id: str
    checkpoint: str
    ts: int
    x: np.ndarray                 # float32 [len(FEATS)]
    seq: np.ndarray               # float32 [SEQ_LEN, len(SEQ_CH)] raw channel values
    seq_len: int
    meta: dict
    feature_hash: str = ""


@dataclass(slots=True)
class Flow:
    key: tuple
    flow_id: str
    first_ts: int
    last_ts: int = 0
    ts: list = field(default_factory=list)
    size: list = field(default_factory=list)
    dirs: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    kfeat: tuple | None = None
    fins: int = 0
    rst: bool = False
    has_reply: bool = False
    done_cp: set = field(default_factory=set)
    rule_hits: set = field(default_factory=set)
    canary_hits: set = field(default_factory=set)
    vsrc: int = 0


def feature_hash(x: np.ndarray) -> str:
    return hashlib.sha256(np.asarray(x, dtype=np.float32).tobytes() + SCHEMA_VERSION.encode()).hexdigest()


class SourceHistory:
    """Per-source flow history for G10 context features (windows from config)."""

    def __init__(self) -> None:
        fc = cfg()["features"]
        self.wins = [int(w * 1e9) for w in fc["history_windows_s"]]
        self.scan_cap = int(fc["context_scan_cap"])
        self.hist: dict[str, list] = {}   # src -> [start_idx, [first_ts...], [(dport, flow)...]]

    def add(self, f: Flow) -> None:
        h = self.hist.setdefault(f.key[0], [0, [], []])
        h[1].append(f.first_ts)
        h[2].append((f.key[3], f))

    def prune(self, now: int) -> None:
        horizon = now - max(self.wins)
        for src in list(self.hist):
            h = self.hist[src]
            i = bisect.bisect_left(h[1], horizon, lo=h[0])
            if i >= len(h[1]):
                del self.hist[src]
            elif i > 4096 and i > len(h[1]) // 2:
                h[0], h[1], h[2] = 0, h[1][i:], h[2][i:]
            else:
                h[0] = i

    def context(self, src: str, ts: int) -> list[float]:
        """Flows started in (ts-w, ts] per window; distinct dst ports and no-reply
        share over the first window, scanning at most context_scan_cap most recent
        flows (PROPOSED bound so floods stay O(cap))."""
        h = self.hist.get(src)
        if h is None:
            return [0.0] * (len(self.wins) + 2)
        firsts = h[1]
        hi = bisect.bisect_right(firsts, ts, lo=h[0])
        counts = [float(hi - max(h[0], bisect.bisect_right(firsts, ts - w, lo=h[0]))) for w in self.wins]
        lo1 = max(h[0], bisect.bisect_right(firsts, ts - self.wins[0], lo=h[0]), hi - self.scan_cap)
        ports, noreply = set(), 0
        for dport, fl in h[2][lo1:hi]:
            ports.add(dport)
            noreply += 0 if fl.has_reply else 1
        n1 = hi - lo1
        return counts + [float(len(ports)), noreply / n1 if n1 else 0.0]


class FlowTable:
    def __init__(self) -> None:
        fc = cfg()["features"]
        self.checkpoints = [int(c) for c in fc["checkpoints"]]
        self.idle_ns = int(fc["flow_idle_timeout_s"] * 1e9)
        self.linger_ns = int(fc["flow_end_linger_s"] * 1e9)
        self.min_dur = fc["rate_min_duration_s"]
        self.black = set(fc.get("blacklist") or [])
        self.white = set(fc.get("whitelist") or [])
        self.flows: dict[tuple, Flow] = {}
        self.hist = SourceHistory()
        self.now = 0
        self.seq_no = 0
        self.tick_ns = int(fc["tick_ms"] * 1e6)
        self.next_tick = 0

    # ---- stream input -------------------------------------------------
    def process(self, p: Pkt) -> list[Snapshot]:
        """Returns checkpoint snapshots for p's flow plus any flows closed by the
        event-time ticker (every tick_ms of stream time)."""
        self.now = max(self.now, p.ts)
        out = []
        if self.now >= self.next_tick:
            out = self.tick()
            self.next_tick = self.now + self.tick_ns
        f = self.flows.get(p.key)
        if f is None:
            self.seq_no += 1
            f = Flow(p.key, f"{p.ts:x}-{self.seq_no:x}", p.ts)
            self.flows[p.key] = f
            self.hist.add(f)
        f.last_ts = p.ts
        f.vsrc = p.vsrc
        if p.rule:
            f.rule_hits.add(p.rule)
        if p.canary:
            f.canary_hits.add(p.canary)
        if p.flags & FIN:
            f.fins += 1
        if p.flags & RST:
            f.rst = True
        if p.dir == 1:
            f.has_reply = True
        else:
            f.kfeat = p.feat
        f.ts.append(p.ts)
        f.size.append(p.length)
        f.dirs.append(p.dir)
        f.flags.append(p.flags)
        n = len(f.ts)
        if n in self.checkpoints and str(n) not in f.done_cp:
            f.done_cp.add(str(n))
            out.append(self.snapshot(f, str(n)))
        return out

    def tick(self, now: int | None = None) -> list[Snapshot]:
        """Close idle / ended flows (event time unless `now` given)."""
        now = self.now if now is None else max(now, self.now)
        out = []
        for k, f in list(self.flows.items()):
            ended = f.rst or f.fins >= 2
            if now - f.last_ts > self.idle_ns or (ended and now - f.last_ts > self.linger_ns):
                del self.flows[k]
                out.append(self.snapshot(f, "end"))
        self.hist.prune(now)
        return out

    def flush(self) -> list[Snapshot]:
        out = [self.snapshot(f, "end") for f in self.flows.values()]
        self.flows.clear()
        return out

    # ---- vectors ------------------------------------------------------
    def snapshot(self, f: Flow, cp: str) -> Snapshot:
        x = np.zeros(len(FEATS), dtype=np.float32)
        ts = np.asarray(f.ts, dtype=np.int64)
        size = np.asarray(f.size, dtype=np.float64)
        dirs = np.asarray(f.dirs, dtype=np.int8)
        flags = np.asarray(f.flags, dtype=np.int16)
        n = len(ts)
        dur = (ts[-1] - ts[0]) / 1e9
        iat = np.diff(ts) / 1e9 if n > 1 else np.zeros(1)
        fwd, bwd = size[dirs == 0], size[dirs == 1]

        def put(name: str, v: float) -> None:
            x[FIDX[name]] = v

        for name, bit in (("f_syn_ratio", SYN), ("f_ack_ratio", ACK), ("f_fin_ratio", FIN),
                          ("f_rst_ratio", RST), ("f_psh_ratio", PSH)):
            put(name, float(np.count_nonzero(flags & bit)) / n)
        put("f_size_mean", size.mean())
        put("f_size_std", size.std())
        put("f_size_max", size.max())
        put("f_size_min", size.min())
        put("f_iat_mean", iat.mean())
        put("f_iat_std", iat.std())
        put("f_iat_max", iat.max())
        put("f_iat_min", iat.min())
        put("f_pps", n / max(dur, self.min_dur))
        put("f_bps", size.sum() / max(dur, self.min_dur))
        put("f_fwd_len_mean", fwd.mean() if len(fwd) else 0.0)
        put("f_bwd_len_mean", bwd.mean() if len(bwd) else 0.0)
        put("f_first_len", size[0])
        put("f_handshake", float(self._handshake(dirs, flags)) if f.key[4] == 6 else 0.0)
        put("f_has_reply", float(len(bwd) > 0))
        put("f_ended", float(f.rst or f.fins > 0))
        put("f_fwd_pkt_ratio", len(fwd) / n)
        fb, bb = fwd.sum(), bwd.sum()
        put("f_byte_asym", (fb - bb) / (fb + bb) if fb + bb else 0.0)
        put("f_duration", dur)
        put("f_n_pkts", n)
        put("f_proto_tcp", float(f.key[4] == 6))
        put("f_proto_udp", float(f.key[4] == 17))
        put("f_proto_icmp", float(f.key[4] == 1))
        if f.kfeat is not None:
            for name, v in zip(KFEAT_NAMES, f.kfeat):
                put(name, float(v))
        ctx = self.hist.context(f.key[0], int(ts[-1]))
        for name, v in zip(("h_flows_1m", "h_flows_10m", "h_flows_1h", "h_dports_1m", "h_noreply_ratio_1m"), ctx):
            put(name, v)
        put("t_reputation", 0.0)  # no threat-intel feed configured (G11 inactive)
        put("l_blacklisted", float(f.key[0] in self.black))
        put("l_whitelisted", float(f.key[0] in self.white))

        m = min(n, SEQ_LEN)
        seq = np.zeros((SEQ_LEN, len(SEQ_CH)), dtype=np.float32)
        dt = np.concatenate([[0.0], np.diff(ts[:m]) / 1e9])
        fl = flags[:m]
        seq[:m, 0] = size[:m]
        seq[:m, 1] = dirs[:m]
        seq[:m, 2] = (fl & SYN) > 0
        seq[:m, 3] = (fl & ACK) > 0
        seq[:m, 4] = (fl & FIN) > 0
        seq[:m, 5] = (fl & RST) > 0
        seq[:m, 6] = (fl & PSH) > 0
        seq[:m, 7] = dt
        cli, srv, cport, sport, proto = f.key
        meta = {"cli": cli, "srv": srv, "cport": cport, "sport": sport, "proto": proto,
                "first_ts": f.first_ts, "last_ts": f.last_ts, "n_pkts": n,
                "rule_hits": sorted(f.rule_hits), "canary_hits": sorted(f.canary_hits), "vsrc": f.vsrc}
        return Snapshot(f.flow_id, cp, int(ts[-1]), x, seq, m, meta, feature_hash(x))

    @staticmethod
    def _handshake(dirs: np.ndarray, flags: np.ndarray) -> bool:
        st = 0
        for d, fl in zip(dirs, flags):
            if st == 0 and d == 0 and fl & SYN and not fl & ACK:
                st = 1
            elif st == 1 and d == 1 and fl & SYN and fl & ACK:
                st = 2
            elif st == 2 and d == 0 and fl & ACK:
                return True
        return False
