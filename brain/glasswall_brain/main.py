"""GLASSWALL brain - online decision loop.

agent events -> FlowTable checkpoints -> GBDT/EBM/CfC probs + group
attributions -> ECS -> Mondrian conformal set (ACI alphas) -> decision table
R1..R7 -> kernel verdict (agent ctl socket) -> SQLite + attested ledger.

Refuses to start without calibrated (LEARNED) values, a model set whose
file hashes match the registry, and a working TPM.

  python -m glasswall_brain.main
"""
from __future__ import annotations

import gzip
import json
import queue
import signal
import threading
import time
from pathlib import Path

import numpy as np

from . import db as dbm
from .config import attack_class_ids, cfg, class_names, config_sha, group_ids, learned, path
from .conformal import ACI, Mondrian
from .decision import ALLOW, ALLOW_SHADOW, BLOCK, QUARANTINE, Decision, decide, kernel_action
from .dp import Ctl, event_lines, parse_line
from .ecs import ecs, topk_groups
from .features import FEATS, FlowTable, Snapshot
from .ledger import GENESIS, Ledger
from .models import ModelSet, sha256_file

ACT_CODE = {"PASS": 0, "DROP": 1, "RATE_LIMIT": 2}
RANK = {"PASS": 0, "RATE_LIMIT": 1, "DROP": 2}


def log(*a) -> None:
    print(time.strftime("%H:%M:%S"), *a, flush=True)


class Brain:
    def __init__(self) -> None:
        C = cfg()
        self.C = C
        self.con = dbm.init()
        self.L = learned(self.con)                      # raises MissingLearned
        row = self.con.execute("SELECT id FROM model_sets WHERE active=1").fetchone()
        if row is None:
            raise RuntimeError("no active model set")
        exp = {r["kind"]: r["sha256"] for r in self.con.execute(
            "SELECT kind, sha256 FROM model_artifacts WHERE model_set_id=?", (row["id"],))}
        self.ms = ModelSet(path("models_dir") / row["id"], exp)
        if self.L["model_set_id"] != self.ms.id:
            raise RuntimeError(f"active config_version was calibrated for {self.L['model_set_id']}, "
                               f"not {self.ms.id} - re-run calibrate")
        cf = Path(self.L["conformal"]["file"])
        if sha256_file(cf) != self.L["conformal"]["sha256"]:
            raise RuntimeError("conformal calibration file hash mismatch")
        self.cp = Mondrian.from_state(json.loads(cf.read_text()))
        st = {r["class_id"]: r["alpha_t"] for r in self.con.execute("SELECT class_id, alpha_t FROM aci_state")}
        self.aci = ACI(self.ms.classes, C["conformal"]["alpha_target"], C["conformal"]["aci_gamma"], st or None)
        self.k, self.alpha = self.L["ecs"]["k"], self.L["ecs"]["alpha"]
        self.tau_lo, self.tau_hi = self.L["decision"]["tau_lo"], self.L["decision"]["tau_hi"]
        self.names = class_names()
        self.benign = self.names.index("Benign")
        self.attack = attack_class_ids()
        self.groups = group_ids()
        self.full_idx = [FEATS.index(c) for c in self.ms.cols]
        self.ctl = Ctl()
        self.hello = self.ctl.hello()
        self.con.execute("INSERT INTO enforcement_path_log (created_at, path, detail) VALUES (?,?,?)",
                         (dbm.now(), self.hello.get("path", "?"), json.dumps(self.hello)))
        self.con.commit()
        self.safety_ips = set(C["safety_allowlist"]["ips"] or [])
        self.ledger = Ledger(self.ms.id, GENESIS, self.con)
        self.ledger.reset_measurements()
        self.ledger.measure("model_set", self.ms.set_hash, self.ms.id)
        cfg_digest = __import__("hashlib").sha256((config_sha() + json.dumps(self.L, sort_keys=True)).encode()).hexdigest()
        self.ledger.measure("config", cfg_digest, f"config_version:{self.L['_config_version_id']}")
        self.ledger.measure("ruleset", GENESIS, "empty")
        self.ft = FlowTable()
        self.q: queue.Queue = queue.Queue(maxsize=200000)
        self.src_verdict: dict[str, tuple[str, float]] = {}   # cli -> (kernel action, expires wall time)
        self.stop = False
        self.stats = {"events": 0, "snapshots": 0, "decisions": 0, "batches": 0, "dropped_queue": 0,
                      "by_action": {}, "last_batch_ms": 0.0, "lat_ms": []}
        from river import drift as rdrift
        self.adwin = rdrift.ADWIN(delta=C["drift"]["adwin_delta"])
        self.archive = gzip.open(path("capture_dir") / f"online_{time.strftime('%Y%m%d-%H%M%S')}.events.gz",
                                 "wt", compresslevel=3)
        self.rules = None
        log(f"brain ready: model set {self.ms.id} ({self.ms.set_hash[:12]}), config_version "
            f"{self.L['_config_version_id']}, k={self.k} alpha={self.alpha} tau_lo={self.tau_lo:.4f} "
            f"tau_hi={self.tau_hi:.4f}, path={self.hello.get('path')}")

    # ------------------------------------------------------------------ input
    def reader(self) -> None:
        while not self.stop:
            try:
                for ln in event_lines():
                    if self.stop:
                        return
                    try:
                        self.q.put_nowait(ln)
                    except queue.Full:
                        self.stats["dropped_queue"] += 1
            except OSError as e:
                log("events socket error", e, "- retrying")
                time.sleep(1)

    # ------------------------------------------------------------------ loop
    def run(self) -> None:
        threading.Thread(target=self.reader, daemon=True).start()
        bc = self.C["brain"]
        last_idle_tick = time.monotonic()
        last_status = 0.0
        while not self.stop:
            snaps: list[Snapshot] = []
            t_end = time.monotonic() + bc["batch_wait_ms"] / 1000
            n = 0
            while n < bc["max_batch_events"] and time.monotonic() < t_end:
                try:
                    ln = self.q.get(timeout=0.01)
                except queue.Empty:
                    continue
                n += 1
                self.archive.write(ln + "\n")
                p = parse_line(ln)
                if p is None:
                    continue
                self.stats["events"] += 1
                snaps.extend(self.ft.process(p))
            if time.monotonic() - last_idle_tick > bc["idle_tick_s"]:
                snaps.extend(self.ft.tick(time.monotonic_ns()))
                last_idle_tick = time.monotonic()
            if snaps:
                for i in range(0, len(snaps), bc["max_batch_decisions"]):
                    self.decide_batch(snaps[i:i + bc["max_batch_decisions"]])
            self.admin_actions()
            self.labels_to_aci()
            self.ledger.maybe_seal()
            if self.rules is not None:
                self.rules.step()
            if time.monotonic() - last_status > 1.0:
                self.write_status()
                last_status = time.monotonic()
        self.ledger.seal_now()
        self.archive.close()

    # ------------------------------------------------------------------ decide
    def decide_batch(self, snaps: list[Snapshot]) -> None:
        t0 = time.perf_counter()
        n = len(snaps)
        X = np.stack([s.x for s in snaps])[:, self.full_idx].astype(np.float64)
        seq = np.stack([s.seq for s in snaps])
        lens = np.asarray([max(s.seq_len, 1) for s in snaps], dtype=np.int64)
        t1 = time.perf_counter()
        pr = self.ms.proba(X, seq, lens)
        t2 = time.perf_counter()
        target = pr["ens"].argmax(1)
        at = self.ms.attributions(X, seq, lens, target, with_seq=True)
        t3 = time.perf_counter()
        E, pairs = ecs(at, self.k, self.alpha)
        alphas = dict(self.aci.alpha)
        mem = self.cp.sets(pr["ens"], alphas)
        q_thr = self.cp.thresholds(alphas)
        t4 = time.perf_counter()
        topk = {s: topk_groups(at[s], self.k, self.groups) for s in ("gbdt", "ebm", "cfc")}
        now_ns = time.monotonic_ns()
        rows, ledger_rows = [], []
        for i, s in enumerate(snaps):
            S = {self.ms.classes[j] for j in np.flatnonzero(mem[i])}
            d = decide(S, float(E[i]), self.tau_lo, self.tau_hi, self.attack, self.benign)
            ka = kernel_action(d)
            enf = self.enforce(s, d, ka)
            pred = self.ms.classes[int(target[i])]
            probs = {self.names[c]: round(float(pr["ens"][i, j]), 6) for j, c in enumerate(self.ms.classes)}
            m = s.meta
            rec = {
                "flow_id": s.flow_id, "checkpoint": s.checkpoint, "ts_ns": s.ts, "feature_hash": s.feature_hash,
                "probs": probs, "pred_class": pred, "set": sorted(S), "ecs": round(float(E[i]), 6),
                "pairs": {p: {k2: round(float(v[i]), 6) for k2, v in d2.items()} for p, d2 in pairs.items()},
                "attr": {src: [round(float(v), 6) for v in at[src][i]] for src in ("gbdt", "ebm", "cfc")},
                "topk": {src: topk[src][i] for src in topk}, "decision": d, "kernel": ka, "enf": enf,
                "conformal": {"alphas": {self.names[c]: round(a, 6) for c, a in alphas.items()},
                              "thresholds": {self.names[c]: (None if not np.isfinite(q) else round(float(q), 6))
                                             for c, q in zip(self.ms.classes, q_thr)},
                              "nonconformity": {self.names[c]: round(1 - float(pr["ens"][i, j]), 6)
                                                for j, c in enumerate(self.ms.classes)},
                              "per_model": {mname: {self.names[c]: round(float(pr[mname][i, j]), 4)
                                                    for j, c in enumerate(self.ms.classes)}
                                            for mname in ("gbdt", "ebm", "cfc")}},
                "features": [round(float(v), 6) for v in X[i]],
                "seq_attr": np.round(np.abs(at["cfc_seq"][i, :s.seq_len]), 5).tolist(),
                "seq_raw": np.round(s.seq[:s.seq_len], 6).tolist(),
                "meta": m, "decided_ns": now_ns}
            rows.append(rec)
        t5 = time.perf_counter()
        lat = {"batch": n, "fx_ms": (t1 - t0) * 1e3, "models_ms": (t2 - t1) * 1e3, "explain_ms": (t3 - t2) * 1e3,
               "ecs_conformal_ms": (t4 - t3) * 1e3, "decide_enforce_ms": (t5 - t4) * 1e3}
        self.persist(rows, lat, t0)
        if self.rules is not None:
            self.rules.observe(rows)
        self.stats["batches"] += 1
        self.stats["snapshots"] += n
        for r in rows:
            score = 1 - r["probs"]["Benign"]
            self.adwin.update(score)
            if self.adwin.drift_detected:
                self.con.execute("INSERT INTO drift_events (created_at, stream, detail_json, action) VALUES (?,?,?,?)",
                                 (dbm.now(), "ensemble_attack_score", json.dumps({"width": self.adwin.width,
                                  "estimation": self.adwin.estimation}), "recalibration+retrain queued"))
                self.con.execute("INSERT INTO retrain_jobs (created_at, reason, status) VALUES (?,?,?)",
                                 (dbm.now(), "ADWIN drift on ensemble attack score", "queued"))
        self.con.commit()

    def enforce(self, s: Snapshot, d: Decision, ka: str) -> dict:
        C = self.C
        cli = s.meta["cli"]
        if ka == "PASS" or cli in self.safety_ips:
            return {"cmd": None, "ok": None}
        cur = self.src_verdict.get(cli)
        wall = time.time()
        if ka == "DROP":
            ttl_ms = int(C["decision"]["block_ttl_s"] * 1000)
            rate = burst = 0
            scope = C["decision"]["block_scope"]
        else:
            ttl_ms = int(C["quarantine"]["ttl_s"] * 1000)
            rate, burst = C["quarantine"]["rate_pps"], C["quarantine"]["burst"]
            scope = C["quarantine"]["scope_by_row"][d.row]
        # never downgrade a live stronger source verdict; refresh at most every refresh_s
        if cur and cur[1] > wall and (RANK[cur[0]] > RANK[ka] or
                                      (cur[0] == ka and cur[1] - wall > ttl_ms / 1000 - C["brain"]["refresh_s"])):
            return {"cmd": "cached", "ok": True, "active": cur[0]}
        if scope == "flow":
            m = s.meta
            cmd = (f"FV {cli} {m['srv']} {m['cport']} {m['sport']} {m['proto']} {ACT_CODE[ka]} {rate} {burst} "
                   f"{ttl_ms} 0")
        else:
            cmd = f"SV {cli} {ACT_CODE[ka]} {rate} {burst} {ttl_ms} 0"
        t = time.perf_counter()
        try:
            ok, us, rest = self.ctl.cmd(cmd)
        except OSError as e:
            ok, us, rest = False, 0, str(e)
        rtt_us = (time.perf_counter() - t) * 1e6
        if ok and scope == "source":
            self.src_verdict[cli] = (ka, wall + ttl_ms / 1000)
        self.con.execute("INSERT INTO enforcement_entries (created_at, kind, key, action, ttl_ms, ok, latency_us, "
                         "reply) VALUES (?,?,?,?,?,?,?,?)", (dbm.now(), cmd.split()[0], cli, ka, ttl_ms, int(ok), us,
                                                             rest[:200]))
        return {"cmd": cmd, "ok": ok, "agent_us": us, "rtt_us": round(rtt_us, 1), "reply": rest[:100]}

    # ------------------------------------------------------------------ persist
    def persist(self, rows: list[dict], lat: dict, t0: float) -> None:
        con = self.con
        for r in rows:
            d: Decision = r["decision"]
            m = r["meta"]
            batch_ms = (time.perf_counter() - t0) * 1e3
            lat_r = {**lat, "batch_total_ms": batch_ms,
                     "event_to_decision_ms": (r["decided_ns"] - r["ts_ns"]) / 1e6}
            cur = con.execute(
                "INSERT INTO decisions (flow_id, checkpoint, ts_ns, created_at, model_set_id, config_version_id, "
                "feature_hash, probs_json, pred_class, conf_set_json, ecs, ecs_pairs_json, attributions_json, "
                "topk_json, decision, row_id, adversarial, kernel_action, enforce_json, latency_json, conformal_json,"
                " features_json, seq_attr_json, rule_id, cli, srv, cport, sport, proto, n_pkts) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["flow_id"], r["checkpoint"], r["ts_ns"], dbm.now(), self.ms.id, self.L["_config_version_id"],
                 r["feature_hash"], dbm.jdump(r["probs"]), r["pred_class"], dbm.jdump(r["set"]), r["ecs"],
                 dbm.jdump(r["pairs"]), dbm.jdump(r["attr"]), dbm.jdump(r["topk"]), d.action, d.row,
                 int(d.adversarial), r["kernel"], dbm.jdump(r["enf"]), dbm.jdump(lat_r), dbm.jdump(r["conformal"]),
                 dbm.jdump(r["features"]), dbm.jdump({"attr": r["seq_attr"], "raw": r["seq_raw"]}),
                 (m["rule_hits"] or [None])[0], m["cli"], m["srv"], m["cport"], m["sport"], m["proto"], m["n_pkts"]))
            did = cur.lastrowid
            con.execute("INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(flow_id) DO UPDATE SET "
                        "last_ts=excluded.last_ts, n_pkts=excluded.n_pkts, last_decision_id=excluded.last_decision_id",
                        (r["flow_id"], m["cli"], m["srv"], m["cport"], m["sport"], m["proto"], m["first_ts"],
                         m["last_ts"], m["n_pkts"], did, dbm.now()))
            if d.adversarial:
                con.execute("INSERT INTO adversarial_signals (decision_id, kind, value, detail_json, created_at) "
                            "VALUES (?,?,?,?,?)", (did, "ecs_collapse", r["ecs"],
                                                   dbm.jdump({"tau_lo": self.tau_lo}), dbm.now()))
            if not r["set"]:
                con.execute("INSERT INTO adversarial_signals (decision_id, kind, value, detail_json, created_at) "
                            "VALUES (?,?,?,?,?)", (did, "ood_empty_set",
                                                   min(r["conformal"]["nonconformity"].values()), "{}", dbm.now()))
            if d.action == QUARANTINE:
                t = con.execute("SELECT id FROM review_tickets WHERE status='open' AND cli=?", (m["cli"],)).fetchone()
                if t:
                    con.execute("UPDATE review_tickets SET n_decisions=n_decisions+1, last_decision_id=? WHERE id=?",
                                (did, t["id"]))
                else:
                    con.execute("INSERT INTO review_tickets (decision_id, flow_id, cli, opened_at, status, reason, "
                                "adversarial, last_decision_id) VALUES (?,?,?,?,?,?,?,?)",
                                (did, r["flow_id"], m["cli"], dbm.now(), "open", d.row, int(d.adversarial), did))
            payload = {"decision_id": did, "flow_id": r["flow_id"], "checkpoint": r["checkpoint"],
                       "feature_hash": r["feature_hash"], "model_set": self.ms.id,
                       "model_set_hash": self.ms.set_hash, "config_version": self.L["_config_version_id"],
                       "decision": d.action, "row": d.row, "adversarial": d.adversarial, "conformal_set": r["set"],
                       "ecs": r["ecs"], "topk": {s: [[g, v] for g, v in r["topk"][s]] for s in r["topk"]},
                       "rule_id": (m["rule_hits"] or [None])[0], "kernel_action": r["kernel"]}
            seq = self.ledger.append("decision", str(did), payload)
            con.execute("UPDATE decisions SET ledger_seq=? WHERE id=?", (seq, did))
            self.stats["decisions"] += 1
            self.stats["by_action"][d.action] = self.stats["by_action"].get(d.action, 0) + 1
            self.stats["lat_ms"].append(lat_r["event_to_decision_ms"])
        self.stats["last_batch_ms"] = (time.perf_counter() - t0) * 1e3
        self.stats["lat_ms"] = self.stats["lat_ms"][-5000:]

    # ------------------------------------------------------------------ admin + labels
    def admin_actions(self) -> None:
        for a in self.con.execute("SELECT * FROM admin_actions WHERE status='pending' ORDER BY id").fetchall():
            p = json.loads(a["payload_json"] or "{}")
            res, ok = "", True
            try:
                if a["kind"] == "src_verdict":
                    cli = p["cli"]
                    if cli in self.safety_ips:
                        raise ValueError("safety allow-list")
                    if p["action"] == "PASS":
                        ok, _, res = self.ctl.cmd(f"DSV {cli}")
                        self.src_verdict.pop(cli, None)
                    else:
                        ttl = int(self.C["decision"]["block_ttl_s"] * 1000)
                        ok, _, res = self.ctl.cmd(f"SV {cli} {ACT_CODE[p['action']]} 0 0 {ttl} 0")
                        self.src_verdict[cli] = (p["action"], time.time() + ttl / 1000)
                elif a["kind"] == "kernel_stats":
                    ok, _, st = self.ctl.cmd("STATS")
                    hits = {}
                    for r in self.con.execute("SELECT id FROM rules").fetchall():
                        _, _, h = self.ctl.cmd(f"RH {r['id']}")
                        hits[r["id"]] = [int(x) for x in h.split()[:2]]
                    names = ["total", "pass", "safety", "drop_flow", "drop_src", "drop_prefix", "drop_rule",
                             "rate_drop", "rb_full", "emitted", "non_ip"]
                    vals = st.split()
                    res = json.dumps({"stats": dict(zip(names, map(int, vals[:11]))), "extra": vals[11:],
                                      "rule_hits": hits})
                elif a["kind"].startswith("rule_") and self.rules is not None:
                    res = self.rules.admin(a["kind"], p)
                else:
                    ok, res = False, f"unknown action {a['kind']}"
            except Exception as e:  # recorded, never silently ignored
                ok, res = False, repr(e)
            self.con.execute("UPDATE admin_actions SET status=?, result=?, done_at=? WHERE id=?",
                             ("done" if ok else "failed", str(res)[:4000], dbm.now(), a["id"]))
            self.ledger.append("admin_action", str(a["id"]), {"kind": a["kind"], "payload": p, "user": a["username"],
                                                               "ok": bool(ok), "result": str(res)[:200]})
        self.con.commit()

    def labels_to_aci(self) -> None:
        rows = self.con.execute("SELECT l.id, l.class_id, d.conf_set_json FROM labels l JOIN decisions d "
                                "ON d.id = l.decision_id WHERE l.aci_done=0").fetchall()
        for r in rows:
            if r["class_id"] in self.aci.alpha:
                covered = r["class_id"] in json.loads(r["conf_set_json"])
                a = self.aci.update(r["class_id"], covered)
                self.con.execute("UPDATE aci_state SET alpha_t=?, n_updates=n_updates+1, n_err=n_err+?, updated_at=? "
                                 "WHERE class_id=?", (a, int(not covered), dbm.now(), r["class_id"]))
            self.con.execute("UPDATE labels SET aci_done=1 WHERE id=?", (r["id"],))
        if rows:
            self.con.commit()

    def write_status(self) -> None:
        lat = self.stats["lat_ms"]
        st = {k: v for k, v in self.stats.items() if k != "lat_ms"}
        st.update({"p50_event_to_decision_ms": float(np.percentile(lat, 50)) if lat else None,
                   "p99_event_to_decision_ms": float(np.percentile(lat, 99)) if lat else None,
                   "open_flows": len(self.ft.flows), "queue": self.q.qsize(), "model_set": self.ms.id,
                   "model_set_hash": self.ms.set_hash, "config_version": self.L["_config_version_id"],
                   "path": self.hello.get("path"), "aci_alpha": {self.names[c]: a for c, a in self.aci.alpha.items()},
                   "tpm": self.C["environment"]["tpm_label"], "env": self.C["environment"]["label"],
                   "ledger_seq": self.ledger.seq, "ruleset_sha": self.ledger.ruleset_sha,
                   "policy": self.C["decision"]["policy"], "pid": __import__("os").getpid()})
        self.con.execute("INSERT INTO brain_status VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET updated_at=excluded."
                         "updated_at, json=excluded.json", (dbm.now(), json.dumps(st, default=float)))
        self.con.commit()


def main() -> None:
    b = Brain()
    from .rules import RuleCompiler
    b.rules = RuleCompiler(b)

    def on_sig(*_):
        b.stop = True

    signal.signal(signal.SIGTERM, on_sig)
    signal.signal(signal.SIGINT, on_sig)
    b.run()
    log("brain stopped", json.dumps({k: v for k, v in b.stats.items() if k != "lat_ms"}))


if __name__ == "__main__":
    main()
