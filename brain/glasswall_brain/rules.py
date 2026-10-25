"""Explanation-to-rule compiler (Invention 3).

Replay buffer: the brain's recent decisions on REAL traffic (kernel feature
snapshot k_*, model verdict, group attributions). Every trigger_interval_s:

 1 cluster recent BLOCK/QUARANTINE decisions by (predicted class, dominant
   attributed group of the 3-source mean attribution)       [PROPOSED clustering]
 2 distil a shallow DecisionTree (max_depth) on kernel-realizable features of
   the cluster's top-k attributed groups (fallback: all realizable), targets =
   model verdicts (cluster = 1, model-benign = 0), fitted on the older 70% of
   the replay window                                          [PROPOSED split]
 3 best positive leaf path -> conjunction of <= MAX_PRED integer predicates
 4 fidelity on the newer 30%: agreement with the model and FPR on model-benign
   rows; thresholds rules.min_agreement / rules.max_fpr (LEARNED/policy)
 5 Ed25519-signed certificate (ledger key) -> ledger
 6 canary: rule staged LOG_ONLY for canary_seconds; would-have-dropped benign
   (canary-matched flows the model judged benign) must stay <= max_fpr
 7 promote: stage active set + rule in the inactive array, FLIP (atomic),
   ruleset hash extended into the PCR, TTL rules.ttl_s
 8 FP monitor: rule-matched flows (kernel reports rule drops) that the model
   judges benign + admin FP reports; > rollback_fp_limit with >=
   rollback_min_matches -> automatic rollback (re-stage without it + FLIP)
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import deque

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier

from . import db as dbm
from .config import cfg, feature_group_map, kernel_features, path
from .ledger import canon

OPS = {"GT": 0, "GE": 1, "LT": 2, "LE": 3}
OPSYM = {"GT": ">", "GE": ">=", "LT": "<", "LE": "<="}
ACT = {"DROP": 1, "RATE_LIMIT": 2}


class RuleCompiler:
    def __init__(self, brain) -> None:
        self.b = brain
        self.C = cfg()["rules"]
        self.L = brain.L["rules"]
        self.max_pred = int(brain.hello["max_pred"])
        self.max_rules = int(brain.hello["max_rules"])
        # realizable features: the agent's HELLO list is the single source of truth
        hello = dict(x.split(":") for x in brain.hello["realizable"].split(","))
        self.kfeat = {name: int(i) for i, name in hello.items()}
        cfg_k = {k["name"]: k["id"] for k in kernel_features()}
        if self.kfeat != cfg_k:
            raise RuntimeError(f"agent realizable list {self.kfeat} != config {cfg_k}")
        self.kcols = [c for c in brain.ms.cols if c in self.kfeat]
        self.kidx = [brain.ms.cols.index(c) for c in self.kcols]
        self.gmap = feature_group_map()
        self.buf: deque = deque()
        self.last_run = time.monotonic()
        self.canary_obs: dict[int, dict] = {}
        self.fp_obs: dict[int, dict] = {}
        self.con = brain.con

    # ---------------------------------------------------------------- input
    def observe(self, rows: list[dict]) -> None:
        now = time.time()
        for r in rows:
            m = r["meta"]
            x = np.asarray(r["features"])
            att = np.mean([r["attr"][s] for s in ("gbdt", "ebm", "cfc")], axis=0)
            malicious = r["decision"].action in ("BLOCK", "QUARANTINE") and r["pred_class"] in self.b.attack
            model_benign = r["pred_class"] == self.b.benign
            self.buf.append({"t": now, "k": x[self.kidx], "mal": malicious, "benign": model_benign,
                             "cls": r["pred_class"], "att": att, "cli": m["cli"], "flow": r["flow_id"],
                             "cp": r["checkpoint"]})
            for rid in m["canary_hits"]:
                o = self.canary_obs.get(rid)
                if o is not None:
                    o["matched_flows"].add(r["flow_id"])
                    if model_benign:
                        o["benign_matched"].add(r["flow_id"])
            for rid in m["rule_hits"]:
                o = self.fp_obs.get(rid)
                if o is not None:
                    o["matched_flows"].add(r["flow_id"])
                    if model_benign:
                        o["fp_flows"].add(r["flow_id"])
            if model_benign:
                for o in self.canary_obs.values():
                    o["benign_seen"].add(r["flow_id"])
        horizon = now - self.C["window_s"]
        while self.buf and self.buf[0]["t"] < horizon:
            self.buf.popleft()

    # ---------------------------------------------------------------- loop
    def step(self) -> None:
        now = time.time()
        for r in self.con.execute("SELECT * FROM rules WHERE status='CANARY'").fetchall():
            if now - r["promoted_at"] >= self.C["canary_seconds"]:
                self.finish_canary(r)
        for r in self.con.execute("SELECT * FROM rules WHERE status='PROMOTED'").fetchall():
            if r["expires_at"] and now >= r["expires_at"]:
                self.end_rule(r["id"], "EXPIRED", "ttl elapsed")
            else:
                self.check_fp(r)
        if time.monotonic() - self.last_run >= self.C["trigger_interval_s"]:
            self.last_run = time.monotonic()
            self.compile()

    # ---------------------------------------------------------------- compile
    def compile(self) -> None:
        rows = list(self.buf)
        mal = [r for r in rows if r["mal"]]
        ben = [r for r in rows if r["benign"]]
        if len(mal) < self.C["min_cluster_flows"] or len(ben) < self.C["min_cluster_flows"]:
            return
        groups = self.b.groups
        clusters: dict[tuple, list] = {}
        for r in mal:
            clusters.setdefault((int(r["cls"]), groups[int(np.argmax(np.abs(r["att"])))]), []).append(r)
        live = {tuple(json.loads(r["cluster_json"])["key"]) for r in self.con.execute(
            "SELECT cluster_json FROM rules WHERE status IN ('CANARY','PROMOTED','PROPOSED') "
            "AND cluster_json IS NOT NULL")}
        for key, members in clusters.items():
            if len(members) < self.C["min_cluster_flows"] or tuple(key) in live:
                continue
            self.propose(list(key), members, ben)

    def propose(self, key: list, pos: list, neg: list) -> int | None:
        att = np.mean([r["att"] for r in pos], axis=0)
        top = [self.b.groups[i] for i in np.argsort(-np.abs(att))[: self.b.k] if att[i] != 0]
        cols = [i for i, c in enumerate(self.kcols) if self.gmap[c] in top]
        restricted = bool(cols)
        if not cols:
            cols = list(range(len(self.kcols)))
        data = sorted([(r, 1) for r in pos] + [(r, 0) for r in neg], key=lambda t: t[0]["t"])
        X = np.asarray([d[0]["k"] for d in data])[:, cols]
        y = np.asarray([d[1] for d in data])
        cut = int(len(y) * 0.7)
        if len(np.unique(y[:cut])) < 2 or len(np.unique(y[cut:])) < 2:
            return None
        tree = DecisionTreeClassifier(max_depth=self.C["max_depth"], class_weight="balanced",
                                      random_state=cfg()["models"]["seed"]).fit(X[:cut], y[:cut])
        preds = self._best_path(tree, [self.kcols[i] for i in cols], X[:cut], y[:cut])
        if not preds:
            return None
        match = self.match(preds, np.asarray([d[0]["k"] for d in data]))
        hold = slice(cut, None)
        agreement = float((match[hold] == y[hold].astype(bool)).mean())
        neg_hold = y[hold] == 0
        fpr = float(match[hold][neg_hold].mean()) if neg_hold.any() else 1.0
        recall = float(match[hold][~neg_hold].mean()) if (~neg_hold).any() else 0.0
        certified = agreement >= self.L["min_agreement"] and fpr <= self.L["max_fpr"]
        fid = {"agreement": agreement, "fpr": fpr, "recall": recall, "n_fit": cut, "n_holdout": int(len(y) - cut),
               "n_pos": len(pos), "n_neg": len(neg), "min_agreement": self.L["min_agreement"],
               "max_fpr": self.L["max_fpr"], "features_restricted_to_top_groups": restricted, "top_groups": top}
        text = " AND ".join(f"{p['feat']} {OPSYM[p['op']]} {p['thresh']}" for p in preds)
        action = "DROP"
        rp = self.replay_snapshot(data)
        cert = {"rule": {"predicates": preds, "action": action, "class": self.b.names[key[0]]},
                "cluster": {"key": key, "size": len(pos)}, "fidelity": fid, "model_set": self.b.ms.id,
                "model_set_hash": self.b.ms.set_hash, "config_version": self.b.L["_config_version_id"],
                "replay": rp, "created_at": time.time()}
        sig = self.b.ledger.key.sign(canon(cert)).hex()
        status = "CANARY" if certified else "FIDELITY_FAILED"
        cur = self.con.execute(
            "INSERT INTO rules (created_at, status, class_id, action, predicates_json, text, groups_json, cluster_json,"
            " fidelity_json, certificate_json, signature, certified) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (dbm.now(), "PROPOSED", key[0], action, json.dumps(preds), text, json.dumps(top),
             json.dumps({"key": key, "size": len(pos)}), json.dumps(fid), canon(cert).decode(), sig, int(certified)))
        rid = cur.lastrowid
        dec_ids = [r[0] for r in self.con.execute(
            f"SELECT id FROM decisions WHERE flow_id IN ({','.join('?' * min(len(pos), 500))}) ",
            [r["flow"] for r in pos[:500]])]
        self.con.executemany("INSERT INTO rule_provenance VALUES (?,?)", [(rid, d) for d in dec_ids])
        self.con.commit()
        self.b.ledger.append("rule_proposed", str(rid), {"rule_id": rid, "text": text, "certificate_sha256":
                             hashlib.sha256(canon(cert)).hexdigest(), "signature": sig, "status": status,
                             "provenance_decisions": len(dec_ids)})
        if certified:
            self.start_canary(rid)
        else:
            self.con.execute("UPDATE rules SET status='FIDELITY_FAILED', ended_at=?, reason=? WHERE id=?",
                             (dbm.now(), f"agreement {agreement:.4f} / fpr {fpr:.4f} vs thresholds", rid))
            self.con.commit()
        return rid

    def replay_snapshot(self, data: list) -> dict:
        d = path("replay_dir")
        name = f"replay_{time.strftime('%Y%m%d-%H%M%S')}_{len(data)}.parquet"
        df = pd.DataFrame([{**{c: float(v) for c, v in zip(self.kcols, r["k"])}, "target": y, "t": r["t"],
                            "flow": r["flow"]} for r, y in data])
        df.to_parquet(d / name, index=False)
        return {"file": name, "rows": len(df), "sha256": hashlib.sha256((d / name).read_bytes()).hexdigest()}

    def _best_path(self, tree, names: list[str], X, y) -> list[dict]:
        t = tree.tree_
        best, best_score = None, -1.0
        stack = [(0, [])]
        while stack:
            node, conds = stack.pop()
            if t.children_left[node] == -1:
                v = t.value[node][0]
                if len(v) < 2 or v[1] <= v[0]:
                    continue
                m = np.ones(len(X), dtype=bool)
                for f, op, th in conds:
                    m &= X[:, f] <= th if op == "LE" else X[:, f] > th
                if not m.any():
                    continue
                prec = y[m].mean()
                cov = m[y == 1].mean() if (y == 1).any() else 0
                score = prec * cov
                if score > best_score:
                    best, best_score = conds, score
                continue
            f, th = t.feature[node], t.threshold[node]
            stack.append((t.children_left[node], conds + [(f, "LE", th)]))
            stack.append((t.children_right[node], conds + [(f, "GT", th)]))
        if best is None:
            return []
        # merge to one bound per (feature, direction); kernel compares unsigned integers
        merged: dict[tuple, float] = {}
        for f, op, th in best:
            k = (f, op)
            merged[k] = min(merged.get(k, th), th) if op == "LE" else max(merged.get(k, th), th)
        preds = []
        for (f, op), th in merged.items():
            v = int(np.floor(th))
            if op == "LE" and th < 0:
                return []                      # unsatisfiable for unsigned counters
            preds.append({"feat": names[f], "feat_id": self.kfeat[names[f]], "op": op, "thresh": max(v, 0)})
        if len(preds) > self.max_pred:
            return []
        return preds

    def match(self, preds: list[dict], K: np.ndarray) -> np.ndarray:
        m = np.ones(len(K), dtype=bool)
        for p in preds:
            col = K[:, self.kcols.index(p["feat"])]
            th = p["thresh"]
            m &= {"GT": col > th, "GE": col >= th, "LT": col < th, "LE": col <= th}[p["op"]]
        return m

    # ---------------------------------------------------------------- kernel staging
    def stage(self, reason: str) -> str:
        """Write the full ruleset (PROMOTED enforce + CANARY log-only) into the
        inactive array, then FLIP in one map update. Returns ruleset sha."""
        rules = self.con.execute("SELECT * FROM rules WHERE status IN ('PROMOTED','CANARY') ORDER BY id").fetchall()
        if len(rules) > self.max_rules:
            raise RuntimeError("ruleset exceeds kernel capacity")
        ctl = self.b.ctl
        ok, _, rest = ctl.cmd("RCLR")
        if not ok:
            raise RuntimeError(f"RCLR failed: {rest}")
        spec = []
        now = time.time()
        for slot, r in enumerate(rules):
            preds = json.loads(r["predicates_json"])
            mode = 0 if r["status"] == "PROMOTED" else 1
            ttl_ms = max(1, int((r["expires_at"] - now) * 1000)) if r["expires_at"] else 0
            parts = " ".join(f"{p['feat_id']} {OPS[p['op']]} {p['thresh']}" for p in preds)
            cmd = f"RS {slot} {r['id']} {mode} {ACT[r['action']]} 0 0 {ttl_ms} {len(preds)} {parts}"
            ok, _, rest = ctl.cmd(cmd)
            if not ok:
                raise RuntimeError(f"{cmd}: {rest}")
            self.con.execute("UPDATE rules SET kernel_slot=? WHERE id=?", (slot, r["id"]))
            spec.append({"id": r["id"], "mode": "ENFORCE" if mode == 0 else "LOG_ONLY", "predicates": preds,
                         "action": r["action"]})
        t = time.perf_counter()
        ok, us, rest = ctl.cmd("FLIP")
        flip_us = (time.perf_counter() - t) * 1e6
        if not ok:
            raise RuntimeError(f"FLIP failed: {rest}")
        sha = hashlib.sha256(canon(spec)).hexdigest()
        self.con.execute("INSERT INTO rule_set_versions (created_at, rules_json, sha256, active_index, reason) "
                         "VALUES (?,?,?,?,?)", (dbm.now(), json.dumps(spec), sha, int(rest.split("=")[1]), reason))
        self.con.commit()
        self.b.ledger.ruleset_sha = sha
        self.b.ledger.measure("ruleset", sha, reason)
        self.b.ledger.append("ruleset_flip", sha[:16], {"sha256": sha, "rules": [s["id"] for s in spec],
                                                         "reason": reason, "flip_agent_us": us,
                                                         "flip_rtt_us": round(flip_us, 1)})
        return sha

    def start_canary(self, rid: int) -> None:
        self.con.execute("UPDATE rules SET status='CANARY', promoted_at=? WHERE id=?", (time.time(), rid))
        self.con.commit()
        self.canary_obs[rid] = {"matched_flows": set(), "benign_matched": set(), "benign_seen": set(),
                                "start": time.time()}
        self.stage(f"canary rule {rid}")

    def finish_canary(self, r) -> None:
        rid = r["id"]
        o = self.canary_obs.pop(rid, {"matched_flows": set(), "benign_matched": set(), "benign_seen": set()})
        ok, _, rest = self.b.ctl.cmd(f"RH {rid}")
        kmatched = int(rest.split()[0]) if ok else None
        nb = len(o["benign_seen"])
        fp = len(o["benign_matched"]) / nb if nb else 0.0
        res = {"kernel_matched_pkts": kmatched, "matched_flows": len(o["matched_flows"]),
               "benign_flows_seen": nb, "benign_flows_matched": len(o["benign_matched"]), "canary_fp_rate": fp,
               "max_fpr": self.L["max_fpr"], "seconds": self.C["canary_seconds"]}
        passed = fp <= self.L["max_fpr"]
        if passed:
            self.con.execute("UPDATE rules SET status='PROMOTED', canary_json=?, promoted_at=?, expires_at=? "
                             "WHERE id=?", (json.dumps(res), time.time(), time.time() + self.C["ttl_s"], rid))
            self.fp_obs[rid] = {"matched_flows": set(), "fp_flows": set(), "admin_fp": 0}
        else:
            self.con.execute("UPDATE rules SET status='CANARY_FAILED', canary_json=?, ended_at=?, reason=? WHERE id=?",
                             (json.dumps(res), time.time(), "canary false-positive rate above max_fpr", rid))
        self.con.commit()
        self.b.ledger.append("rule_canary", str(rid), {"rule_id": rid, "passed": passed, **res})
        self.stage(f"{'promote' if passed else 'canary-failed'} rule {rid}")

    def check_fp(self, r) -> None:
        rid = r["id"]
        o = self.fp_obs.setdefault(rid, {"matched_flows": set(), "fp_flows": set(), "admin_fp": 0})
        n = len(o["matched_flows"]) + o["admin_fp"]
        fp = len(o["fp_flows"]) + o["admin_fp"]
        rate = fp / n if n else 0.0
        fpj = {"matched_flows": len(o["matched_flows"]), "model_benign_flows": len(o["fp_flows"]),
               "admin_fp_reports": o["admin_fp"], "fp_rate": rate, "limit": self.C["rollback_fp_limit"],
               "min_matches": self.C["rollback_min_matches"]}
        self.con.execute("UPDATE rules SET fp_json=? WHERE id=?", (json.dumps(fpj), rid))
        if n >= self.C["rollback_min_matches"] and rate > self.C["rollback_fp_limit"]:
            self.con.execute("INSERT INTO rollback_events (rule_id, created_at, reason, fp_json) VALUES (?,?,?,?)",
                             (rid, dbm.now(), "automatic: FP rate above rollback_fp_limit", json.dumps(fpj)))
            self.end_rule(rid, "ROLLED_BACK", f"automatic rollback: fp_rate {rate:.4f} > {self.C['rollback_fp_limit']}")
        self.con.commit()

    def end_rule(self, rid: int, status: str, reason: str) -> None:
        self.con.execute("UPDATE rules SET status=?, ended_at=?, reason=? WHERE id=?", (status, dbm.now(), reason, rid))
        self.con.commit()
        self.fp_obs.pop(rid, None)
        self.canary_obs.pop(rid, None)
        self.b.ledger.append("rule_" + status.lower(), str(rid), {"rule_id": rid, "reason": reason})
        self.stage(f"{status.lower()} rule {rid}")

    # ---------------------------------------------------------------- admin
    def admin(self, kind: str, p: dict) -> str:
        rid = int(p["rule_id"])
        r = self.con.execute("SELECT * FROM rules WHERE id=?", (rid,)).fetchone()
        if r is None:
            raise ValueError("no such rule")
        if kind == "rule_reject":
            self.end_rule(rid, "REJECTED", p.get("notes") or "rejected by admin")
        elif kind == "rule_expire":
            self.end_rule(rid, "EXPIRED", "expired by admin")
        elif kind == "rule_accept":
            if r["status"] != "CANARY":
                raise ValueError("only a rule in canary can be accepted early")
            self.con.execute("UPDATE rules SET promoted_at=? WHERE id=?", (time.time() - self.C["canary_seconds"], rid))
            self.con.commit()
            self.finish_canary(self.con.execute("SELECT * FROM rules WHERE id=?", (rid,)).fetchone())
        elif kind == "rule_fp":
            o = self.fp_obs.setdefault(rid, {"matched_flows": set(), "fp_flows": set(), "admin_fp": 0})
            o["admin_fp"] += int(p.get("count", 1))
            self.check_fp(r)
        return f"{kind} rule {rid}: ok"
