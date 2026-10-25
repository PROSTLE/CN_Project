"""GLASSWALL admin API (FastAPI) + static console.

Reads the brain's SQLite DB. Never talks to the kernel directly: actions that
change enforcement are queued in admin_actions and executed (and ledgered) by
the brain, which owns the agent control socket.

  uvicorn app.main:app --host 127.0.0.1 --port 8000   (cwd = api/)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "brain"))
sys.path.insert(0, str(ROOT))
from glasswall_brain import db as dbm  # noqa: E402
from glasswall_brain.config import (MissingLearned, attack_class_ids, cfg, class_names, groups,  # noqa: E402
                                    learned, path, scenarios_cfg)
from glasswall_brain.narrator import narrate  # noqa: E402

app = FastAPI(title="GLASSWALL console API")
CON = dbm.init()
NAMES = class_names()
ROLES = {"admin": {"admin", "analyst", "auditor", "demo"}, "analyst": {"analyst"}, "auditor": {"auditor"},
         "demo": {"demo", "analyst"}}
_MS = None


def q(sql: str, args: tuple = ()) -> list[dict]:
    return [dict(r) for r in CON.execute(sql, args).fetchall()]


def q1(sql: str, args: tuple = ()) -> dict | None:
    r = CON.execute(sql, args).fetchone()
    return dict(r) if r else None


def J(s: str | None, default: Any = None) -> Any:
    return json.loads(s) if s else default


# ---------------------------------------------------------------- auth
def hash_pw(pw: str, salt: str) -> str:
    return hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()


def user(request: Request) -> dict:
    tok = request.cookies.get("gw_session")
    row = q1("SELECT u.username, u.role FROM sessions s JOIN users u ON u.username=s.username WHERE s.token=?",
             (tok or "",))
    if not row:
        raise HTTPException(401, "login required")
    return row


def need(*roles: str):
    def dep(u: dict = Depends(user)) -> dict:
        if not ROLES[u["role"]] & set(roles):
            raise HTTPException(403, f"role {u['role']} may not do this")
        return u
    return dep


def audit_log(u: dict, action: str, detail: Any) -> None:
    CON.execute("INSERT INTO ui_audit_log (created_at, username, action, detail) VALUES (?,?,?,?)",
                (dbm.now(), u["username"], action, json.dumps(detail)))
    CON.commit()


class Login(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(body: Login, response: Response) -> dict:
    u = q1("SELECT * FROM users WHERE username=?", (body.username,))
    if not u or not hmac.compare_digest(hash_pw(body.password, u["salt"]), u["pw_hash"]):
        raise HTTPException(401, "invalid credentials")
    tok = secrets.token_hex(32)
    CON.execute("INSERT INTO sessions VALUES (?,?,?)", (tok, u["username"], dbm.now()))
    CON.commit()
    response.set_cookie("gw_session", tok, httponly=True, samesite="strict")
    return {"username": u["username"], "role": u["role"]}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response) -> dict:
    CON.execute("DELETE FROM sessions WHERE token=?", (request.cookies.get("gw_session", ""),))
    CON.commit()
    response.delete_cookie("gw_session")
    return {"ok": True}


@app.get("/api/auth/me")
def me(u: dict = Depends(user)) -> dict:
    return u


# ---------------------------------------------------------------- meta / status
def learned_or_none() -> dict | None:
    try:
        return learned(CON)
    except MissingLearned:
        return None


@app.get("/api/meta")
def meta() -> dict:
    L = learned_or_none()
    st = q1("SELECT updated_at, json FROM brain_status WHERE id=1")
    status = J(st["json"]) if st else None
    if st:
        status["age_s"] = time.time() - st["updated_at"]
    ms = q1("SELECT id, set_hash, created_at, meta_json FROM model_sets WHERE active=1")
    vr = q1("SELECT * FROM verification_runs ORDER BY id DESC LIMIT 1")
    ep = q1("SELECT * FROM enforcement_path_log ORDER BY id DESC LIMIT 1")
    C = cfg()
    return {
        "classes": [{"id": i, "name": c["name"], "attack": c["attack"]} for i, c in enumerate(C["classes"])],
        "classes_modelled": J(ms["meta_json"])["classes"] if ms else [],
        "groups": groups(),
        "features": q("SELECT name, group_id, section, kernel_realizable FROM features"),
        "learned": None if L is None else {"k": L["ecs"]["k"], "alpha": L["ecs"]["alpha"],
                                           "tau_lo": L["decision"]["tau_lo"], "tau_hi": L["decision"]["tau_hi"],
                                           "rules_min_agreement": L["rules"]["min_agreement"],
                                           "rules_max_fpr": L["rules"]["max_fpr"],
                                           "config_version": L["_config_version_id"],
                                           "source_run_id": L["_source_run_id"]},
        "policy": {"mode": C["decision"]["policy"], "fpr_budget": C["decision"]["fpr_budget"],
                   "block_ttl_s": C["decision"]["block_ttl_s"], "quarantine": C["quarantine"],
                   "block_scope": C["decision"]["block_scope"], "alpha_target": C["conformal"]["alpha_target"],
                   "aci_gamma": C["conformal"]["aci_gamma"]},
        "checkpoints": C["features"]["checkpoints"] + ["end"],
        "safety_allowlist": C["safety_allowlist"],
        "env": {"label": C["environment"]["label"], "tpm": C["environment"]["tpm_label"]},
        "enforcement_path": ep,
        "model_set": None if not ms else {"id": ms["id"], "set_hash": ms["set_hash"], "created_at": ms["created_at"]},
        "brain": status,
        "last_verification": vr,
        "narrator": {"endpoint": C["narrator"]["endpoint"], "model": C["narrator"]["model"]},
        "scenarios": {k: {"class": v["class"], "duration": v["duration"], "evasion": bool(v.get("evasion"))}
                      for k, v in scenarios_cfg()["scenarios"].items()},
    }


@app.get("/api/stats")
def stats(window_s: int = 60) -> dict:
    since = time.time() - window_s
    rows = q("SELECT decision, COUNT(*) n, SUM(adversarial) adv FROM decisions WHERE created_at>=? GROUP BY decision",
             (since,))
    lat = [J(r["latency_json"])["event_to_decision_ms"] for r in
           q("SELECT latency_json FROM decisions WHERE created_at>=? ORDER BY id DESC LIMIT 5000", (since,))]
    total = sum(r["n"] for r in rows)
    return {"window_s": window_s, "total": total, "per_s": total / window_s,
            "by_decision": {r["decision"]: r["n"] for r in rows},
            "adversarial": sum(r["adv"] or 0 for r in rows),
            "p50_ms": float(np.percentile(lat, 50)) if lat else None,
            "p99_ms": float(np.percentile(lat, 99)) if lat else None,
            "promoted_rules": q1("SELECT COUNT(*) n FROM rules WHERE status='PROMOTED'")["n"],
            "drift_events": q1("SELECT COUNT(*) n FROM drift_events WHERE created_at>=?", (since,))["n"],
            "open_tickets": q1("SELECT COUNT(*) n FROM review_tickets WHERE status='open'")["n"]}


# ---------------------------------------------------------------- decisions
LIGHT = ("id, flow_id, checkpoint, created_at, decision, row_id, adversarial, ecs, pred_class, conf_set_json, "
         "probs_json, topk_json, kernel_action, rule_id, ledger_seq, cli, srv, cport, sport, proto, n_pkts")


def light(r: dict) -> dict:
    r["conf_set"] = J(r.pop("conf_set_json"), [])
    r["probs"] = J(r.pop("probs_json"), {})
    r["topk"] = J(r.pop("topk_json"), {})
    return r


@app.get("/api/decisions")
def decisions(limit: int = 200, action: str | None = None, adversarial: bool = False, cli: str | None = None,
              since_id: int = 0, rule_id: int | None = None, ecs_max: float | None = None,
              pred_class: int | None = None) -> list[dict]:
    w, a = ["id > ?"], [since_id]
    if action:
        w.append("decision = ?")
        a.append(action)
    if adversarial:
        w.append("adversarial = 1")
    if cli:
        w.append("cli = ?")
        a.append(cli)
    if rule_id is not None:
        w.append("rule_id = ?")
        a.append(rule_id)
    if ecs_max is not None:
        w.append("ecs <= ?")
        a.append(ecs_max)
    if pred_class is not None:
        w.append("pred_class = ?")
        a.append(pred_class)
    return [light(r) for r in q(f"SELECT {LIGHT} FROM decisions WHERE {' AND '.join(w)} ORDER BY id DESC LIMIT ?",
                                (*a, min(limit, 2000)))]


def full_decision(did: int) -> dict:
    r = q1("SELECT * FROM decisions WHERE id=?", (did,))
    if not r:
        raise HTTPException(404, "no such decision")
    for k in ("probs_json", "conf_set_json", "ecs_pairs_json", "attributions_json", "topk_json", "enforce_json",
              "latency_json", "conformal_json", "features_json", "seq_attr_json"):
        r[k.removesuffix("_json")] = J(r.pop(k))
    ms = q1("SELECT meta_json FROM model_sets WHERE id=?", (r["model_set_id"],))
    cols = J(ms["meta_json"])["cols"] if ms else []
    feats = {f["name"]: f for f in q("SELECT name, group_id, kernel_realizable FROM features")}
    r["features"] = [{"name": c, "group": feats[c]["group_id"], "value": v, "realizable": bool(feats[c]["kernel_realizable"])}
                     for c, v in zip(cols, r["features"] or [])]
    r["timeline"] = [light(x) for x in q(f"SELECT {LIGHT} FROM decisions WHERE flow_id=? ORDER BY id", (r["flow_id"],))]
    le = q1("SELECT seq, entry_hash, batch_id, created_at FROM ledger_entries WHERE seq=?", (r["ledger_seq"] or -1,))
    if le and le["batch_id"]:
        b = q1("SELECT id, root, created_at, signature, model_set_id FROM merkle_batches WHERE id=?", (le["batch_id"],))
        le["batch"] = b
    r["ledger"] = le
    r["adversarial_signals"] = q("SELECT kind, value, detail_json, created_at FROM adversarial_signals "
                                 "WHERE decision_id=?", (did,))
    r["offline"] = q("SELECT * FROM offline_explanations WHERE decision_id=? ORDER BY id", (did,))
    L = learned_or_none()
    nar_in = {"decision": r["decision"], "row": r["row_id"], "pred_name": NAMES[r["pred_class"]],
              "prob": r["probs"].get(NAMES[r["pred_class"]], 0.0), "set_names": [NAMES[c] for c in r["conf_set"]],
              "ecs": r["ecs"], "tau_lo": L["decision"]["tau_lo"] if L else 0.0,
              "tau_hi": L["decision"]["tau_hi"] if L else 0.0, "topk": r["topk"]}
    r["narration"] = narrate(nar_in)
    r["ticket"] = q1("SELECT * FROM review_tickets WHERE decision_id=? OR last_decision_id=? ORDER BY id DESC LIMIT 1",
                     (did, did))
    return r


@app.get("/api/decisions/{did}")
def decision(did: int) -> dict:
    return full_decision(did)


def model_set():
    global _MS
    from glasswall_brain.models import ModelSet
    ms = q1("SELECT id FROM model_sets WHERE active=1")
    if ms is None:
        raise HTTPException(409, "no active model set")
    if _MS is None or _MS.id != ms["id"]:
        exp = {r["kind"]: r["sha256"] for r in q("SELECT kind, sha256 FROM model_artifacts WHERE model_set_id=?",
                                                  (ms["id"],))}
        _MS = ModelSet(path("models_dir") / ms["id"], exp)
    return _MS


def reconstruct(r: dict) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    X = np.asarray([[f["value"] for f in r["features"]]], dtype=np.float64)
    raw = np.asarray(r["seq_attr"]["raw"], dtype=np.float32)
    L = cfg()["datapath"]["seq_len_n"]
    seq = np.zeros((1, L, raw.shape[1] if raw.size else 8), dtype=np.float32)
    seq[0, :len(raw)] = raw
    return X, seq, np.asarray([max(len(raw), 1)])


def evaluate(ms, X, seq, lens) -> dict:
    from glasswall_brain.conformal import Mondrian
    from glasswall_brain.decision import decide
    from glasswall_brain.ecs import ecs
    L = learned_or_none()
    if L is None:
        raise HTTPException(409, "not calibrated")
    pr = ms.proba(X, seq, lens)
    tgt = pr["ens"].argmax(1)
    at = ms.attributions(X, seq, lens, tgt)
    E, _ = ecs(at, L["ecs"]["k"], L["ecs"]["alpha"])
    M = Mondrian.from_state(json.loads(Path(L["conformal"]["file"]).read_text()))
    alphas = {r["class_id"]: r["alpha_t"] for r in q("SELECT class_id, alpha_t FROM aci_state")}
    mem = M.sets(pr["ens"], alphas)
    S = {ms.classes[j] for j in np.flatnonzero(mem[0])}
    d = decide(S, float(E[0]), L["decision"]["tau_lo"], L["decision"]["tau_hi"], attack_class_ids(),
               NAMES.index("Benign"))
    return {"probs": {NAMES[c]: float(pr["ens"][0, j]) for j, c in enumerate(ms.classes)},
            "pred": NAMES[ms.classes[int(tgt[0])]], "ecs": float(E[0]), "set": [NAMES[c] for c in sorted(S)],
            "decision": d.action, "row": d.row, "adversarial": d.adversarial,
            "groups": {s: at[s][0].tolist() for s in ("gbdt", "ebm", "cfc")}}


class WhatIf(BaseModel):
    decision_id: int
    changes: dict[str, float] = {}


@app.post("/api/whatif")
def whatif(body: WhatIf, u: dict = Depends(user)) -> dict:
    """Sandbox only - never enforces. Changes limited to kernel-realizable features."""
    r = full_decision(body.decision_id)
    ms = model_set()
    X, seq, lens = reconstruct(r)
    realizable = {f["name"] for f in r["features"] if f["realizable"]}
    for k in body.changes:
        if k not in realizable:
            raise HTTPException(400, f"{k} is not kernel-realizable")
    base = evaluate(ms, X, seq, lens)
    X2 = X.copy()
    for k, v in body.changes.items():
        X2[0, ms.cols.index(k)] = v
    out = evaluate(ms, X2, seq, lens)
    # counterfactual search (PROPOSED, DiCE-style simplified): single realizable feature,
    # candidate values = quantiles of that feature in the validation split
    cf = []
    try:
        z = np.load(path("models_dir") / ms.id / "eval_val.npz")
        Xv = z["X"]
        if base["decision"] not in ("ALLOW", "ALLOW_SHADOW"):
            for name in sorted(realizable):
                j = ms.cols.index(name)
                cands = np.unique(np.quantile(Xv[:, j], np.linspace(0, 1, 21)))
                cands = sorted(cands, key=lambda v: abs(v - X[0, j]))
                for v in cands:
                    X3 = X.copy()
                    X3[0, j] = v
                    e = evaluate(ms, X3, seq, lens)
                    if e["decision"] in ("ALLOW", "ALLOW_SHADOW"):
                        cf.append({"feature": name, "from": float(X[0, j]), "to": float(v),
                                   "decision": e["decision"], "pred": e["pred"], "ecs": e["ecs"]})
                        break
    except FileNotFoundError:
        pass
    return {"base": base, "changed": out, "changes": body.changes, "counterfactuals": cf,
            "label": "Simulation - not applied to traffic"}


class Offline(BaseModel):
    method: str = "kernelshap"


@app.post("/api/decisions/{did}/offline-explain")
async def offline_explain(did: int, body: Offline, u: dict = Depends(user)) -> dict:
    from glasswall_brain.adversarial import offline_explain as run
    r = full_decision(did)
    ms = model_set()
    X, seq, lens = reconstruct(r)
    res = await asyncio.to_thread(run, ms, X, seq, lens, body.method, r["attributions"])
    CON.execute("INSERT INTO offline_explanations (decision_id, method, groups_json, disagreement, seconds, "
                "created_at) VALUES (?,?,?,?,?,?)", (did, body.method, json.dumps(res["groups"]),
                                                     res["disagreement"], res["seconds"], dbm.now()))
    if res["flag"]:
        CON.execute("INSERT INTO adversarial_signals (decision_id, kind, value, detail_json, created_at) VALUES "
                    "(?,?,?,?,?)", (did, f"offline_disagreement_{body.method}", res["disagreement"],
                                    json.dumps({"threshold": res["threshold"]}), dbm.now()))
    CON.commit()
    return res


# ---------------------------------------------------------------- review
@app.get("/api/review")
def review(status: str = "open", limit: int = 200) -> list[dict]:
    rows = q("SELECT t.*, d.ecs, d.conf_set_json, d.topk_json, d.pred_class, d.decision, d.kernel_action "
             "FROM review_tickets t JOIN decisions d ON d.id = t.last_decision_id WHERE t.status=? "
             "ORDER BY t.adversarial DESC, t.opened_at DESC LIMIT ?", (status, limit))
    for r in rows:
        r["conf_set"] = J(r.pop("conf_set_json"), [])
        r["topk"] = J(r.pop("topk_json"), {})
    return rows


class Verdict(BaseModel):
    class_id: int
    action: str               # ALLOW | BLOCK
    apply_to_source: bool = True
    notes: str = ""
    time_to_decision_s: float | None = None


@app.post("/api/review/{tid}/verdict")
def verdict(tid: int, body: Verdict, u: dict = Depends(need("analyst"))) -> dict:
    t = q1("SELECT * FROM review_tickets WHERE id=?", (tid,))
    if not t or t["status"] != "open":
        raise HTTPException(404, "no open ticket")
    if body.action not in ("ALLOW", "BLOCK") or not 0 <= body.class_id < len(NAMES):
        raise HTTPException(400, "bad verdict")
    d = q1("SELECT pred_class FROM decisions WHERE id=?", (t["last_decision_id"],))
    if d and d["pred_class"] != body.class_id and not body.notes.strip():
        raise HTTPException(400, "notes are required when overruling the model")
    if t["cli"] in (cfg()["safety_allowlist"]["ips"] or []):
        raise HTTPException(403, "safety allow-listed address")
    ids = [r["id"] for r in q("SELECT id FROM decisions WHERE cli=? AND id BETWEEN ? AND ?",
                              (t["cli"], t["decision_id"], t["last_decision_id"]))]
    CON.executemany("INSERT INTO labels (decision_id, flow_id, class_id, source, created_at) VALUES (?,?,?,?,?)",
                    [(i, None, body.class_id, f"admin:{u['username']}", dbm.now()) for i in ids])
    CON.execute("UPDATE review_tickets SET status='closed', verdict_class=?, verdict_action=?, scope=?, notes=?, "
                "closed_at=?, closed_by=?, time_to_decision_s=? WHERE id=?",
                (body.class_id, body.action, "source" if body.apply_to_source else "flow", body.notes, dbm.now(),
                 u["username"], body.time_to_decision_s, tid))
    if body.apply_to_source:
        CON.execute("INSERT INTO admin_actions (created_at, username, kind, payload_json) VALUES (?,?,?,?)",
                    (dbm.now(), u["username"], "src_verdict",
                     json.dumps({"cli": t["cli"], "action": "PASS" if body.action == "ALLOW" else "DROP",
                                 "ticket": tid, "class_id": body.class_id})))
    CON.commit()
    audit_log(u, "review_verdict", {"ticket": tid, **body.model_dump()})
    return {"ok": True, "labels": len(ids), "message": "Verdict recorded, feeding ACI"}


# ---------------------------------------------------------------- rules
@app.get("/api/rules")
def rules(status: str | None = None) -> list[dict]:
    rows = q("SELECT * FROM rules" + (" WHERE status=?" if status else "") + " ORDER BY id DESC", (status,) if status else ())
    for r in rows:
        for k in ("predicates_json", "groups_json", "cluster_json", "fidelity_json", "canary_json", "fp_json"):
            r[k.removesuffix("_json")] = J(r.pop(k))
        r.pop("certificate_json", None)
    return rows


@app.get("/api/rules/{rid}")
def rule(rid: int) -> dict:
    r = q1("SELECT * FROM rules WHERE id=?", (rid,))
    if not r:
        raise HTTPException(404)
    for k in ("predicates_json", "groups_json", "cluster_json", "fidelity_json", "canary_json", "fp_json",
              "certificate_json"):
        r[k.removesuffix("_json")] = J(r.pop(k))
    r["provenance"] = q("SELECT decision_id FROM rule_provenance WHERE rule_id=? LIMIT 200", (rid,))
    r["rollbacks"] = q("SELECT * FROM rollback_events WHERE rule_id=?", (rid,))
    r["ledger"] = q("SELECT seq, kind, created_at, entry_hash FROM ledger_entries WHERE ref=? AND kind LIKE 'rule%' "
                    "ORDER BY seq", (str(rid),))
    pub = q1("SELECT pubkey_hex FROM signing_keys ORDER BY id DESC LIMIT 1")
    r["signing_pubkey"] = pub["pubkey_hex"] if pub else None
    return r


@app.post("/api/rules/{rid}/{op}")
def rule_op(rid: int, op: str, body: dict | None = None, u: dict = Depends(need("admin"))) -> dict:
    if op not in ("accept", "reject", "expire", "fp"):
        raise HTTPException(400)
    CON.execute("INSERT INTO admin_actions (created_at, username, kind, payload_json) VALUES (?,?,?,?)",
                (dbm.now(), u["username"], f"rule_{op}", json.dumps({"rule_id": rid, **(body or {})})))
    CON.commit()
    audit_log(u, f"rule_{op}", {"rule_id": rid})
    return {"queued": True}


@app.get("/api/admin_actions")
def admin_actions(limit: int = 50) -> list[dict]:
    return q("SELECT * FROM admin_actions ORDER BY id DESC LIMIT ?", (limit,))


# ---------------------------------------------------------------- audit
@app.get("/api/audit/decisions")
def audit_decisions(cli: str | None = None, decision_: str | None = None, limit: int = 200) -> list[dict]:
    return decisions(limit=limit, action=decision_, cli=cli)


@app.post("/api/audit/verify")
async def audit_verify(u: dict = Depends(need("auditor", "admin"))) -> dict:
    r = await asyncio.to_thread(subprocess.run, [sys.executable, str(ROOT / "scripts/verify_ledger.py"), "--json",
                                                 "--record"], capture_output=True, text=True)
    try:
        res = json.loads(r.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        raise HTTPException(500, r.stderr[-500:])
    audit_log(u, "verify_ledger", {"ok": res["ok"]})
    return res


@app.get("/api/audit/attestation")
def attestation() -> dict:
    b = q1("SELECT id, created_at, from_seq, to_seq, root, signature, model_set_id, ruleset_sha, quote_json "
           "FROM merkle_batches ORDER BY id DESC LIMIT 1")
    if b:
        qj = J(b.pop("quote_json"), {})
        b["quote"] = {k: qj.get(k) for k in ("nonce", "pcr_index", "pcr_value")}
    return {"latest_batch": b, "signing_key": q1("SELECT * FROM signing_keys ORDER BY id DESC LIMIT 1"),
            "pcr_events": q("SELECT * FROM pcr_events ORDER BY id DESC LIMIT 50"),
            "counts": {"entries": q1("SELECT COUNT(*) n FROM ledger_entries")["n"],
                       "batches": q1("SELECT COUNT(*) n FROM merkle_batches")["n"]},
            "verification_runs": q("SELECT * FROM verification_runs ORDER BY id DESC LIMIT 10"),
            "tpm_label": cfg()["environment"]["tpm_label"]}


class Export(BaseModel):
    cli: str | None = None
    limit: int = 500


@app.post("/api/audit/export")
def audit_export(body: Export, u: dict = Depends(need("auditor", "admin"))) -> JSONResponse:
    ds = decisions(limit=body.limit, cli=body.cli)
    seqs = [d["ledger_seq"] for d in ds if d["ledger_seq"]]
    entries = q(f"SELECT * FROM ledger_entries WHERE seq IN ({','.join('?' * len(seqs))})", tuple(seqs)) if seqs else []
    bids = sorted({e["batch_id"] for e in entries if e["batch_id"]})
    batches = q(f"SELECT * FROM merkle_batches WHERE id IN ({','.join('?' * len(bids))})", tuple(bids)) if bids else []
    bundle = {"generated_at": time.time(), "by": u["username"], "filter": body.model_dump(), "decisions": ds,
              "ledger_entries": entries, "merkle_batches": batches,
              "signing_keys": q("SELECT * FROM signing_keys"), "environment": cfg()["environment"],
              "how_to_verify": "recompute entry_hash = sha256(prev_hash || payload); Merkle root over the batch "
                               "range (needs all entries of the batch); Ed25519 over canonical batch message; "
                               "tpm2_checkquote with ak_pub_pem from quote_json"}
    audit_log(u, "export", body.model_dump())
    return JSONResponse(bundle, headers={"Content-Disposition": "attachment; filename=glasswall_audit.json"})


# ---------------------------------------------------------------- models / drift / experiments
@app.get("/api/models")
def models() -> dict:
    return {"model_sets": [{**r, "meta": J(r.pop("meta_json"))} for r in q("SELECT * FROM model_sets ORDER BY created_at DESC")],
            "artifacts": q("SELECT * FROM model_artifacts ORDER BY id DESC LIMIT 50"),
            "config_versions": [{**r, "values": J(r.pop("values_json"))} for r in
                                q("SELECT * FROM config_versions ORDER BY id DESC")],
            "aci_state": q("SELECT * FROM aci_state")}


@app.get("/api/drift")
def drift() -> dict:
    return {"events": q("SELECT * FROM drift_events ORDER BY id DESC LIMIT 100"),
            "retrain_jobs": q("SELECT * FROM retrain_jobs ORDER BY id DESC LIMIT 50")}


@app.get("/api/experiments")
def experiments() -> list[dict]:
    out = []
    for r in q("SELECT * FROM experiment_runs ORDER BY created_at DESC"):
        r["results"] = J(r.pop("results_json"))
        md = sorted(Path(r["evidence_dir"]).glob("*.md")) if r["evidence_dir"] else []
        r["report_md"] = md[0].read_text() if md else None
        out.append(r)
    return out


# ---------------------------------------------------------------- demo
class Attack(BaseModel):
    scenario: str


@app.post("/api/demo/attack")
def demo_attack(body: Attack, u: dict = Depends(need("demo"))) -> dict:
    if body.scenario not in scenarios_cfg()["scenarios"]:
        raise HTTPException(400, "scenario not in allow-listed catalogue")
    out = path("capture_dir") / "demo_runs"
    out.mkdir(parents=True, exist_ok=True)
    subprocess.Popen([sys.executable, str(ROOT / "lab/scenarios.py"), "one", body.scenario, str(out)],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    audit_log(u, "demo_attack", body.model_dump())
    return {"started": body.scenario, "duration_s": scenarios_cfg()["scenarios"][body.scenario]["duration"]}


@app.get("/api/demo/runs")
def demo_runs() -> list[dict]:
    f = path("capture_dir") / "demo_runs" / "attack_runs.jsonl"
    if not f.exists():
        return []
    return [json.loads(x) for x in f.read_text().splitlines()[-30:]][::-1]


class Tamper(BaseModel):
    confirm: str
    seq: int | None = None


@app.post("/api/demo/tamper")
def demo_tamper(body: Tamper, u: dict = Depends(need("demo"))) -> dict:
    """D5: edit one ledger payload the way a privileged attacker with DB file
    access would (append-only triggers dropped, row edited, triggers restored)."""
    if body.confirm != "TAMPER":
        raise HTTPException(400, "type TAMPER to confirm")
    row = (q1("SELECT seq, payload FROM ledger_entries WHERE seq=?", (body.seq,)) if body.seq else
           q1("SELECT seq, payload FROM ledger_entries WHERE kind='decision' ORDER BY seq DESC LIMIT 1 OFFSET 50"))
    if not row:
        raise HTTPException(404, "no ledger entry to tamper")
    p = json.loads(row["payload"])
    before = p["data"].get("decision")
    p["data"]["decision"] = "ALLOW" if before != "ALLOW" else "BLOCK"
    from glasswall_brain.ledger import canon
    CON.executescript("DROP TRIGGER IF EXISTS ledger_entries_no_update;")
    CON.execute("UPDATE ledger_entries SET payload=? WHERE seq=?", (canon(p).decode(), row["seq"]))
    CON.commit()
    CON.executescript(dbm.triggers_sql())
    audit_log(u, "demo_tamper", {"seq": row["seq"], "decision_before": before, "after": p["data"]["decision"]})
    return {"tampered_seq": row["seq"], "decision_before": before, "decision_after": p["data"]["decision"]}


# ---------------------------------------------------------------- websocket
@app.websocket("/ws")
async def ws(sock: WebSocket) -> None:
    await sock.accept()
    last = (q1("SELECT MAX(id) m FROM decisions") or {"m": 0})["m"] or 0
    last_rule = ""
    try:
        while True:
            rows = [light(r) for r in q(f"SELECT {LIGHT} FROM decisions WHERE id > ? ORDER BY id LIMIT 300", (last,))]
            if rows:
                last = rows[-1]["id"]
                await sock.send_json({"channel": "decisions", "payload": rows})
            rs = q1("SELECT GROUP_CONCAT(id || status) s FROM rules")
            if rs and (rs["s"] or "") != last_rule:
                last_rule = rs["s"] or ""
                await sock.send_json({"channel": "rules", "payload": {"changed": True}})
            await asyncio.sleep(0.5)
    except (WebSocketDisconnect, RuntimeError):
        return


# ---------------------------------------------------------------- static UI
DIST = ROOT / "ui" / "dist"
if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(404)
        f = DIST / full_path
        return FileResponse(f if f.is_file() else DIST / "index.html")
