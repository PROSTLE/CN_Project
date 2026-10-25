"""Online end-to-end run against the live system (agent + brain running).

Benign users run from the client namespace the whole time; each scenario is
launched from the attacker namespace via the allow-listed runner. After each
scenario the attacker's source verdict is cleared (admin action through the
brain) so the next scenario starts unblocked; promoted kernel rules stay live.

  python ml/experiments/online.py
"""
from __future__ import annotations

import json
import random
import subprocess
import sys
import time
import uuid
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "brain"))
sys.path.insert(0, str(ROOT))
from glasswall_brain import db as dbm  # noqa: E402
from glasswall_brain.config import cfg, path, scenarios_cfg  # noqa: E402
from ml.eval.metrics import md_table  # noqa: E402

C = cfg()
LAB = C["lab"]
PY = sys.executable
SCEN = ["portscan_syn", "bruteforce_ssh", "dos_synflood", "webattack_enum", "dos_slowloris", "ddos_spoofed",
        "portscan_connect", "bruteforce_lowslow", "portscan_slow", "dos_padded", "portscan_syn"]
HOSTS = {LAB["attacker_ip"], LAB["client_ip"], LAB["victim_ip"]} | {l["gw_ip"].split("/")[0] for l in LAB["links"]}


def admin(con, kind: str, payload: dict, wait: float = 10.0) -> dict:
    cur = con.execute("INSERT INTO admin_actions (created_at, username, kind, payload_json) VALUES (?,?,?,?)",
                      (dbm.now(), "experiment", kind, json.dumps(payload)))
    con.commit()
    aid = cur.lastrowid
    t = time.time()
    while time.time() - t < wait:
        r = con.execute("SELECT status, result FROM admin_actions WHERE id=?", (aid,)).fetchone()
        if r["status"] != "pending":
            return {"status": r["status"], "result": r["result"]}
        time.sleep(0.2)
    return {"status": "timeout"}


def kstats(con) -> dict:
    r = admin(con, "kernel_stats", {})
    return json.loads(r["result"]) if r.get("status") == "done" else {}


def main() -> None:
    con = dbm.connect()
    st = con.execute("SELECT updated_at FROM brain_status WHERE id=1").fetchone()
    if not st or time.time() - st["updated_at"] > 5:
        sys.exit("brain is not running")
    sc = scenarios_cfg()["scenarios"]
    total = sum(sc[s]["duration"] + 12 for s in SCEN) + 30
    out_dir = path("capture_dir") / f"online_runs_{time.strftime('%Y%m%d-%H%M%S')}"
    out_dir.mkdir(parents=True)
    t0_all = time.time()
    first_id = (con.execute("SELECT MAX(id) m FROM decisions").fetchone()["m"] or 0)
    bg = subprocess.Popen(["ip", "netns", "exec", LAB["namespaces"]["client"], PY, str(ROOT / "lab/gen/benign_mix.py"),
                           "--target", LAB["victim_ip"], "--duration", str(total), "--seed", str(random.randint(0, 2**31))],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(20)   # benign-only warm-up
    k_before = kstats(con)
    runs = []
    for s in SCEN:
        admin(con, "src_verdict", {"cli": LAB["attacker_ip"], "action": "PASS"})
        time.sleep(2)
        w0 = time.time()
        subprocess.run([PY, str(ROOT / "lab/scenarios.py"), "one", s, str(out_dir)], capture_output=True)
        w1 = time.time()
        time.sleep(8)   # let idle flows close and decisions land
        spoof = sc[s]["label"] == "spoofed"
        rows = con.execute("SELECT created_at, decision, kernel_action, rule_id, adversarial, row_id, cli, ecs, "
                           "latency_json FROM decisions WHERE created_at BETWEEN ? AND ?", (w0, w1 + 8)).fetchall()
        mine = [r for r in rows if (r["cli"] not in HOSTS if spoof else r["cli"] == LAB["attacker_ip"])]
        acts = [r["decision"] for r in mine]
        hit = [r["created_at"] for r in mine if r["decision"] in ("BLOCK", "QUARANTINE")]
        ks = kstats(con)
        runs.append({"scenario": s, "class": sc[s]["class"], "evasion": bool(sc[s].get("evasion")),
                     "duration_s": w1 - w0, "decisions": len(mine),
                     "by_action": {a: acts.count(a) for a in set(acts)},
                     "intercept_share": (len(hit) / len(mine)) if mine else None,
                     "time_to_first_block_or_quarantine_s": (min(hit) - w0) if hit else None,
                     "adversarial_flags": sum(r["adversarial"] for r in mine),
                     "rule_hit_decisions": sum(1 for r in mine if r["rule_id"]),
                     "mean_ecs": float(np.mean([r["ecs"] for r in mine])) if mine else None,
                     "kernel_after": ks.get("stats"), "rule_hits_after": ks.get("rule_hits")})
        print(json.dumps({k: v for k, v in runs[-1].items() if k not in ("kernel_after", "rule_hits_after")}), flush=True)
    admin(con, "src_verdict", {"cli": LAB["attacker_ip"], "action": "PASS"})
    bg.terminate()
    bg.wait()
    t1_all = time.time()
    dec = con.execute("SELECT decision, cli, latency_json FROM decisions WHERE id > ?", (first_id,)).fetchall()
    ben = [r for r in dec if r["cli"] == LAB["client_ip"]]
    bacts = [r["decision"] for r in ben]
    lat = [json.loads(r["latency_json"]) for r in dec]
    e2d = np.asarray([x["event_to_decision_ms"] for x in lat])
    per = np.asarray([x["batch_total_ms"] / max(1, x["batch"]) for x in lat])
    rules = [dict(r) for r in con.execute("SELECT id, status, text, class_id, fidelity_json, canary_json, fp_json, "
                                          "reason FROM rules WHERE created_at >= ?", (t0_all,))]
    k_after = kstats(con)
    res = {"runs": runs, "benign_client": {"decisions": len(ben), "by_action": {a: bacts.count(a) for a in set(bacts)}},
           "latency": {"event_to_decision_ms_p50": float(np.percentile(e2d, 50)), "p99": float(np.percentile(e2d, 99)),
                       "amortised_decide_ms_per_snapshot_p50": float(np.percentile(per, 50)),
                       "amortised_p99": float(np.percentile(per, 99)), "n": len(lat)},
           "decisions_per_s": len(dec) / (t1_all - t0_all), "rules": rules, "kernel_before": k_before,
           "kernel_after": k_after, "seconds": t1_all - t0_all}
    rid = f"ONLINE-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
    d = path("evidence_dir") / rid
    d.mkdir(parents=True, exist_ok=True)
    f = lambda v, n=3: "-" if v is None else f"{v:.{n}f}"  # noqa: E731
    bc = res["benign_client"]
    md = [f"# Online end-to-end run ({rid})", "",
          f"Environment: {C['environment']['label']}; {C['environment']['tpm_label']}. Live agent + brain; benign users "
          f"from the client namespace throughout; scenarios from the attacker namespace. {len(dec)} decisions in "
          f"{res['seconds']:.0f} s ({res['decisions_per_s']:.1f}/s).", "",
          md_table(["scenario", "class", "evasion", "decisions", "BLOCK", "QUAR", "ALLOW(+shadow)", "intercept share",
                    "time to first BLOCK/QUAR s", "adv flags", "decided on rule-dropped pkts"],
                   [[r["scenario"], r["class"], "yes" if r["evasion"] else "", r["decisions"], r["by_action"].get("BLOCK", 0),
                     r["by_action"].get("QUARANTINE", 0), r["by_action"].get("ALLOW", 0) + r["by_action"].get("ALLOW_SHADOW", 0),
                     f(r["intercept_share"]), f(r["time_to_first_block_or_quarantine_s"], 2), r["adversarial_flags"],
                     r["rule_hit_decisions"]] for r in runs]),
          "", f"Benign client during the run: {bc['decisions']} decisions, {bc['by_action']}.", "",
          f"Latency: event->decision p50 {f(res['latency']['event_to_decision_ms_p50'], 1)} ms, p99 "
          f"{f(res['latency']['p99'], 1)} ms; amortised decide cost per snapshot p50 "
          f"{f(res['latency']['amortised_decide_ms_per_snapshot_p50'], 2)} ms, p99 {f(res['latency']['amortised_p99'], 2)} ms "
          f"(includes 3 models + 3 explainers incl. IG, ECS, conformal, enforcement, ledger).", "",
          "## Rules compiled during the run", "",
          md_table(["id", "status", "rule", "reason"], [[r["id"], r["status"], r["text"], r["reason"] or ""] for r in rules])
          if rules else "No rule was proposed.", "",
          f"Kernel counters before: {json.dumps(k_before.get('stats'))}", "",
          f"Kernel counters after: {json.dumps(k_after.get('stats'))}", "",
          f"Rule hits (matched, dropped) after: {json.dumps(k_after.get('rule_hits'))}"]
    (d / "online.md").write_text("\n".join(md))
    (d / "online.json").write_text(json.dumps(res, indent=2, default=float))
    dbm.record_experiment(con, rid, "Online end-to-end run", res, str(d), dataset="live lab")
    print("\n".join(md))


if __name__ == "__main__":
    main()
