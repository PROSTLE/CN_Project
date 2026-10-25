"""Fit every LEARNED value from validation data and write an active
config_versions row (with source run id). Nothing here is typed by hand.

  python scripts/calibrate.py

  conformal : Mondrian calibration scores from the `cal` split (ensemble probs)
  ecs.k, ecs.alpha : grid (config k_grid x alpha_grid) on `val`, objective =
      ROC-AUC of ECS for separating correct vs wrong ensemble decisions
      (PROPOSED objective, TRD TR-E-3)
  decision.tau_lo : largest ECS cut with P(ECS < cut | correct) <= fpr_budget
  decision.tau_hi : smallest ECS cut > tau_lo with P(BLOCK | benign) <= fpr_budget
      on `val` (maximises BLOCK recall subject to the budget)
  rules.max_fpr : = fpr_budget (policy input)
  rules.min_agreement : agreement on `cal` of a depth<=max_depth tree on
      kernel-realizable features distilled from the ensemble on `val` - i.e.
      what a kernel rule can faithfully achieve (PROPOSED)
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "brain"))
sys.path.insert(0, str(ROOT))
from glasswall_brain import db as dbm  # noqa: E402
from glasswall_brain.conformal import Mondrian  # noqa: E402
from glasswall_brain.config import attack_class_ids, cfg, class_names, config_sha, path  # noqa: E402
from glasswall_brain.decision import BLOCK, decide  # noqa: E402
from glasswall_brain.ecs import ecs  # noqa: E402
from glasswall_brain.models import sha256_file  # noqa: E402
from ml.eval.metrics import md_table  # noqa: E402


def load_eval(md: Path, split: str) -> dict:
    z = np.load(md / f"eval_{split}.npz", allow_pickle=False)
    return {k: z[k] for k in z.files}


def sets_list(M: Mondrian, P: np.ndarray, alpha: float) -> list[set[int]]:
    mem = M.sets(P, {c: alpha for c in M.classes})
    return [{M.classes[j] for j in np.flatnonzero(r)} for r in mem]


def main() -> None:
    run_id = "cal-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    con = dbm.init()
    ms = con.execute("SELECT id, meta_json FROM model_sets WHERE active=1").fetchone()
    if ms is None:
        sys.exit("no active model set - run ml/train/train_all.py first")
    meta = json.loads(ms["meta_json"])
    md = path("models_dir") / ms["id"]
    classes = meta["classes"]
    names = class_names()
    benign = names.index("Benign")
    attack = attack_class_ids()
    C = cfg()
    budget = C["decision"]["fpr_budget"]
    alpha_target = C["conformal"]["alpha_target"]
    val, cal = load_eval(md, "val"), load_eval(md, "cal")

    # ---- conformal --------------------------------------------------------
    M = Mondrian.fit(classes, cal["ens"], cal["y"])
    conf_file = md / "conformal.json"
    conf_file.write_text(json.dumps(M.state()))
    S_val = sets_list(M, val["ens"], alpha_target)
    y_val_g = np.asarray([classes[i] for i in val["y"]])
    cov = float(np.mean([y in s for y, s in zip(y_val_g, S_val)]))
    set_sizes = np.bincount([len(s) for s in S_val], minlength=len(classes) + 1).tolist()

    # ---- ECS grid ---------------------------------------------------------
    correct = val["ens"].argmax(1) == val["y"]
    attr = {"gbdt": val["a_gbdt"], "ebm": val["a_ebm"], "cfc": val["a_cfc"]}
    n_wrong = int((~correct).sum())
    grid = []
    for k in C["ecs"]["k_grid"]:
        for a in C["ecs"]["alpha_grid"]:
            E, _ = ecs(attr, k, a)
            auc = roc_auc_score(correct, E) if 0 < n_wrong < len(correct) else None
            grid.append({"k": k, "alpha": a, "auc_correct_vs_wrong": auc,
                         "mean_ecs_correct": float(E[correct].mean()),
                         "mean_ecs_wrong": float(E[~correct].mean()) if n_wrong else None})
    if n_wrong == 0:
        sys.exit("validation split has no wrong decisions - ECS objective undefined; refusing to guess k/alpha")
    best = max(grid, key=lambda g: (g["auc_correct_vs_wrong"], -g["k"], g["alpha"]))
    k, alpha = int(best["k"]), float(best["alpha"])
    E, _ = ecs(attr, k, alpha)

    # ---- tau_lo ----------------------------------------------------------
    cands = np.unique(np.concatenate([[0.0], E]))
    Ec = E[correct]
    ok_lo = [c for c in cands if np.mean(Ec < c) <= budget]
    tau_lo = float(max(ok_lo))
    # ---- tau_hi ----------------------------------------------------------
    is_benign = y_val_g == benign
    is_attack = ~is_benign
    hi_table = []
    tau_hi = None
    for c in cands[cands > tau_lo]:
        dec = [decide(s, e, tau_lo, float(c), attack, benign).action for s, e in zip(S_val, E)]
        dec = np.asarray(dec)
        fpr = float(np.mean(dec[is_benign] == BLOCK)) if is_benign.any() else 0.0
        rec = float(np.mean(dec[is_attack] == BLOCK)) if is_attack.any() else 0.0
        hi_table.append({"tau_hi": float(c), "benign_block_rate": fpr, "attack_block_rate": rec})
        if tau_hi is None and fpr <= budget:
            tau_hi = float(c)
    if tau_hi is None:
        sys.exit("no tau_hi > tau_lo meets the FPR budget on validation; refusing to guess")

    # ---- rule fidelity reference ------------------------------------------
    kcols = [i for i, c in enumerate(meta["cols"]) if c.startswith("k_")]
    tgt_val = np.isin([classes[i] for i in val["ens"].argmax(1)], list(attack))
    tgt_cal = np.isin([classes[i] for i in cal["ens"].argmax(1)], list(attack))
    tree = DecisionTreeClassifier(max_depth=C["rules"]["max_depth"], random_state=C["models"]["seed"])
    tree.fit(val["X"][:, kcols], tgt_val)
    min_agreement = float((tree.predict(cal["X"][:, kcols]) == tgt_cal).mean())

    values = {"ecs": {"k": k, "alpha": alpha}, "decision": {"tau_lo": tau_lo, "tau_hi": tau_hi},
              "rules": {"min_agreement": min_agreement, "max_fpr": budget},
              "conformal": {"file": str(conf_file), "sha256": sha256_file(conf_file), "alpha_target": alpha_target},
              "model_set_id": ms["id"]}
    con.execute("UPDATE config_versions SET active=0")
    con.execute("INSERT INTO config_versions (created_at, values_json, source_run_id, config_sha, active, notes) "
                "VALUES (?,?,?,?,1,?)", (dbm.now(), json.dumps(values), run_id, config_sha(),
                                          "scripts/calibrate.py on val/cal splits of " + ms["id"]))
    # reset ACI state to alpha_target for the new calibration
    con.execute("DELETE FROM aci_state")
    con.executemany("INSERT INTO aci_state VALUES (?,?,?,?,?)",
                    [(c, alpha_target, 0, 0, dbm.now()) for c in classes])
    con.commit()

    ev = path("evidence_dir") / f"calibrate_{run_id}"
    ev.mkdir(parents=True, exist_ok=True)
    out = {"run_id": run_id, "model_set_id": ms["id"], "values": values, "ecs_grid": grid,
           "tau_hi_table": hi_table, "val_n": int(len(E)), "val_wrong": n_wrong,
           "val_conformal_coverage_at_target": cov, "val_set_size_hist": set_sizes,
           "cal_n_per_class": {names[c]: int(len(M.scores[c])) for c in classes}}
    (ev / "calibration.json").write_text(json.dumps(out, indent=2))
    txt = [f"# Calibration {run_id}", "", f"Model set {ms['id']}; validation n={len(E)}, wrong={n_wrong}", "",
           f"Learned: k={k}, alpha={alpha}, tau_lo={tau_lo:.4f}, tau_hi={tau_hi:.4f}, "
           f"rules.min_agreement={min_agreement:.4f}, rules.max_fpr={budget}", "",
           f"Conformal coverage on val at alpha_target={alpha_target}: {cov:.4f}; set-size histogram {set_sizes}", "",
           "## ECS grid (val)", "",
           md_table(["k", "alpha", "AUC correct-vs-wrong", "mean ECS correct", "mean ECS wrong"],
                    [[g["k"], g["alpha"], f"{g['auc_correct_vs_wrong']:.4f}", f"{g['mean_ecs_correct']:.4f}",
                      f"{g['mean_ecs_wrong']:.4f}" if g["mean_ecs_wrong"] is not None else "-"] for g in grid])]
    (ev / "calibration.md").write_text("\n".join(txt))
    dbm.record_experiment(con, run_id, "calibration", out, str(ev), dataset=meta["dataset"])
    print("\n".join(txt[:6]))


if __name__ == "__main__":
    main()
