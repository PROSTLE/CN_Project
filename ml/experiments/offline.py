"""Offline experiments on the active model set's real held-out data.

  python ml/experiments/offline.py e1|e2|e3|e6|all

E1  ECS-gated tri-state vs (a) conformal-only tri-state, (b) ensemble argmax;
    FPR at equal recall; share of wrong ensemble decisions caught.        (test split)
E2  conformal coverage vs target on a time-ordered stream (test split then
    the separately recorded evasion capture = distribution shift), fixed
    alpha vs ACI with delayed labels.
E3  certified vs uncertified distilled kernel rules; canary-then-promote vs
    direct promotion. Rules are distilled from sliding windows of the val
    stream exactly as the online compiler does; evaluated on the test split.
E6  (a) evasion variants (low-and-slow, padding, slow scan; never trained on):
    interception with vs without ECS gating; (b) Slack-style scaffolding
    attack on the offline LIME path: disagreement flag rate vs honest LIME.
Every number below is computed here from stored predictions/attributions.
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "brain"))
sys.path.insert(0, str(ROOT))
from glasswall_brain import db as dbm  # noqa: E402
from glasswall_brain.conformal import ACI, Mondrian  # noqa: E402
from glasswall_brain.config import attack_class_ids, cfg, class_names, learned, model_feature_names, path  # noqa: E402
from glasswall_brain.decision import decide  # noqa: E402
from glasswall_brain.ecs import ecs  # noqa: E402
from glasswall_brain.models import ModelSet, group_matrix  # noqa: E402
from ml.eval.metrics import md_table  # noqa: E402

NAMES = class_names()
BENIGN = NAMES.index("Benign")
ATTACK = attack_class_ids()
C = cfg()


def ctx():
    con = dbm.init()
    L = learned(con)
    ms_id = L["model_set_id"]
    exp = {r["kind"]: r["sha256"] for r in con.execute("SELECT kind, sha256 FROM model_artifacts WHERE model_set_id=?",
                                                       (ms_id,))}
    ms = ModelSet(path("models_dir") / ms_id, exp)
    M = Mondrian.from_state(json.loads(Path(L["conformal"]["file"]).read_text()))
    return con, L, ms, M


def load(ms: ModelSet, split: str) -> dict:
    z = np.load(ms.dir / f"eval_{split}.npz", allow_pickle=False)
    return {k: z[k] for k in z.files}


def sets_of(M: Mondrian, P: np.ndarray, alpha: dict) -> list[set[int]]:
    mem = M.sets(P, alpha)
    return [{M.classes[j] for j in np.flatnonzero(r)} for r in mem]


def tri(S, E, L, gated: bool) -> list[tuple[str, str]]:
    out = []
    for s, e in zip(S, E):
        if gated:
            d = decide(s, float(e), L["decision"]["tau_lo"], L["decision"]["tau_hi"], ATTACK, BENIGN)
            out.append((d.action, d.row))
        else:   # conformal-only: same table with ECS ignored (E treated as 1)
            d = decide(s, 1.0, 0.0, 1e-9, ATTACK, BENIGN)
            out.append((d.action, d.row))
    return out


def summarize(y_g: np.ndarray, acts: list[str]) -> dict:
    a = np.asarray(acts)
    ben, att = y_g == BENIGN, y_g != BENIGN
    r = lambda m, v: float(np.mean(a[m] == v)) if m.any() else None  # noqa: E731
    return {"benign_block_rate": r(ben, "BLOCK"), "benign_quarantine_rate": r(ben, "QUARANTINE"),
            "attack_block_recall": r(att, "BLOCK"),
            "attack_intercept_recall": float(np.mean(np.isin(a[att], ["BLOCK", "QUARANTINE"]))) if att.any() else None,
            "attack_quarantine_rate": r(att, "QUARANTINE"), "n_benign": int(ben.sum()), "n_attack": int(att.sum())}


def evidence(name: str) -> tuple[str, Path]:
    rid = f"{name}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
    d = path("evidence_dir") / rid
    d.mkdir(parents=True, exist_ok=True)
    return rid, d


# ------------------------------------------------------------------ E1
def e1() -> dict:
    con, L, ms, M = ctx()
    t = load(ms, "test")
    y_g = np.asarray([ms.classes[i] for i in t["y"]])
    E, _ = ecs({"gbdt": t["a_gbdt"], "ebm": t["a_ebm"], "cfc": t["a_cfc"]}, L["ecs"]["k"], L["ecs"]["alpha"])
    alpha = {c: C["conformal"]["alpha_target"] for c in ms.classes}
    S = sets_of(M, t["ens"], alpha)
    g = tri(S, E, L, True)
    u = tri(S, E, L, False)
    pred_g = np.asarray([ms.classes[i] for i in t["ens"].argmax(1)])
    argmax_act = np.where(np.isin(pred_g, list(ATTACK)), "BLOCK", "ALLOW")
    res = {"gated": summarize(y_g, [a for a, _ in g]), "conformal_only": summarize(y_g, [a for a, _ in u]),
           "argmax": summarize(y_g, list(argmax_act))}
    # FPR at equal recall: threshold on 1 - p(benign) matched to gated intercept recall
    bl = ms.classes.index(BENIGN)
    score = 1 - t["ens"][:, bl]
    target = res["gated"]["attack_intercept_recall"]
    att = y_g != BENIGN
    thr = np.quantile(score[att], 1 - target) if target else 1.0
    res["argmax_threshold_at_gated_recall"] = {"recall": float(np.mean(score[att] >= thr)),
                                               "benign_flag_rate": float(np.mean(score[~att] >= thr)),
                                               "threshold": float(thr)}
    wrong = pred_g != y_g
    rows = np.asarray([r for _, r in g])
    acts = np.asarray([a for a, _ in g])
    res["wrong_decisions"] = {"n_wrong": int(wrong.sum()), "n": int(len(y_g)),
                              "caught_by_quarantine": float(np.mean(acts[wrong] == "QUARANTINE")) if wrong.any() else None,
                              "caught_by_low_ecs_R1": float(np.mean(rows[wrong] == "R1")) if wrong.any() else None,
                              "caught_by_ecs_band_R6_R7": float(np.mean(np.isin(rows[wrong], ["R6", "R7"]))) if wrong.any() else None,
                              "caught_conformal_only": float(np.mean(np.asarray([a for a, _ in u])[wrong] == "QUARANTINE")) if wrong.any() else None,
                              "ecs_mean_wrong": float(E[wrong].mean()) if wrong.any() else None,
                              "ecs_mean_correct": float(E[~wrong].mean())}
    res["row_hist"] = pd.Series(rows).value_counts().to_dict()
    rid, d = evidence("E1")
    f = lambda v: "n/a" if v is None else f"{v:.4f}"  # noqa: E731
    tab = md_table(["policy", "benign BLOCK", "benign QUARANTINE", "attack BLOCK recall", "attack intercept recall"],
                   [[k, f(v["benign_block_rate"]), f(v["benign_quarantine_rate"]), f(v["attack_block_recall"]),
                     f(v["attack_intercept_recall"])] for k, v in res.items() if k in ("gated", "conformal_only", "argmax")])
    w = res["wrong_decisions"]
    md = [f"# E1 - ECS-gated quarantine vs ungated ({rid})", "",
          f"Test split of {ms.id} (temporal, lab capture). n={len(y_g)}; benign {res['gated']['n_benign']}, "
          f"attack {res['gated']['n_attack']}. Learned k={L['ecs']['k']}, alpha={L['ecs']['alpha']}, "
          f"tau_lo={L['decision']['tau_lo']:.4f}, tau_hi={L['decision']['tau_hi']:.4f}; alpha_target={C['conformal']['alpha_target']}.",
          "", tab, "",
          f"Argmax score thresholded to the gated intercept recall ({f(target)}): benign flagged = "
          f"{f(res['argmax_threshold_at_gated_recall']['benign_flag_rate'])}.", "",
          f"Wrong ensemble decisions: {w['n_wrong']} of {w['n']}. Sent to QUARANTINE by the gated table: "
          f"{f(w['caught_by_quarantine'])} (R1 low ECS {f(w['caught_by_low_ecs_R1'])}, R6/R7 ECS band "
          f"{f(w['caught_by_ecs_band_R6_R7'])}); conformal-only table: {f(w['caught_conformal_only'])}. "
          f"Mean ECS wrong {f(w['ecs_mean_wrong'])} vs correct {f(w['ecs_mean_correct'])}.", "",
          f"Decision-row histogram (gated): {res['row_hist']}"]
    (d / "e1.md").write_text("\n".join(md))
    (d / "e1.json").write_text(json.dumps(res, indent=2))
    dbm.record_experiment(con, rid, "E1 ECS-gated vs ungated", res, str(d), dataset=ms.meta["dataset"], split="test")
    print("\n".join(md))
    return res


# ------------------------------------------------------------------ E2
def predict_dataset(ms: ModelSet, ds: Path, cap: int, with_attr: bool = False) -> dict:
    df = pd.read_parquet(ds / "snapshots.parquet")
    seqs = np.load(ds / "sequences.npy")
    lens = np.load(ds / "seq_len.npy").astype(np.int64)
    df = df[df["class_id"].isin(ms.classes)].reset_index()
    rng = np.random.default_rng(C["models"]["seed"])
    ix = np.sort(rng.choice(len(df), min(cap, len(df)), replace=False))
    sub = df.iloc[ix]
    X = sub[ms.cols].to_numpy(np.float64)
    sq, ln = seqs[sub["index"].to_numpy()], lens[sub["index"].to_numpy()]
    pr = ms.proba(X, sq, ln)
    out = {"ens": pr["ens"], "y_g": sub["class_id"].to_numpy(), "ts": sub["ts"].to_numpy(),
           "scenario": sub["scenario"].to_numpy(), "X": X}
    if with_attr:
        at = ms.attributions(X, sq, ln, pr["ens"].argmax(1))
        out.update({"a_gbdt": at["gbdt"], "a_ebm": at["ebm"], "a_cfc": at["cfc"]})
    return out


def e2() -> dict:
    con, L, ms, M = ctx()
    t = load(ms, "test")
    ev = predict_dataset(ms, path("state_dir") / "datasets/evasion1", C["models"]["eval_cap"])
    o = np.argsort(t["ts"])
    P = np.concatenate([t["ens"][o], ev["ens"][np.argsort(ev["ts"])]])
    y = np.concatenate([np.asarray([ms.classes[i] for i in t["y"][o]]), ev["y_g"][np.argsort(ev["ts"])]])
    seg = np.asarray(["test"] * len(o) + ["evasion"] * len(ev["y_g"]))
    delay = C["experiments"]["e2_label_delay"]
    target = C["conformal"]["alpha_target"]
    res = {}
    for mode in ("fixed", "aci"):
        aci = ACI(ms.classes, target, C["conformal"]["aci_gamma"])
        cov = np.zeros(len(y), dtype=bool)
        size = np.zeros(len(y))
        pend = []
        for i in range(len(y)):
            alpha = aci.alpha if mode == "aci" else {c: target for c in ms.classes}
            S = sets_of(M, P[i:i + 1], alpha)[0]
            cov[i] = y[i] in S
            size[i] = len(S)
            pend.append((i, S))
            if len(pend) > delay:          # label of decision i-delay arrives now
                j, Sj = pend.pop(0)
                aci.update(int(y[j]), int(y[j]) in Sj)
        res[mode] = {s: {"coverage": float(cov[seg == s].mean()), "mean_set_size": float(size[seg == s].mean()),
                         "n": int((seg == s).sum())} for s in ("test", "evasion")}
        res[mode]["overall"] = {"coverage": float(cov.mean()), "mean_set_size": float(size.mean())}
        w = C["experiments"]["e2_window"]
        res[mode]["rolling"] = [float(cov[i:i + w].mean()) for i in range(0, len(cov), w)]
        res[mode]["per_class"] = {NAMES[c]: float(cov[y == c].mean()) for c in np.unique(y)}
    res["target_coverage"] = 1 - target
    res["label_delay"] = delay
    rid, d = evidence("E2")
    f = lambda v: f"{v:.4f}"  # noqa: E731
    md = [f"# E2 - conformal coverage vs target under shift ({rid})", "",
          f"Stream: test split (time-ordered, n={res['fixed']['test']['n']}) followed by the separately recorded "
          f"evasion capture (n={res['fixed']['evasion']['n']}; low-and-slow brute force, padded SYN flood, slow scan "
          f"+ benign). Target coverage {1 - target:.2f}; labels arrive with a delay of {delay} decisions; "
          f"gamma={C['conformal']['aci_gamma']}.", "",
          md_table(["mode", "coverage test", "coverage evasion", "coverage overall", "mean |S| test", "mean |S| evasion"],
                   [[m, f(res[m]["test"]["coverage"]), f(res[m]["evasion"]["coverage"]), f(res[m]["overall"]["coverage"]),
                     f(res[m]["test"]["mean_set_size"]), f(res[m]["evasion"]["mean_set_size"])] for m in ("fixed", "aci")]),
          "", "Per-class coverage (ACI): " + json.dumps({k: round(v, 4) for k, v in res["aci"]["per_class"].items()}),
          "", "Per-class coverage (fixed): " + json.dumps({k: round(v, 4) for k, v in res["fixed"]["per_class"].items()})]
    (d / "e2.md").write_text("\n".join(md))
    (d / "e2.json").write_text(json.dumps(res, indent=2))
    dbm.record_experiment(con, rid, "E2 conformal + ACI coverage", res, str(d), dataset=ms.meta["dataset"], split="test+evasion1")
    print("\n".join(md))
    return res


# ------------------------------------------------------------------ E3
def e3() -> dict:
    from sklearn.tree import DecisionTreeClassifier
    con, L, ms, M = ctx()
    v, t = load(ms, "val"), load(ms, "test")
    kc = [i for i, c in enumerate(ms.cols) if c.startswith("k_")]
    kn = [ms.cols[i] for i in kc]
    gm = group_matrix(kn)
    rc = C["rules"]
    W = C["experiments"]["e3_window"]
    o = np.argsort(v["ts"])
    Xv, pv = v["X"][o][:, kc], np.asarray([ms.classes[i] for i in v["ens"].argmax(1)[o]])
    av = np.mean([v["a_gbdt"][o], v["a_ebm"][o], v["a_cfc"][o]], axis=0)
    Xt, yt = t["X"][:, kc], np.asarray([ms.classes[i] for i in t["y"]])
    cands = []
    for start in range(0, len(o) - W, W // 2):
        sl = slice(start, start + W)
        Xw, pw, aw = Xv[sl], pv[sl], av[sl]
        for c in sorted(set(pw) & ATTACK):
            pos = pw == c
            neg = pw == BENIGN
            if pos.sum() < rc["min_cluster_flows"] or neg.sum() < rc["min_cluster_flows"]:
                continue
            att = aw[pos].mean(0)
            top = set(np.argsort(-np.abs(att))[:L["ecs"]["k"]])
            cols = [j for j in range(len(kn)) if int(np.argmax(gm[j])) in top] or list(range(len(kn)))
            idx = np.flatnonzero(pos | neg)
            Xs, ys = Xw[idx][:, cols], pos[idx].astype(int)
            cut = int(len(ys) * 0.7)
            if len(set(ys[:cut])) < 2 or len(set(ys[cut:])) < 2:
                continue
            tree = DecisionTreeClassifier(max_depth=rc["max_depth"], class_weight="balanced",
                                          random_state=C["models"]["seed"]).fit(Xs[:cut], ys[:cut])
            m_hold = tree.predict(Xs[cut:]).astype(bool)
            agree = float((m_hold == ys[cut:].astype(bool)).mean())
            fpr_h = float(m_hold[ys[cut:] == 0].mean())
            certified = agree >= L["rules"]["min_agreement"] and fpr_h <= L["rules"]["max_fpr"]
            # canary: next window's model-benign traffic
            nxt = slice(start + W, start + 2 * W)
            Xn, pn = Xv[nxt], pv[nxt]
            canary_fp = float(tree.predict(Xn[pn == BENIGN][:, cols]).mean()) if (pn == BENIGN).any() else 0.0
            canary_ok = canary_fp <= L["rules"]["max_fpr"]
            mt = tree.predict(Xt[:, cols]).astype(bool)
            cands.append({"window": start, "class": NAMES[c], "certified": certified, "holdout_agreement": agree,
                          "holdout_fpr": fpr_h, "canary_fp": canary_fp, "canary_ok": canary_ok,
                          "test_fpr_benign": float(mt[yt == BENIGN].mean()), "test_recall_class": float(mt[yt == c].mean())
                          if (yt == c).any() else None})
    df = pd.DataFrame(cands)
    res = {"n_candidates": len(df)}
    if len(df):
        grp = lambda m: {"n": int(m.sum()), "test_fpr_mean": float(df[m].test_fpr_benign.mean()) if m.any() else None,  # noqa: E731
                         "test_fpr_max": float(df[m].test_fpr_benign.max()) if m.any() else None,
                         "test_recall_mean": float(df[m].test_recall_class.mean()) if m.any() else None,
                         "share_test_fpr_above_budget": float((df[m].test_fpr_benign > L["rules"]["max_fpr"]).mean()) if m.any() else None}
        res.update({"certified": grp(df.certified), "uncertified": grp(~df.certified),
                    "direct_promotion_all": grp(df.certified | True), "canary_then_promote": grp(df.certified & df.canary_ok),
                    "certified_but_failed_canary": int((df.certified & ~df.canary_ok).sum())})
    rid, d = evidence("E3")
    df.to_csv(d / "e3_candidates.csv", index=False)
    f = lambda v: "n/a" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v))  # noqa: E731
    keys = ["certified", "uncertified", "direct_promotion_all", "canary_then_promote"]
    md = [f"# E3 - certified vs uncertified rules; canary vs direct ({rid})", "",
          f"{res['n_candidates']} candidate kernel rules distilled (depth<={rc['max_depth']}, kernel-realizable features of "
          f"top-{L['ecs']['k']} groups) from sliding windows of {W} val snapshots; fidelity gate = agreement >= "
          f"{L['rules']['min_agreement']:.4f} and holdout FPR <= {L['rules']['max_fpr']}; canary = FP on next window's "
          f"model-benign traffic. Evaluated on the test split.", ""]
    if len(df):
        md.append(md_table(["group", "n rules", "test FPR mean", "test FPR max", "share FPR > budget", "test recall mean"],
                           [[k, res[k]["n"], f(res[k]["test_fpr_mean"]), f(res[k]["test_fpr_max"]),
                             f(res[k]["share_test_fpr_above_budget"]), f(res[k]["test_recall_mean"])] for k in keys]))
        md.append(f"\nCertified rules that failed the canary: {res['certified_but_failed_canary']}")
    (d / "e3.md").write_text("\n".join(md))
    (d / "e3.json").write_text(json.dumps(res, indent=2))
    dbm.record_experiment(con, rid, "E3 certified vs uncertified rules", res, str(d), dataset=ms.meta["dataset"], split="val->test")
    print("\n".join(md))
    return res


# ------------------------------------------------------------------ E6
def e6() -> dict:
    con, L, ms, M = ctx()
    ev = predict_dataset(ms, path("state_dir") / "datasets/evasion1", C["models"]["eval_cap"], with_attr=True)
    E, _ = ecs({"gbdt": ev["a_gbdt"], "ebm": ev["a_ebm"], "cfc": ev["a_cfc"]}, L["ecs"]["k"], L["ecs"]["alpha"])
    S = sets_of(M, ev["ens"], {c: C["conformal"]["alpha_target"] for c in ms.classes})
    g = tri(S, E, L, True)
    u = tri(S, E, L, False)
    pred = np.asarray([ms.classes[i] for i in ev["ens"].argmax(1)])
    am = np.where(np.isin(pred, list(ATTACK)), "BLOCK", "ALLOW")
    res = {"evasion": {}}
    for sc in sorted(set(ev["scenario"])):
        m = ev["scenario"] == sc
        ga = np.asarray([a for a, _ in g])[m]
        res["evasion"][sc] = {"n": int(m.sum()),
                              "gated_intercept": float(np.isin(ga, ["BLOCK", "QUARANTINE"]).mean()),
                              "gated_adversarial_R1": float(np.mean(np.asarray([r for _, r in g])[m] == "R1")),
                              "conformal_only_intercept": float(np.isin(np.asarray([a for a, _ in u])[m], ["BLOCK", "QUARANTINE"]).mean()),
                              "argmax_block": float(np.mean(am[m] == "BLOCK")),
                              "mean_ecs": float(E[m].mean())}
    # (b) Slack et al. scaffolding against offline LIME
    res["scaffolding"] = scaffolding(ms, L)
    rid, d = evidence("E6")
    f = lambda v: f"{v:.4f}"  # noqa: E731
    sc = res["scaffolding"]
    md = [f"# E6 - evasion and explainer-manipulation detection ({rid})", "",
          "## (a) Evasion variants never seen in training (evasion1 capture)", "",
          md_table(["scenario", "n", "GLASSWALL intercept (BLOCK+QUAR)", "of which R1 adversarial", "conformal-only intercept",
                    "argmax BLOCK", "mean ECS"],
                   [[k, v["n"], f(v["gated_intercept"]), f(v["gated_adversarial_R1"]), f(v["conformal_only_intercept"]),
                     f(v["argmax_block"]), f(v["mean_ecs"])] for k, v in res["evasion"].items()]),
          "", "For benign_* rows 'intercept' is the benign impact rate (lower is better).", "",
          "## (b) Slack-style scaffolding attack on the offline LIME path", "",
          f"{sc['n']} attack-predicted test snapshots. Scaffold = real model on-manifold, innocuous feature "
          f"`{sc['innocuous_feature']}` off-manifold (OOD detector accuracy on held-out real-vs-LIME-perturbation: "
          f"{f(sc['ood_accuracy'])}).", "",
          md_table(["LIME explains", f"flag rate @ learned threshold {sc['learned_threshold']:.4f}",
                    f"flag rate @ tau_lo {sc['threshold_tau_lo']:.4f}", "mean agreement with hot path",
                    "innocuous group in LIME top-k"],
                   [["honest model", f(sc["honest_flag_rate_learned"]), f(sc["honest_flag_rate"]),
                     f(sc["honest_mean_agreement"]), f(sc["honest_innocuous_topk"])],
                    ["scaffolded model", f(sc["scaffold_flag_rate_learned"]), f(sc["scaffold_flag_rate"]),
                     f(sc["scaffold_mean_agreement"]), f(sc["scaffold_innocuous_topk"])]]),
          "", f"Learned threshold = {C['decision']['fpr_budget']} quantile of honest-LIME agreement on "
          f"{sc['n_calibration_val']} validation samples (separate from the {sc['n']} test samples).",
          "", "Without the consensus check there is no comparison, so a manipulated LIME explanation is shown as-is "
          "(detection rate 0 by construction)."]
    (d / "e6.md").write_text("\n".join(md))
    (d / "e6.json").write_text(json.dumps(res, indent=2, default=float))
    dbm.record_experiment(con, rid, "E6 evasion + explainer manipulation", res, str(d), dataset="evasion1 + test", split="test")
    print("\n".join(md))
    return res


def scaffolding(ms: ModelSet, L: dict) -> dict:
    from lime.lime_tabular import LimeTabularExplainer
    from sklearn.ensemble import RandomForestClassifier
    from glasswall_brain.adversarial import pair_agreement
    ec = C["experiments"]
    rng = np.random.default_rng(C["models"]["seed"])
    v, t = load(ms, "val"), load(ms, "test")
    gmat = group_matrix(ms.cols)
    # LIME tabular (discretize_continuous=False) perturbs with N(mean, std) of the training data
    mu, sd = v["X"].mean(0), v["X"].std(0) + 1e-9
    pert = rng.normal(mu, sd, size=v["X"].shape)
    Zr, Zp = ms.prep.static(v["X"]), ms.prep.static(pert)
    ood = RandomForestClassifier(n_estimators=100, random_state=C["models"]["seed"], n_jobs=8)
    Zall = np.vstack([Zr, Zp])
    lab = np.r_[np.ones(len(Zr)), np.zeros(len(Zp))]
    perm = rng.permutation(len(lab))
    cut = int(len(lab) * 0.7)
    ood.fit(Zall[perm[:cut]], lab[perm[:cut]])
    ood_acc = float((ood.predict(Zall[perm[cut:]]) == lab[perm[cut:]]).mean())
    # innocuous feature: lowest mean |TreeSHAP| on val, not in a top group of any sample
    gb_feat_imp = np.abs(np.asarray(ms.gbdt.predict(v["X"][:2000], pred_contrib=True))).reshape(
        min(2000, len(v["X"])), len(ms.classes), len(ms.cols) + 1)[:, :, :-1].mean((0, 1))
    inn = int(np.argmin(gb_feat_imp + (np.std(v["X"], 0) == 0) * 1e9))
    inn_thr = float(np.median(v["X"][:, inn]))
    expl = LimeTabularExplainer(v["X"], feature_names=ms.cols, mode="regression", discretize_continuous=False,
                                random_state=C["models"]["seed"])
    k, alpha = L["ecs"]["k"], L["ecs"]["alpha"]
    inn_group = int(np.argmax(gmat[inn]))

    def run(split: dict, idx: np.ndarray, which: tuple) -> dict:
        out = {w: [] for w in which} | {w + "_inn": [] for w in which}
        for i in idx:
            x = split["X"][i]
            cls = int(split["ens"][i].argmax())

            def real(Z, cls=cls):
                return ms.gbdt.predict(Z)[:, cls]

            def scaf(Z, real=real):
                on = ood.predict(ms.prep.static(Z)) == 1
                return np.where(on, real(Z), (Z[:, inn] > inn_thr).astype(float))

            hot = np.vstack([split["a_gbdt"][i], split["a_ebm"][i], split["a_cfc"][i]])
            for name, fn in (("honest", real), ("scaffold", scaf)):
                if name not in which:
                    continue
                e = expl.explain_instance(x, fn, num_features=len(ms.cols), num_samples=ec["e6_lime_samples"])
                phi = np.zeros(len(ms.cols))
                for j, w in e.as_map()[0]:
                    phi[j] = w
                gv = (phi @ gmat)[None, :]
                out[name].append(float(np.mean([pair_agreement(gv, hot[s:s + 1], k, alpha)[0] for s in range(3)])))
                out[name + "_inn"].append(inn_group in set(np.argsort(-np.abs(gv[0]))[:k]))
        return out

    def attack_idx(split: dict) -> np.ndarray:
        a = np.flatnonzero(np.isin([ms.classes[i] for i in split["ens"].argmax(1)], list(ATTACK)))
        return rng.choice(a, min(ec["e6_scaffold_n"], len(a)), replace=False)

    # threshold learned on HONEST LIME runs on validation samples: the fpr_budget quantile
    # of honest offline-vs-hot-path agreement (PROPOSED); evaluated on separate test samples
    calib = run(v, attack_idx(v), ("honest",))
    thr = float(np.quantile(calib["honest"], C["decision"]["fpr_budget"]))
    out = run(t, attack_idx(t), ("honest", "scaffold"))
    tl = L["decision"]["tau_lo"]
    h, s = np.asarray(out["honest"]), np.asarray(out["scaffold"])
    return {"n": int(len(h)), "n_calibration_val": len(calib["honest"]), "innocuous_feature": ms.cols[inn],
            "ood_accuracy": ood_acc, "learned_threshold": thr, "threshold_tau_lo": tl,
            "honest_flag_rate_learned": float(np.mean(h < thr)), "scaffold_flag_rate_learned": float(np.mean(s < thr)),
            "honest_flag_rate": float(np.mean(h < tl)), "scaffold_flag_rate": float(np.mean(s < tl)),
            "honest_mean_agreement": float(h.mean()), "scaffold_mean_agreement": float(s.mean()),
            "honest_innocuous_topk": float(np.mean(out["honest_inn"])), "scaffold_innocuous_topk": float(np.mean(out["scaffold_inn"]))}


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    for name, fn in (("e1", e1), ("e2", e2), ("e3", e3), ("e6", e6)):
        if which in (name, "all"):
            fn()
