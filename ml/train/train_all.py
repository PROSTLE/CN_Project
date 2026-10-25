"""Train the GLASSWALL model set + baselines on a lab dataset; evaluate on a
temporal split; register artifacts with SHA-256; write evidence.

  python ml/train/train_all.py <dataset_dir>

Hygiene: rows with non-finite values dropped; constant columns (on train)
dropped; exact duplicate (features, label) rows removed within each split;
class weights computed inside the train fold only; identity fields (IP/port)
never in the model input (separate ablation shows why).
"""
from __future__ import annotations

import hashlib
import json
import pickle
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
from glasswall_brain.config import cfg, class_names, config_sha, model_feature_names, path  # noqa: E402
from glasswall_brain.models import (GROUPS, ModelSet, Prep, SeqNet, ensemble, seqnet_proba,  # noqa: E402
                                    sha256_file, train_seqnet)
from ml.eval.metrics import detection_metrics, md_table  # noqa: E402

MC = cfg()["models"]
NAMES = class_names()
LOG: list[str] = []


def log(*a) -> None:
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    LOG.append(s)


def temporal_split(df: pd.DataFrame) -> pd.Series:
    """mode=rounds: last round -> test, the round before -> val/cal (by flow-id
    hash parity), earlier rounds -> train. Keeps time order train < val/cal <
    test and every scenario in every split. mode=fraction: flow-start quantiles."""
    sp = MC["split"]
    if sp["mode"] == "rounds":
        R = int(df["round"].max())
        test_from = R - sp["test_rounds"] + 1
        vc_from = test_from - sp["valcal_rounds"]
        if vc_from < 2:
            raise SystemExit(f"need more rounds than {R} for split {sp}")
        par = df["flow_id"].map(lambda f: int(hashlib.sha256(f.encode()).hexdigest(), 16) % 2)
        return pd.Series(np.where(df["round"] >= test_from, "test",
                                  np.where(df["round"] >= vc_from, np.where(par == 0, "val", "cal"), "train")),
                         index=df.index)
    fr = MC["split_fractions"]
    flows = df.groupby("flow_id")["first_ts"].min().sort_values()
    q = np.cumsum([fr["train"], fr["val"], fr["cal"]])
    pos = np.arange(len(flows)) / len(flows)
    lab = np.where(pos < q[0], "train", np.where(pos < q[1], "val", np.where(pos < q[2], "cal", "test")))
    return df["flow_id"].map(dict(zip(flows.index, lab)))


def main(ds: Path) -> None:
    t_start = time.time()
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    ev_dir = path("evidence_dir") / f"train_{run_id}"
    ev_dir.mkdir(parents=True, exist_ok=True)
    df = pd.read_parquet(ds / "snapshots.parquet")
    seqs = np.load(ds / "sequences.npy")
    lens = np.load(ds / "seq_len.npy").astype(np.int64)
    manifest = json.loads((ds / "manifest.json").read_text())
    full_cols = model_feature_names()
    log(f"dataset {ds}: {len(df)} snapshots, {df.flow_id.nunique()} flows")

    keep = ~df["evasion"].to_numpy()
    fin = np.isfinite(df[full_cols].to_numpy()).all(1)
    log(f"dropped evasion rows: {(~keep).sum()}, non-finite rows: {(~fin).sum()}")
    df = df[keep & fin].reset_index(drop=True)
    seqs, lens = seqs[keep & fin], lens[keep & fin]
    df["split"] = temporal_split(df)

    tr = df["split"] == "train"
    const = [c for c in full_cols if df.loc[tr, c].nunique() <= 1]
    cols = [c for c in full_cols if c not in const]
    log(f"constant columns dropped (train): {const}")

    # de-duplicate within split
    before = len(df)
    dup = df.duplicated(subset=cols + ["class_id", "split"])
    df, seqs, lens = df[~dup].reset_index(drop=True), seqs[~dup.to_numpy()], lens[~dup.to_numpy()]
    log(f"exact duplicates removed within splits: {before - len(df)}")

    # leakage check: no flow spans two splits; splits are time-ordered
    assert df.groupby("flow_id")["split"].nunique().max() == 1

    # minimum class support: Mondrian conformal needs n_c >= ceil((1-a)/a) calibration
    # points for a finite threshold at a = alpha_target (else the class is in every set)
    a_t = cfg()["conformal"]["alpha_target"]
    min_support = int(np.ceil((1 - a_t) / a_t))
    sup = df.groupby(["split", "class_id"]).size().unstack(fill_value=0)
    weak = [int(c) for c in sup.columns if sup[c].min() < min_support]
    insufficient = {NAMES[c]: sup[c].to_dict() for c in weak}
    if weak:
        log(f"classes below minimum support {min_support} in some split (not modelled): {insufficient}")
        keepc = ~df["class_id"].isin(weak).to_numpy()
        df, seqs, lens = df[keepc].reset_index(drop=True), seqs[keepc], lens[keepc]
    rng = np.random.default_rng(MC["seed"])
    tr_idx = np.flatnonzero(df["split"] == "train")
    capped = []
    for c in np.unique(df.loc[tr_idx, "class_id"]):
        ids = tr_idx[df.loc[tr_idx, "class_id"].to_numpy() == c]
        if len(ids) > MC["train_cap_per_class"]:
            ids = rng.choice(ids, MC["train_cap_per_class"], replace=False)
        capped.append(ids)
    tr_idx = np.sort(np.concatenate(capped))
    classes = sorted(int(c) for c in np.unique(df.loc[tr_idx, "class_id"]))
    loc = {c: i for i, c in enumerate(classes)}
    y_all = df["class_id"].map(loc).fillna(-1).astype(int).to_numpy()
    X_all = df[cols].to_numpy(np.float64)
    split_idx = {"train": tr_idx}
    for s in ("val", "cal", "test"):
        ids = np.flatnonzero((df["split"] == s).to_numpy() & (y_all >= 0))
        split_idx[s] = ids
    counts = {s: df.iloc[ix].groupby("label")["flow_id"].nunique().to_dict() for s, ix in split_idx.items()}
    snap_counts = {s: df.iloc[ix]["label"].value_counts().to_dict() for s, ix in split_idx.items()}
    log("flows per split/class:", json.dumps(counts))
    log("snapshots per split/class:", json.dumps(snap_counts))
    absent = [NAMES[i] for i in range(len(NAMES)) if i not in classes and i not in weak]
    log(f"classes with no lab data (not modelled): {absent}")

    Xtr, ytr = X_all[tr_idx], y_all[tr_idx]
    K = len(classes)
    cw = len(ytr) / (K * np.bincount(ytr, minlength=K))
    wtr = cw[ytr]
    Xv, yv = X_all[split_idx["val"]], y_all[split_idx["val"]]
    Xte, yte = X_all[split_idx["test"]], y_all[split_idx["test"]]
    S = {s: (seqs[ix], lens[ix]) for s, ix in split_idx.items()}

    results, probs_test, probs_val, timings, params = {}, {}, {}, {}, {}

    # ---- GBDT (LightGBM) ---------------------------------------------
    import lightgbm as lgb
    t = time.time()
    p = {"objective": "multiclass", "num_class": K, "learning_rate": 0.05, "num_leaves": 31, "seed": MC["seed"],
         "verbose": -1, "min_data_in_leaf": 20, "feature_fraction": 0.9, "deterministic": True,
         "num_threads": 8}
    gbdt = lgb.train(p, lgb.Dataset(Xtr, ytr, weight=wtr, feature_name=cols), MC["gbdt_rounds"],
                     valid_sets=[lgb.Dataset(Xv, yv, feature_name=cols)],
                     callbacks=[lgb.early_stopping(MC["gbdt_early_stop"], verbose=False)])
    timings["gbdt_train_s"] = time.time() - t
    probs_val["gbdt"], probs_test["gbdt"] = gbdt.predict(Xv), gbdt.predict(Xte)
    log(f"lightgbm: {gbdt.best_iteration} rounds, {timings['gbdt_train_s']:.1f}s")

    # ---- XGBoost (baseline / alternative gate) ----------------------
    import xgboost as xgb
    t = time.time()
    xg = xgb.XGBClassifier(n_estimators=MC["gbdt_rounds"], learning_rate=0.05, max_depth=6, random_state=MC["seed"],
                           n_jobs=8, early_stopping_rounds=MC["gbdt_early_stop"], eval_metric="mlogloss")
    xg.fit(Xtr, ytr, sample_weight=wtr, eval_set=[(Xv, yv)], verbose=False)
    timings["xgb_train_s"] = time.time() - t
    probs_val["xgb"], probs_test["xgb"] = xg.predict_proba(Xv), xg.predict_proba(Xte)

    # ---- EBM -----------------------------------------------------------
    from interpret.glassbox import ExplainableBoostingClassifier
    t = time.time()
    try:
        ebm = ExplainableBoostingClassifier(feature_names=cols, interactions=MC["ebm_interactions"],
                                            outer_bags=MC["ebm_outer_bags"], random_state=MC["seed"], n_jobs=8)
        ebm.fit(Xtr, ytr, sample_weight=wtr)
        ebm_inter = MC["ebm_interactions"]
    except Exception as e:  # multiclass interactions unsupported in some versions
        log(f"EBM with interactions failed ({e}); refitting with interactions=0")
        ebm = ExplainableBoostingClassifier(feature_names=cols, interactions=0, outer_bags=MC["ebm_outer_bags"],
                                            random_state=MC["seed"], n_jobs=8)
        ebm.fit(Xtr, ytr, sample_weight=wtr)
        ebm_inter = 0
    timings["ebm_train_s"] = time.time() - t
    probs_val["ebm"], probs_test["ebm"] = ebm.predict_proba(Xv), ebm.predict_proba(Xte)
    log(f"ebm: {len(ebm.term_features_)} terms (interactions={ebm_inter}), {timings['ebm_train_s']:.1f}s")

    # ---- sequence models: CfC + ablations ------------------------------
    prep = Prep(cols).fit(Xtr, S["train"][0], S["train"][1])
    nets = {}
    for kind in ("cfc", "lstm", "gru", "cnn"):
        t = time.time()
        nets[kind] = train_seqnet(kind, prep, Xtr, S["train"][0], S["train"][1], ytr, wtr, K,
                                  Xv, S["val"][0], S["val"][1], yv, log=log)
        timings[f"{kind}_train_s"] = time.time() - t
        params[kind] = int(sum(p.numel() for p in nets[kind].parameters()))
        probs_val[kind] = seqnet_proba(nets[kind], prep, Xv, *S["val"])
        probs_test[kind] = seqnet_proba(nets[kind], prep, Xte, *S["test"])

    # ---- sklearn baselines --------------------------------------------
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.neural_network import MLPClassifier
    t = time.time()
    rf = RandomForestClassifier(n_estimators=200, n_jobs=8, random_state=MC["seed"], class_weight="balanced")
    rf.fit(Xtr, ytr)
    timings["rf_train_s"] = time.time() - t
    probs_val["rf"], probs_test["rf"] = rf.predict_proba(Xv), rf.predict_proba(Xte)
    t = time.time()
    mlp = MLPClassifier(hidden_layer_sizes=(64, 64), max_iter=200, random_state=MC["seed"], early_stopping=True)
    mlp.fit(prep.static(Xtr), ytr)
    timings["mlp_train_s"] = time.time() - t
    probs_val["mlp"], probs_test["mlp"] = mlp.predict_proba(prep.static(Xv)), mlp.predict_proba(prep.static(Xte))

    # ---- ensemble weights + temperature (val) ---------------------------
    Pv = np.stack([probs_val[m] for m in ("gbdt", "ebm", "cfc")])
    step = MC["ensemble_weight_step"]
    grid = [(a, b, round(1 - a - b, 6)) for a in np.arange(0, 1 + 1e-9, step) for b in np.arange(0, 1 - a + 1e-9, step)]
    best = None
    for w in grid:
        for T in MC["temperature_grid"]:
            pe = ensemble(Pv, np.asarray(w), T)
            nll = -np.mean(np.log(np.clip(pe[np.arange(len(yv)), yv], 1e-12, 1)))
            if best is None or nll < best[0]:
                best = (nll, w, T)
    ens_w, ens_T = np.asarray(best[1]), best[2]
    log(f"ensemble weights (gbdt, ebm, cfc) = {ens_w.round(3).tolist()}, temperature {ens_T}, val NLL {best[0]:.4f}")
    probs_test["ensemble"] = ensemble(np.stack([probs_test[m] for m in ("gbdt", "ebm", "cfc")]), ens_w, ens_T)
    probs_val["ensemble"] = ensemble(Pv, ens_w, ens_T)

    # ---- metrics ---------------------------------------------------------
    cls_names = [NAMES[c] for c in classes]
    benign_local = loc.get(NAMES.index("Benign"))
    for m, pt in probs_test.items():
        results[m] = detection_metrics(yte, pt, cls_names, benign_local, MC["fixed_recall"])
    cp = df.iloc[split_idx["test"]]["checkpoint"].to_numpy()
    per_cp = {c: detection_metrics(yte[cp == c], probs_test["ensemble"][cp == c], cls_names, benign_local,
                                   MC["fixed_recall"])["macro_f1"] for c in np.unique(cp)}

    # identity-feature ablation (never deployed)
    id_cols = ["cport", "sport", "proto"]
    oct_ = lambda s: s.str.split(".").str[-1].astype(float)  # noqa: E731
    Xid = np.column_stack([X_all, df[id_cols].to_numpy(float), oct_(df["cli"]), oct_(df["srv"])])
    gid = lgb.train(p, lgb.Dataset(Xid[tr_idx], ytr, weight=wtr), MC["gbdt_rounds"],
                    valid_sets=[lgb.Dataset(Xid[split_idx["val"]], yv)],
                    callbacks=[lgb.early_stopping(MC["gbdt_early_stop"], verbose=False)])
    results["ablation_gbdt_with_identity"] = detection_metrics(yte, gid.predict(Xid[split_idx["test"]]),
                                                               cls_names, benign_local, MC["fixed_recall"])
    imp = dict(zip(cols + id_cols + ["cli_octet", "srv_octet"], gid.feature_importance("gain")))
    id_gain_share = sum(imp[c] for c in id_cols + ["cli_octet", "srv_octet"]) / sum(imp.values())

    # ---- latency (single-snapshot inference, CPU) -------------------------
    lat = {}
    x1, s1, l1 = Xte[:1], S["test"][0][:1], S["test"][1][:1]
    for name, fn in {"gbdt": lambda: gbdt.predict(x1), "ebm": lambda: ebm.predict_proba(x1),
                     "cfc": lambda: seqnet_proba(nets["cfc"], prep, x1, s1, l1),
                     "lstm": lambda: seqnet_proba(nets["lstm"], prep, x1, s1, l1),
                     "xgb": lambda: xg.predict_proba(x1)}.items():
        ts_ = []
        for _ in range(100):
            t = time.perf_counter()
            fn()
            ts_.append((time.perf_counter() - t) * 1e3)
        lat[name] = {"p50_ms": float(np.percentile(ts_, 50)), "p99_ms": float(np.percentile(ts_, 99))}

    # ---- save model set -----------------------------------------------------
    ms_id = f"ms-{run_id}"
    md = path("models_dir") / ms_id
    md.mkdir(parents=True, exist_ok=True)
    gbdt.save_model(str(md / "gbdt.txt"), num_iteration=gbdt.best_iteration)
    with open(md / "ebm.pkl", "wb") as f:
        pickle.dump(ebm, f)
    import torch
    torch.save(nets["cfc"].state_dict(), md / "cfc.pt")
    (md / "prep.json").write_text(json.dumps(prep.state()))
    (md / "ensemble.json").write_text(json.dumps({"weights": ens_w.tolist(), "temperature": ens_T,
                                                   "fit_on": "val", "val_nll": best[0]}))
    xg.save_model(str(md / "xgb_baseline.json"))
    sha = {k: sha256_file(md / fn) for k, fn in ModelSet.FILES.items()}
    import hashlib
    set_hash = hashlib.sha256("".join(sha[k] for k in sorted(sha)).encode()).hexdigest()
    meta = {"model_set_id": ms_id, "set_hash": set_hash, "sha256": sha, "classes": classes, "cols": cols,
            "dropped_constant": const, "dataset": str(ds), "manifest": manifest, "run_id": run_id,
            "ebm_interactions": ebm_inter, "cfc_params": params["cfc"]}
    (md / "meta.json").write_text(json.dumps(meta, indent=2))

    con = dbm.init()
    con.execute("UPDATE model_sets SET active=0")
    con.execute("INSERT INTO model_sets VALUES (?,?,?,?,?,?,1)",
                (ms_id, dbm.now(), str(ds), json.dumps(MC["split"]), set_hash, json.dumps(meta)))
    for k, fn in ModelSet.FILES.items():
        con.execute("INSERT INTO model_artifacts (model_set_id, kind, path, sha256, params_json, created_at) "
                    "VALUES (?,?,?,?,?,?)", (ms_id, k, str(md / fn), sha[k], "{}", dbm.now()))
    con.commit()

    # ---- hot-path attributions on val/cal/test for calibration + experiments --
    ms = ModelSet(md)
    for s in ("val", "cal", "test"):
        # per-class cap (eval_cap / K): rare classes keep every row so Mondrian
        # calibration keeps its support (a uniform subsample dropped them below it)
        ix_all = split_idx[s]
        per = MC["eval_cap"] // K
        parts = []
        for li in range(K):
            ids = ix_all[y_all[ix_all] == li]
            parts.append(rng.choice(ids, per, replace=False) if len(ids) > per else ids)
        ix = np.sort(np.concatenate(parts))
        X, (sq, ln) = X_all[ix], (seqs[ix], lens[ix])
        t = time.time()
        pr = ms.proba(X, sq, ln)
        target = pr["ens"].argmax(1)
        at = ms.attributions(X, sq, ln, target)
        el = time.time() - t
        np.savez_compressed(md / f"eval_{s}.npz", idx=ix, y=y_all[ix], gbdt=pr["gbdt"], ebm=pr["ebm"],
                            cfc=pr["cfc"], ens=pr["ens"], a_gbdt=at["gbdt"], a_ebm=at["ebm"], a_cfc=at["cfc"],
                            ig_gap=at["ig_gap"], X=X, first_ts=df["first_ts"].to_numpy()[ix],
                            ts=df["ts"].to_numpy()[ix], checkpoint=df["checkpoint"].to_numpy()[ix].astype(str),
                            scenario=df["scenario"].to_numpy()[ix].astype(str),
                            flow_id=df["flow_id"].to_numpy()[ix].astype(str), cli=df["cli"].to_numpy()[ix].astype(str))
        timings[f"attr_{s}_s_per_snapshot"] = el / max(len(ix), 1)
        log(f"attributions {s}: {len(ix)} snapshots in {el:.1f}s; IG completeness gap median "
            f"{np.median(at['ig_gap']):.4g}, p99 {np.percentile(at['ig_gap'], 99):.4g}")

    # ---- evidence -----------------------------------------------------------
    order = ["ensemble", "gbdt", "xgb", "ebm", "cfc", "lstm", "gru", "cnn", "rf", "mlp", "ablation_gbdt_with_identity"]
    summary = {m: {k: results[m][k] for k in ("macro_f1", "pr_auc_macro", "fpr_at_recall", "recall_threshold_met",
                                               "accuracy")} for m in order}
    out = {"run_id": run_id, "model_set_id": ms_id, "set_hash": set_hash, "classes_modelled": cls_names,
           "classes_without_data": absent, "classes_insufficient_support": insufficient,
           "min_class_support": min_support, "flows_per_split": counts, "snapshots_per_split": snap_counts,
           "summary": summary, "per_class": {m: results[m]["per_class"] for m in order},
           "confusion": {m: results[m]["confusion"] for m in ("ensemble", "gbdt", "ebm", "cfc")},
           "ensemble_macro_f1_by_checkpoint": per_cp, "latency_single_snapshot": lat, "params": params,
           "timings": timings, "identity_gain_share_in_ablation": id_gain_share, "dropped_constant": const,
           "ensemble": {"weights": ens_w.tolist(), "temperature": ens_T},
           "environment": cfg()["environment"]["label"], "config_sha": config_sha(),
           "seconds_total": time.time() - t_start}
    (ev_dir / "metrics.json").write_text(json.dumps(out, indent=2, default=float))
    rows = [[m, f"{summary[m]['macro_f1']:.4f}", f"{summary[m]['pr_auc_macro']:.4f}",
             f"{summary[m]['fpr_at_recall']:.4f}" if summary[m]["fpr_at_recall"] is not None else "n/a",
             f"{summary[m]['accuracy']:.4f}"] for m in order]
    md_txt = [f"# Detection results (test split, temporal) - run {run_id}", "",
              f"Environment: {cfg()['environment']['label']}. Dataset: own lab capture (labels by construction).", "",
              md_table(["model", "macro-F1", "PR-AUC (macro)", f"FPR @ recall {MC['fixed_recall']}", "accuracy"], rows),
              "", "## Per-class (ensemble)", "",
              md_table(["class", "precision", "recall", "F1", "support"],
                       [[c, f"{v['precision']:.4f}", f"{v['recall']:.4f}", f"{v['f1']:.4f}", v["support"]]
                        for c, v in results["ensemble"]["per_class"].items()]),
              "", "## Ensemble macro-F1 by checkpoint", "",
              md_table(["checkpoint", "macro-F1"], [[k, f"{v:.4f}"] for k, v in per_cp.items()]),
              "", "## Sequence models: accuracy per parameter", "",
              md_table(["model", "params", "macro-F1", "p50 latency ms (batch 1)"],
                       [[k, params[k], f"{summary[k]['macro_f1']:.4f}",
                         f"{lat[k]['p50_ms']:.3f}" if k in lat else "-"] for k in ("cfc", "lstm", "gru", "cnn")]),
              "", f"Identity ablation: share of LightGBM gain on IP/port columns = {id_gain_share:.3f}",
              "", f"Classes without lab data (not modelled): {absent}",
              f"Classes below minimum support {min_support} = ceil((1-alpha)/alpha) in some split after de-duplication "
              f"(not modelled): {insufficient}", "", "## Log", "", "```", *LOG, "```"]
    (ev_dir / "metrics.md").write_text("\n".join(md_txt))
    dbm.record_experiment(con, f"P3-{run_id}", "P3 detection (temporal split)", out, str(ev_dir),
                          dataset=str(ds), split=json.dumps(MC["split"]))
    log(f"model set {ms_id} registered; evidence {ev_dir}; total {time.time() - t_start:.0f}s")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
