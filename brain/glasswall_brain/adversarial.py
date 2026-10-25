"""Manipulation & evasion signals (Invention 5).

offline_explain : KernelSHAP (shap) or LIME (lime) on the ensemble's
    probability of the predicted class over the static feature vector (the
    packet sequence held fixed) -> 14-group vector -> agreement with each
    hot-path source using the learned ECS pair formula; flagged when the mean
    agreement falls below the learned tau_lo (PROPOSED: same scale as ECS).
    Offline / audit only - never on the hot path.
lipschitz : local stability of hot-path group attributions under small
    protocol-constrained perturbations of kernel-realizable counters (integer,
    non-negative, relative step from config).
"""
from __future__ import annotations

import time

import numpy as np

from .config import cfg, learned
from .ecs import topk_mask
from .models import GROUPS, ModelSet, group_matrix


def pair_agreement(a: np.ndarray, b: np.ndarray, k: int, alpha: float) -> np.ndarray:
    ma, mb = topk_mask(a, k), topk_mask(b, k)
    inter, union = ma & mb, ma | mb
    ni, nu = inter.sum(1), union.sum(1)
    jac = np.where(nu > 0, ni / np.maximum(nu, 1), 0.0)
    sg = np.where(ni > 0, (inter & (np.sign(a) == np.sign(b))).sum(1) / np.maximum(ni, 1), 0.0)
    return alpha * jac + (1 - alpha) * sg


def _background(ms: ModelSet, n: int) -> np.ndarray:
    z = np.load(ms.dir / "eval_val.npz")
    rng = np.random.default_rng(cfg()["models"]["seed"])
    X = z["X"]
    return X[rng.choice(len(X), min(n, len(X)), replace=False)]


def offline_explain(ms: ModelSet, X: np.ndarray, seq, lens, method: str, hot: dict) -> dict:
    ac = cfg()["adversarial"]
    L = learned()
    t0 = time.perf_counter()
    target = int(ms.proba(X, seq, lens)["ens"].argmax(1)[0])

    def f(Z: np.ndarray) -> np.ndarray:
        n = len(Z)
        return ms.proba(Z, np.repeat(seq, n, 0), np.repeat(lens, n, 0))["ens"][:, target]

    bg = _background(ms, ac["background_n"])
    if method == "kernelshap":
        import shap
        ex = shap.KernelExplainer(f, bg)
        phi = np.asarray(ex.shap_values(X, nsamples=ac["kernelshap_nsamples"], silent=True)).reshape(1, -1)
    elif method == "lime":
        from lime.lime_tabular import LimeTabularExplainer
        ex = LimeTabularExplainer(bg, feature_names=ms.cols, mode="regression", discretize_continuous=False,
                                  random_state=cfg()["models"]["seed"])
        e = ex.explain_instance(X[0], f, num_features=len(ms.cols), num_samples=ac["lime_samples"])
        phi = np.zeros((1, len(ms.cols)))
        for j, w in e.as_map()[0]:
            phi[0, j] = w
    else:
        raise ValueError("method must be kernelshap or lime")
    g = phi @ group_matrix(ms.cols)
    k, alpha = L["ecs"]["k"], L["ecs"]["alpha"]
    agree = {s: float(pair_agreement(g, np.asarray([hot[s]]), k, alpha)[0]) for s in ("gbdt", "ebm", "cfc")}
    mean = float(np.mean(list(agree.values())))
    return {"method": method, "groups": g[0].tolist(), "group_names": GROUPS, "agreement": agree,
            "disagreement": 1 - mean, "threshold": L["decision"]["tau_lo"], "flag": mean < L["decision"]["tau_lo"],
            "seconds": time.perf_counter() - t0, "label": "offline, sampling-based"}


def lipschitz(ms: ModelSet, X: np.ndarray, seq, lens, rng: np.random.Generator) -> np.ndarray:
    """max_m ||attr(x') - attr(x)|| / ||x' - x|| (normalised feature space),
    perturbing only kernel-realizable counters by +-max(1, rel_eps * value)."""
    ac = cfg()["adversarial"]
    kidx = [i for i, c in enumerate(ms.cols) if c.startswith("k_")]
    pr = ms.proba(X, seq, lens)
    tgt = pr["ens"].argmax(1)
    base = ms.attributions(X, seq, lens, tgt)
    A0 = np.concatenate([base[s] for s in ("gbdt", "ebm", "cfc")], 1)
    Z0 = ms.prep.static(X)
    best = np.zeros(len(X))
    for _ in range(ac["lipschitz_samples"]):
        Xp = X.copy()
        step = np.maximum(1.0, np.abs(X[:, kidx]) * ac["lipschitz_rel_eps"])
        Xp[:, kidx] = np.maximum(0, np.round(X[:, kidx] + rng.choice([-1, 1], size=step.shape) * step))
        a = ms.attributions(Xp, seq, lens, tgt)
        A1 = np.concatenate([a[s] for s in ("gbdt", "ebm", "cfc")], 1)
        dx = np.linalg.norm(ms.prep.static(Xp) - Z0, axis=1)
        da = np.linalg.norm(A1 - A0, axis=1)
        best = np.maximum(best, np.where(dx > 0, da / np.maximum(dx, 1e-12), 0))
    return best
