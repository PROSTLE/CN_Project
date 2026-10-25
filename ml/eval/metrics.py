"""Detection metrics: per-class P/R/F1, macro-F1, PR-AUC, FPR at fixed recall."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support


def fpr_at_recall(y_attack: np.ndarray, score: np.ndarray, recall: float) -> tuple[float | None, float | None, bool]:
    """Binary attack-vs-benign: lowest threshold reaching `recall` -> FPR there.
    Returns (fpr, threshold, met)."""
    if y_attack.sum() == 0 or (~y_attack).sum() == 0:
        return None, None, False
    order = np.argsort(-score, kind="stable")
    s, ya = score[order], y_attack[order]
    tp = np.cumsum(ya)
    fp = np.cumsum(~ya)
    rec = tp / ya.sum()
    i = int(np.searchsorted(rec, recall))
    if i >= len(s):
        return None, None, False
    # include ties at the threshold
    thr = s[i]
    j = np.searchsorted(-s, -thr, side="right") - 1
    return float(fp[j] / (~ya).sum()), float(thr), True


def detection_metrics(y: np.ndarray, P: np.ndarray, names: list[str], benign: int | None, recall: float) -> dict:
    K = P.shape[1]
    pred = P.argmax(1)
    pr, rc, f1, sup = precision_recall_fscore_support(y, pred, labels=list(range(K)), zero_division=0)
    present = sup > 0
    aps = []
    for k in range(K):
        if present[k] and (y != k).any():
            aps.append(average_precision_score(y == k, P[:, k]))
    out = {"macro_f1": float(f1[present].mean()) if present.any() else 0.0,
           "pr_auc_macro": float(np.mean(aps)) if aps else 0.0,
           "accuracy": float((pred == y).mean()) if len(y) else 0.0,
           "per_class": {names[k]: {"precision": float(pr[k]), "recall": float(rc[k]), "f1": float(f1[k]),
                                    "support": int(sup[k])} for k in range(K)},
           "confusion": confusion_matrix(y, pred, labels=list(range(K))).tolist(), "n": int(len(y))}
    if benign is not None:
        fpr, thr, met = fpr_at_recall(y != benign, 1 - P[:, benign], recall)
        out.update({"fpr_at_recall": fpr, "threshold_at_recall": thr, "recall_threshold_met": met})
    else:
        out.update({"fpr_at_recall": None, "threshold_at_recall": None, "recall_threshold_met": False})
    return out


def md_table(head: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(map(str, head)) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(map(str, r)) + " |" for r in rows]
    return "\n".join(out)
