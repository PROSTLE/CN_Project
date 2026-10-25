"""Explanation Consensus Score (Invention 1).

For each pair of explanation sources (i, j):
    A_ij = alpha * J_k(T_i, T_j) + (1 - alpha) * signAgree(T_i, T_j)
    ECS  = mean over the 3 pairs, in [0, 1]
T_i = top-k groups of source i by |attribution|. Groups with exactly zero
attribution are never "top" (PROPOSED), so |T_i| <= k.
J_k = |T_i & T_j| / |T_i | T_j| (0 if both empty, PROPOSED).
signAgree = share of groups in T_i & T_j whose attributions have the same
sign; 0 when the intersection is empty (PROPOSED, TRD TR-E-2).
"""
from __future__ import annotations

from itertools import combinations

import numpy as np

SOURCES = ("gbdt", "ebm", "cfc")
PAIRS = list(combinations(SOURCES, 2))


def topk_mask(a: np.ndarray, k: int) -> np.ndarray:
    """a: [n, G] -> boolean [n, G] marking the top-k non-zero |a| groups
    (ties broken by group order, stable)."""
    order = np.argsort(-np.abs(a), axis=1, kind="stable")[:, :k]
    m = np.zeros(a.shape, dtype=bool)
    np.put_along_axis(m, order, True, axis=1)
    return m & (a != 0)


def ecs(attr: dict[str, np.ndarray], k: int, alpha: float) -> tuple[np.ndarray, dict]:
    """Returns (ECS [n], pairs {"gbdt-ebm": {"jaccard": [n], "sign": [n], "A": [n]}, ...})."""
    masks = {s: topk_mask(attr[s], k) for s in SOURCES}
    signs = {s: np.sign(attr[s]) for s in SOURCES}
    pairs, total = {}, 0.0
    for i, j in PAIRS:
        inter = masks[i] & masks[j]
        union = masks[i] | masks[j]
        ni, nu = inter.sum(1), union.sum(1)
        jac = np.where(nu > 0, ni / np.maximum(nu, 1), 0.0)
        same = (inter & (signs[i] == signs[j])).sum(1)
        sg = np.where(ni > 0, same / np.maximum(ni, 1), 0.0)
        A = alpha * jac + (1 - alpha) * sg
        pairs[f"{i}-{j}"] = {"jaccard": jac, "sign": sg, "A": A}
        total = total + A
    return total / len(PAIRS), pairs


def topk_groups(a: np.ndarray, k: int, names: list[str]) -> list[list[tuple[str, float]]]:
    m = topk_mask(a, k)
    out = []
    for row, mr in zip(a, m):
        idx = [i for i in np.argsort(-np.abs(row), kind="stable") if mr[i]]
        out.append([(names[i], float(row[i])) for i in idx])
    return out
