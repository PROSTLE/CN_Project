"""Mondrian (class-conditional) split conformal + Adaptive Conformal Inference.

Nonconformity s(x, c) = 1 - p_ens(c | x). For class c with calibration scores
{s_i : y_i = c} (n_c of them), the threshold at level alpha is the
ceil((n_c + 1)(1 - alpha))-th smallest score (inf if that rank exceeds n_c).
Prediction set S(x) = {c : s(x, c) <= q_c(alpha_c)}.

ACI (per class, Gibbs & Candes 2021): when a delayed label y arrives for a
past decision, err = 1[y not in S]; alpha_y <- clip(alpha_y + gamma *
(alpha_target - err), 0, 1). gamma and alpha_target come from config.
Implemented here instead of MAPIE (PROPOSED: ~40 lines, exact, auditable).
"""
from __future__ import annotations

import numpy as np


class Mondrian:
    def __init__(self, classes: list[int], cal_scores: dict[int, np.ndarray]) -> None:
        self.classes = classes
        self.scores = {c: np.sort(np.asarray(cal_scores.get(c, []), dtype=np.float64)) for c in classes}

    @classmethod
    def fit(cls, classes: list[int], P_cal: np.ndarray, y_cal_local: np.ndarray) -> "Mondrian":
        sc = {}
        for li, c in enumerate(classes):
            m = y_cal_local == li
            sc[c] = 1.0 - P_cal[m, li]
        return cls(classes, sc)

    def quantile(self, c: int, alpha: float) -> float:
        s = self.scores[c]
        n = len(s)
        if n == 0 or alpha <= 0:
            return np.inf
        if alpha >= 1:
            return -np.inf
        r = int(np.ceil((n + 1) * (1 - alpha)))
        return np.inf if r > n else float(s[r - 1])

    def thresholds(self, alphas: dict[int, float]) -> np.ndarray:
        return np.asarray([self.quantile(c, alphas[c]) for c in self.classes])

    def sets(self, P: np.ndarray, alphas: dict[int, float]) -> np.ndarray:
        """P: [n, K] local-class probs -> boolean [n, K] membership."""
        q = self.thresholds(alphas)
        return (1.0 - P) <= q[None, :]

    def state(self) -> dict:
        return {"classes": self.classes, "scores": {str(c): v.tolist() for c, v in self.scores.items()}}

    @classmethod
    def from_state(cls, s: dict) -> "Mondrian":
        return cls(s["classes"], {int(c): np.asarray(v) for c, v in s["scores"].items()})


class ACI:
    def __init__(self, classes: list[int], alpha_target: float, gamma: float,
                 alphas: dict[int, float] | None = None) -> None:
        self.target, self.gamma = alpha_target, gamma
        self.alpha = dict(alphas) if alphas else {c: alpha_target for c in classes}
        self.n = {c: 0 for c in classes}
        self.err = {c: 0 for c in classes}

    def update(self, y: int, covered: bool) -> float:
        e = 0.0 if covered else 1.0
        self.alpha[y] = float(np.clip(self.alpha[y] + self.gamma * (self.target - e), 0.0, 1.0))
        self.n[y] += 1
        self.err[y] += int(e)
        return self.alpha[y]
