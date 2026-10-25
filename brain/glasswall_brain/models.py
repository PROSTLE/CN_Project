"""Three structurally different models and their hot-path explanations, all
reported in the shared 14-group semantic space.

  gbdt : LightGBM multiclass; exact TreeSHAP via Booster.predict(pred_contrib=True)
  ebm  : InterpretML EBM; exact additive terms via eval_terms (pairs split
         equally across member features' groups - PROPOSED, TRD TR-M-2)
  cfc  : ncps CfC with AutoNCP wiring over the first-N packet sequence,
         static context concatenated at readout; integrated gradients
         (ig_steps from config, zero baseline in normalised space = training
         mean - PROPOSED)

Attributions are for the logit of a target class (the ensemble's predicted
class): positive = pushes towards that class.
"""
from __future__ import annotations

import hashlib
import json
import pickle
from pathlib import Path

import numpy as np
import torch
from torch import nn

from .config import cfg, feature_group_map, group_ids, sequence_channels

GROUPS = group_ids()
GIDX = {g: i for i, g in enumerate(GROUPS)}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- preprocessing
class Prep:
    """Static: signed log1p then standardise. Sequence: log1p(size), log1p(dt ms)
    standardised; binary channels as is; padded steps zeroed (= IG baseline)."""

    def __init__(self, cols: list[str], mu=None, sd=None, smu=None, ssd=None) -> None:
        self.cols = cols
        self.mu, self.sd, self.smu, self.ssd = mu, sd, smu, ssd

    @staticmethod
    def _slog(x: np.ndarray) -> np.ndarray:
        return np.sign(x) * np.log1p(np.abs(x))

    def fit(self, X: np.ndarray, seq: np.ndarray, lens: np.ndarray) -> "Prep":
        z = self._slog(X)
        self.mu, self.sd = z.mean(0), np.maximum(z.std(0), 1e-6)
        mask = np.arange(seq.shape[1])[None, :] < lens[:, None]
        s = self._seq_raw(seq)[mask]
        self.smu, self.ssd = s.mean(0), np.maximum(s.std(0), 1e-6)
        self.smu[1:7], self.ssd[1:7] = 0.0, 1.0   # binary channels untouched
        return self

    @staticmethod
    def _seq_raw(seq: np.ndarray) -> np.ndarray:
        s = seq.astype(np.float32).copy()
        s[..., 0] = np.log1p(s[..., 0])
        s[..., 7] = np.log1p(s[..., 7] * 1e3)
        return s

    def static(self, X: np.ndarray) -> np.ndarray:
        return ((self._slog(X) - self.mu) / self.sd).astype(np.float32)

    def sequence(self, seq: np.ndarray, lens: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        mask = (np.arange(seq.shape[1])[None, :] < lens[:, None]).astype(np.float32)
        s = (self._seq_raw(seq) - self.smu) / self.ssd * mask[..., None]
        ts = np.clip(seq[..., 7], 1e-6, 10.0).astype(np.float32) * mask + (1 - mask) * 1e-6
        return s.astype(np.float32), ts.astype(np.float32)

    def state(self) -> dict:
        return {"cols": self.cols, "mu": self.mu.tolist(), "sd": self.sd.tolist(),
                "smu": self.smu.tolist(), "ssd": self.ssd.tolist()}

    @classmethod
    def from_state(cls, s: dict) -> "Prep":
        return cls(s["cols"], *(np.asarray(s[k], dtype=np.float64) for k in ("mu", "sd", "smu", "ssd")))


# ---------------------------------------------------------------- sequence nets
class SeqNet(nn.Module):
    """kind: cfc | lstm | gru | cnn. Readout = [sequence state, static] -> logits."""

    def __init__(self, kind: str, n_ch: int, n_static: int, n_cls: int, units: int, seed: int) -> None:
        super().__init__()
        self.kind = kind
        if kind == "cfc":
            from ncps.torch import CfC
            from ncps.wirings import AutoNCP
            motor = max(4, units // 3)
            self.rnn = CfC(n_ch, AutoNCP(units, motor, seed=seed), batch_first=True, return_sequences=True)
            h = motor
        elif kind in ("lstm", "gru"):
            self.rnn = (nn.LSTM if kind == "lstm" else nn.GRU)(n_ch, units, batch_first=True)
            h = units
        elif kind == "cnn":
            self.rnn = nn.Sequential(nn.Conv1d(n_ch, units, 3, padding=1), nn.ReLU(),
                                     nn.Conv1d(units, units, 3, padding=1), nn.ReLU())
            h = units
        self.head = nn.Sequential(nn.Linear(h + n_static, 64), nn.ReLU(), nn.Linear(64, n_cls))

    def forward(self, seq, ts, lens, static):
        if self.kind == "cfc":
            # Same recurrence as ncps.torch.CfC.forward, but timespans passed as
            # [B, 1]: ncps 0.0.2 squeezes them to [B], which cannot broadcast
            # against [B, units] inside CfCCell (t_a * ts) for batched input.
            h = torch.zeros(seq.shape[0], self.rnn.state_size)
            outs = []
            for t in range(seq.shape[1]):
                h_out, h = self.rnn.rnn_cell(seq[:, t], h, ts[:, t:t + 1])
                outs.append(self.rnn.fc(h_out))
            out = torch.stack(outs, 1)
        elif self.kind == "cnn":
            out = self.rnn(seq.transpose(1, 2)).transpose(1, 2)
        else:
            out, _ = self.rnn(seq)
        if self.kind == "cnn":
            m = (torch.arange(seq.shape[1])[None, :] < lens[:, None]).float()[..., None]
            last = (out * m).sum(1) / m.sum(1).clamp(min=1)
        else:
            idx = (lens - 1).clamp(min=0).long()
            last = out[torch.arange(out.shape[0]), idx]
        return self.head(torch.cat([last, static], 1))


def train_seqnet(kind: str, prep: Prep, X, seq, lens, y, w, n_cls: int, Xv=None, seqv=None, lensv=None, yv=None,
                 log=print) -> SeqNet:
    mc = cfg()["models"]
    torch.manual_seed(mc["seed"])
    net = SeqNet(kind, seq.shape[2], X.shape[1], n_cls, mc["cfc_units"], mc["seed"])
    s, ts = prep.sequence(seq, lens)
    st = prep.static(X)
    T = [torch.from_numpy(a) for a in (s, ts, lens.astype(np.int64), st, y.astype(np.int64), w.astype(np.float32))]
    opt = torch.optim.Adam(net.parameters(), lr=mc["seq_lr"])
    bs = mc["seq_batch"]
    rng = np.random.default_rng(mc["seed"])
    n = len(y)
    for ep in range(mc["cfc_epochs"]):
        net.train()
        perm = rng.permutation(n)
        tot = 0.0
        for i in range(0, n, bs):
            b = torch.from_numpy(perm[i:i + bs])
            logits = net(T[0][b], T[1][b], T[2][b], T[3][b])
            loss = (nn.functional.cross_entropy(logits, T[4][b], reduction="none") * T[5][b]).mean()
            opt.zero_grad()
            loss.backward()
            opt.step()
            tot += float(loss) * len(b)
        msg = f"  [{kind}] epoch {ep + 1}/{mc['cfc_epochs']} loss {tot / n:.4f}"
        if Xv is not None:
            pv = seqnet_proba(net, prep, Xv, seqv, lensv)
            msg += f" val_acc {(pv.argmax(1) == yv).mean():.4f}"
        log(msg)
    net.eval()
    return net


@torch.no_grad()
def seqnet_proba(net: SeqNet, prep: Prep, X, seq, lens, bs: int = 4096) -> np.ndarray:
    net.eval()
    s, ts = prep.sequence(seq, lens)
    st = prep.static(X)
    out = []
    for i in range(0, len(X), bs):
        lg = net(torch.from_numpy(s[i:i + bs]), torch.from_numpy(ts[i:i + bs]),
                 torch.from_numpy(lens[i:i + bs].astype(np.int64)), torch.from_numpy(st[i:i + bs]))
        out.append(torch.softmax(lg, 1).numpy())
    return np.concatenate(out) if out else np.zeros((0, net.head[-1].out_features))


def integrated_gradients(net: SeqNet, prep: Prep, X, seq, lens, target: np.ndarray, steps: int,
                         bs: int = 512) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """IG on (sequence, static) inputs w.r.t. the target-class logit, zero
    baseline in normalised space. Returns (seq_attr [n,L,C], static_attr [n,F],
    completeness_gap [n] = |sum attr - (f(x) - f(baseline))|)."""
    s, ts = prep.sequence(seq, lens)
    st = prep.static(X)
    alphas = (torch.arange(steps, dtype=torch.float32) + 0.5) / steps
    sa_all, xa_all, gap_all = [], [], []
    for i in range(0, len(X), bs):
        S = torch.from_numpy(s[i:i + bs])
        TS = torch.from_numpy(ts[i:i + bs])
        L = torch.from_numpy(lens[i:i + bs].astype(np.int64))
        ST = torch.from_numpy(st[i:i + bs])
        tg = torch.from_numpy(target[i:i + bs].astype(np.int64))
        b = S.shape[0]
        a = alphas.repeat_interleave(b)
        Si = (S.repeat(steps, 1, 1) * a[:, None, None]).requires_grad_(True)
        STi = (ST.repeat(steps, 1) * a[:, None]).requires_grad_(True)
        lg = net(Si, TS.repeat(steps, 1), L.repeat(steps), STi)
        sel = lg.gather(1, tg.repeat(steps)[:, None]).sum()
        gS, gST = torch.autograd.grad(sel, (Si, STi))
        gS = gS.view(steps, b, *S.shape[1:]).mean(0)
        gST = gST.view(steps, b, ST.shape[1]).mean(0)
        sattr = (S * gS).numpy()
        xattr = (ST * gST).numpy()
        with torch.no_grad():
            fx = net(S, TS, L, ST).gather(1, tg[:, None])[:, 0]
            f0 = net(torch.zeros_like(S), TS, L, torch.zeros_like(ST)).gather(1, tg[:, None])[:, 0]
        gap = np.abs(sattr.sum((1, 2)) + xattr.sum(1) - (fx - f0).numpy())
        sa_all.append(sattr)
        xa_all.append(xattr)
        gap_all.append(gap)
    return np.concatenate(sa_all), np.concatenate(xa_all), np.concatenate(gap_all)


# ---------------------------------------------------------------- grouping
def group_matrix(cols: list[str]) -> np.ndarray:
    gm = feature_group_map()
    M = np.zeros((len(cols), len(GROUPS)), dtype=np.float64)
    for i, c in enumerate(cols):
        M[i, GIDX[gm[c]]] = 1.0
    return M


def seq_group_matrix() -> np.ndarray:
    return group_matrix(sequence_channels())


# ---------------------------------------------------------------- model set
class ModelSet:
    """Loads a trained model set from disk, verifying every file's SHA-256
    against meta.json (and, when given, the DB registry)."""

    FILES = {"gbdt": "gbdt.txt", "ebm": "ebm.pkl", "cfc": "cfc.pt", "prep": "prep.json", "ens": "ensemble.json"}

    def __init__(self, d: Path, expected: dict[str, str] | None = None) -> None:
        import lightgbm as lgb
        self.dir = Path(d)
        self.meta = json.loads((self.dir / "meta.json").read_text())
        exp = expected or self.meta["sha256"]
        for k, fn in self.FILES.items():
            got = sha256_file(self.dir / fn)
            if got != exp[k]:
                raise RuntimeError(f"model file {fn} sha256 mismatch: {got} != {exp[k]} - refusing to start")
        self.id = self.meta["model_set_id"]
        self.set_hash = self.meta["set_hash"]
        self.classes: list[int] = self.meta["classes"]          # local index -> global class id
        self.cols: list[str] = self.meta["cols"]
        self.gbdt = lgb.Booster(model_file=str(self.dir / "gbdt.txt"))
        with open(self.dir / "ebm.pkl", "rb") as f:
            self.ebm = pickle.load(f)
        self.prep = Prep.from_state(json.loads((self.dir / "prep.json").read_text()))
        ens = json.loads((self.dir / "ensemble.json").read_text())
        self.w = np.asarray(ens["weights"])
        self.temp = float(ens["temperature"])
        self.cfc = SeqNet("cfc", len(sequence_channels()), len(self.cols), len(self.classes),
                          cfg()["models"]["cfc_units"], cfg()["models"]["seed"])
        self.cfc.load_state_dict(torch.load(self.dir / "cfc.pt", weights_only=True))
        self.cfc.eval()
        self.G = group_matrix(self.cols)
        self.SG = seq_group_matrix()
        self.ebm_term_groups = self._ebm_term_groups()

    def _ebm_term_groups(self) -> np.ndarray:
        gm = feature_group_map()
        T = np.zeros((len(self.ebm.term_features_), len(GROUPS)))
        for t, feats in enumerate(self.ebm.term_features_):
            for fi in feats:
                T[t, GIDX[gm[self.cols[fi]]]] += 1.0 / len(feats)
        return T

    def select(self, X_full: np.ndarray, full_cols: list[str]) -> np.ndarray:
        idx = [full_cols.index(c) for c in self.cols]
        return X_full[:, idx]

    def proba(self, X, seq, lens) -> dict[str, np.ndarray]:
        pg = self.gbdt.predict(X)
        pe = self.ebm.predict_proba(X)
        pc = seqnet_proba(self.cfc, self.prep, X, seq, lens)
        return {"gbdt": pg, "ebm": pe, "cfc": pc, "ens": ensemble(np.stack([pg, pe, pc]), self.w, self.temp)}

    def attributions(self, X, seq, lens, target: np.ndarray, with_seq: bool = False) -> dict[str, np.ndarray]:
        K = len(self.classes)
        F = X.shape[1]
        n = len(X)
        contrib = np.asarray(self.gbdt.predict(X, pred_contrib=True)).reshape(n, K, F + 1)
        g_feat = contrib[np.arange(n), target, :F]
        e_terms = self.ebm.eval_terms(X)                         # (n, T, K)
        if e_terms.ndim == 2:
            e_terms = e_terms[..., None]
        e_t = e_terms[np.arange(n), :, target]
        sattr, xattr, gap = integrated_gradients(self.cfc, self.prep, X, seq, lens, target,
                                                 cfg()["models"]["ig_steps"])
        out = {"gbdt": g_feat @ self.G, "ebm": e_t @ self.ebm_term_groups,
               "cfc": xattr @ self.G + sattr.sum(1) @ self.SG, "ig_gap": gap, "gbdt_feat": g_feat,
               "cfc_static_feat": xattr}
        if with_seq:
            out["cfc_seq"] = sattr
        return out


def ensemble(P: np.ndarray, w: np.ndarray, temp: float) -> np.ndarray:
    """P: [3, n, K] model probabilities -> temperature-scaled weighted mixture."""
    p = np.tensordot(w, P, axes=1)
    z = np.log(np.clip(p, 1e-12, 1)) / temp
    z -= z.max(1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(1, keepdims=True)
