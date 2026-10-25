"""Unit tests: ECS math (hand-computed), decision rows R1-R7, conformal + ACI,
identity-feature exclusion, feature hashing. Synthetic fixtures only."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "brain"))
from glasswall_brain.conformal import ACI, Mondrian  # noqa: E402
from glasswall_brain.config import model_feature_names  # noqa: E402
from glasswall_brain.decision import decide  # noqa: E402
from glasswall_brain.ecs import ecs, topk_mask  # noqa: E402
from glasswall_brain.features import feature_hash  # noqa: E402

G = 14


def vec(d):
    v = np.zeros((1, G))
    for i, x in d.items():
        v[0, i] = x
    return v


def test_topk_excludes_zero_and_ties_stable():
    m = topk_mask(vec({0: 1.0, 3: -2.0}), 3)
    assert m[0].tolist() == [i in (0, 3) for i in range(G)]


def test_ecs_identical_sources_is_one():
    a = vec({0: 3, 1: -2, 2: 1})
    e, _ = ecs({"gbdt": a, "ebm": a, "cfc": a}, k=2, alpha=0.5)
    assert e[0] == pytest.approx(1.0)


def test_ecs_hand_computed():
    # top-2: gbdt {0,1}, ebm {0,2}, cfc {1,2}
    g = vec({0: 3, 1: 2, 2: 0.1})
    b = vec({0: 3, 2: -2, 1: 0.1})
    c = vec({1: -3, 2: -2, 0: 0.1})
    e, p = ecs({"gbdt": g, "ebm": b, "cfc": c}, k=2, alpha=0.5)
    # each pair: Jaccard 1/3; sign agree: gbdt-ebm share {0}: + vs + -> 1;
    # gbdt-cfc share {1}: + vs - -> 0; ebm-cfc share {2}: - vs - -> 1
    assert p["gbdt-ebm"]["jaccard"][0] == pytest.approx(1 / 3)
    assert p["gbdt-ebm"]["sign"][0] == 1.0
    assert p["gbdt-cfc"]["sign"][0] == 0.0
    assert p["ebm-cfc"]["sign"][0] == 1.0
    exp = np.mean([0.5 / 3 + 0.5 * 1, 0.5 / 3 + 0, 0.5 / 3 + 0.5 * 1])
    assert e[0] == pytest.approx(exp)


def test_ecs_disjoint_is_zero():
    e, _ = ecs({"gbdt": vec({0: 1}), "ebm": vec({1: 1}), "cfc": vec({2: 1})}, k=1, alpha=0.3)
    assert e[0] == 0.0


ATT, BEN = {1, 2, 3}, 0


@pytest.mark.parametrize("S,E,row,action,adv", [
    ({1}, 0.05, "R1", "QUARANTINE", True),
    (set(), 0.9, "R2", "QUARANTINE", False),
    ({0, 1}, 0.9, "R3", "QUARANTINE", False),
    ({1, 2}, 0.9, "R4", "BLOCK", False),
    ({0}, 0.9, "R5", "ALLOW", False),
    ({3}, 0.5, "R6", "QUARANTINE", False),
    ({0}, 0.5, "R7", "ALLOW_SHADOW", False),
    (set(), 0.05, "R1", "QUARANTINE", True),   # R1 first: "any S"
])
def test_decision_rows(S, E, row, action, adv):
    d = decide(S, E, 0.2, 0.8, ATT, BEN)
    assert (d.row, d.action, d.adversarial) == (row, action, adv)


def test_decision_requires_ordered_taus():
    with pytest.raises(ValueError):
        decide({0}, 0.5, 0.5, 0.5, ATT, BEN)


def test_mondrian_quantile_rank():
    m = Mondrian([0], {0: np.arange(1, 10) / 10})   # 9 scores 0.1..0.9
    # ceil((9+1)*0.8)=8 -> 8th smallest = 0.8
    assert m.quantile(0, 0.2) == pytest.approx(0.8)
    assert m.quantile(0, 0.05) == np.inf             # rank 10 > n
    assert m.quantile(0, 0.0) == np.inf


def test_mondrian_sets():
    m = Mondrian([0, 5], {0: np.array([0.1, 0.2, 0.3]), 5: np.array([0.1, 0.2, 0.3])})
    S = m.sets(np.array([[0.75, 0.25]]), {0: 0.5, 5: 0.5})   # q = 2nd smallest = 0.2
    assert S.tolist() == [[False, False]]
    S = m.sets(np.array([[0.85, 0.15]]), {0: 0.5, 5: 0.5})
    assert S.tolist() == [[True, False]]


def test_aci_update_direction_and_clip():
    a = ACI([0], alpha_target=0.1, gamma=0.5)
    a.update(0, covered=False)       # miss -> alpha decreases (wider sets)
    assert a.alpha[0] == 0.0         # 0.1 + 0.5 * (0.1 - 1) = -0.35 -> clipped to 0
    a2 = ACI([0], alpha_target=0.1, gamma=0.01)
    a2.update(0, covered=True)       # hit -> alpha increases
    assert a2.alpha[0] == pytest.approx(0.101)


def test_no_identity_features_in_model_input():
    banned = ("ip", "port", "addr", "cli", "srv", "sport", "dport", "cport")
    for f in model_feature_names():
        tok = f.split("_")
        assert not any(b in tok for b in banned), f


def test_feature_hash_changes_with_value():
    x = np.zeros(len(model_feature_names()), dtype=np.float32)
    h1 = feature_hash(x)
    x[0] = 1
    assert feature_hash(x) != h1 and len(h1) == 64
