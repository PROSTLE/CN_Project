"""Narrator verifier, canonical JSON, hash chain and Merkle unit tests (fixtures only)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "brain"))
from glasswall_brain.ledger import GENESIS, canon, entry_hash, merkle_root  # noqa: E402
from glasswall_brain.narrator import template, verify  # noqa: E402

FIXTURE = {"decision": "BLOCK", "row": "R4", "pred_name": "PortScan", "prob": 0.97, "set_names": ["PortScan"],
           "ecs": 0.81, "tau_lo": 0.2, "tau_hi": 0.6,
           "topk": {"gbdt": [["G5", 2.5], ["G1", 1.25]], "ebm": [["G5", 1.0]], "cfc": [["G1", 0.5]]}}


def test_template_passes_verifier():
    ok, bad = verify(template(FIXTURE), FIXTURE)
    assert ok, bad


def test_invented_number_rejected():
    ok, bad = verify("Blocked with 99.9% certainty because port fan-out was 4000.", FIXTURE)
    assert not ok and "4000" in bad


def test_invented_group_rejected():
    ok, bad = verify("Rate (G4) drove the decision with ECS 0.81.", FIXTURE)
    assert not ok and "G4" in bad


def test_invented_class_rejected():
    ok, bad = verify("This looks like DDoS.", FIXTURE)
    assert not ok and "DDoS" in bad


def test_canonical_json_is_order_independent():
    assert canon({"b": 1, "a": [1, 2]}) == canon({"a": [1, 2], "b": 1}) == b'{"a":[1,2],"b":1}'


def test_hash_chain_detects_edit():
    h1 = entry_hash(GENESIS, canon({"x": 1}))
    h2 = entry_hash(h1, canon({"x": 2}))
    assert entry_hash(GENESIS, canon({"x": 9})) != h1
    assert entry_hash(h1, canon({"x": 2})) == h2


def test_merkle_odd_duplicates_last():
    import hashlib
    a, b, c = (hashlib.sha256(x).hexdigest() for x in (b"a", b"b", b"c"))
    ab = hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).digest()
    cc = hashlib.sha256(bytes.fromhex(c) * 2).digest()
    assert merkle_root([a, b, c]) == hashlib.sha256(ab + cc).hexdigest()
    assert merkle_root([a]) == a
