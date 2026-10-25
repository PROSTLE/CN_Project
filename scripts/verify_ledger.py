"""Verify the GLASSWALL ledger: hash chain, gapless seq, Merkle roots, Ed25519
batch signatures, TPM quotes (tpm2_checkquote) and PCR replay of pcr_events.

  python scripts/verify_ledger.py [--db PATH] [--from N] [--to M] [--no-quote] [--json]
Exit code 0 = intact, 1 = tampering detected (first bad seq + kind printed).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "brain"))
from glasswall_brain import tpm  # noqa: E402
from glasswall_brain.db import connect  # noqa: E402
from glasswall_brain.ledger import GENESIS, batch_message, entry_hash, merkle_root, public_key  # noqa: E402


def pcr_replay(con, upto_ts: float) -> str | None:
    """Expected PCR value at time upto_ts from the measurement log (since last reset)."""
    evs = con.execute("SELECT what, digest, created_at FROM pcr_events WHERE created_at <= ? ORDER BY id",
                      (upto_ts,)).fetchall()
    v = None
    for e in evs:
        if e["what"] == "reset":
            v = "0" * 64
        elif v is not None:
            v = hashlib.sha256(bytes.fromhex(v) + bytes.fromhex(e["digest"])).hexdigest()
    return v


def verify(db: str | None, a: int | None = None, b: int | None = None, quotes: bool = True) -> dict:
    t0 = time.perf_counter()
    con = connect(db, readonly=True) if db else connect(readonly=True)
    res = {"ok": True, "first_bad_seq": None, "kind": None, "entries": 0, "batches": 0, "quotes_checked": 0,
           "detail": ""}

    def fail(seq, kind, detail):
        if res["ok"]:
            res.update(ok=False, first_bad_seq=seq, kind=kind, detail=detail)

    rows = con.execute("SELECT seq, payload, prev_hash, entry_hash, batch_id FROM ledger_entries ORDER BY rowid").fetchall()
    recomputed: dict[int, str] = {}
    prev, expect = GENESIS, 1
    for r in rows:
        res["entries"] += 1
        if r["seq"] != expect:
            fail(expect, "delete" if r["seq"] > expect else "reorder",
                 f"expected seq {expect}, found {r['seq']}")
            expect = r["seq"]
        if r["prev_hash"] != prev:
            fail(r["seq"], "chain-link", "prev_hash does not match previous entry_hash")
        h = entry_hash(prev, r["payload"].encode())
        if h != r["entry_hash"]:
            fail(r["seq"], "edit", "entry_hash does not match payload")
        recomputed[r["seq"]] = h
        prev = r["entry_hash"]
        expect += 1

    batches = con.execute("SELECT * FROM merkle_batches ORDER BY id").fetchall()
    tmp = Path(tempfile.mkdtemp(prefix="gwverify"))
    for bt in batches:
        if a is not None and bt["to_seq"] < a or b is not None and bt["from_seq"] > b:
            continue
        res["batches"] += 1
        hs = [recomputed.get(s) for s in range(bt["from_seq"], bt["to_seq"] + 1)]
        if any(h is None for h in hs):
            missing = next(s for s, h in zip(range(bt["from_seq"], bt["to_seq"] + 1), hs) if h is None)
            fail(missing, "delete", f"batch {bt['id']} covers missing seq {missing}")
            continue
        root = merkle_root(hs)
        if root != bt["root"]:
            # locate first entry whose recomputed hash differs from the stored one
            first = next((s for s in range(bt["from_seq"], bt["to_seq"] + 1)
                          if con.execute("SELECT entry_hash FROM ledger_entries WHERE seq=?", (s,)).fetchone()
                          ["entry_hash"] != recomputed[s]), bt["from_seq"])
            fail(first, "merkle-root", f"batch {bt['id']} root mismatch (entries rewritten after signing)")
        q = json.loads(bt["quote_json"]) if bt["quote_json"] else None
        pcr_value = q["pcr_value"] if q else ""
        msg = batch_message(bt["root"], bt["from_seq"], bt["to_seq"], bt["model_set_id"] or "",
                            bt["ruleset_sha"] or GENESIS, pcr_value)
        try:
            public_key(con, bt["key_id"]).verify(bytes.fromhex(bt["signature"]), msg)
        except Exception:
            fail(bt["from_seq"], "signature", f"batch {bt['id']} Ed25519 signature invalid")
        if quotes and q:
            ok, out = tpm.check_quote(q, tmp / f"b{bt['id']}")
            res["quotes_checked"] += 1
            if not ok:
                fail(bt["from_seq"], "tpm-quote", f"batch {bt['id']}: {out}")
            if q["nonce"] != bt["root"]:
                fail(bt["from_seq"], "tpm-quote", f"batch {bt['id']} quote nonce != root")
            exp = pcr_replay(con, bt["created_at"])
            if exp is not None and exp != q["pcr_value"]:
                fail(bt["from_seq"], "pcr-replay", f"batch {bt['id']} PCR {q['pcr_value'][:16]} != replay {exp[:16]}")
    res["seconds"] = time.perf_counter() - t0
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db")
    ap.add_argument("--from", dest="a", type=int)
    ap.add_argument("--to", dest="b", type=int)
    ap.add_argument("--no-quote", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--record", action="store_true", help="store a verification_runs row")
    x = ap.parse_args()
    r = verify(x.db, x.a, x.b, not x.no_quote)
    if x.record:
        from glasswall_brain.db import now
        con = connect(x.db) if x.db else connect()
        con.execute("INSERT INTO verification_runs (created_at, ok, entries, batches, first_bad_seq, kind, seconds, "
                    "detail_json) VALUES (?,?,?,?,?,?,?,?)", (now(), int(r["ok"]), r["entries"], r["batches"],
                    r["first_bad_seq"], r["kind"], r["seconds"], json.dumps(r)))
        con.commit()
    if x.json:
        print(json.dumps(r))
    else:
        print(("LEDGER OK" if r["ok"] else f"TAMPERING DETECTED at seq {r['first_bad_seq']} ({r['kind']}): "
               f"{r['detail']}") + f"  [{r['entries']} entries, {r['batches']} batches, "
              f"{r['quotes_checked']} quotes, {r['seconds']:.3f}s]")
    sys.exit(0 if r["ok"] else 1)


if __name__ == "__main__":
    main()
