"""E5 - ledger tamper detection, TPM quote verification, verify time.

Works on COPIES of the real ledger database (the live one is never touched).
For each tamper kind and trial, a fresh copy is modified the way an attacker
with file access would (append-only triggers dropped) and verified.

  python ml/experiments/e5.py [trials_per_kind]
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
import time
import uuid
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "brain"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))
from glasswall_brain import db as dbm  # noqa: E402
from glasswall_brain.config import cfg, path  # noqa: E402
from glasswall_brain.ledger import GENESIS, canon, entry_hash  # noqa: E402
from ml.eval.metrics import md_table  # noqa: E402
from verify_ledger import verify  # noqa: E402

KINDS = ["edit_payload", "delete_entry", "reorder_entries", "edit_and_rechain", "forge_quote_nonce", "edit_pcr_event"]


def open_rw(p: Path) -> sqlite3.Connection:
    c = sqlite3.connect(p)
    c.row_factory = sqlite3.Row
    for t in dbm.APPEND_ONLY:
        c.execute(f"DROP TRIGGER IF EXISTS {t}_no_update")
        c.execute(f"DROP TRIGGER IF EXISTS {t}_no_delete")
    return c


def tamper(p: Path, kind: str, rng: np.random.Generator) -> int | None:
    c = open_rw(p)
    sealed = c.execute("SELECT MAX(to_seq) m FROM merkle_batches").fetchone()["m"] or 0
    if sealed < 3:
        raise SystemExit("ledger has too few sealed entries for E5 - run the brain first")
    s = int(rng.integers(2, sealed))
    if kind == "edit_payload":
        r = c.execute("SELECT payload FROM ledger_entries WHERE seq=?", (s,)).fetchone()
        p_ = json.loads(r["payload"])
        p_["ts"] = p_["ts"] + 1.0
        c.execute("UPDATE ledger_entries SET payload=? WHERE seq=?", (canon(p_).decode(), s))
    elif kind == "delete_entry":
        c.execute("DELETE FROM ledger_entries WHERE seq=?", (s,))
    elif kind == "reorder_entries":
        a = c.execute("SELECT payload FROM ledger_entries WHERE seq=?", (s,)).fetchone()["payload"]
        b = c.execute("SELECT payload FROM ledger_entries WHERE seq=?", (s + 1,)).fetchone()["payload"]
        c.execute("UPDATE ledger_entries SET payload=? WHERE seq=?", (b, s))
        c.execute("UPDATE ledger_entries SET payload=? WHERE seq=?", (a, s + 1))
    elif kind == "edit_and_rechain":
        # strongest file-level attacker: edit, then recompute every later hash so the
        # chain itself is consistent; only the signed Merkle roots can catch this
        r = c.execute("SELECT payload FROM ledger_entries WHERE seq=?", (s,)).fetchone()
        p_ = json.loads(r["payload"])
        p_["ts"] = p_["ts"] + 1.0
        c.execute("UPDATE ledger_entries SET payload=? WHERE seq=?", (canon(p_).decode(), s))
        prev = c.execute("SELECT entry_hash FROM ledger_entries WHERE seq=?", (s - 1,)).fetchone()["entry_hash"]
        for row in c.execute("SELECT seq, payload FROM ledger_entries WHERE seq>=? ORDER BY seq", (s,)).fetchall():
            h = entry_hash(prev, row["payload"].encode())
            c.execute("UPDATE ledger_entries SET prev_hash=?, entry_hash=? WHERE seq=?", (prev, h, row["seq"]))
            prev = h
    elif kind == "forge_quote_nonce":
        b = c.execute("SELECT id, quote_json FROM merkle_batches ORDER BY RANDOM() LIMIT 1").fetchone()
        q = json.loads(b["quote_json"])
        q["nonce"] = hashlib.sha256(q["nonce"].encode()).hexdigest()
        c.execute("UPDATE merkle_batches SET quote_json=? WHERE id=?", (json.dumps(q), b["id"]))
        s = None
    elif kind == "edit_pcr_event":
        e = c.execute("SELECT id FROM pcr_events WHERE what != 'reset' ORDER BY RANDOM() LIMIT 1").fetchone()
        c.execute("UPDATE pcr_events SET digest=? WHERE id=?", (hashlib.sha256(b"forged").hexdigest(), e["id"]))
        s = None
    c.commit()
    c.close()
    return s


def main() -> None:
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    rng = np.random.default_rng(cfg()["models"]["seed"])
    live = path("db_file")
    tmp = Path(tempfile.mkdtemp(prefix="gw_e5_"))
    base = tmp / "base.db"
    src = sqlite3.connect(live)
    dst = sqlite3.connect(base)
    src.backup(dst)
    src.close()
    dst.execute("PRAGMA journal_mode=DELETE")   # no -wal side file to leak between trials
    dst.close()
    clean = verify(str(base), quotes=True)
    if not clean["ok"]:
        raise SystemExit(f"live ledger copy does not verify cleanly: {clean}")
    res = {"clean": clean, "kinds": {}}
    for kind in KINDS:
        rows = []
        for _ in range(trials):
            p = tmp / f"{kind}.db"
            for side in (p, Path(f"{p}-wal"), Path(f"{p}-shm")):
                side.unlink(missing_ok=True)
            shutil.copy(base, p)
            s = tamper(p, kind, rng)
            needs_quote = kind in ("forge_quote_nonce", "edit_pcr_event")
            r = verify(str(p), quotes=needs_quote)
            loc_ok = None if s is None or r["first_bad_seq"] is None else (r["first_bad_seq"] == s)
            rows.append({"detected": not r["ok"], "first_bad_seq": r["first_bad_seq"], "tampered_seq": s,
                         "located": loc_ok, "kind_reported": r["kind"], "seconds": r["seconds"]})
        det = np.mean([x["detected"] for x in rows])
        locs = [x["located"] for x in rows if x["located"] is not None]
        res["kinds"][kind] = {"trials": trials, "detection_rate": float(det),
                              "located_exact_rate": float(np.mean(locs)) if locs else None,
                              "reported_kinds": sorted({x["kind_reported"] for x in rows if x["kind_reported"]}),
                              "verify_s_mean": float(np.mean([x["seconds"] for x in rows]))}
    shutil.rmtree(tmp, ignore_errors=True)
    rid = f"E5-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
    d = path("evidence_dir") / rid
    d.mkdir(parents=True, exist_ok=True)
    f = lambda v: "n/a" if v is None else f"{v:.4f}"  # noqa: E731
    md = [f"# E5 - ledger tamper detection ({rid})", "",
          f"Copy of the live ledger: {clean['entries']} entries, {clean['batches']} signed Merkle batches, "
          f"{clean['quotes_checked']} TPM quotes ({cfg()['environment']['tpm_label']}). Clean full verification "
          f"(chain + Merkle + Ed25519 + tpm2_checkquote + PCR replay): {'OK' if clean['ok'] else 'FAILED'} in "
          f"{clean['seconds']:.3f} s.", "",
          md_table(["tamper", "trials", "detected", "first bad seq = tampered seq", "reported as", "verify s (mean)"],
                   [[k, v["trials"], f(v["detection_rate"]), f(v["located_exact_rate"]), ", ".join(v["reported_kinds"]),
                     f(v["verify_s_mean"])] for k, v in res["kinds"].items()]),
          "", "Tamper trials without TPM checks run chain/Merkle/signature verification only (quotes are verified "
          "for the quote and PCR-log tamper kinds)."]
    (d / "e5.md").write_text("\n".join(md))
    (d / "e5.json").write_text(json.dumps(res, indent=2, default=float))
    con = dbm.connect()
    dbm.record_experiment(con, rid, "E5 ledger tamper detection", res, str(d), dataset="live ledger copy")
    print("\n".join(md))


if __name__ == "__main__":
    main()
