"""Attested ledger (Invention 4).

entry_hash = SHA-256(prev_hash || canonical_json(payload)); seq is gapless.
Batches (batch_size entries or batch_max_seconds) are sealed into a Merkle
tree (SHA-256, duplicate-last for odd levels - PROPOSED); the signed message
is canonical {root, from_seq, to_seq, model_set, ruleset_sha, pcr_value};
a TPM quote over the measurement PCR uses nonce = root.
canonical_json: sorted keys, no whitespace, UTF-8 (RFC 8785-like - PROPOSED;
floats use Python's shortest round-trip repr).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import tpm
from .config import cfg
from .db import connect, now

GENESIS = "0" * 64


def canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def entry_hash(prev: str, payload_canon: bytes) -> str:
    return hashlib.sha256(bytes.fromhex(prev) + payload_canon).hexdigest()


def merkle_root(hashes: list[str]) -> str:
    level = [bytes.fromhex(h) for h in hashes]
    if not level:
        return GENESIS
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def batch_message(root: str, a: int, b: int, model_set: str, ruleset_sha: str, pcr_value: str) -> bytes:
    return canon({"root": root, "from_seq": a, "to_seq": b, "model_set": model_set, "ruleset_sha": ruleset_sha,
                  "pcr_value": pcr_value})


class Ledger:
    """Single writer. Thread-safe append; batches sealed inline."""

    KEY_NAME = "ledger_ed25519"

    def __init__(self, model_set_id: str = "", ruleset_sha: str = GENESIS, con=None) -> None:
        lc = cfg()["ledger"]
        self.batch_size, self.batch_s = lc["batch_size"], lc["batch_max_seconds"]
        # share the caller's connection: a second writer connection would block on the
        # caller's open write transaction
        self.con = con or connect()
        self.lock = threading.Lock()
        self.model_set_id, self.ruleset_sha = model_set_id, ruleset_sha
        tpm.ensure_swtpm()
        tpm.ensure_keys()
        self.key, self.key_id = self._load_key()
        last = self.con.execute("SELECT seq, entry_hash FROM ledger_entries ORDER BY seq DESC LIMIT 1").fetchone()
        self.seq, self.prev = (last["seq"], last["entry_hash"]) if last else (0, GENESIS)
        self.last_batch_t = time.monotonic()
        self.tpm_label = cfg()["environment"]["tpm_label"]

    def _load_key(self) -> tuple[Ed25519PrivateKey, int]:
        row = self.con.execute("SELECT id, pubkey_hex FROM signing_keys ORDER BY id DESC LIMIT 1").fetchone()
        sealed = tpm.tpm_dir() / f"{self.KEY_NAME}.priv"
        if row and sealed.exists():
            raw = tpm.unseal(self.KEY_NAME)
            k = Ed25519PrivateKey.from_private_bytes(raw)
            pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
            if pub != row["pubkey_hex"]:
                raise RuntimeError("unsealed ledger key does not match registered public key")
            return k, row["id"]
        k = Ed25519PrivateKey.generate()
        raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                              serialization.NoEncryption())
        tpm.seal(raw, self.KEY_NAME)
        del raw
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        cur = self.con.execute("INSERT INTO signing_keys (created_at, pubkey_hex, protection, sealed_path) "
                               "VALUES (?,?,?,?)", (now(), pub, "Ed25519 private key sealed as TPM2 sealed-data "
                               "object under persistent SRK 0x81000001 of swtpm (software TPM 2.0)",
                               str(tpm.tpm_dir() / f"{self.KEY_NAME}.priv")))
        self.con.commit()
        return k, cur.lastrowid

    # ---- measurements -----------------------------------------------------
    def measure(self, what: str, digest_hex: str, ref: str) -> str:
        with self.lock:
            after = tpm.pcr_extend(digest_hex)
            self.con.execute("INSERT INTO pcr_events (created_at, pcr_index, digest, what, ref, pcr_after) "
                             "VALUES (?,?,?,?,?,?)", (now(), tpm.pcr_index(), digest_hex, what, ref, after))
            self.con.commit()
            self._append_locked("pcr_extend", ref, {"what": what, "digest": digest_hex, "pcr_after": after})
            return after

    def reset_measurements(self) -> None:
        with self.lock:
            tpm.pcr_reset()
            v = tpm.pcr_read()
            self.con.execute("INSERT INTO pcr_events (created_at, pcr_index, digest, what, ref, pcr_after) "
                             "VALUES (?,?,?,?,?,?)", (now(), tpm.pcr_index(), "", "reset", "brain-start", v))
            self.con.commit()

    # ---- entries ------------------------------------------------------------
    def append(self, kind: str, ref: str, payload: dict) -> int:
        with self.lock:
            return self._append_locked(kind, ref, payload)

    def _append_locked(self, kind: str, ref: str, payload: dict) -> int:
        body = {"kind": kind, "ref": ref, "ts": now(), "data": payload}
        c = canon(body)
        h = entry_hash(self.prev, c)
        self.seq += 1
        self.con.execute("INSERT INTO ledger_entries (seq, created_at, kind, ref, payload, prev_hash, entry_hash) "
                         "VALUES (?,?,?,?,?,?,?)", (self.seq, body["ts"], kind, ref, c.decode(), self.prev, h))
        self.prev = h
        self.con.commit()
        if (self.seq - self._last_batched()) >= self.batch_size:
            self._seal_locked()
        return self.seq

    def _last_batched(self) -> int:
        r = self.con.execute("SELECT MAX(to_seq) m FROM merkle_batches").fetchone()
        return r["m"] or 0

    def maybe_seal(self) -> None:
        with self.lock:
            if time.monotonic() - self.last_batch_t >= self.batch_s and self.seq > self._last_batched():
                self._seal_locked()

    def seal_now(self) -> None:
        with self.lock:
            if self.seq > self._last_batched():
                self._seal_locked()

    def _seal_locked(self) -> None:
        a = self._last_batched() + 1
        b = self.seq
        hs = [r["entry_hash"] for r in self.con.execute(
            "SELECT entry_hash FROM ledger_entries WHERE seq BETWEEN ? AND ? ORDER BY seq", (a, b))]
        root = merkle_root(hs)
        pcr_value = tpm.pcr_read()
        msg = batch_message(root, a, b, self.model_set_id, self.ruleset_sha, pcr_value)
        sig = self.key.sign(msg).hex()
        bid = (self.con.execute("SELECT MAX(id) m FROM merkle_batches").fetchone()["m"] or 0) + 1
        q = tpm.quote(root, f"batch{bid}")
        self.con.execute("INSERT INTO merkle_batches VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (bid, now(), a, b, root, sig, self.key_id, json.dumps(q), self.model_set_id,
                          self.ruleset_sha))
        self.con.execute("UPDATE ledger_entries SET batch_id=? WHERE seq BETWEEN ? AND ?", (bid, a, b))
        self.con.commit()
        self.last_batch_t = time.monotonic()


def public_key(con, key_id: int) -> Ed25519PublicKey:
    r = con.execute("SELECT pubkey_hex FROM signing_keys WHERE id=?", (key_id,)).fetchone()
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(r["pubkey_hex"]))
