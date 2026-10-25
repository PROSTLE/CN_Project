"""SQLite persistence (WAL). Schema follows docs/database_schema.txt, reduced
to what this build uses. PROPOSED: SQLite instead of Postgres (no Docker on
this host); append-only ledger tables are enforced with triggers.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .config import cfg, class_names, features_cfg, groups

SCHEMA = """
CREATE TABLE IF NOT EXISTS feature_groups (id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS features (name TEXT PRIMARY KEY, group_id TEXT NOT NULL REFERENCES feature_groups(id),
  section TEXT NOT NULL, kernel_realizable INTEGER NOT NULL, kernel_id INTEGER);
CREATE TABLE IF NOT EXISTS class_labels (id INTEGER PRIMARY KEY, name TEXT NOT NULL, is_attack INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS config_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
  values_json TEXT NOT NULL, source_run_id TEXT, config_sha TEXT, active INTEGER NOT NULL DEFAULT 0, notes TEXT);
CREATE TABLE IF NOT EXISTS model_sets (id TEXT PRIMARY KEY, created_at REAL NOT NULL, dataset TEXT, split_json TEXT,
  set_hash TEXT NOT NULL, meta_json TEXT, active INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS model_artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, model_set_id TEXT NOT NULL,
  kind TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, params_json TEXT, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS aci_state (class_id INTEGER PRIMARY KEY, alpha_t REAL NOT NULL, n_updates INTEGER NOT NULL,
  n_err INTEGER NOT NULL DEFAULT 0, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS attack_runs (run_id TEXT PRIMARY KEY, session TEXT, scenario TEXT, class TEXT, src_ip TEXT,
  label_rule TEXT, evasion INTEGER, t_start_ns INTEGER, t_end_ns INTEGER, cmd TEXT, exit_code INTEGER, created_at REAL);
CREATE TABLE IF NOT EXISTS flows (flow_id TEXT PRIMARY KEY, cli TEXT, srv TEXT, cport INTEGER, sport INTEGER,
  proto INTEGER, first_ts INTEGER, last_ts INTEGER, n_pkts INTEGER, last_decision_id INTEGER, created_at REAL);
CREATE TABLE IF NOT EXISTS decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id TEXT NOT NULL, checkpoint TEXT,
  ts_ns INTEGER, created_at REAL NOT NULL, model_set_id TEXT, config_version_id INTEGER, feature_hash TEXT,
  probs_json TEXT, pred_class INTEGER, conf_set_json TEXT, ecs REAL, ecs_pairs_json TEXT, attributions_json TEXT,
  topk_json TEXT, decision TEXT, row_id TEXT, adversarial INTEGER, kernel_action TEXT, enforce_json TEXT,
  latency_json TEXT, conformal_json TEXT, features_json TEXT, seq_attr_json TEXT, rule_id INTEGER,
  ledger_seq INTEGER, cli TEXT, srv TEXT, cport INTEGER, sport INTEGER, proto INTEGER, n_pkts INTEGER);
CREATE INDEX IF NOT EXISTS ix_dec_flow ON decisions(flow_id);
CREATE INDEX IF NOT EXISTS ix_dec_created ON decisions(created_at);
CREATE INDEX IF NOT EXISTS ix_dec_decision ON decisions(decision);
CREATE TABLE IF NOT EXISTS adversarial_signals (id INTEGER PRIMARY KEY AUTOINCREMENT, decision_id INTEGER,
  kind TEXT NOT NULL, value REAL, detail_json TEXT, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS offline_explanations (id INTEGER PRIMARY KEY AUTOINCREMENT, decision_id INTEGER, method TEXT,
  groups_json TEXT, disagreement REAL, seconds REAL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS narrations (decision_id INTEGER PRIMARY KEY, text TEXT, source TEXT, verified INTEGER,
  created_at REAL);
CREATE TABLE IF NOT EXISTS enforcement_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
  kind TEXT, key TEXT, action TEXT, ttl_ms INTEGER, ok INTEGER, latency_us INTEGER, reply TEXT, decision_id INTEGER);
CREATE TABLE IF NOT EXISTS enforcement_path_log (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
  path TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS review_tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, decision_id INTEGER NOT NULL,
  flow_id TEXT, cli TEXT, opened_at REAL NOT NULL, status TEXT NOT NULL, reason TEXT, adversarial INTEGER,
  verdict_class INTEGER, verdict_action TEXT, scope TEXT, notes TEXT, closed_at REAL, closed_by TEXT,
  time_to_decision_s REAL, n_decisions INTEGER DEFAULT 1, last_decision_id INTEGER);
CREATE INDEX IF NOT EXISTS ix_ticket_status ON review_tickets(status, cli);
CREATE TABLE IF NOT EXISTS labels (id INTEGER PRIMARY KEY AUTOINCREMENT, decision_id INTEGER, flow_id TEXT,
  class_id INTEGER, source TEXT, created_at REAL NOT NULL, aci_done INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS admin_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
  username TEXT, kind TEXT NOT NULL, payload_json TEXT, status TEXT NOT NULL DEFAULT 'pending', result TEXT,
  done_at REAL);
CREATE TABLE IF NOT EXISTS brain_status (id INTEGER PRIMARY KEY CHECK (id = 1), updated_at REAL, json TEXT);
CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL, status TEXT NOT NULL,
  class_id INTEGER, action TEXT, predicates_json TEXT, text TEXT, groups_json TEXT, cluster_json TEXT,
  fidelity_json TEXT, certificate_json TEXT, signature TEXT, canary_json TEXT, kernel_slot INTEGER,
  promoted_at REAL, expires_at REAL, ended_at REAL, reason TEXT, fp_json TEXT, certified INTEGER);
CREATE TABLE IF NOT EXISTS rule_provenance (rule_id INTEGER NOT NULL, decision_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rule_set_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
  rules_json TEXT NOT NULL, sha256 TEXT NOT NULL, active_index INTEGER, reason TEXT);
CREATE TABLE IF NOT EXISTS rollback_events (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER, created_at REAL,
  reason TEXT, fp_json TEXT);
CREATE TABLE IF NOT EXISTS ledger_entries (seq INTEGER PRIMARY KEY, created_at REAL NOT NULL, kind TEXT NOT NULL,
  ref TEXT, payload TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL, batch_id INTEGER);
CREATE TABLE IF NOT EXISTS merkle_batches (id INTEGER PRIMARY KEY, created_at REAL NOT NULL, from_seq INTEGER NOT NULL,
  to_seq INTEGER NOT NULL, root TEXT NOT NULL, signature TEXT NOT NULL, key_id INTEGER NOT NULL,
  quote_json TEXT, model_set_id TEXT, ruleset_sha TEXT);
CREATE TABLE IF NOT EXISTS pcr_events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
  pcr_index INTEGER NOT NULL, digest TEXT NOT NULL, what TEXT NOT NULL, ref TEXT, pcr_after TEXT);
CREATE TABLE IF NOT EXISTS signing_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
  pubkey_hex TEXT NOT NULL, protection TEXT NOT NULL, sealed_path TEXT);
CREATE TABLE IF NOT EXISTS verification_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
  ok INTEGER, entries INTEGER, batches INTEGER, first_bad_seq INTEGER, kind TEXT, seconds REAL, detail_json TEXT);
CREATE TABLE IF NOT EXISTS drift_events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
  stream TEXT, detail_json TEXT, action TEXT);
CREATE TABLE IF NOT EXISTS retrain_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
  reason TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS experiment_runs (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at REAL NOT NULL,
  dataset TEXT, split TEXT, seed INTEGER, config_sha TEXT, commit_hash TEXT, env TEXT, results_json TEXT,
  evidence_dir TEXT);
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, role TEXT NOT NULL, pw_hash TEXT NOT NULL, salt TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS ui_audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL, username TEXT,
  action TEXT, detail TEXT);
"""

APPEND_ONLY = ["ledger_entries", "merkle_batches", "pcr_events", "signing_keys"]


def triggers_sql() -> str:
    out = []
    for t in APPEND_ONLY:
        out.append(f"CREATE TRIGGER IF NOT EXISTS {t}_no_update BEFORE UPDATE ON {t} "
                   f"BEGIN SELECT RAISE(ABORT, '{t} is append-only'); END;")
        out.append(f"CREATE TRIGGER IF NOT EXISTS {t}_no_delete BEFORE DELETE ON {t} "
                   f"BEGIN SELECT RAISE(ABORT, '{t} is append-only'); END;")
    # batch_id is filled exactly once when the entry is sealed into a Merkle batch
    out[0] = ("CREATE TRIGGER IF NOT EXISTS ledger_entries_no_update BEFORE UPDATE ON ledger_entries "
              "WHEN NOT (OLD.batch_id IS NULL AND NEW.batch_id IS NOT NULL AND OLD.payload = NEW.payload "
              "AND OLD.entry_hash = NEW.entry_hash AND OLD.prev_hash = NEW.prev_hash AND OLD.seq = NEW.seq "
              "AND OLD.kind = NEW.kind AND OLD.created_at = NEW.created_at AND OLD.ref IS NEW.ref) "
              "BEGIN SELECT RAISE(ABORT, 'ledger_entries is append-only'); END;")
    return "\n".join(out)


def connect(path: str | Path | None = None, readonly: bool = False) -> sqlite3.Connection:
    from .config import path as cpath
    p = Path(path or cpath("db_file"))
    p.parent.mkdir(parents=True, exist_ok=True)
    if readonly:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=30, check_same_thread=False)
    else:
        con = sqlite3.connect(p, timeout=30, check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
    con.row_factory = sqlite3.Row
    return con


def init(con: sqlite3.Connection | None = None) -> sqlite3.Connection:
    con = con or connect()
    con.executescript(SCHEMA)
    con.executescript(triggers_sql())
    f = features_cfg()
    con.executemany("INSERT OR REPLACE INTO feature_groups VALUES (?,?)", list(groups().items()))
    rows = []
    for sect in ("flow_features", "kernel_features", "context_features", "sequence_channels"):
        for x in f[sect]:
            rows.append((x["name"], x["group"], sect, int(sect == "kernel_features"), x.get("id")))
    con.executemany("INSERT OR REPLACE INTO features VALUES (?,?,?,?,?)", rows)
    con.executemany("INSERT OR REPLACE INTO class_labels VALUES (?,?,?)",
                    [(i, c["name"], int(c["attack"])) for i, c in enumerate(cfg()["classes"])])
    con.commit()
    return con


def now() -> float:
    return time.time()


def jdump(o) -> str:
    return json.dumps(o, separators=(",", ":"), default=float)


def record_experiment(con: sqlite3.Connection, run_id: str, name: str, results: dict, evidence_dir: str,
                      dataset: str = "", split: str = "", seed: int | None = None) -> None:
    from .config import config_sha
    con.execute("INSERT OR REPLACE INTO experiment_runs VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, name, now(), dataset, split, seed if seed is not None else cfg()["models"]["seed"],
                 config_sha(), "no-git (repo not under version control)", cfg()["environment"]["label"],
                 jdump(results), evidence_dir))
    con.commit()


__all__ = ["connect", "init", "now", "jdump", "record_experiment", "class_names"]
