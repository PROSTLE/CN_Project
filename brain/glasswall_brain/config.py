"""Single source of configuration: config/*.yaml + learned values from DB.

LEARNED keys are null in config/glasswall.yaml and are filled from the active
config_versions row (written by scripts/calibrate.py). `learned()` raises if
any is missing, so the engine refuses to decide without calibration.
"""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
LEARNED_KEYS = [("ecs", "k"), ("ecs", "alpha"), ("decision", "tau_lo"), ("decision", "tau_hi"),
                ("rules", "min_agreement"), ("rules", "max_fpr")]


@lru_cache
def cfg() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "config/glasswall.yaml").read_text())


@lru_cache
def features_cfg() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "config/features.yaml").read_text())


@lru_cache
def scenarios_cfg() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "config/scenarios.yaml").read_text())


def config_sha() -> str:
    h = hashlib.sha256()
    for f in ("glasswall.yaml", "features.yaml", "scenarios.yaml"):
        h.update((ROOT / "config" / f).read_bytes())
    return h.hexdigest()


def path(key: str) -> Path:
    """Configured path; env GW_PATH_<KEY> overrides (used only for isolated smoke tests)."""
    import os
    p = Path(os.environ.get(f"GW_PATH_{key.upper()}", cfg()["paths"][key]))
    if key.endswith("_dir"):
        p.mkdir(parents=True, exist_ok=True)
    return p


def class_names() -> list[str]:
    return [c["name"] for c in cfg()["classes"]]


def attack_class_ids() -> set[int]:
    return {i for i, c in enumerate(cfg()["classes"]) if c["attack"]}


def groups() -> dict[str, str]:
    return features_cfg()["groups"]


def group_ids() -> list[str]:
    return list(groups())


def model_feature_names() -> list[str]:
    """Static model input (flow + kernel snapshot + context). No IP/port."""
    f = features_cfg()
    return ([x["name"] for x in f["flow_features"]] + [x["name"] for x in f["kernel_features"]]
            + [x["name"] for x in f["context_features"]])


def feature_group_map() -> dict[str, str]:
    f = features_cfg()
    out = {}
    for sect in ("flow_features", "kernel_features", "context_features", "sequence_channels"):
        for x in f[sect]:
            out[x["name"]] = x["group"]
    return out


def kernel_features() -> list[dict[str, Any]]:
    return features_cfg()["kernel_features"]


def sequence_channels() -> list[str]:
    return [x["name"] for x in features_cfg()["sequence_channels"]]


class MissingLearned(RuntimeError):
    pass


def learned(db=None) -> dict[str, Any]:
    """Active learned values with provenance; raises MissingLearned."""
    from . import db as dbm
    con = db or dbm.connect()
    row = con.execute("SELECT id, values_json, source_run_id, created_at FROM config_versions "
                      "WHERE active=1 ORDER BY id DESC LIMIT 1").fetchone()
    if row is None:
        raise MissingLearned("no active config_version - run scripts/calibrate.py")
    vals = json.loads(row["values_json"])
    missing = [f"{a}.{b}" for a, b in LEARNED_KEYS if vals.get(a, {}).get(b) is None]
    if missing:
        raise MissingLearned(f"learned keys missing in config_version {row['id']}: {missing}")
    vals["_config_version_id"] = row["id"]
    vals["_source_run_id"] = row["source_run_id"]
    return vals
