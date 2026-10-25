"""Build a labelled snapshot dataset from a recorded lab capture.

Replays <capture>/events.gz through glasswall_brain.features.FlowTable (the
exact online code path) and labels every flow from attack_runs.jsonl
(labels by construction). Flows that match no run are left unlabelled and
dropped (counted in the manifest).

  python ml/data/build_dataset.py <capture_dir> <out_dir>
Outputs: snapshots.parquet (features + labels + identity meta for analysis
only), sequences.npy, seq_len.npy, manifest.json
"""
from __future__ import annotations

import bisect
import gzip
import json
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "brain"))
from glasswall_brain.config import cfg, class_names, scenarios_cfg  # noqa: E402
from glasswall_brain.dp import parse_line  # noqa: E402
from glasswall_brain.features import FEATS, SCHEMA_VERSION, FlowTable  # noqa: E402


class Labeler:
    def __init__(self, runs: list[dict]) -> None:
        lab = cfg()["lab"]
        self.hosts = {lab["attacker_ip"], lab["client_ip"], lab["victim_ip"]} | {
            ln["gw_ip"].split("/")[0] for ln in lab["links"]}
        self.grace = int(scenarios_cfg()["label_grace_s"] * 1e9)
        self.runs = sorted(runs, key=lambda r: r["t_start_ns"])
        self.starts = [r["t_start_ns"] for r in self.runs]

    def __call__(self, cli: str, first_ts: int) -> dict | None:
        i = bisect.bisect_right(self.starts, first_ts)
        best = None
        for r in self.runs[:i]:
            if first_ts > r["t_end_ns"] + self.grace:
                continue
            if r["label"] == "source" and cli != r["src_ip"]:
                continue
            if r["label"] == "spoofed" and cli in self.hosts:
                continue
            if best is None or r["t_start_ns"] > best["t_start_ns"]:
                best = r
        return best


def round_starts(runs: list[dict], cap: Path) -> list[int]:
    """Start time of each schedule round (runs are recorded in execution order;
    the schedule name is in schedule.log's first round header length)."""
    sched = [r for r in runs if r["scenario"] != "benign_client"]
    per_round = None
    log = cap / "schedule.log"
    if log.exists():
        first = next((ln for ln in log.read_text().splitlines() if ln.startswith("--- round")), "")
        if "[" in first:
            per_round = first.count("'") // 2
    if not per_round:
        return [sched[0]["t_start_ns"]] if sched else [0]
    return [sched[i]["t_start_ns"] for i in range(0, len(sched), per_round)]


def build(cap: Path, out: Path) -> dict:
    t0 = time.time()
    runs = [json.loads(x) for x in (cap / "attack_runs.jsonl").read_text().splitlines() if x.strip()]
    lab = Labeler(runs)
    rstarts = round_starts(runs, cap)
    ft = FlowTable()
    rows, seqs, lens = [], [], []
    unlabelled = Counter()
    n_events = bad = 0
    names = class_names()

    def emit(snaps) -> None:
        for s in snaps:
            r = lab(s.meta["cli"], s.meta["first_ts"])
            if r is None:
                unlabelled[s.checkpoint] += 1
                continue
            rows.append({"flow_id": s.flow_id, "checkpoint": s.checkpoint, "ts": s.ts,
                         "first_ts": s.meta["first_ts"], "label": r["class"],
                         "class_id": names.index(r["class"]), "run_id": r["run_id"],
                         "scenario": r["scenario"], "evasion": r["evasion"], "feature_hash": s.feature_hash,
                         "round": max(1, bisect.bisect_right(rstarts, s.meta["first_ts"])),
                         "cli": s.meta["cli"], "srv": s.meta["srv"], "cport": s.meta["cport"],
                         "sport": s.meta["sport"], "proto": s.meta["proto"], "n_pkts": s.meta["n_pkts"],
                         **{n: float(v) for n, v in zip(FEATS, s.x)}})
            seqs.append(s.seq)
            lens.append(s.seq_len)

    with gzip.open(cap / "events.gz", "rt") as f:
        for ln in f:
            p = parse_line(ln)
            if p is None:
                bad += 1
                continue
            n_events += 1
            emit(ft.process(p))
    emit(ft.tick(ft.now + 10**12))
    emit(ft.flush())
    out.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_parquet(out / "snapshots.parquet", index=False)
    np.save(out / "sequences.npy", np.stack(seqs) if seqs else np.zeros((0,)))
    np.save(out / "seq_len.npy", np.asarray(lens, dtype=np.int16))
    man = {"capture": str(cap), "schema_version": SCHEMA_VERSION, "events": n_events, "bad_lines": bad,
           "snapshots": len(df), "flows": int(df["flow_id"].nunique()) if len(df) else 0,
           "by_class_flows": df.groupby("label")["flow_id"].nunique().to_dict() if len(df) else {},
           "by_scenario_flows": df.groupby("scenario")["flow_id"].nunique().to_dict() if len(df) else {},
           "by_checkpoint": df["checkpoint"].value_counts().to_dict() if len(df) else {},
           "unlabelled_snapshots": dict(unlabelled), "runs": len(runs), "seconds": round(time.time() - t0, 1)}
    (out / "manifest.json").write_text(json.dumps(man, indent=2))
    return man


if __name__ == "__main__":
    print(json.dumps(build(Path(sys.argv[1]), Path(sys.argv[2])), indent=2))
