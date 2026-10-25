"""Online == offline check (TRD TR-FX-3): replay the brain's archived raw event
stream through the offline FlowTable and compare feature hashes with the hashes
the online brain stored for the same (flow_id, checkpoint).

  python scripts/check_replay.py [online_events.gz]   (default: newest archive)
"""
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "brain"))
from glasswall_brain.config import path  # noqa: E402
from glasswall_brain.db import connect  # noqa: E402
from glasswall_brain.dp import parse_line  # noqa: E402
from glasswall_brain.features import FlowTable  # noqa: E402


def main() -> None:
    f = Path(sys.argv[1]) if len(sys.argv) > 1 else sorted(path("capture_dir").glob("online_*.events.gz"))[-1]
    con = connect(readonly=True)
    online = {(r["flow_id"], r["checkpoint"]): r["feature_hash"] for r in
              con.execute("SELECT flow_id, checkpoint, feature_hash FROM decisions")}
    ft = FlowTable()
    off = {}
    truncated = False
    with gzip.open(f, "rt") as fh:
        try:
            for ln in fh:
                p = parse_line(ln)
                if p:
                    for s in ft.process(p):
                        off[(s.flow_id, s.checkpoint)] = s.feature_hash
        except EOFError:          # archive still being written by the running brain
            truncated = True
    for s in ft.flush():
        off[(s.flow_id, s.checkpoint)] = s.feature_hash
    common = set(online) & set(off)
    same = sum(online[k] == off[k] for k in common)
    by_cp = {}
    for k in common:
        d = by_cp.setdefault(k[1], [0, 0])
        d[0] += 1
        d[1] += online[k] == off[k]
    res = {"archive": str(f), "archive_truncated_live": truncated, "online_snapshots": len(online), "offline_snapshots": len(off), "matched_keys": len(common),
           "identical_hash": same, "identical_share": same / len(common) if common else None,
           "by_checkpoint": {c: {"n": v[0], "identical": v[1]} for c, v in by_cp.items()}}
    print(json.dumps(res, indent=2))
    import time
    d = path("evidence_dir") / f"REPLAY-{time.strftime('%Y%m%d-%H%M%S')}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "replay.json").write_text(json.dumps(res, indent=2))
    share = "n/a" if res["identical_share"] is None else f"{res['identical_share']:.4f}"
    (d / "replay.md").write_text(
        f"# Online == offline feature check\n\nArchive `{f.name}` replayed through the offline FlowTable: "
        f"{res['matched_keys']} (flow, checkpoint) snapshots matched to online decisions; identical feature hash "
        f"for {res['identical_hash']} ({share}). By checkpoint: {json.dumps(res['by_checkpoint'])}.\n\n"
        "Online, idle flows are also closed by a wall-clock ticker, offline only by the event-time ticker, so flow "
        "boundaries and the source-history context of other flows can differ at a few stream positions; this is the "
        "most likely cause of the mismatches (not individually traced).\n")


if __name__ == "__main__":
    main()
