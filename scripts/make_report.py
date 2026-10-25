"""Assemble evidence/REPORT.md from the newest evidence folder of each kind.
Numbers are copied from the experiment outputs only - nothing typed by hand.

  python scripts/make_report.py
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "brain"))
from glasswall_brain.config import cfg, path  # noqa: E402

EV = path("evidence_dir")
ORDER = [("train_", "metrics.md", "P1-P5 detection (temporal split)"), ("calibrate_", "calibration.md", "Calibration of LEARNED values"),
         ("E1-", "e1.md", "E1"), ("E2-", "e2.md", "E2"), ("E3-", "e3.md", "E3"), ("E4-", "e4.md", "E4"),
         ("E5-", "e5.md", "E5"), ("E6-", "e6.md", "E6"), ("ONLINE-", "online.md", "Online end-to-end run"),
         ("REPLAY-", "replay.md", "Online == offline feature check"), ("SMOKE-", "smoke.md", "Datapath smoke test")]

LIMITS = """## Honest limitations (read before quoting any number)

- **Lab data only.** Every result comes from our own WSL2 namespace lab (labels known by construction).
  No public dataset (CIC-IDS2017/2018, UNSW-NB15, ...) was used tonight, so there is **no cross-dataset
  result**; lab traffic is far more separable than real traffic, which is why detection scores are very
  high. They must not be presented as real-world accuracy.
- **Classes**: Botnet and Infiltration have no lab generator (not modelled). DDoS (spoofed-source SYN
  flood from one host) collapses to a single unique flow pattern after de-duplication, below the minimum
  Mondrian calibration support ceil((1-alpha)/alpha); it is not modelled. BruteForce has few flows (long
  multi-attempt SSH connections).
- **ECS calibration signal is weak**: validation contains very few wrong decisions, so the ROC-AUC
  objective used to pick k and alpha rests on a handful of errors (see Calibration).
- **WSL2 / xdpgeneric on veth**, virtualised: no line-rate claims. **swtpm** is a software TPM; the
  Ed25519 key is a TPM2 sealed-data object, not a TPM-resident signing key.
- Not built tonight: Docker/compose topology, Postgres/Redis (SQLite used), Go agent (C+libbpf used),
  tc/nftables enforcer fallbacks, Treelite compilation, LLM narrator (Ollama not installed -> template
  narrator with verifier), DiCE (single-feature counterfactual search instead), user-space drop baseline
  for E4, human study, Mamba/Transformer ablations.
- EBM trained with main effects only (pairwise interactions were >10x slower on this CPU).
- The ensemble-weight search on validation put all weight on GBDT; EBM and CfC contribute explanations (ECS)
  but not the ensemble probability.
- Online (live run) the brain falls behind under floods: event->decision latency p50 is seconds, although
  the per-snapshot compute is milliseconds (single Python process; batches queue during floods).
- Online benign impact was higher than offline: about 11% of benign-client decisions were QUARANTINE in the
  live run vs about 1% on the offline test split (see Online run). Not yet diagnosed.
- E6(b): the learned offline-disagreement threshold collapsed to 0 (many honest LIME runs already have zero
  agreement with the hot path), so it flags nothing; at tau_lo it flags 78% of manipulated vs 35% of honest
  LIME runs - a signal, not a clean detector.
- IG completeness gap (16 steps) has a heavy tail (p99 > 1 logit) - CfC attributions are approximate.
"""


def newest(prefix: str, fname: str):
    c = sorted([d for d in EV.glob(prefix + "*") if d.is_dir() and (d / fname).exists()])
    return c[-1] if c else None


def main() -> None:
    parts = [f"# GLASSWALL - results report", "",
             f"Generated {time.strftime('%Y-%m-%d %H:%M')} from `evidence/` by scripts/make_report.py. "
             f"Environment: {cfg()['environment']['label']}; {cfg()['environment']['tpm_label']}.", "",
             "Each section below is the verbatim output of the experiment named in its heading; the folder "
             "holds the raw JSON.", ""]
    missing = []
    for prefix, fname, title in ORDER:
        d = newest(prefix, fname)
        if d is None:
            missing.append(title)
            continue
        body = (d / fname).read_text()
        body = body.split("## Log")[0]          # training log stays in the folder
        parts += [f"---", f"<!-- source: evidence/{d.name}/{fname} -->", body.replace("\n# ", "\n## ", 1), ""]
    parts += ["---", LIMITS]
    if missing:
        parts += ["", "Not run / no evidence: " + ", ".join(missing)]
    (EV / "REPORT.md").write_text("\n".join(parts))
    print(f"wrote {EV / 'REPORT.md'}; missing: {missing}")


if __name__ == "__main__":
    main()
