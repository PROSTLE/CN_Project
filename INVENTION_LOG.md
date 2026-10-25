# INVENTION LOG — DRAFT (CONFIDENTIAL)

Fill in names (who conceived / who reduced to practice) and confirm dates. Entries below describe what
was **implemented and run** in this repository; result numbers are in the referenced evidence folders
(never copy numbers here by hand).

| date | invention | what was reduced to practice | code | evidence | conceived by | implemented by |
|---|---|---|---|---|---|---|
| 2026-10-18/19 | 1 — Explanation Consensus Score | ECS over three structurally different hot-path explainers (exact TreeSHAP, EBM additive terms, CfC integrated gradients) mapped into 14 semantic groups; k and alpha learned on validation (grid, ROC-AUC correct-vs-wrong objective) | `brain/glasswall_brain/ecs.py`, `models.py`, `scripts/calibrate.py` | `evidence/calibrate_*`, `evidence/E1-*` | | |
| 2026-10-18/19 | 2 — Conformal + ECS tri-state | Mondrian split conformal + per-class ACI with delayed labels; decision table R1–R7 (R1 low ECS → QUARANTINE + adversarial flag); tau_lo/tau_hi learned for an FPR budget; QUARANTINE = in-kernel token-bucket rate limit + review ticket | `conformal.py`, `decision.py`, `main.py` | `evidence/E1-*`, `evidence/E2-*` | | |
| 2026-10-18/19 | 3 — Explanation-to-rule compiler | clusters of BLOCK/QUARANTINE decisions → shallow tree on kernel-realizable counters of the top attributed groups → integer predicates → fidelity certificate (Ed25519) → LOG_ONLY canary in kernel → atomic A/B array flip → TTL → FP monitor (kernel reports rule drops) → automatic rollback | `rules.py`, `datapath/bpf/glasswall.bpf.c` | `evidence/E3-*`, live rules table | | |
| 2026-10-18/19 | 4 — Attested ledger | hash chain + Merkle batches + Ed25519 root signatures; key sealed as TPM2 sealed-data object (swtpm); model-set, config and ruleset hashes extended into PCR 16; quote with nonce = Merkle root; verifier with PCR-log replay | `ledger.py`, `tpm.py`, `scripts/verify_ledger.py` | `evidence/E5-*` | | |
| 2026-10-18/19 | 5 — Manipulation / evasion detection | ECS-collapse flag, empty-set OOD signal, offline KernelSHAP/LIME vs hot-path agreement flag, Lipschitz probe; Slack-style scaffolding attack on offline LIME reproduced | `adversarial.py`, `ml/experiments/offline.py` | `evidence/E6-*` | | |

Open items for the patent agent: embodiments not built here (tc / nftables enforcers, hardware TPM,
Treelite-compiled GBDT, Go agent), and the honest-limitations list in `evidence/REPORT.md`.
