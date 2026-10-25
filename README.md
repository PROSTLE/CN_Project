# GLASSWALL — internal README (CONFIDENTIAL, do not publish before the provisional filing)

Explainable AI firewall: in-kernel XDP enforcement, three-model brain (GBDT/EBM/CfC) with group-level
explanations, Explanation Consensus Score, Mondrian conformal + ACI tri-state decisions, an
explanation-to-rule compiler with canary/rollback, and a TPM-attested ledger. Specs live in `docs/`.

Everything below runs inside **WSL2 Ubuntu as root** (`wsl -d Ubuntu -u root`). Docker is not used:
the lab is built from Linux network namespaces (`lab/topology.py`).

## Layout

| path | what |
|---|---|
| `datapath/bpf/glasswall.bpf.c` | XDP program: safety allow-list → flow → source → prefix → rule array (A/B, atomic flip); token-bucket rate limit; ring-buffer packet records |
| `datapath/agent/agent.c` | C + libbpf agent: attach xdpgeneric, events socket, control socket (SV/FV/PFX/RS/FLIP/RH/…), reaper |
| `brain/glasswall_brain/` | features (shared online/offline), models, ECS, conformal+ACI, decision table, rule compiler, ledger, TPM, adversarial, narrator, online loop (`main.py`) |
| `ml/` | dataset builder, training + baselines + ablations, metrics, experiments E1–E6 |
| `api/app/main.py` | FastAPI: REST + WebSocket + session auth/RBAC; serves the console |
| `ui/` | React + TypeScript console (Vite) |
| `lab/` | namespace topology, allow-listed scenario runner, benign/attack generators |
| `config/` | `glasswall.yaml` (all tunables; LEARNED keys null), `features.yaml`, `scenarios.yaml` |
| `scripts/` | `capture_session.sh`, `pipeline.sh`, `calibrate.py`, `verify_ledger.py`, `gw.sh`, `check_replay.py`, `create_user.py` |
| `evidence/` | every experiment's tables/logs (`superseded/` = runs replaced after a found flaw, kept for the record) |

## Run

```bash
cd /mnt/c/Lang/CN
make -C datapath                                   # BPF object + agent (config_gen.h from glasswall.yaml)
bash scripts/capture_session.sh train train2       # labelled lab capture (~17 min)
bash scripts/capture_session.sh evasion evasion1   # evasion capture (~4 min)
bash scripts/pipeline.sh all                       # datasets -> train -> calibrate (writes config_versions)
/opt/glasswall/venv/bin/python scripts/create_user.py admin admin
bash scripts/gw.sh start                           # lab + agent + brain + API on http://127.0.0.1:8000
/opt/glasswall/venv/bin/python -m pytest tests/
```

Experiments: `python ml/experiments/offline.py all` (E1, E2, E3, E6), `python ml/experiments/e5.py`
(needs a ledger, i.e. after a brain run), `python ml/experiments/e4.py` (brain stopped).

The brain refuses to start if any LEARNED value is missing, if a model file's SHA-256 does not match
the registry, or if the TPM (swtpm) is unavailable.
