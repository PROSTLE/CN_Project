# GLASSWALL - results report

Generated 2026-10-18 19:50 from `evidence/` by scripts/make_report.py. Environment: WSL2 lab (network namespaces, xdpgeneric on veth); swtpm (software TPM 2.0) - demo, not hardware TPM.

Each section below is the verbatim output of the experiment named in its heading; the folder holds the raw JSON.

---
<!-- source: evidence/train_20261018-192542-de1bed/metrics.md -->
# Detection results (test split, temporal) - run 20261018-192542-de1bed

Environment: WSL2 lab (network namespaces, xdpgeneric on veth). Dataset: own lab capture (labels by construction).

| model | macro-F1 | PR-AUC (macro) | FPR @ recall 0.95 | accuracy |
|---|---|---|---|---|
| ensemble | 0.9907 | 0.9994 | 0.0000 | 0.9998 |
| gbdt | 0.9907 | 0.9994 | 0.0000 | 0.9998 |
| xgb | 0.9927 | 0.9992 | 0.0000 | 0.9995 |
| ebm | 0.9842 | 0.9884 | 0.0000 | 0.9995 |
| cfc | 0.9919 | 0.9941 | 0.0000 | 0.9988 |
| lstm | 0.9920 | 0.9958 | 0.0000 | 0.9989 |
| gru | 0.9917 | 0.9969 | 0.0000 | 0.9988 |
| cnn | 0.9945 | 0.9987 | 0.0000 | 0.9992 |
| rf | 0.9928 | 0.9899 | 0.0000 | 0.9996 |
| mlp | 0.9911 | 0.9898 | 0.0000 | 0.9984 |
| ablation_gbdt_with_identity | 0.9953 | 0.9999 | 0.0000 | 0.9998 |

## Per-class (ensemble)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| Benign | 0.9998 | 0.9996 | 0.9997 | 4455 |
| DoS | 0.9992 | 1.0000 | 0.9996 | 3642 |
| PortScan | 1.0000 | 1.0000 | 1.0000 | 2003 |
| BruteForce | 0.9767 | 0.9333 | 0.9545 | 45 |
| WebAttack | 0.9999 | 0.9999 | 0.9999 | 17336 |

## Ensemble macro-F1 by checkpoint

| checkpoint | macro-F1 |
|---|---|
| 16 | 1.0000 |
| 32 | 1.0000 |
| 8 | 0.9913 |
| end | 0.9804 |

## Sequence models: accuracy per parameter

| model | params | macro-F1 | p50 latency ms (batch 1) |
|---|---|---|---|
| cfc | 5497 | 0.9919 | 17.420 |
| lstm | 7749 | 0.9920 | 0.939 |
| gru | 6933 | 0.9917 | - |
| cnn | 6837 | 0.9945 | - |

Identity ablation: share of LightGBM gain on IP/port columns = 0.133

Classes without lab data (not modelled): ['Botnet', 'Infiltration']
Classes below minimum support 19 = ceil((1-alpha)/alpha) in some split after de-duplication (not modelled): {'DDoS': {'cal': 1, 'test': 1, 'train': 1, 'val': 1}}



---
<!-- source: evidence/calibrate_cal-20261018-193120-13bdbc/calibration.md -->
# Calibration cal-20261018-193120-13bdbc

Model set ms-20261018-192542-de1bed; validation n=4623, wrong=4

Learned: k=2, alpha=0.0, tau_lo=0.3333, tau_hi=0.6667, rules.min_agreement=0.9976, rules.max_fpr=0.01

Conformal coverage on val at alpha_target=0.05: 0.9554; set-size histogram [205, 4418, 0, 0, 0, 0]

## ECS grid (val)

| k | alpha | AUC correct-vs-wrong | mean ECS correct | mean ECS wrong |
|---|---|---|---|---|
| 2 | 0.0 | 0.9545 | 0.8469 | 0.2500 |
| 2 | 0.25 | 0.9433 | 0.7354 | 0.2361 |
| 2 | 0.5 | 0.9160 | 0.6238 | 0.2222 |
| 2 | 0.75 | 0.8500 | 0.5123 | 0.2083 |
| 2 | 1.0 | 0.7777 | 0.4008 | 0.1944 |
| 3 | 0.0 | 0.8727 | 0.9952 | 0.5000 |
| 3 | 0.25 | 0.8824 | 0.8710 | 0.4521 |
| 3 | 0.5 | 0.8824 | 0.7467 | 0.4042 |
| 3 | 0.75 | 0.8806 | 0.6225 | 0.3563 |
| 3 | 1.0 | 0.8566 | 0.4983 | 0.3083 |
| 4 | 0.0 | 0.8574 | 0.9906 | 0.7639 |
| 4 | 0.25 | 0.9233 | 0.8911 | 0.6745 |
| 4 | 0.5 | 0.9254 | 0.7916 | 0.5851 |
| 4 | 0.75 | 0.9267 | 0.6920 | 0.4957 |
| 4 | 1.0 | 0.8890 | 0.5925 | 0.4063 |
| 5 | 0.0 | 0.8323 | 0.9722 | 0.7847 |
| 5 | 0.25 | 0.9087 | 0.8955 | 0.7168 |
| 5 | 0.5 | 0.9155 | 0.8189 | 0.6488 |
| 5 | 0.75 | 0.8771 | 0.7422 | 0.5809 |
| 5 | 1.0 | 0.8336 | 0.6655 | 0.5129 |

---
<!-- source: evidence/E1-20261018-193129-0ff4/e1.md -->
# E1 - ECS-gated quarantine vs ungated (E1-20261018-193129-0ff4)

Test split of ms-20261018-192542-de1bed (temporal, lab capture). n=4845; benign 1200, attack 3645. Learned k=2, alpha=0.0, tau_lo=0.3333, tau_hi=0.6667; alpha_target=0.05.

| policy | benign BLOCK | benign QUARANTINE | attack BLOCK recall | attack intercept recall |
|---|---|---|---|---|
| gated | 0.0000 | 0.0125 | 0.9616 | 1.0000 |
| conformal_only | 0.0000 | 0.0125 | 0.9813 | 1.0000 |
| argmax | 0.0008 | 0.0000 | 1.0000 | 1.0000 |

Argmax score thresholded to the gated intercept recall (1.0000): benign flagged = 0.0008.

Wrong ensemble decisions: 4 of 4845. Sent to QUARANTINE by the gated table: 1.0000 (R1 low ECS 0.0000, R6/R7 ECS band 0.0000); conformal-only table: 1.0000. Mean ECS wrong 0.7500 vs correct 0.8933.

Decision-row histogram (gated): {'R4': 3505, 'R5': 1177, 'R2': 82, 'R6': 66, 'R7': 8, 'R1': 7}

---
<!-- source: evidence/E2-20261018-193131-4a3a/e2.md -->
# E2 - conformal coverage vs target under shift (E2-20261018-193131-4a3a)

Stream: test split (time-ordered, n=4845) followed by the separately recorded evasion capture (n=6000; low-and-slow brute force, padded SYN flood, slow scan + benign). Target coverage 0.95; labels arrive with a delay of 200 decisions; gamma=0.005.

| mode | coverage test | coverage evasion | coverage overall | mean |S| test | mean |S| evasion |
|---|---|---|---|---|---|
| fixed | 0.9829 | 0.6712 | 0.8104 | 0.9829 | 0.6718 |
| aci | 0.9319 | 0.7905 | 0.8537 | 0.9531 | 0.9187 |

Per-class coverage (ACI): {"Benign": 0.944, "DoS": 0.6327, "PortScan": 0.9929, "BruteForce": 0.8113, "WebAttack": 0.8958}

Per-class coverage (fixed): {"Benign": 0.993, "DoS": 0.3781, "PortScan": 0.9929, "BruteForce": 0.8113, "WebAttack": 0.9592}

---
<!-- source: evidence/E3-20261018-193131-346d/e3.md -->
# E3 - certified vs uncertified rules; canary vs direct (E3-20261018-193131-346d)

6 candidate kernel rules distilled (depth<=3, kernel-realizable features of top-2 groups) from sliding windows of 2000 val snapshots; fidelity gate = agreement >= 0.9976 and holdout FPR <= 0.01; canary = FP on next window's model-benign traffic. Evaluated on the test split.

| group | n rules | test FPR mean | test FPR max | share FPR > budget | test recall mean |
|---|---|---|---|---|---|
| certified | 4 | 0.0123 | 0.0442 | 0.2500 | 0.7442 |
| uncertified | 2 | 0.1275 | 0.1308 | 1.0000 | 1.0000 |
| direct_promotion_all | 6 | 0.0507 | 0.1308 | 0.5000 | 0.8294 |
| canary_then_promote | 4 | 0.0123 | 0.0442 | 0.2500 | 0.7442 |

Certified rules that failed the canary: 0

---
<!-- source: evidence/E4-20261018-193319-149e/e4.md -->
# E4 - in-kernel datapath measurements (E4-20261018-193319-149e)

Environment: WSL2 lab (network namespaces, xdpgeneric on veth) (virtualised, no line-rate claim). Agent: OK 8 path=xdp_generic ifaces=v-att,v-cli,v-vic realizable=0:k_src_pkts,1:k_src_syn_ratio_pm,2:k_src_rst_ratio_pm,3:k_src_mean_size,4:k_src_dports,5:k_src_dsts,6:k_src_pps,7:k_src_syn_count max_rules=32 max_pred=4

## (a) Atomic A/B rule-array swap under load

| run | ICMP sent | received | lost | flips | stage+flip p50 us | max us |
|---|---|---|---|---|---|---|
| baseline | 6000 | 6000 | 0 | 0 | - | - |
| with_flips | 6000 | 6000 | 0 | 300 | 44988.69400049443 | 54394.38700068422 |

## (b) Drop path at equal offered load (hping3 --flood SYN, single sender)

| mode | packets seen at XDP | dropped by XDP | dropped by netfilter | seen pps | host system+softirq CPU share |
|---|---|---|---|---|---|
| none | 156156 | 0 | - | 31231 | 0.146 |
| xdp | 341921 | 341901 | - | 68384 | 0.075 |
| netfilter | 169512 | 0 | 169511 | 33902 | 0.145 |

User-space drop baseline (nfqueue) not implemented in this build; not reported.

---
<!-- source: evidence/E5-20261018-194944-3fa1/e5.md -->
# E5 - ledger tamper detection (E5-20261018-194944-3fa1)

Copy of the live ledger: 14803 entries, 80 signed Merkle batches, 80 TPM quotes (swtpm (software TPM 2.0) - demo, not hardware TPM). Clean full verification (chain + Merkle + Ed25519 + tpm2_checkquote + PCR replay): OK in 2.045 s.

| tamper | trials | detected | first bad seq = tampered seq | reported as | verify s (mean) |
|---|---|---|---|---|---|
| edit_payload | 20 | 1.0000 | 1.0000 | edit | 0.1916 |
| delete_entry | 20 | 1.0000 | 1.0000 | delete | 0.2170 |
| reorder_entries | 20 | 1.0000 | 1.0000 | edit | 0.2274 |
| edit_and_rechain | 20 | 1.0000 | 0.0000 | merkle-root | 0.4399 |
| forge_quote_nonce | 20 | 1.0000 | n/a | tpm-quote | 2.0309 |
| edit_pcr_event | 20 | 1.0000 | n/a | pcr-replay | 2.0388 |

Tamper trials without TPM checks run chain/Merkle/signature verification only (quotes are verified for the quote and PCR-log tamper kinds).

---
<!-- source: evidence/E6-20261018-193213-61b5/e6.md -->
# E6 - evasion and explainer-manipulation detection (E6-20261018-193213-61b5)

## (a) Evasion variants never seen in training (evasion1 capture)

| scenario | n | GLASSWALL intercept (BLOCK+QUAR) | of which R1 adversarial | conformal-only intercept | argmax BLOCK | mean ECS |
|---|---|---|---|---|---|---|
| benign_attacker | 677 | 0.0236 | 0.0015 | 0.0222 | 0.0000 | 0.9407 |
| benign_client | 3301 | 0.0018 | 0.0000 | 0.0018 | 0.0009 | 0.9773 |
| bruteforce_lowslow | 8 | 0.5000 | 0.0000 | 0.5000 | 0.2500 | 0.7292 |
| dos_padded | 1939 | 1.0000 | 0.0217 | 1.0000 | 0.9979 | 0.3263 |
| portscan_slow | 75 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.9733 |

For benign_* rows 'intercept' is the benign impact rate (lower is better).

## (b) Slack-style scaffolding attack on the offline LIME path

60 attack-predicted test snapshots. Scaffold = real model on-manifold, innocuous feature `f_has_reply` off-manifold (OOD detector accuracy on held-out real-vs-LIME-perturbation: 1.0000).

| LIME explains | flag rate @ learned threshold 0.0000 | flag rate @ tau_lo 0.3333 | mean agreement with hot path | innocuous group in LIME top-k |
|---|---|---|---|---|
| honest model | 0.0000 | 0.3500 | 0.3361 | 0.0000 |
| scaffolded model | 0.0000 | 0.7833 | 0.1167 | 0.9833 |

Learned threshold = 0.01 quantile of honest-LIME agreement on 60 validation samples (separate from the 60 test samples).

Without the consensus check there is no comparison, so a manipulated LIME explanation is shown as-is (detection rate 0 by construction).

---
<!-- source: evidence/ONLINE-20261018-194256-358c/online.md -->
# Online end-to-end run (ONLINE-20261018-194256-358c)

Environment: WSL2 lab (network namespaces, xdpgeneric on veth); swtpm (software TPM 2.0) - demo, not hardware TPM. Live agent + brain; benign users from the client namespace throughout; scenarios from the attacker namespace. 14716 decisions in 353 s (41.7/s).

| scenario | class | evasion | decisions | BLOCK | QUAR | ALLOW(+shadow) | intercept share | time to first BLOCK/QUAR s | adv flags | decided on rule-dropped pkts |
|---|---|---|---|---|---|---|---|---|---|---|
| portscan_syn | PortScan |  | 1003 | 999 | 4 | 0 | 1.000 | 1.27 | 0 | 0 |
| bruteforce_ssh | BruteForce |  | 3 | 3 | 0 | 0 | 1.000 | 0.83 | 0 | 0 |
| dos_synflood | DoS |  | 1514 | 0 | 1514 | 0 | 1.000 | 3.80 | 80 | 1494 |
| webattack_enum | WebAttack |  | 5 | 0 | 5 | 0 | 1.000 | 5.97 | 0 | 5 |
| dos_slowloris | DoS |  | 152 | 0 | 152 | 0 | 1.000 | 5.62 | 0 | 152 |
| ddos_spoofed | DDoS |  | 241 | 0 | 241 | 0 | 1.000 | 3.74 | 0 | 241 |
| portscan_connect | PortScan |  | 754 | 0 | 754 | 0 | 1.000 | 17.58 | 726 | 753 |
| bruteforce_lowslow | BruteForce | yes | 7 | 4 | 3 | 0 | 1.000 | 10.80 | 0 | 1 |
| portscan_slow | PortScan | yes | 21 | 3 | 18 | 0 | 1.000 | 4.16 | 0 | 17 |
| dos_padded | DoS | yes | 583 | 0 | 583 | 0 | 1.000 | 3.80 | 0 | 583 |
| portscan_syn | PortScan |  | 1946 | 110 | 1836 | 0 | 1.000 | 5.27 | 975 | 1832 |

Benign client during the run: 4472 decisions, {'QUARANTINE': 481, 'ALLOW_SHADOW': 179, 'ALLOW': 3812}.

Latency: event->decision p50 8340.8 ms, p99 35436.8 ms; amortised decide cost per snapshot p50 8.50 ms, p99 146.32 ms (includes 3 models + 3 explainers incl. IG, ECS, conformal, enforcement, ledger).

## Rules compiled during the run

| id | status | rule | reason |
|---|---|---|---|
| 1 | ROLLED_BACK | k_src_syn_ratio_pm > 266 | automatic rollback: fp_rate 0.0936 > 0.05 |
| 2 | PROMOTED | k_src_syn_ratio_pm > 625 AND k_src_syn_count > 41 |  |
| 3 | PROMOTED | k_src_mean_size <= 361 |  |
| 4 | FIDELITY_FAILED | k_src_pkts <= 69 AND k_src_pps <= 1 | agreement 0.8902 / fpr 0.0000 vs thresholds |
| 5 | FIDELITY_FAILED | k_src_pkts <= 2326 AND k_src_mean_size <= 50 | agreement 0.8815 / fpr 0.0000 vs thresholds |
| 6 | FIDELITY_FAILED | k_src_mean_size <= 72 AND k_src_mean_size > 36 | agreement 0.9286 / fpr 0.0718 vs thresholds |
| 7 | PROMOTED | k_src_syn_ratio_pm > 237 AND k_src_pkts <= 67 |  |
| 8 | FIDELITY_FAILED | k_src_syn_count <= 20 AND k_src_syn_ratio_pm > 28 AND k_src_syn_ratio_pm <= 912 | agreement 0.1844 / fpr 0.4308 vs thresholds |

Kernel counters before: {"total": 30404, "pass": 30382, "safety": 0, "drop_flow": 0, "drop_src": 0, "drop_prefix": 0, "drop_rule": 0, "rate_drop": 0, "rb_full": 0, "emitted": 5170, "non_ip": 22}

Kernel counters after: {"total": 209700, "pass": 186119, "safety": 3, "drop_flow": 0, "drop_src": 241, "drop_prefix": 0, "drop_rule": 10194, "rate_drop": 13102, "rb_full": 0, "emitted": 44270, "non_ip": 41}

Rule hits (matched, dropped) after: {"1": [9174, 9171], "2": [938, 938], "3": [85, 85], "4": [0, 0], "5": [0, 0], "6": [0, 0], "7": [0, 0], "8": [0, 0]}

---
<!-- source: evidence/REPLAY-20261018-194954/replay.md -->
# Online == offline feature check

Archive `online_20261018-193456.events.gz` replayed through the offline FlowTable: 1915 (flow, checkpoint) snapshots matched to online decisions; identical feature hash for 1911 (0.9979). By checkpoint: {"end": {"n": 1277, "identical": 1275}, "16": {"n": 199, "identical": 198}, "8": {"n": 274, "identical": 274}, "32": {"n": 165, "identical": 164}}.

Online, idle flows are also closed by a wall-clock ticker, offline only by the event-time ticker, so flow boundaries and the source-history context of other flows can differ at a few stream positions; this is the most likely cause of the mismatches (not individually traced).


---
<!-- source: evidence/SMOKE-20261018-193320/smoke.md -->
# Datapath smoke test

Environment: WSL2 6.6.87.2-microsoft-standard-WSL2, network namespaces, xdpgeneric on veth. Raw output:

```
lab up: namespaces present: ['gwgw', 'gwatt', 'gwcli', 'gwvic']
attached xdpgeneric on v-att (ifindex 40)
attached xdpgeneric on v-cli (ifindex 42)
attached xdpgeneric on v-vic (ifindex 44)
agent ready: events=/run/glasswall/dp_events.sock ctl=/run/glasswall/dp_ctl.sock
--- HELLO
OK 7 path=xdp_generic ifaces=v-att,v-cli,v-vic realizable=0:k_src_pkts,1:k_src_syn_ratio_pm,2:k_src_rst_ratio_pm,3:k_src_mean_size,4:k_src_dports,5:k_src_dsts,6:k_src_pps,7:k_src_syn_count max_rules=32 max_pred=4
--- baseline curl attacker->victim (HTTP code)
200
--- DROP attacker source
OK 39
000
curl failed (expected: dropped)
--- client still allowed
200
--- agent refuses a verdict on the safety port 2222
ERR safety-allowlist
--- RATE_LIMIT attacker 20pps burst 40, ping flood 200 pkts at 500 pps
OK 28
200 packets transmitted, 69 received, 65.5% packet loss, time 1485ms
rtt min/avg/max/mdev = 0.037/0.250/11.601/1.377 ms
OK 16
--- rule: k_src_syn_count >= 50 -> DROP staged in the inactive array, then FLIP
OK 21 0
OK 92
OK 20
OK 21 active=1
OK 17 1

Nmap done: 1 IP address (1 host up) scanned in 65.13 seconds
--- rule 7 hits (matched dropped)
OK 46 1143 1143
--- STATS (total pass safety drop_flow drop_src drop_prefix drop_rule rate_drop rb_full emitted non_ip)
OK 718 2153 853 0 0 3 0 1143 131 0 1886 23 ev_dropped=1886 active=1
agent stopped, XDP detached
```


---
## Honest limitations (read before quoting any number)

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
