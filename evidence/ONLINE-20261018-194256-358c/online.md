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