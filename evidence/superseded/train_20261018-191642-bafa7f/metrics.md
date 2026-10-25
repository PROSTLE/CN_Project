# Detection results (test split, temporal) - run 20261018-191642-bafa7f

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
| cfc | 5497 | 0.9919 | 18.046 |
| lstm | 7749 | 0.9920 | 0.926 |
| gru | 6933 | 0.9917 | - |
| cnn | 6837 | 0.9945 | - |

Identity ablation: share of LightGBM gain on IP/port columns = 0.133

Classes without lab data (not modelled): ['Botnet', 'Infiltration']
Classes below minimum support 19 = ceil((1-alpha)/alpha) in some split after de-duplication (not modelled): {'DDoS': {'cal': 1, 'test': 1, 'train': 1, 'val': 1}}

## Log

```
dataset /var/lib/glasswall/datasets/train2: 156118 snapshots, 102516 flows
dropped evasion rows: 0, non-finite rows: 0
constant columns dropped (train): ['k_src_dsts', 't_reputation', 'l_blacklisted', 'l_whitelisted']
exact duplicates removed within splits: 11371
classes below minimum support 19 in some split (not modelled): {'DDoS': {'cal': 1, 'test': 1, 'train': 1, 'val': 1}}
flows per split/class: {"train": {"Benign": 3264, "BruteForce": 51, "DoS": 4995, "PortScan": 5000, "WebAttack": 4788}, "val": {"Benign": 774, "BruteForce": 8, "DoS": 2021, "PortScan": 999, "WebAttack": 5350}, "cal": {"Benign": 789, "BruteForce": 9, "DoS": 1939, "PortScan": 1005, "WebAttack": 5232}, "test": {"Benign": 1614, "BruteForce": 17, "DoS": 3641, "PortScan": 2003, "WebAttack": 13789}}
snapshots per split/class: {"train": {"Benign": 5000, "PortScan": 5000, "WebAttack": 5000, "DoS": 5000, "BruteForce": 153}, "val": {"WebAttack": 7903, "Benign": 2161, "DoS": 2024, "PortScan": 999, "BruteForce": 24}, "cal": {"WebAttack": 7725, "Benign": 2219, "DoS": 1941, "PortScan": 1005, "BruteForce": 27}, "test": {"WebAttack": 17336, "Benign": 4455, "DoS": 3642, "PortScan": 2003, "BruteForce": 45}}
classes with no lab data (not modelled): ['Botnet', 'Infiltration']
lightgbm: 211 rounds, 4.4s
ebm: 40 terms (interactions=0), 37.0s
  [cfc] epoch 1/15 loss 0.2760 val_acc 0.9889
  [cfc] epoch 2/15 loss 0.0203 val_acc 0.9896
  [cfc] epoch 3/15 loss 0.0109 val_acc 0.9896
  [cfc] epoch 4/15 loss 0.0075 val_acc 0.9915
  [cfc] epoch 5/15 loss 0.0054 val_acc 0.9921
  [cfc] epoch 6/15 loss 0.0042 val_acc 0.9919
  [cfc] epoch 7/15 loss 0.0034 val_acc 0.9926
  [cfc] epoch 8/15 loss 0.0026 val_acc 0.9924
  [cfc] epoch 9/15 loss 0.0020 val_acc 0.9932
  [cfc] epoch 10/15 loss 0.0016 val_acc 0.9921
  [cfc] epoch 11/15 loss 0.0011 val_acc 0.9937
  [cfc] epoch 12/15 loss 0.0012 val_acc 0.9935
  [cfc] epoch 13/15 loss 0.0008 val_acc 0.9934
  [cfc] epoch 14/15 loss 0.0012 val_acc 0.9940
  [cfc] epoch 15/15 loss 0.0006 val_acc 0.9947
  [lstm] epoch 1/15 loss 0.2948 val_acc 0.9904
  [lstm] epoch 2/15 loss 0.0177 val_acc 0.9905
  [lstm] epoch 3/15 loss 0.0104 val_acc 0.9896
  [lstm] epoch 4/15 loss 0.0066 val_acc 0.9938
  [lstm] epoch 5/15 loss 0.0049 val_acc 0.9928
  [lstm] epoch 6/15 loss 0.0039 val_acc 0.9931
  [lstm] epoch 7/15 loss 0.0036 val_acc 0.9934
  [lstm] epoch 8/15 loss 0.0029 val_acc 0.9931
  [lstm] epoch 9/15 loss 0.0021 val_acc 0.9939
  [lstm] epoch 10/15 loss 0.0019 val_acc 0.9941
  [lstm] epoch 11/15 loss 0.0018 val_acc 0.9945
  [lstm] epoch 12/15 loss 0.0016 val_acc 0.9946
  [lstm] epoch 13/15 loss 0.0012 val_acc 0.9942
  [lstm] epoch 14/15 loss 0.0013 val_acc 0.9948
  [lstm] epoch 15/15 loss 0.0011 val_acc 0.9949
  [gru] epoch 1/15 loss 0.2606 val_acc 0.9893
  [gru] epoch 2/15 loss 0.0185 val_acc 0.9902
  [gru] epoch 3/15 loss 0.0110 val_acc 0.9913
  [gru] epoch 4/15 loss 0.0074 val_acc 0.9916
  [gru] epoch 5/15 loss 0.0057 val_acc 0.9922
  [gru] epoch 6/15 loss 0.0045 val_acc 0.9928
  [gru] epoch 7/15 loss 0.0039 val_acc 0.9937
  [gru] epoch 8/15 loss 0.0031 val_acc 0.9937
  [gru] epoch 9/15 loss 0.0023 val_acc 0.9942
  [gru] epoch 10/15 loss 0.0023 val_acc 0.9942
  [gru] epoch 11/15 loss 0.0025 val_acc 0.9940
  [gru] epoch 12/15 loss 0.0017 val_acc 0.9947
  [gru] epoch 13/15 loss 0.0013 val_acc 0.9945
  [gru] epoch 14/15 loss 0.0012 val_acc 0.9948
  [gru] epoch 15/15 loss 0.0011 val_acc 0.9949
  [cnn] epoch 1/15 loss 0.2865 val_acc 0.9899
  [cnn] epoch 2/15 loss 0.0201 val_acc 0.9914
  [cnn] epoch 3/15 loss 0.0104 val_acc 0.9921
  [cnn] epoch 4/15 loss 0.0067 val_acc 0.9928
  [cnn] epoch 5/15 loss 0.0051 val_acc 0.9938
  [cnn] epoch 6/15 loss 0.0040 val_acc 0.9940
  [cnn] epoch 7/15 loss 0.0035 val_acc 0.9947
  [cnn] epoch 8/15 loss 0.0027 val_acc 0.9954
  [cnn] epoch 9/15 loss 0.0021 val_acc 0.9962
  [cnn] epoch 10/15 loss 0.0030 val_acc 0.9934
  [cnn] epoch 11/15 loss 0.0017 val_acc 0.9952
  [cnn] epoch 12/15 loss 0.0013 val_acc 0.9954
  [cnn] epoch 13/15 loss 0.0010 val_acc 0.9967
  [cnn] epoch 14/15 loss 0.0009 val_acc 0.9970
  [cnn] epoch 15/15 loss 0.0010 val_acc 0.9969
ensemble weights (gbdt, ebm, cfc) = [1.0, 0.0, 0.0], temperature 1.25, val NLL 0.0017
attributions val: 6000 snapshots in 22.2s; IG completeness gap median 0.03128, p99 0.7332
attributions cal: 6000 snapshots in 22.8s; IG completeness gap median 0.03242, p99 0.9646
attributions test: 6000 snapshots in 22.6s; IG completeness gap median 0.03228, p99 1.11
```