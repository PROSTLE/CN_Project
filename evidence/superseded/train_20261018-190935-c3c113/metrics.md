# Detection results (test split, temporal) - run 20261018-190935-c3c113

Environment: WSL2 lab (network namespaces, xdpgeneric on veth). Dataset: own lab capture (labels by construction).

| model | macro-F1 | PR-AUC (macro) | FPR @ recall 0.95 | accuracy |
|---|---|---|---|---|
| ensemble | 0.9941 | 0.9989 | 0.0000 | 0.9997 |
| gbdt | 0.9941 | 0.9990 | 0.0000 | 0.9997 |
| xgb | 0.9922 | 0.9987 | 0.0000 | 0.9996 |
| ebm | 0.9923 | 0.9902 | 0.0000 | 0.9997 |
| cfc | 0.9903 | 0.9947 | 0.0000 | 0.9948 |
| lstm | 0.9930 | 0.9980 | 0.0000 | 0.9986 |
| gru | 0.9934 | 0.9979 | 0.0000 | 0.9992 |
| cnn | 0.9931 | 0.9991 | 0.0000 | 0.9989 |
| rf | 0.9940 | 0.9903 | 0.0000 | 0.9997 |
| mlp | 0.9909 | 0.9983 | 0.0000 | 0.9985 |
| ablation_gbdt_with_identity | 0.9980 | 1.0000 | 0.0000 | 0.9998 |

## Per-class (ensemble)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| Benign | 0.9998 | 0.9993 | 0.9996 | 4455 |
| DoS | 0.9992 | 1.0000 | 0.9996 | 3642 |
| DDoS | 1.0000 | 1.0000 | 1.0000 | 1 |
| PortScan | 1.0000 | 1.0000 | 1.0000 | 2003 |
| BruteForce | 1.0000 | 0.9333 | 0.9655 | 45 |
| WebAttack | 0.9998 | 0.9999 | 0.9999 | 17336 |

## Ensemble macro-F1 by checkpoint

| checkpoint | macro-F1 |
|---|---|
| 16 | 1.0000 |
| 32 | 1.0000 |
| 8 | 0.9166 |
| end | 0.9836 |

## Sequence models: accuracy per parameter

| model | params | macro-F1 | p50 latency ms (batch 1) |
|---|---|---|---|
| cfc | 5562 | 0.9903 | 8.079 |
| lstm | 7814 | 0.9930 | 0.457 |
| gru | 6998 | 0.9934 | - |
| cnn | 6902 | 0.9931 | - |

Identity ablation: share of LightGBM gain on IP/port columns = 0.136

Classes without lab data (not modelled): ['Botnet', 'Infiltration']

## Log

```
dataset /var/lib/glasswall/datasets/train2: 156118 snapshots, 102516 flows
dropped evasion rows: 0, non-finite rows: 0
constant columns dropped (train): ['k_src_dsts', 't_reputation', 'l_blacklisted', 'l_whitelisted']
exact duplicates removed within splits: 11371
flows per split/class: {"train": {"Benign": 3264, "BruteForce": 51, "DDoS": 1, "DoS": 4995, "PortScan": 5000, "WebAttack": 4788}, "val": {"Benign": 774, "BruteForce": 8, "DDoS": 1, "DoS": 2021, "PortScan": 999, "WebAttack": 5350}, "cal": {"Benign": 789, "BruteForce": 9, "DDoS": 1, "DoS": 1939, "PortScan": 1005, "WebAttack": 5232}, "test": {"Benign": 1614, "BruteForce": 17, "DDoS": 1, "DoS": 3641, "PortScan": 2003, "WebAttack": 13789}}
snapshots per split/class: {"train": {"Benign": 5000, "PortScan": 5000, "WebAttack": 5000, "DoS": 5000, "BruteForce": 153, "DDoS": 1}, "val": {"WebAttack": 7903, "Benign": 2161, "DoS": 2024, "PortScan": 999, "BruteForce": 24, "DDoS": 1}, "cal": {"WebAttack": 7725, "Benign": 2219, "DoS": 1941, "PortScan": 1005, "BruteForce": 27, "DDoS": 1}, "test": {"WebAttack": 17336, "Benign": 4455, "DoS": 3642, "PortScan": 2003, "BruteForce": 45, "DDoS": 1}}
classes with no lab data (not modelled): ['Botnet', 'Infiltration']
lightgbm: 168 rounds, 2.3s
ebm: 40 terms (interactions=0), 27.5s
  [cfc] epoch 1/15 loss 2.8596 val_acc 0.9893
  [cfc] epoch 2/15 loss 0.8841 val_acc 0.9910
  [cfc] epoch 3/15 loss 0.0163 val_acc 0.9913
  [cfc] epoch 4/15 loss 0.0101 val_acc 0.9915
  [cfc] epoch 5/15 loss 0.0075 val_acc 0.9918
  [cfc] epoch 6/15 loss 0.0059 val_acc 0.9925
  [cfc] epoch 7/15 loss 0.0051 val_acc 0.9931
  [cfc] epoch 8/15 loss 0.0040 val_acc 0.9931
  [cfc] epoch 9/15 loss 0.0032 val_acc 0.9928
  [cfc] epoch 10/15 loss 0.0028 val_acc 0.9927
  [cfc] epoch 11/15 loss 0.0024 val_acc 0.9931
  [cfc] epoch 12/15 loss 0.0020 val_acc 0.9935
  [cfc] epoch 13/15 loss 0.0017 val_acc 0.9931
  [cfc] epoch 14/15 loss 0.0015 val_acc 0.9934
  [cfc] epoch 15/15 loss 0.0014 val_acc 0.9934
  [lstm] epoch 1/15 loss 2.4054 val_acc 0.9895
  [lstm] epoch 2/15 loss 0.7334 val_acc 0.9921
  [lstm] epoch 3/15 loss 0.0218 val_acc 0.9908
  [lstm] epoch 4/15 loss 0.0109 val_acc 0.9921
  [lstm] epoch 5/15 loss 0.0082 val_acc 0.9915
  [lstm] epoch 6/15 loss 0.0063 val_acc 0.9924
  [lstm] epoch 7/15 loss 0.0056 val_acc 0.9927
  [lstm] epoch 8/15 loss 0.0045 val_acc 0.9928
  [lstm] epoch 9/15 loss 0.0040 val_acc 0.9922
  [lstm] epoch 10/15 loss 0.0041 val_acc 0.9932
  [lstm] epoch 11/15 loss 0.0032 val_acc 0.9935
  [lstm] epoch 12/15 loss 0.0027 val_acc 0.9937
  [lstm] epoch 13/15 loss 0.0025 val_acc 0.9928
  [lstm] epoch 14/15 loss 0.0022 val_acc 0.9936
  [lstm] epoch 15/15 loss 0.0020 val_acc 0.9936
  [gru] epoch 1/15 loss 2.2531 val_acc 0.9880
  [gru] epoch 2/15 loss 0.6653 val_acc 0.9927
  [gru] epoch 3/15 loss 0.0583 val_acc 0.9913
  [gru] epoch 4/15 loss 0.0183 val_acc 0.9934
  [gru] epoch 5/15 loss 0.0084 val_acc 0.9934
  [gru] epoch 6/15 loss 0.0059 val_acc 0.9940
  [gru] epoch 7/15 loss 0.0048 val_acc 0.9940
  [gru] epoch 8/15 loss 0.0036 val_acc 0.9950
  [gru] epoch 9/15 loss 0.0031 val_acc 0.9954
  [gru] epoch 10/15 loss 0.0027 val_acc 0.9953
  [gru] epoch 11/15 loss 0.0023 val_acc 0.9955
  [gru] epoch 12/15 loss 0.0020 val_acc 0.9957
  [gru] epoch 13/15 loss 0.0017 val_acc 0.9953
  [gru] epoch 14/15 loss 0.0016 val_acc 0.9960
  [gru] epoch 15/15 loss 0.0014 val_acc 0.9949
  [cnn] epoch 1/15 loss 2.8684 val_acc 0.9905
  [cnn] epoch 2/15 loss 0.4475 val_acc 0.9899
  [cnn] epoch 3/15 loss 0.0116 val_acc 0.9940
  [cnn] epoch 4/15 loss 0.0075 val_acc 0.9951
  [cnn] epoch 5/15 loss 0.0054 val_acc 0.9954
  [cnn] epoch 6/15 loss 0.0042 val_acc 0.9960
  [cnn] epoch 7/15 loss 0.0035 val_acc 0.9957
  [cnn] epoch 8/15 loss 0.0027 val_acc 0.9966
  [cnn] epoch 9/15 loss 0.0024 val_acc 0.9963
  [cnn] epoch 10/15 loss 0.0021 val_acc 0.9964
  [cnn] epoch 11/15 loss 0.0017 val_acc 0.9973
  [cnn] epoch 12/15 loss 0.0015 val_acc 0.9973
  [cnn] epoch 13/15 loss 0.0013 val_acc 0.9972
  [cnn] epoch 14/15 loss 0.0013 val_acc 0.9978
  [cnn] epoch 15/15 loss 0.0010 val_acc 0.9977
ensemble weights (gbdt, ebm, cfc) = [1.0, 0.0, 0.0], temperature 1.25, val NLL 0.0016
attributions val: 6000 snapshots in 13.5s; IG completeness gap median 0.02114, p99 0.1774
attributions cal: 6000 snapshots in 13.3s; IG completeness gap median 0.02236, p99 0.1766
attributions test: 6000 snapshots in 12.8s; IG completeness gap median 0.03189, p99 0.1922
```