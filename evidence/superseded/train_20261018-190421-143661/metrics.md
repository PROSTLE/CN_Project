# Detection results (test split, temporal) - run 20261018-190421-143661

Environment: WSL2 lab (network namespaces, xdpgeneric on veth). Dataset: own lab capture (labels by construction).

| model | macro-F1 | PR-AUC (macro) | FPR @ recall 0.95 | accuracy |
|---|---|---|---|---|
| ensemble | 0.9997 | 1.0000 | 0.0000 | 0.9998 |
| gbdt | 0.9997 | 1.0000 | 0.0000 | 0.9997 |
| xgb | 0.9994 | 0.9999 | 0.0000 | 0.9994 |
| ebm | 0.9997 | 1.0000 | 0.0000 | 0.9998 |
| cfc | 0.9830 | 0.9999 | 0.0000 | 0.9860 |
| lstm | 0.9839 | 0.9999 | 0.0000 | 0.9876 |
| gru | 0.9709 | 0.9998 | 0.0000 | 0.9798 |
| cnn | 0.9900 | 0.9999 | 0.0000 | 0.9912 |
| rf | 0.9995 | 1.0000 | 0.0000 | 0.9995 |
| mlp | 0.7383 | 0.7496 | 0.0000 | 0.9895 |
| ablation_gbdt_with_identity | 0.9996 | 1.0000 | 0.0000 | 0.9996 |

## Per-class (ensemble)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| Benign | 1.0000 | 0.9994 | 0.9997 | 3475 |
| DoS | 0.9992 | 0.9995 | 0.9993 | 3642 |
| DDoS | 1.0000 | 1.0000 | 1.0000 | 1 |
| PortScan | 0.0000 | 0.0000 | 0.0000 | 0 |
| BruteForce | 0.0000 | 0.0000 | 0.0000 | 0 |
| WebAttack | 0.9998 | 0.9999 | 0.9999 | 17336 |

## Ensemble macro-F1 by checkpoint

| checkpoint | macro-F1 |
|---|---|
| 16 | 1.0000 |
| 32 | 1.0000 |
| 8 | 0.8887 |
| end | 0.9997 |

## Sequence models: accuracy per parameter

| model | params | macro-F1 | p50 latency ms (batch 1) |
|---|---|---|---|
| cfc | 5562 | 0.9830 | 8.030 |
| lstm | 7814 | 0.9839 | 0.484 |
| gru | 6998 | 0.9709 | - |
| cnn | 6902 | 0.9900 | - |

Identity ablation: share of LightGBM gain on IP/port columns = 0.014

Classes without lab data (not modelled): ['Botnet', 'Infiltration']

## Log

```
dataset /var/lib/glasswall/datasets/train2: 156118 snapshots, 102516 flows
dropped evasion rows: 0, non-finite rows: 0
constant columns dropped (train): ['k_src_dsts', 't_reputation', 'l_blacklisted', 'l_whitelisted']
exact duplicates removed within splits: 11372
flows per split/class: {"train": {"Benign": 2883, "BruteForce": 34, "DDoS": 1, "DoS": 4996, "PortScan": 4302, "WebAttack": 4796}, "val": {"Benign": 2280, "BruteForce": 17, "DDoS": 1, "DoS": 4379, "PortScan": 3715, "WebAttack": 3101}, "cal": {"Benign": 733, "BruteForce": 34, "PortScan": 2003, "WebAttack": 7481}, "test": {"Benign": 1279, "DDoS": 1, "DoS": 3641, "WebAttack": 13789}}
snapshots per split/class: {"train": {"Benign": 5000, "WebAttack": 5000, "DoS": 5000, "PortScan": 4302, "BruteForce": 102, "DDoS": 1}, "val": {"Benign": 6434, "WebAttack": 4764, "DoS": 4388, "PortScan": 3715, "BruteForce": 51, "DDoS": 1}, "cal": {"WebAttack": 10864, "Benign": 2087, "PortScan": 2003, "BruteForce": 96}, "test": {"WebAttack": 17336, "DoS": 3642, "Benign": 3475, "DDoS": 1}}
classes with no lab data (not modelled): ['Botnet', 'Infiltration']
lightgbm: 57 rounds, 1.0s
ebm: 40 terms (interactions=0), 10.2s
  [cfc] epoch 1/15 loss 4.4948 val_acc 0.9185
  [cfc] epoch 2/15 loss 1.6424 val_acc 0.9422
  [cfc] epoch 3/15 loss 0.0075 val_acc 0.9456
  [cfc] epoch 4/15 loss 0.0046 val_acc 0.9459
  [cfc] epoch 5/15 loss 0.0033 val_acc 0.9479
  [cfc] epoch 6/15 loss 0.0025 val_acc 0.9508
  [cfc] epoch 7/15 loss 0.0021 val_acc 0.9511
  [cfc] epoch 8/15 loss 0.0016 val_acc 0.9535
  [cfc] epoch 9/15 loss 0.0013 val_acc 0.9553
  [cfc] epoch 10/15 loss 0.0010 val_acc 0.9570
  [cfc] epoch 11/15 loss 0.0009 val_acc 0.9571
  [cfc] epoch 12/15 loss 0.0008 val_acc 0.9593
  [cfc] epoch 13/15 loss 0.0008 val_acc 0.9584
  [cfc] epoch 14/15 loss 0.0007 val_acc 0.9592
  [cfc] epoch 15/15 loss 0.0006 val_acc 0.9604
  [lstm] epoch 1/15 loss 4.7536 val_acc 0.9073
  [lstm] epoch 2/15 loss 1.9964 val_acc 0.9173
  [lstm] epoch 3/15 loss 0.9941 val_acc 0.9243
  [lstm] epoch 4/15 loss 0.0051 val_acc 0.9242
  [lstm] epoch 5/15 loss 0.0034 val_acc 0.9237
  [lstm] epoch 6/15 loss 0.0026 val_acc 0.9319
  [lstm] epoch 7/15 loss 0.0020 val_acc 0.9279
  [lstm] epoch 8/15 loss 0.0016 val_acc 0.9294
  [lstm] epoch 9/15 loss 0.0017 val_acc 0.9332
  [lstm] epoch 10/15 loss 0.0012 val_acc 0.9301
  [lstm] epoch 11/15 loss 0.0011 val_acc 0.9306
  [lstm] epoch 12/15 loss 0.0010 val_acc 0.9303
  [lstm] epoch 13/15 loss 0.0008 val_acc 0.9309
  [lstm] epoch 14/15 loss 0.0007 val_acc 0.9318
  [lstm] epoch 15/15 loss 0.0007 val_acc 0.9319
  [gru] epoch 1/15 loss 3.6127 val_acc 0.9137
  [gru] epoch 2/15 loss 2.6181 val_acc 0.9175
  [gru] epoch 3/15 loss 0.3292 val_acc 0.9295
  [gru] epoch 4/15 loss 0.0044 val_acc 0.9256
  [gru] epoch 5/15 loss 0.0030 val_acc 0.9286
  [gru] epoch 6/15 loss 0.0024 val_acc 0.9377
  [gru] epoch 7/15 loss 0.0020 val_acc 0.9341
  [gru] epoch 8/15 loss 0.0015 val_acc 0.9380
  [gru] epoch 9/15 loss 0.0013 val_acc 0.9401
  [gru] epoch 10/15 loss 0.0012 val_acc 0.9398
  [gru] epoch 11/15 loss 0.0010 val_acc 0.9426
  [gru] epoch 12/15 loss 0.0009 val_acc 0.9452
  [gru] epoch 13/15 loss 0.0007 val_acc 0.9470
  [gru] epoch 14/15 loss 0.0006 val_acc 0.9477
  [gru] epoch 15/15 loss 0.0007 val_acc 0.9476
  [cnn] epoch 1/15 loss 4.3882 val_acc 0.9476
  [cnn] epoch 2/15 loss 1.3573 val_acc 0.9589
  [cnn] epoch 3/15 loss 0.0068 val_acc 0.9620
  [cnn] epoch 4/15 loss 0.0051 val_acc 0.9647
  [cnn] epoch 5/15 loss 0.0030 val_acc 0.9627
  [cnn] epoch 6/15 loss 0.0024 val_acc 0.9665
  [cnn] epoch 7/15 loss 0.0020 val_acc 0.9689
  [cnn] epoch 8/15 loss 0.0015 val_acc 0.9682
  [cnn] epoch 9/15 loss 0.0015 val_acc 0.9690
  [cnn] epoch 10/15 loss 0.0012 val_acc 0.9673
  [cnn] epoch 11/15 loss 0.0010 val_acc 0.9670
  [cnn] epoch 12/15 loss 0.0008 val_acc 0.9677
  [cnn] epoch 13/15 loss 0.0006 val_acc 0.9694
  [cnn] epoch 14/15 loss 0.0004 val_acc 0.9736
  [cnn] epoch 15/15 loss 0.0005 val_acc 0.9724
ensemble weights (gbdt, ebm, cfc) = [0.0, 1.0, 0.0], temperature 1.5, val NLL 0.0668
attributions val: 6000 snapshots in 8.1s; IG completeness gap median 0.02076, p99 0.1674
attributions cal: 6000 snapshots in 7.6s; IG completeness gap median 0.01592, p99 0.0893
attributions test: 6000 snapshots in 7.6s; IG completeness gap median 0.01751, p99 0.101
```