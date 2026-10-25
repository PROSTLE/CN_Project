Superseded: first train2 run used a flow-count-quantile temporal split that left classes missing from val/cal/test (see metrics.md flows-per-split). Replaced by the round-based temporal split.
Superseded: train_20261018-190935 modelled DDoS with 1 unique calibration point; Mondrian threshold infinite -> DDoS in every set (calibration refused tau_hi). Replaced by run with minimum class support.
Superseded: run ms-20261018-191642 - eval/calibration files were uniformly subsampled, leaving BruteForce with 10 calibration points (< min support 19) -> infinite Mondrian threshold -> BruteForce in every set -> ~99% benign QUARANTINE in E1. Fixed with per-class subsampling.
Superseded: SMOKE-20261018-192355 - HELLO sent before agent socket was ready (fixed: wait for 'agent ready').
Superseded: E5-20261018-194541 - stale SQLite -wal files leaked tampering between trials (detection valid, localization not). Fixed and re-run.
