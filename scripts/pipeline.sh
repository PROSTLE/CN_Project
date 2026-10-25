#!/usr/bin/env bash
# Offline pipeline: datasets -> train -> calibrate. Each stage logs to evidence.
#   scripts/pipeline.sh datasets|train|calibrate|all
set -euo pipefail
ROOT=/mnt/c/Lang/CN
PY=/opt/glasswall/venv/bin/python
S=/var/lib/glasswall
cd "$ROOT"
stage=${1:-all}
summ() { $PY - "$1" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print(sys.argv[1], json.dumps({k: m[k] for k in ("events", "bad_lines", "flows", "by_class_flows",
                                                "by_scenario_flows", "unlabelled_snapshots")}))
PY
}
if [[ $stage == datasets || $stage == all ]]; then
  for c in train2 evasion1; do
    $PY ml/data/build_dataset.py $S/capture/$c $S/datasets/$c > /dev/null
    summ $S/datasets/$c/manifest.json
  done
fi
if [[ $stage == train || $stage == all ]]; then
  $PY ml/train/train_all.py $S/datasets/train2 2>&1 | grep -v -i warning
fi
if [[ $stage == calibrate || $stage == all ]]; then
  $PY scripts/calibrate.py
fi
