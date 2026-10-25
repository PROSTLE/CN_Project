"""Write a flow-level random subsample of a dataset (for pipeline smoke tests only)."""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

src, dst, frac = Path(sys.argv[1]), Path(sys.argv[2]), float(sys.argv[3])
df = pd.read_parquet(src / "snapshots.parquet")
rng = np.random.default_rng(0)
flows = df["flow_id"].unique()
keep_flows = set(rng.choice(flows, int(len(flows) * frac), replace=False))
m = df["flow_id"].isin(keep_flows) | (df["label"].isin(["Benign", "BruteForce"]))
dst.mkdir(parents=True, exist_ok=True)
df[m].to_parquet(dst / "snapshots.parquet", index=False)
np.save(dst / "sequences.npy", np.load(src / "sequences.npy")[m.to_numpy()])
np.save(dst / "seq_len.npy", np.load(src / "seq_len.npy")[m.to_numpy()])
man = json.loads((src / "manifest.json").read_text())
man["subsample_of"] = str(src); man["fraction"] = frac
(dst / "manifest.json").write_text(json.dumps(man))
print(int(m.sum()), "rows")
