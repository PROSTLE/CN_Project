"""Mark experiment_runs whose evidence folder was moved to evidence/superseded/."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "brain"))
from glasswall_brain.config import path
from glasswall_brain.db import connect

con = connect()
sup = path("evidence_dir") / "superseded"
n = 0
for r in con.execute("SELECT id, name, evidence_dir FROM experiment_runs").fetchall():
    p = Path(r["evidence_dir"] or "")
    if r["evidence_dir"] and not p.exists() and (sup / p.name).exists():
        con.execute("UPDATE experiment_runs SET name=?, evidence_dir=? WHERE id=?",
                    ("[superseded] " + r["name"].removeprefix("[superseded] "), str(sup / p.name), r["id"]))
        n += 1
con.commit()
print("marked", n)
