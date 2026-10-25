"""Integration check (not a pytest unit test): real swtpm + ledger + verifier on a scratch DB.
Run as root in WSL with GW_PATH_DB_FILE pointing at a scratch file."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "brain"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from glasswall_brain import db as dbm, tpm
from glasswall_brain.ledger import Ledger
from verify_ledger import verify

con = dbm.init()
L = Ledger("ms-integration-test", con=con)
L.reset_measurements()
print("pcr after reset", tpm.pcr_read()[:16])
print("pcr after extend", L.measure("model_set", "ab" * 32, "fixture")[:16])
for i in range(600):
    L.append("fixture", str(i), {"i": i})
L.seal_now()
n = con.execute("SELECT COUNT(*) FROM merkle_batches").fetchone()[0]
print("batches", n)
r = verify(None, quotes=True)
print("verify:", r)
try:
    con.execute("UPDATE ledger_entries SET payload='x' WHERE seq=5")
    print("ERROR: update allowed")
except Exception as e:
    print("append-only trigger:", e)
