"""Quick live status: decision counts, brain status, rules."""
import json, sqlite3
c = sqlite3.connect("file:/var/lib/glasswall/glasswall.db?mode=ro", uri=True)
print(c.execute("select decision,count(*) from decisions group by decision").fetchall())
s = json.loads(c.execute("select json from brain_status").fetchone()[0])
print({k: s[k] for k in ("events", "decisions", "queue", "p50_event_to_decision_ms", "p99_event_to_decision_ms", "dropped_queue", "ledger_seq")})
print(c.execute("select id,status,text,reason from rules").fetchall())
