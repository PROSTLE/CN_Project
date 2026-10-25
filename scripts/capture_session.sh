#!/usr/bin/env bash
# Record a labelled lab capture: lab up -> agent attach (no enforcement) ->
# raw event capture -> scenario schedule -> stop.
#   scripts/capture_session.sh <schedule> <session_name>
set -euo pipefail
ROOT=/mnt/c/Lang/CN
PY=/opt/glasswall/venv/bin/python
SCHED=$1
NAME=$2
OUT=/var/lib/glasswall/capture/$NAME
mkdir -p "$OUT" /run/glasswall
rm -f "$OUT/attack_runs.jsonl"
cd "$ROOT"
$PY lab/topology.py up
ip netns exec gwgw ./datapath/build/agent datapath/build/glasswall.bpf.o datapath/build/agent.conf \
  > "$OUT/agent.log" 2>&1 &
AGENT=$!
sleep 2
PYTHONPATH=brain ip netns exec gwgw $PY -m glasswall_brain.capture "$OUT/events.gz" 2> "$OUT/capture.log" &
CAP=$!
sleep 1
$PY lab/scenarios.py schedule "$SCHED" "$OUT" | tee "$OUT/schedule.log"
sleep 4   # let idle flows finish in the stream
python3 - <<'PY' > "$OUT/agent_stats.txt"
import socket
s=socket.socket(socket.AF_UNIX); s.connect("/run/glasswall/dp_ctl.sock")
s.sendall(b"STATS\n"); print(s.recv(4096).decode().strip())
PY
kill $CAP; wait $CAP || true
kill $AGENT; wait $AGENT || true
cat "$OUT/capture.log" "$OUT/agent_stats.txt"
ls -la "$OUT"
