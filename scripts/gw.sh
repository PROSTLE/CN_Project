#!/usr/bin/env bash
# GLASSWALL runtime control (run as root inside WSL2 Ubuntu).
#   scripts/gw.sh start | stop | status | logs
set -uo pipefail
ROOT=/mnt/c/Lang/CN
PY=/opt/glasswall/venv/bin/python
RUN=/run/glasswall
LOG=/var/lib/glasswall/logs
mkdir -p $RUN $LOG
cd $ROOT

start() {
  $PY lab/topology.py up
  ip netns exec gwgw ./datapath/build/agent datapath/build/glasswall.bpf.o datapath/build/agent.conf \
    > $LOG/agent.log 2>&1 &
  echo $! > $RUN/agent.pid
  for i in $(seq 50); do grep -q "agent ready" $LOG/agent.log 2>/dev/null && break; sleep 0.2; done
  grep -q "agent ready" $LOG/agent.log || { cat $LOG/agent.log; echo "agent failed"; exit 1; }
  PYTHONPATH=brain nohup $PY -m glasswall_brain.main > $LOG/brain.log 2>&1 &
  echo $! > $RUN/brain.pid
  (cd api && nohup $PY -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > $LOG/api.log 2>&1 &
   echo $! > $RUN/api.pid)
  sleep 6
  tail -3 $LOG/brain.log
  echo "console: http://127.0.0.1:8000"
}

stop() {
  for p in api brain agent; do
    [ -f $RUN/$p.pid ] && kill "$(cat $RUN/$p.pid)" 2>/dev/null && echo "stopped $p"
    rm -f $RUN/$p.pid
  done
  sleep 2
}

status() {
  for p in agent brain api; do
    if [ -f $RUN/$p.pid ] && kill -0 "$(cat $RUN/$p.pid)" 2>/dev/null; then echo "$p: running"; else echo "$p: stopped"; fi
  done
}

case ${1:-status} in
  start) start ;;
  stop) stop ;;
  status) status ;;
  logs) tail -n 30 $LOG/agent.log $LOG/brain.log $LOG/api.log ;;
esac
