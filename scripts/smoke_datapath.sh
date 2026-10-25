#!/usr/bin/env bash
# Datapath smoke test: lab up, agent attach, traffic, DROP / RATE_LIMIT / safety / rule swap.
# Output is saved to evidence/SMOKE-<ts>/smoke.md (brain must not be running).
set -u
cd /mnt/c/Lang/CN
EV=evidence/SMOKE-$(date +%Y%m%d-%H%M%S)
mkdir -p $EV /run/glasswall
{
echo '# Datapath smoke test'
echo
echo "Environment: WSL2 $(uname -r), network namespaces, xdpgeneric on veth. Raw output:"
echo
echo '```'
/opt/glasswall/venv/bin/python lab/topology.py up
GW=gwgw
ip netns exec $GW ./datapath/build/agent datapath/build/glasswall.bpf.o datapath/build/agent.conf > /run/glasswall/agent.log 2>&1 &
for i in $(seq 50); do grep -q "agent ready" /run/glasswall/agent.log 2>/dev/null && break; sleep 0.2; done
cat /run/glasswall/agent.log
ctl() { /opt/glasswall/venv/bin/python - "$@" <<'PY'
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect("/run/glasswall/dp_ctl.sock")
s.sendall((" ".join(sys.argv[1:])+"\n").encode()); print(s.recv(4096).decode().strip())
PY
}
echo "--- HELLO"; ctl HELLO
echo "--- baseline curl attacker->victim (HTTP code)"; ip netns exec gwatt curl -s -o /dev/null -w "%{http_code}\n" -m 3 http://10.10.9.2/
echo "--- DROP attacker source"; ctl SV 10.10.1.2 1 0 0 0 0
ip netns exec gwatt curl -s -o /dev/null -w "%{http_code}\n" -m 3 http://10.10.9.2/ || echo "curl failed (expected: dropped)"
echo "--- client still allowed"; ip netns exec gwcli curl -s -o /dev/null -w "%{http_code}\n" -m 3 http://10.10.9.2/
echo "--- agent refuses a verdict on the safety port 2222"; ctl FV 10.10.1.2 10.10.9.2 5555 2222 6 1 0 0 0 0
echo "--- RATE_LIMIT attacker 20pps burst 40, ping flood 200 pkts at 500 pps"; ctl SV 10.10.1.2 2 20 40 0 0
ip netns exec gwatt ping -q -i 0.002 -c 200 -W 1 10.10.9.2 | tail -2
ctl DSV 10.10.1.2
echo "--- rule: k_src_syn_count >= 50 -> DROP staged in the inactive array, then FLIP"
ctl ACTIVE; ctl RCLR; ctl RS 0 7 0 1 0 0 0 1 7 1 50; ctl FLIP; ctl ACTIVE
ip netns exec gwatt nmap -sS -p 1-400 -T4 -n 10.10.9.2 2>&1 | tail -2
echo "--- rule 7 hits (matched dropped)"; ctl RH 7
echo "--- STATS (total pass safety drop_flow drop_src drop_prefix drop_rule rate_drop rb_full emitted non_ip)"; ctl STATS
kill %1; sleep 1; tail -1 /run/glasswall/agent.log
echo '```'
} 2>&1 | tee $EV/smoke.md
