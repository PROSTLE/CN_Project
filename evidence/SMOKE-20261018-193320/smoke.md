# Datapath smoke test

Environment: WSL2 6.6.87.2-microsoft-standard-WSL2, network namespaces, xdpgeneric on veth. Raw output:

```
lab up: namespaces present: ['gwgw', 'gwatt', 'gwcli', 'gwvic']
attached xdpgeneric on v-att (ifindex 40)
attached xdpgeneric on v-cli (ifindex 42)
attached xdpgeneric on v-vic (ifindex 44)
agent ready: events=/run/glasswall/dp_events.sock ctl=/run/glasswall/dp_ctl.sock
--- HELLO
OK 7 path=xdp_generic ifaces=v-att,v-cli,v-vic realizable=0:k_src_pkts,1:k_src_syn_ratio_pm,2:k_src_rst_ratio_pm,3:k_src_mean_size,4:k_src_dports,5:k_src_dsts,6:k_src_pps,7:k_src_syn_count max_rules=32 max_pred=4
--- baseline curl attacker->victim (HTTP code)
200
--- DROP attacker source
OK 39
000
curl failed (expected: dropped)
--- client still allowed
200
--- agent refuses a verdict on the safety port 2222
ERR safety-allowlist
--- RATE_LIMIT attacker 20pps burst 40, ping flood 200 pkts at 500 pps
OK 28
200 packets transmitted, 69 received, 65.5% packet loss, time 1485ms
rtt min/avg/max/mdev = 0.037/0.250/11.601/1.377 ms
OK 16
--- rule: k_src_syn_count >= 50 -> DROP staged in the inactive array, then FLIP
OK 21 0
OK 92
OK 20
OK 21 active=1
OK 17 1

Nmap done: 1 IP address (1 host up) scanned in 65.13 seconds
--- rule 7 hits (matched dropped)
OK 46 1143 1143
--- STATS (total pass safety drop_flow drop_src drop_prefix drop_rule rate_drop rb_full emitted non_ip)
OK 718 2153 853 0 0 3 0 1143 131 0 1886 23 ev_dropped=1886 active=1
agent stopped, XDP detached
```
