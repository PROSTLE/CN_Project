# Datapath smoke test

Environment: WSL2 6.6.87.2-microsoft-standard-WSL2, network namespaces, xdpgeneric on veth. Raw output:

```
lab up: namespaces present: ['gwgw', 'gwatt', 'gwcli', 'gwvic']
--- HELLO
Traceback (most recent call last):
  File "<stdin>", line 2, in <module>
FileNotFoundError: [Errno 2] No such file or directory
--- baseline curl attacker->victim (HTTP code)
200
--- DROP attacker source
OK 130
000
curl failed (expected: dropped)
--- client still allowed
200
--- agent refuses a verdict on the safety port 2222
ERR safety-allowlist
--- RATE_LIMIT attacker 20pps burst 40, ping flood 200 pkts at 500 pps
OK 35
200 packets transmitted, 69 received, 65.5% packet loss, time 1476ms
rtt min/avg/max/mdev = 0.058/0.186/2.023/0.252 ms
OK 14
--- rule: k_src_syn_count >= 50 -> DROP staged in the inactive array, then FLIP
OK 20 0
OK 109
OK 24
OK 22 active=1
OK 20 1

Nmap done: 1 IP address (1 host up) scanned in 36.36 seconds
--- rule 7 hits (matched dropped)
OK 24 832 832
--- STATS (total pass safety drop_flow drop_src drop_prefix drop_rule rate_drop rb_full emitted non_ip)
OK 508 1622 643 0 0 3 0 832 131 0 1365 13 ev_dropped=1365 active=1
agent stopped, XDP detached
```
