"""E4 - datapath measurements (run as root in WSL; brain must NOT be running).

 (a) atomic rule swap under load: ping flood attacker->victim while the agent
     re-stages the rule array and FLIPs `flips` times; loss vs no-flip baseline.
 (b) drop cost, same host + same offered load (hping3 --flood SYN, fixed
     duration): XDP DROP (source verdict) vs netfilter DROP (iptables FORWARD,
     XDP passing) vs no drop. Reports packets seen/dropped and gateway CPU
     (system+softirq jiffies from /proc/stat over the run).
User-space drop (nfqueue) is NOT implemented in this build - not reported.

  python ml/experiments/e4.py
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "brain"))
sys.path.insert(0, str(ROOT))
from glasswall_brain import db as dbm  # noqa: E402
from glasswall_brain.config import cfg, path  # noqa: E402
from ml.eval.metrics import md_table  # noqa: E402

C = cfg()
LAB = C["lab"]
NS = LAB["namespaces"]
EC = {"ping_interval_s": 0.001, "ping_count": 6000, "flips": 300, "flood_s": 5}


class Agent:
    def __init__(self) -> None:
        self.p = subprocess.Popen(["ip", "netns", "exec", NS["gateway"], str(ROOT / "datapath/build/agent"),
                                   str(ROOT / "datapath/build/glasswall.bpf.o"), str(ROOT / "datapath/build/agent.conf")],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(2)
        self.s = socket.socket(socket.AF_UNIX)
        self.s.connect(C["datapath"]["ctl_socket"])
        self.f = self.s.makefile("r")

    def cmd(self, c: str) -> str:
        self.s.sendall((c + "\n").encode())
        return self.f.readline().strip()

    def stats(self) -> list[int]:
        r = self.cmd("STATS").split()
        return [int(x) for x in r[2:2 + 11]]

    def stop(self) -> None:
        self.s.close()
        self.p.terminate()
        self.p.wait()


def cpu() -> tuple[int, int]:
    v = [int(x) for x in open("/proc/stat").readline().split()[1:]]
    return v[2] + v[6], sum(v)   # system + softirq, total


def ping_loss(agent: Agent | None, flips: int) -> dict:
    p = subprocess.Popen(["ip", "netns", "exec", NS["attacker"], "ping", "-q", "-i", str(EC["ping_interval_s"]),
                          "-c", str(EC["ping_count"]), "-W", "1", LAB["victim_ip"]], stdout=subprocess.PIPE, text=True)
    lat = []
    if agent and flips:
        time.sleep(0.5)
        for i in range(flips):
            t = time.perf_counter()
            agent.cmd("RCLR")
            # log-only rule that never matches traffic of interest (src pkts > 2^62)
            agent.cmd(f"RS 0 {9000 + i % 7} 1 1 0 0 0 1 0 0 4611686018427387904")
            agent.cmd("FLIP")
            lat.append((time.perf_counter() - t) * 1e6)
            time.sleep(EC["ping_count"] * EC["ping_interval_s"] / flips * 0.8)
    out = p.communicate()[0]
    m = re.search(r"(\d+) packets transmitted, (\d+) received", out)
    tx, rx = int(m.group(1)), int(m.group(2))
    return {"tx": tx, "rx": rx, "lost": tx - rx, "flips": flips,
            "stage_flip_us_p50": sorted(lat)[len(lat) // 2] if lat else None,
            "stage_flip_us_max": max(lat) if lat else None}


def flood(agent: Agent, mode: str) -> dict:
    gw = NS["gateway"]
    if mode == "netfilter":
        subprocess.run(["ip", "netns", "exec", gw, "iptables", "-I", "FORWARD", "-s", LAB["attacker_ip"], "-j", "DROP"],
                       check=True)
    if mode == "xdp":
        agent.cmd(f"SV {LAB['attacker_ip']} 1 0 0 0 0")
    s0, c0 = agent.stats(), cpu()
    subprocess.run(["ip", "netns", "exec", NS["attacker"], "timeout", str(EC["flood_s"]), "hping3", "-S", "-p",
                    str(LAB["http_port"]), "--flood", LAB["victim_ip"]], capture_output=True)
    s1, c1 = agent.stats(), cpu()
    nf = None
    if mode == "netfilter":
        out = subprocess.run(["ip", "netns", "exec", gw, "iptables", "-L", "FORWARD", "-v", "-x", "-n"],
                             capture_output=True, text=True).stdout
        nf = int([ln.split()[0] for ln in out.splitlines() if "DROP" in ln and LAB["attacker_ip"] in ln][0])
        subprocess.run(["ip", "netns", "exec", gw, "iptables", "-D", "FORWARD", "-s", LAB["attacker_ip"], "-j", "DROP"])
    if mode == "xdp":
        agent.cmd(f"DSV {LAB['attacker_ip']}")
    d = [b - a for a, b in zip(s0, s1)]
    busy = (c1[0] - c0[0]) / max(1, c1[1] - c0[1])
    return {"mode": mode, "xdp_seen": d[0], "xdp_drop_src": d[4], "netfilter_drop": nf, "seconds": EC["flood_s"],
            "seen_pps": d[0] / EC["flood_s"], "host_sys_softirq_share": busy}


def main() -> None:
    subprocess.run([sys.executable, str(ROOT / "lab/topology.py"), "up"], check=True, capture_output=True)
    a = Agent()
    hello = a.cmd("HELLO")
    res = {"hello": hello, "swap": {"baseline": ping_loss(a, 0), "with_flips": ping_loss(a, EC["flips"])},
           "flood": [flood(a, m) for m in ("none", "xdp", "netfilter")], "params": EC,
           "environment": C["environment"]["label"]}
    a.stop()
    rid = f"E4-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
    d = path("evidence_dir") / rid
    d.mkdir(parents=True, exist_ok=True)
    sw = res["swap"]
    md = [f"# E4 - in-kernel datapath measurements ({rid})", "",
          f"Environment: {C['environment']['label']} (virtualised, no line-rate claim). Agent: {hello}", "",
          "## (a) Atomic A/B rule-array swap under load", "",
          md_table(["run", "ICMP sent", "received", "lost", "flips", "stage+flip p50 us", "max us"],
                   [[k, v["tx"], v["rx"], v["lost"], v["flips"], v["stage_flip_us_p50"] or "-", v["stage_flip_us_max"] or "-"]
                    for k, v in sw.items()]),
          "", "## (b) Drop path at equal offered load (hping3 --flood SYN, single sender)", "",
          md_table(["mode", "packets seen at XDP", "dropped by XDP", "dropped by netfilter", "seen pps",
                    "host system+softirq CPU share"],
                   [[f["mode"], f["xdp_seen"], f["xdp_drop_src"], f["netfilter_drop"] if f["netfilter_drop"] is not None else "-",
                     f"{f['seen_pps']:.0f}", f"{f['host_sys_softirq_share']:.3f}"] for f in res["flood"]]),
          "", "User-space drop baseline (nfqueue) not implemented in this build; not reported."]
    (d / "e4.md").write_text("\n".join(md))
    (d / "e4.json").write_text(json.dumps(res, indent=2))
    con = dbm.connect()
    dbm.record_experiment(con, rid, "E4 datapath swap + drop cost", res, str(d), dataset="lab live traffic")
    print("\n".join(md))


if __name__ == "__main__":
    main()
