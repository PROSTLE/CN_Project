"""Benign traffic generator (runs inside a lab namespace).

Randomly mixes web browsing (curl), downloads (wget), interactive SSH with key
auth, short iperf3 TCP/UDP transfers and pings, with exponential think time.
All knobs come from config/scenarios.yaml (benign_mix).
"""
import argparse
import random
import subprocess
import threading
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CFG = yaml.safe_load((ROOT / "config/glasswall.yaml").read_text())
SC = yaml.safe_load((ROOT / "config/scenarios.yaml").read_text())
MIX = SC["benign_mix"]
LAB = CFG["lab"]
KEY = Path(CFG["paths"]["state_dir"]) / "lab/id_ed25519"
PAGES = ["index.html"] + [f"page{i}.html" for i in range(5)]


def run(cmd: list[str], timeout: float) -> None:
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        pass


def action(kind: str, target: str, rng: random.Random) -> None:
    port = LAB["http_port"]
    if kind == "web":
        page = rng.choice(PAGES)
        run(["curl", "-s", "-o", "/dev/null", "-m", "5", f"http://{target}:{port}/{page}"], 6)
    elif kind == "wget":
        page = rng.choice(PAGES[3:])
        run(["wget", "-q", "-O", "/dev/null", "-T", "5", f"http://{target}:{port}/{page}"], 6)
    elif kind == "ssh":
        cmd = rng.choice(["uptime", "ls -la", "cat /etc/hostname", "df -h", "ps aux"])
        run(["ssh", "-i", str(KEY), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-p", str(SC["ssh_port"]),
             f"{SC['lab_user']}@{target}", cmd], 10)
    elif kind == "iperf_tcp":
        run(["iperf3", "-c", target, "-t", str(MIX["iperf_seconds"]), "-b", MIX["iperf_tcp_rate"]],
            MIX["iperf_seconds"] + 5)
    elif kind == "iperf_udp":
        run(["iperf3", "-u", "-c", target, "-t", str(MIX["iperf_seconds"]), "-b", MIX["iperf_udp_rate"]],
            MIX["iperf_seconds"] + 5)
    elif kind == "ping":
        run(["ping", "-c", str(rng.randint(1, 5)), "-i", "0.3", target], 5)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--seed", type=int, required=True)
    a = ap.parse_args()
    kinds = list(MIX["weights"])
    weights = [MIX["weights"][k] for k in kinds]
    end = time.monotonic() + a.duration

    def user(seed: int) -> None:
        rng = random.Random(seed)
        while time.monotonic() < end:
            action(rng.choices(kinds, weights)[0], a.target, rng)
            time.sleep(rng.expovariate(1.0 / MIX["think_mean_s"]))

    ts = [threading.Thread(target=user, args=(a.seed + i,)) for i in range(MIX["workers"])]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


if __name__ == "__main__":
    main()
