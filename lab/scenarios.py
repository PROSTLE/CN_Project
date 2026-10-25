"""Run allow-listed lab scenarios and record attack_runs (labels by construction).

  python lab/scenarios.py schedule <name> <out_dir>   # full capture schedule
  python lab/scenarios.py one <scenario> <out_dir>     # single run (demo)

Every run appends one JSON line to <out_dir>/attack_runs.jsonl with the
monotonic start/end time in ns (CLOCK_MONOTONIC = bpf_ktime_get_ns clock).
"""
import json
import random
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CFG = yaml.safe_load((ROOT / "config/glasswall.yaml").read_text())
SC = yaml.safe_load((ROOT / "config/scenarios.yaml").read_text())
LAB = CFG["lab"]
NS_IP = {
    "attacker": (LAB["namespaces"]["attacker"], LAB["attacker_ip"]),
    "client": (LAB["namespaces"]["client"], LAB["client_ip"]),
}
PY = sys.executable


def render(name: str, seed: int, duration: float | None = None) -> tuple[dict, str]:
    s = SC["scenarios"][name]
    dur = duration if duration is not None else s["duration"]
    cmd = s["cmd"].format(victim=LAB["victim_ip"], http_port=LAB["http_port"], ssh_port=SC["ssh_port"],
                          lab_user=SC["lab_user"], run_dir=CFG["paths"]["run_dir"], root=ROOT, py=PY,
                          duration=int(dur), seed=seed)
    return {**s, "duration": dur}, cmd


def record(out: Path, rec: dict) -> None:
    with (out / "attack_runs.jsonl").open("a") as f:
        f.write(json.dumps(rec) + "\n")


def run_one(name: str, out: Path, seed: int) -> dict:
    s, cmd = render(name, seed)
    ns, ip = NS_IP[s["ns"]]
    full = f"ip netns exec {ns} timeout -s INT {int(s['duration'])} sh -c {shlex.quote(cmd)}"
    t0 = time.monotonic_ns()
    r = subprocess.run(full, shell=True, capture_output=True, text=True)
    t1 = time.monotonic_ns()
    rec = {"run_id": uuid.uuid4().hex[:12], "scenario": name, "class": s["class"], "ns": s["ns"],
           "src_ip": ip, "label": s["label"], "evasion": bool(s.get("evasion")), "t_start_ns": t0,
           "t_end_ns": t1, "cmd": cmd, "exit": r.returncode, "seed": seed,
           "stderr_tail": r.stderr[-300:]}
    record(out, rec)
    print(f"[{name}] class={s['class']} {(t1 - t0) / 1e9:.1f}s exit={r.returncode}", flush=True)
    return rec


def schedule(name: str, out: Path) -> None:
    sch = SC["schedules"][name]
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(CFG["models"]["seed"])
    total = sum(SC["scenarios"][n]["duration"] + sch["gap_s"] for n in sch["scenarios"]) * sch["rounds"]
    # background benign traffic from the client for the whole session
    ns, ip = NS_IP["client"]
    seed = rng.randint(0, 2**31)
    bcmd = f"{PY} {ROOT}/lab/gen/benign_mix.py --target {LAB['victim_ip']} --duration {total + 10} --seed {seed}"
    t0 = time.monotonic_ns()
    bg = subprocess.Popen(f"ip netns exec {ns} {bcmd}", shell=True)
    for rnd in range(sch["rounds"]):
        order = list(sch["scenarios"])
        rng.shuffle(order)
        print(f"--- round {rnd + 1}/{sch['rounds']}: {order}", flush=True)
        for sc_name in order:
            run_one(sc_name, out, rng.randint(0, 2**31))
            time.sleep(sch["gap_s"])
    bg.terminate()
    bg.wait()
    record(out, {"run_id": uuid.uuid4().hex[:12], "scenario": "benign_client", "class": "Benign",
                 "ns": "client", "src_ip": ip, "label": "source", "evasion": False, "t_start_ns": t0,
                 "t_end_ns": time.monotonic_ns(), "cmd": bcmd, "exit": 0, "seed": seed, "stderr_tail": ""})
    print("schedule done", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "schedule":
        schedule(sys.argv[2], Path(sys.argv[3]))
    elif sys.argv[1] == "one":
        o = Path(sys.argv[3])
        o.mkdir(parents=True, exist_ok=True)
        run_one(sys.argv[2], o, random.randint(0, 2**31))
