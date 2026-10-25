"""Build / tear down the GLASSWALL lab with Linux network namespaces.

Replaces the docker-compose topology of the design (Docker is not installed):
  attacker ns  --veth-->  gateway ns (XDP, ip_forward)  --veth-->  victim ns
  client ns    --veth-->/
Victim services: HTTP (python http.server) and sshd on the configured ports.
Run as root inside WSL2:  python lab/topology.py up|down|status
"""
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CFG = yaml.safe_load((ROOT / "config/glasswall.yaml").read_text())
LAB = CFG["lab"]
NS = LAB["namespaces"]
RUN = Path(CFG["paths"]["run_dir"])


def sh(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd}\n{r.stderr}")
    return r


def nsx(ns: str, cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    return sh(f"ip netns exec {ns} {cmd}", check)


def up() -> None:
    down(quiet=True)
    RUN.mkdir(parents=True, exist_ok=True)
    gw = NS["gateway"]
    sh(f"ip netns add {gw}")
    nsx(gw, "ip link set lo up")
    nsx(gw, "sysctl -qw net.ipv4.ip_forward=1")
    for link in LAB["links"]:
        ns, gif = link["ns"], link["gw_if"]
        peer = f"{gif}-p"
        sh(f"ip netns add {ns}")
        nsx(ns, "ip link set lo up")
        sh(f"ip link add {gif} type veth peer name {peer}")
        sh(f"ip link set {gif} netns {gw}")
        sh(f"ip link set {peer} netns {ns}")
        nsx(ns, f"ip link set {peer} name eth0")
        nsx(gw, f"ip addr add {link['gw_ip']} dev {gif}")
        nsx(gw, f"ip link set {gif} up")
        nsx(ns, f"ip addr add {link['host_ip']} dev eth0")
        nsx(ns, "ip link set eth0 up")
        nsx(ns, f"ip route add default via {link['gw_ip'].split('/')[0]}")
        # generic XDP sees GSO super-packets otherwise; keep per-packet records
        nsx(ns, "ethtool -K eth0 tso off gso off gro off", check=False)
        nsx(gw, f"ethtool -K {gif} tso off gso off gro off", check=False)
    start_victim_services()
    print("lab up:", status())


def start_victim_services() -> None:
    vic = NS["victim"]
    www = RUN / "www"
    www.mkdir(parents=True, exist_ok=True)
    # content of varying size for benign browsing
    for i, kb in enumerate((1, 4, 16, 64, 256)):
        (www / f"page{i}.html").write_bytes(b"<html>" + b"x" * (kb * 1024) + b"</html>")
    (www / "index.html").write_text("<html>glasswall lab victim</html>")
    port = LAB["http_port"]
    sh(f"ip netns exec {vic} nohup python3 -m http.server {port} --directory {www} "
       f"> {RUN}/http.log 2>&1 &")
    sshd_cfg = RUN / "sshd_config"
    ports = "\n".join(f"Port {p}" for p in LAB["ssh_ports"])
    sshd_cfg.write_text(
        f"{ports}\nPasswordAuthentication yes\nPermitRootLogin no\nUsePAM no\n"
        f"PidFile {RUN}/sshd.pid\nMaxStartups 100:30:200\nMaxAuthTries 3\n"
    )
    sh("mkdir -p /run/sshd && ssh-keygen -A", check=False)
    sh(f"ip netns exec {vic} /usr/sbin/sshd -f {sshd_cfg}")
    sh(f"ip netns exec {vic} nohup iperf3 -s > {RUN}/iperf3.log 2>&1 &")
    setup_lab_auth()


def setup_lab_auth() -> None:
    """Key for benign SSH sessions; random wordlist (never the real password)
    for brute-force scenarios. The lab user gets a random password so password
    guessing can never succeed."""
    import secrets
    sc = yaml.safe_load((ROOT / "config/scenarios.yaml").read_text())
    user = sc["lab_user"]
    lab = Path(CFG["paths"]["state_dir"]) / "lab"
    lab.mkdir(parents=True, exist_ok=True)
    key = lab / "id_ed25519"
    if not key.exists():
        sh(f"ssh-keygen -q -t ed25519 -N '' -f {key}")
        sh(f"id {user} || useradd -m -s /bin/bash {user}")
        sh(f"echo '{user}:{secrets.token_hex(16)}' | chpasswd")
        home = Path(f"/home/{user}/.ssh")
        home.mkdir(parents=True, exist_ok=True)
        (home / "authorized_keys").write_text((lab / "id_ed25519.pub").read_text())
        sh(f"chown -R {user}:{user} {home} && chmod 700 {home} && chmod 600 {home}/authorized_keys")
    words = RUN / "wordlist.txt"
    words.write_text("\n".join(secrets.token_hex(4) for _ in range(5000)) + "\n")


def down(quiet: bool = False) -> None:
    sh(f"pkill -f 'http.server {LAB['http_port']}'", check=False)
    sh("pkill -f 'iperf3 -s'", check=False)
    pid = RUN / "sshd.pid"
    if pid.exists():
        sh(f"kill $(cat {pid})", check=False)
        pid.unlink(missing_ok=True)
    for ns in list(NS.values()):
        sh(f"ip netns del {ns}", check=False)
    if not quiet:
        print("lab down")


def status() -> str:
    out = sh("ip netns list", check=False).stdout.split()
    present = [n for n in NS.values() if n in out]
    return f"namespaces present: {present}"


if __name__ == "__main__":
    {"up": up, "down": down, "status": lambda: print(status())}[sys.argv[1]]()
