#!/usr/bin/env bash
# GLASSWALL one-shot environment setup inside Ubuntu WSL2 (run as root).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  clang llvm libbpf-dev libelf-dev zlib1g-dev linux-libc-dev gcc make pkg-config \
  iproute2 nmap hping3 iperf3 hydra slowhttptest openssh-server curl \
  python3-venv python3-pip swtpm swtpm-tools tpm2-tools ca-certificates
mkdir -p /opt/glasswall /var/lib/glasswall
if [ ! -d /opt/glasswall/venv ]; then python3 -m venv /opt/glasswall/venv; fi
/opt/glasswall/venv/bin/pip install --upgrade pip
/opt/glasswall/venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu
/opt/glasswall/venv/bin/pip install -r /mnt/c/Lang/CN/requirements.txt
echo SETUP_DONE
