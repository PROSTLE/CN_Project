"""Client side of the datapath agent's two Unix sockets.

Event lines (agent.c):
  P ts cli srv cport sport proto ifindex idx len dir flags vsrc action rule canary f0..f7
  X src <ip>          (reaper expired a source verdict)
Control replies: "OK <latency_us> ..." or "ERR <msg>".
"""
from __future__ import annotations

import socket
import threading
from dataclasses import dataclass

from .config import cfg, kernel_features


@dataclass(slots=True)
class Pkt:
    ts: int
    cli: str
    srv: str
    cport: int
    sport: int
    proto: int
    ifindex: int
    idx: int
    length: int
    dir: int
    flags: int
    vsrc: int
    action: int
    rule: int
    canary: int
    feat: tuple[int, ...]

    @property
    def key(self) -> tuple:
        return (self.cli, self.srv, self.cport, self.sport, self.proto)


N_KFEAT = len(kernel_features())


def parse_line(line: str) -> Pkt | None:
    t = line.split()
    if not t or t[0] != "P" or len(t) != 16 + N_KFEAT:
        return None
    n = [int(x) for x in t[5:16]]   # sport proto ifindex idx len dir flags vsrc action rule canary
    return Pkt(int(t[1]), t[2], t[3], int(t[4]), n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8],
               n[9], n[10], tuple(int(x) for x in t[16:]))


class Ctl:
    """Synchronous control-socket client (thread safe)."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or cfg()["datapath"]["ctl_socket"]
        self.lock = threading.Lock()
        self.sock: socket.socket | None = None
        self.buf = b""

    def _connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(self.path)
        self.sock = s
        self.buf = b""

    def cmd(self, line: str) -> tuple[bool, int, str]:
        """Returns (ok, latency_us, rest)."""
        with self.lock:
            for attempt in (0, 1):
                try:
                    if self.sock is None:
                        self._connect()
                    self.sock.sendall((line + "\n").encode())
                    while b"\n" not in self.buf:
                        chunk = self.sock.recv(65536)
                        if not chunk:
                            raise ConnectionError("agent closed")
                        self.buf += chunk
                    reply, self.buf = self.buf.split(b"\n", 1)
                    break
                except OSError:
                    self.sock = None
                    if attempt:
                        raise
            r = reply.decode().split(" ", 2)
            if r[0] == "OK":
                return True, int(r[1]), r[2] if len(r) > 2 else ""
            return False, 0, " ".join(r[1:])

    def hello(self) -> dict[str, str]:
        ok, _, rest = self.cmd("HELLO")
        if not ok:
            raise RuntimeError(rest)
        return dict(kv.split("=", 1) for kv in rest.split())


def event_lines(path: str | None = None):
    """Yields raw event lines from the agent's events socket (blocking)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path or cfg()["datapath"]["events_socket"])
    buf = b""
    while True:
        chunk = s.recv(1 << 20)
        if not chunk:
            return
        buf += chunk
        *lines, buf = buf.split(b"\n")
        for ln in lines:
            yield ln.decode()
