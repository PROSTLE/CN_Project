"""Web path enumeration (dirb-style brute force) against the lab victim.

One new TCP connection per request, random dictionary-like paths, as fast as
the server answers. Payload content is irrelevant to GLASSWALL (no payload
features); what matters is the connection/timing pattern.
"""
import argparse
import http.client
import random
import string
import time


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--seed", type=int, required=True)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    end = time.monotonic() + a.duration
    while time.monotonic() < end:
        path = "/" + "".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 10)))
        if rng.random() < 0.3:
            path += rng.choice([".php", ".bak", ".old", "/", ".zip", "/admin"])
        try:
            c = http.client.HTTPConnection(a.target, a.port, timeout=3)
            c.request("GET", path)
            c.getresponse().read()
            c.close()
        except OSError:
            pass


if __name__ == "__main__":
    main()
