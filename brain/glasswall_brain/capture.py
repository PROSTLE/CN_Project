"""Record the agent's raw event stream to disk (gzip text, one line per event).

The training set is built by replaying these files through the same
FlowTable used online (features.py), so offline == online by construction.

  python -m glasswall_brain.capture <out.events.gz>
"""
import gzip
import signal
import sys

from .dp import event_lines


def main() -> None:
    out = gzip.open(sys.argv[1], "wt", compresslevel=3)
    def on_sig(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, on_sig)
    signal.signal(signal.SIGINT, on_sig)
    n = 0
    try:
        for ln in event_lines():
            out.write(ln + "\n")
            n += 1
    finally:
        out.close()
        print(f"captured {n} events", file=sys.stderr)


if __name__ == "__main__":
    main()
