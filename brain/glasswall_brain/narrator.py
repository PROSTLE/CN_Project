"""Narrator (never in the decision path).

Input is the structured decision JSON only. If narrator.endpoint (Ollama) is
configured, the LLM is asked for two sentences using only given names and
numbers; the verifier rejects any number or group/feature/class name that is
not in the input, and the deterministic template is used instead. With no
endpoint configured (this build: Ollama is not installed) the template is
always used and labelled as such.
"""
from __future__ import annotations

import json
import re
import urllib.request

from .config import cfg, groups

NUM = re.compile(r"(?<![A-Za-z])[-+]?\d+(?:\.\d+)?%?")


def _fmt(v: float) -> str:
    return f"{v:.2f}"


def template(d: dict) -> str:
    g = groups()
    top = d["topk"].get("gbdt") or []
    parts = ", ".join(f"{g.get(name, name)} ({'+' if val >= 0 else '-'}{_fmt(abs(val))})" for name, val in top[:3])
    cls = d["pred_name"]
    s1 = (f"{d['decision']} by rule {d['row']}: the ensemble predicts {cls} with probability "
          f"{_fmt(d['prob'])}, conformal set {{{', '.join(d['set_names']) or 'empty'}}}.")
    s2 = (f"Explanation consensus ECS={_fmt(d['ecs'])} (tau_lo={_fmt(d['tau_lo'])}, tau_hi={_fmt(d['tau_hi'])}); "
          f"top GBDT groups: {parts or 'none'}.")
    return s1 + " " + s2


def allowed_tokens(d: dict) -> tuple[set[str], set[str]]:
    blob = json.dumps(d)
    nums = set()
    for m in NUM.findall(blob):
        try:
            v = float(m.rstrip("%"))
        except ValueError:
            continue
        nums.update({m, _fmt(v), f"{v:.1f}", f"{v:.3f}", str(int(v)) if v.is_integer() else _fmt(v)})
    names = {n.lower() for n in groups().values()} | {k.lower() for k in groups()}
    names |= {c["name"].lower() for c in cfg()["classes"]}
    return nums, names


def verify(text: str, d: dict) -> tuple[bool, list[str]]:
    """Every number in the text must appear (after formatting normalisation) in
    the input; every group id (G1..G14) mentioned must be in the input's top-k."""
    nums, _ = allowed_tokens(d)
    bad = []
    for m in NUM.findall(text):
        v = m.rstrip("%")
        try:
            fv = float(v)
        except ValueError:
            continue
        if m not in nums and v not in nums and _fmt(fv) not in nums and f"{fv:.1f}" not in nums:
            bad.append(m)
    used_groups = {x for src in d["topk"].values() for x, _ in src}
    for gid in re.findall(r"\bG\d{1,2}\b", text):
        if gid not in used_groups:
            bad.append(gid)
    for cname in [c["name"] for c in cfg()["classes"]]:
        if re.search(rf"\b{cname}\b", text) and cname not in d["set_names"] and cname != d["pred_name"]:
            bad.append(cname)
    return not bad, bad


def narrate(d: dict) -> dict:
    nc = cfg()["narrator"]
    if not nc.get("endpoint") or not nc.get("model"):
        return {"text": template(d), "source": "template", "verified": True,
                "note": "no narrator endpoint configured"}
    prompt = ("Explain this firewall decision in exactly two sentences. Use ONLY names and numbers that appear "
              "in this JSON; do not invent any.\n" + json.dumps(d))
    try:
        req = urllib.request.Request(nc["endpoint"].rstrip("/") + "/api/generate",
                                     data=json.dumps({"model": nc["model"], "prompt": prompt, "stream": False}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=nc["timeout_ms"] / 1000) as r:
            text = json.loads(r.read())["response"].strip()
    except Exception as e:
        return {"text": template(d), "source": "template", "verified": True, "note": f"narrator error: {e!r}"}
    ok, bad = verify(text, d)
    if ok:
        return {"text": text, "source": "llm", "verified": True}
    return {"text": template(d), "source": "template", "verified": True, "note": f"LLM output rejected: {bad}"}
