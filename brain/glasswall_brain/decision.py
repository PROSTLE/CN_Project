"""Tri-state decision table (Invention 2), first match wins (TRD TR-C-3).

  R1 E < tau_lo                      -> QUARANTINE + ADVERSARIAL
  R2 S empty                         -> QUARANTINE
  R3 S has benign AND attack         -> QUARANTINE
  R4 S only attack, E >= tau_hi      -> BLOCK
  R5 S only benign, E >= tau_hi      -> ALLOW
  R6 S only attack, tau_lo<=E<tau_hi -> QUARANTINE
  R7 S only benign, tau_lo<=E<tau_hi -> ALLOW_SHADOW (allow + shadow-log)
"""
from __future__ import annotations

from dataclasses import dataclass

ALLOW, ALLOW_SHADOW, BLOCK, QUARANTINE = "ALLOW", "ALLOW_SHADOW", "BLOCK", "QUARANTINE"


@dataclass(frozen=True, slots=True)
class Decision:
    action: str
    row: str
    adversarial: bool


def decide(S: set[int], E: float, tau_lo: float, tau_hi: float, attack: set[int], benign: int) -> Decision:
    if not tau_hi > tau_lo:
        raise ValueError("tau_hi must be > tau_lo")
    has_att = bool(S & attack)
    has_ben = benign in S
    if E < tau_lo:
        return Decision(QUARANTINE, "R1", True)
    if not S:
        return Decision(QUARANTINE, "R2", False)
    if has_att and has_ben:
        return Decision(QUARANTINE, "R3", False)
    only_att = has_att and S <= attack
    only_ben = S == {benign}
    if only_att and E >= tau_hi:
        return Decision(BLOCK, "R4", False)
    if only_ben and E >= tau_hi:
        return Decision(ALLOW, "R5", False)
    if only_att:
        return Decision(QUARANTINE, "R6", False)
    if only_ben:
        return Decision(ALLOW_SHADOW, "R7", False)
    # S contains only classes that are neither benign nor attack (none configured)
    return Decision(QUARANTINE, "R2", False)


def kernel_action(d: Decision) -> str:
    """BLOCK -> DROP, ALLOW* -> PASS, QUARANTINE -> RATE_LIMIT (TRD TR-C-4)."""
    return {BLOCK: "DROP", ALLOW: "PASS", ALLOW_SHADOW: "PASS", QUARANTINE: "RATE_LIMIT"}[d.action]
