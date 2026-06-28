"""
Map a ShieldCortex Verdict to a Hermes hook decision.

Hermes `pre_tool_call` blocks by returning ``{"action": "block", "message": ...}``
(first block wins) and allows by returning ``None``. We mirror ShieldCortex's
own posture: advisory-first. `enforce=False` (the default) never blocks — it only
surfaces the verdict for logging — so a deployment can watch what *would* be
blocked before turning enforcement on, exactly as the OpenClaw/Environment-Firewall
rollout did.
"""
from __future__ import annotations

try:
    from .sc_client import Verdict  # as a Hermes package
except ImportError:  # pragma: no cover - standalone (tests add the package dir to sys.path)
    from sc_client import Verdict


def tool_call_decision(
    verdict: Verdict,
    *,
    enforce: bool = False,
    quarantine_blocks: bool = True,
):
    """Return a Hermes block dict, or ``None`` to allow.

    - Fail-open: an unavailable scanner never blocks.
    - Advisory: ``enforce=False`` never blocks (warn mode).
    - BLOCK always blocks (when enforcing); QUARANTINE blocks iff ``quarantine_blocks``.
    """
    if not verdict.available:
        return None  # scanner down -> never wedge the agent
    if not enforce:
        return None  # warn mode: caller logs, action proceeds
    should_block = verdict.result == "BLOCK" or (quarantine_blocks and verdict.result == "QUARANTINE")
    if not should_block:
        return None
    detail = verdict.reason or (", ".join(verdict.threats) if verdict.threats else "policy violation")
    return {"action": "block", "message": f"ShieldCortex blocked this action — {detail}"}
