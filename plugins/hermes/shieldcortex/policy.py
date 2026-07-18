"""
Map a ShieldCortex Verdict to a Hermes hook decision.

Hermes `pre_tool_call` blocks by returning ``{"action": "block", "message": ...}``
(first block wins) and allows by returning ``None``.

Posture (v4.47.2): ENFORCE by default. `resolve_enforce` resolves the gate's
posture from config/env — enforcing unless an operator explicitly opts out
(`SHIELDCORTEX_ENFORCE=0` / false / no / off / advisory). `enforce=False` still
means warn-only, so a deployment that wants to watch what *would* be blocked can
opt back into advisory without touching the fail-open behaviour.
"""
from __future__ import annotations

try:
    from .sc_client import Verdict  # as a Hermes package
except ImportError:  # pragma: no cover - standalone (tests add the package dir to sys.path)
    from sc_client import Verdict


# v4.47.2: the gate ENFORCES by default. Only an explicit opt-out disables it —
# so an operator can drop back to advisory (warn-only) with SHIELDCORTEX_ENFORCE=0
# (or false/no/off/advisory) without changing the fail-open behaviour.
_ENFORCE_OPTOUT = frozenset({"0", "false", "no", "off", "advisory"})


def resolve_enforce(value: str | None) -> bool:
    """Resolve the enforce posture from a config/env string.

    Default (unset / blank / unknown) → ``True`` (enforce). Returns ``False``
    only for an explicit opt-out word, so garbage never silently downgrades a
    deployment to advisory.
    """
    return (value or "").strip().lower() not in _ENFORCE_OPTOUT


def tool_call_decision(
    verdict: Verdict,
    *,
    enforce: bool = False,
    quarantine_blocks: bool = True,
    fallback_blocked: bool = False,
):
    """Return a Hermes block dict, or ``None`` to allow.

    - Scanner down (issue #59/WS2): fails CLOSED when the caller's
      dependency-free fallback scan matched a catastrophic shape
      (``fallback_blocked=True``) — this mirrors the OpenClaw posture where
      the hard-block tier ignores advisory mode. Anything the fallback does
      not recognise still fails open — a down scanner must not wedge an
      agent doing normal work.
    - Advisory: ``enforce=False`` never blocks (warn mode) — except the
      catastrophic fallback above.
    - BLOCK always blocks (when enforcing); QUARANTINE blocks iff ``quarantine_blocks``.
    """
    if not verdict.available:
        if fallback_blocked:
            return {
                "action": "block",
                "message": (
                    "ShieldCortex blocked this action — scanner unreachable and the "
                    "fallback scan matched a catastrophic pattern (failing closed)"
                ),
            }
        return None  # scanner down, no catastrophic shape -> never wedge the agent
    if not enforce:
        return None  # warn mode: caller logs, action proceeds
    should_block = verdict.result == "BLOCK" or (quarantine_blocks and verdict.result == "QUARANTINE")
    if not should_block:
        return None
    detail = verdict.reason or (", ".join(verdict.threats) if verdict.threats else "policy violation")
    return {"action": "block", "message": f"ShieldCortex blocked this action — {detail}"}
