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
    from .sc_client import ActionGuardVerdict, Verdict  # as a Hermes package
except ImportError:  # pragma: no cover - standalone (tests add the package dir to sys.path)
    from sc_client import ActionGuardVerdict, Verdict


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
    fallback_dangerous: bool = False,
):
    """Return a Hermes block dict, or ``None`` to allow.

    - Scanner down (issue #59/WS2): fails CLOSED via the dependency-free
      fallback, mirroring the OpenClaw interceptor + Claude Code hook:
        * ``fallback_blocked`` (catastrophic) → block, ALWAYS (ignores advisory
          mode — the hard-block tier).
        * ``fallback_dangerous`` → block when enforcing; ``enforce=False`` opts
          this tier down to advisory (allow + caller logs gate_degraded).
        * neither → fail open — a down scanner must not wedge an agent doing
          normal work.
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
        if fallback_dangerous and enforce:
            return {
                "action": "block",
                "message": (
                    "ShieldCortex blocked this action — scanner unreachable and the "
                    "fallback scan matched a dangerous pattern (failing closed; "
                    "set SHIELDCORTEX_ENFORCE=0 for advisory)"
                ),
            }
        return None  # scanner down, no fallback match (or advisory) -> never wedge the agent
    if not enforce:
        return None  # warn mode: caller logs, action proceeds
    should_block = verdict.result == "BLOCK" or (quarantine_blocks and verdict.result == "QUARANTINE")
    if not should_block:
        return None
    detail = verdict.reason or (", ".join(verdict.threats) if verdict.threats else "policy violation")
    return {"action": "block", "message": f"ShieldCortex blocked this action — {detail}"}


def action_guard_decision(
    verdict: ActionGuardVerdict,
    *,
    enforce: bool = True,
    fallback_blocked: bool = False,
    fallback_dangerous: bool = False,
):
    """Map an Action Guard verdict to a Hermes hook decision.

    Hermes has no approval prompt. ``require_approval`` therefore becomes a
    block when enforcing (same unattended fail-closed the OpenClaw interceptor
    already applies). ``allow`` is None. Scanner-down uses the same fallback
    contract as :func:`tool_call_decision`.

    Issue #63 — name ``shieldcortex approve --denial <actionId>`` ONLY when
    the API recorded a DNP fingerprint (``verdict.denial_action_id``). Bare
    ``shieldcortex approve`` lists held cards that this plane never creates.
    Catastrophic ``block`` never carries an id.

    This function is the ONE renderer of that command. The API's ``reason`` is
    semantic and carries the id in ``denial.actionId``; when both spelled the
    command out, the reject text named it twice. The message stays bounded:
    ``verdict.reason`` is clamped to a single 400-char line by
    ``sanitize_remote_reason`` and the id is regex-validated by
    ``sanitize_denial_action_id``, so the appended sentence is fixed-size.
    """
    if not verdict.available:
        return tool_call_decision(
            Verdict("ERROR", [], verdict.reason, available=False),
            enforce=enforce,
            fallback_blocked=fallback_blocked,
            fallback_dangerous=fallback_dangerous,
        )
    if verdict.decision == "block":
        detail = verdict.reason or "policy violation"
        return {"action": "block", "message": f"ShieldCortex blocked this action — {detail}"}
    if verdict.decision == "require_approval" and enforce:
        detail = verdict.reason or "requires approval"
        message = f"ShieldCortex blocked this action — {detail}"
        action_id = getattr(verdict, "denial_action_id", "")
        if action_id:
            message += (
                " — to allow this exact command once, run in YOUR terminal on this host: "
                f"shieldcortex approve --denial {action_id}"
            )
        return {"action": "block", "message": message}
    return None
