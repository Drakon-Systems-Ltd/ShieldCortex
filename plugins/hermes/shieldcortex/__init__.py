"""
ShieldCortex — Hermes plugin.

Routes Hermes tool calls through ShieldCortex's Action Guard via the
`pre_tool_call` hook (Hermes' real, block-capable interceptor). The heavy logic
lives in `sc_client` (REST call to `POST /api/v1/action-guard`) and `policy`
(verdict → decision) and is unit-tested standalone; this module is thin glue
around `register(ctx)`, the Hermes plugin entrypoint.

Posture: ENFORCE by default (v4.47.2). The gate blocks Action Guard
`block` / `require_approval` verdicts out of the box; set env
`SHIELDCORTEX_ENFORCE=0` (or false/no/off/advisory) to drop `require_approval`
back to advisory (warn-only). Catastrophic `block` still denies. Fail-open on
an unreachable scanner is unchanged — a down scanner never wedges the agent.

Phase 1 (this): pre_tool_call gate. Phase 2: transform_tool_result/terminal
scrubbing, pre_llm_call recall context, pre_approval_request → Overseer Guard,
and a `memory/shieldcortex` MemoryProvider guarding `on_memory_write`.
"""
import json
import logging
import os

try:
    from .sc_client import (
        evaluate_tool_call,
        fallback_catastrophic_match,
        fallback_dangerous_match,
        fallback_surface,
    )
    from .policy import action_guard_decision, resolve_enforce
except ImportError:  # pragma: no cover - standalone import
    from sc_client import (
        evaluate_tool_call,
        fallback_catastrophic_match,
        fallback_dangerous_match,
        fallback_surface,
    )
    from policy import action_guard_decision, resolve_enforce

log = logging.getLogger("shieldcortex.hermes")


def _audit_gate_degraded(tool_name: str, reason: str, denied: bool) -> None:
    """Best-effort `gate_degraded` audit breadcrumb (issue #59).

    Appends to the same ~/.shieldcortex/audit/realtime-*.jsonl stream the
    OpenClaw plugin and Claude Code hook write, so "could not scan" is
    distinguishable from "scanned & allowed" in one unified trail. Never
    raises — an unwritable sink must not affect the gate decision (it is
    logged loudly by the caller's warning either way).
    """
    try:
        from datetime import datetime, timezone

        audit_dir = os.path.expanduser("~/.shieldcortex/audit")
        os.makedirs(audit_dir, exist_ok=True)
        now = datetime.now(timezone.utc)
        entry = {
            "type": "intercept",
            "origin": "hermes-plugin",
            "tool": tool_name,
            "severity": "critical" if denied else "medium",
            "firewallResult": "ACTION_GUARD",
            "threats": ["fallback-scan"] if denied else [],
            "anomalyScore": 1 if denied else 0.5,
            "trustScore": 0,
            "sensitivityLevel": "INTERNAL",
            "fragmentationScore": None,
            "pipelineDurationMs": 0,
            "preview": f"gate_degraded: {reason}"[:200],
            "ts": now.isoformat(),
            "action": "gate_degraded",
            "outcome": "failure_denied" if denied else "failure_allowed",
        }
        path = os.path.join(audit_dir, f"realtime-{now.date().isoformat()}.jsonl")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("[shieldcortex] audit sink unwritable, gate_degraded entry DROPPED: %s", exc)


def _enforce_default() -> bool:
    # v4.47.2: ENFORCE by default. Opt out with SHIELDCORTEX_ENFORCE=0
    # (or false/no/off/advisory). Fail-open on an unreachable scanner is
    # unchanged and lives in policy.tool_call_decision.
    return resolve_enforce(os.environ.get("SHIELDCORTEX_ENFORCE"))


def register(ctx):
    """Hermes plugin entrypoint — registers the pre_tool_call gate."""
    enforce = _enforce_default()

    def pre_tool_call(tool_name, args, task_id=None, **_kw):
        tool_args = args if isinstance(args, dict) else {}
        verdict = evaluate_tool_call(tool_name, tool_args)
        # Issue #59/WS2: scanner unreachable no longer means blanket fail-open.
        # The dependency-free fallback scan (raw exec surface, not the JSON blob)
        # denies catastrophic shapes always and dangerous shapes when enforcing;
        # everything else still fails open — loudly, as gate_degraded.
        fallback_blocked = False
        fallback_dangerous = False
        if not verdict.available:
            surface = fallback_surface(tool_args)
            fallback_blocked = fallback_catastrophic_match(surface)
            fallback_dangerous = fallback_dangerous_match(surface)
            denied = fallback_blocked or (fallback_dangerous and enforce)
            _audit_gate_degraded(tool_name, verdict.reason, denied)
        fallback_denies = fallback_blocked or (fallback_dangerous and enforce)
        if (verdict.available and verdict.decision != "allow") or fallback_denies:
            tier = "FALLBACK_BLOCK (catastrophic)" if fallback_blocked else (
                "FALLBACK_BLOCK (dangerous)" if fallback_denies else verdict.decision)
            log.warning(
                "[shieldcortex] %s on tool %r: %s",
                tier, tool_name, verdict.reason or verdict.signals,
            )
        elif not verdict.available:
            log.warning(
                "[shieldcortex] gate_degraded on tool %r — scanner unavailable, fallback "
                "%s, allowing (fail-open): %s",
                tool_name,
                "matched a dangerous shape but advisory mode is on" if fallback_dangerous
                else "matched nothing",
                verdict.reason,
            )
        else:
            log.info("[shieldcortex] %s on tool %r", verdict.decision, tool_name)
        return action_guard_decision(
            verdict, enforce=enforce,
            fallback_blocked=fallback_blocked, fallback_dangerous=fallback_dangerous,
        )

    ctx.register_hook("pre_tool_call", pre_tool_call)
    log.info("[shieldcortex] Hermes plugin registered (pre_tool_call, enforce=%s)", enforce)
    return {"name": "shieldcortex", "hooks": ["pre_tool_call"], "enforce": enforce}
