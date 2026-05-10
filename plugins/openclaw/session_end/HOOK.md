---
name: session_end
description: Clear interceptor deny cache on session end
---

# session_end

Resets the interceptor's per-session deny cache when a session ends, so
short-lived blocks don't carry over to a new agent session. Best-effort —
older OpenClaw runtimes that don't expose a session_end hook fall back to
the interceptor's TTL safety net.

The handler is registered at runtime by the plugin's main entry point
(`./dist/index.js` via `openclaw.extensions` in `package.json`), which calls
`api.registerHook("session_end", ...)` during plugin init. This directory and
its `handler.js` exist to satisfy OpenClaw 2026.5.5+'s install-time hook-pack
validation; the file in this directory is not what gets invoked at runtime.

## Defence audit guarantees

The auto-extract path (`scripts/session-end-hook.mjs`) routes every
captured candidate through the full defence pipeline before insert. ALLOW
rows produce a `defence_audit` row with `source_type = 'hook'` and land
in `memories`. QUARANTINE rows go to the `quarantine` table for review.
BLOCK rows are dropped with an audit trail. Pipeline failures are also
audited so no capture is silently lost. See
`hooks/openclaw/cortex-memory/HOOK.md` for the full guarantees.
