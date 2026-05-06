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
