---
name: before_tool_call
description: Active threat gating on tool calls
---

# before_tool_call

Active threat gating for tool calls. The interceptor inspects each tool call's
arguments against the ShieldCortex defence pipeline and either allows, warns,
or blocks based on severity action policy. Block decisions throw a
`ShieldCortex: …` error which propagates to the caller; non-block errors are
logged and the tool call is allowed through (interceptor must never wedge a
session).

The handler is registered at runtime by the plugin's main entry point
(`./dist/index.js` via `openclaw.extensions` in `package.json`), which calls
`api.registerHook("before_tool_call", ...)` during plugin init. This directory
and its `handler.js` exist to satisfy OpenClaw 2026.5.5+'s install-time
hook-pack validation; the file in this directory is not what gets invoked at
runtime.
