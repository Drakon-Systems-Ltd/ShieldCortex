---
name: llm_input
description: Real-time threat scanning on LLM input
---

# llm_input

Scans inbound LLM prompts (user message + recent history) for prompt-injection
patterns, credential leaks, and other threats. Findings are logged to
`~/.shieldcortex/audit/realtime-<date>.jsonl` and forwarded to ShieldCortex
Cloud when configured.

The handler is registered at runtime by the plugin's main entry point
(`./dist/index.js` via `openclaw.extensions` in `package.json`), which calls
`api.registerHook("llm_input", ...)` during plugin init. This directory and
its `handler.js` exist to satisfy OpenClaw 2026.5.5+'s install-time hook-pack
validation; the file in this directory is not what gets invoked at runtime.
