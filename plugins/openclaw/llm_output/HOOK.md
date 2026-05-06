---
name: llm_output
description: Memory extraction from LLM output
---

# llm_output

Inspects assistant text from LLM output for high-signal patterns (decisions,
fixes, learnings, preferences) and writes them to ShieldCortex memory via the
`remember` MCP tool. Includes a Jaccard-similarity novelty gate to suppress
near-duplicate memories.

The handler is registered at runtime by the plugin's main entry point
(`./dist/index.js` via `openclaw.extensions` in `package.json`), which calls
`api.registerHook("llm_output", ...)` during plugin init. This directory and
its `handler.js` exist to satisfy OpenClaw 2026.5.5+'s install-time hook-pack
validation; the file in this directory is not what gets invoked at runtime.
