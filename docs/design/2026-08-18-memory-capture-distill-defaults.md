# Capture distill — user defaults (zero-config)

**Date:** 2026-08-18  
**PR:** #355 · Track C / epic #347

## What a normal user does

**Nothing extra**, if they already use Hermes (or have OpenAI/Anthropic keys in the environment).

1. Install / upgrade ShieldCortex with Memory SOTA capture hooks.
2. Turn on plane flags (or run `shieldcortex setup --with-stop-hook --with-session-end`):
   - `openclawAutoMemory: true` (or proactiveRecall)
   - Stop + SessionEnd hooks wired
3. Distill **automatically**:
   - Uses **Hermes OAuth on disk** when no API key is set (`xai-oauth` → `openai-codex`)
   - Uses a **cheap background model** by default (`grok-4.3` on xAI, not the main chat model)
   - Fail-closed: if OAuth/model call fails → skip (no silent junk), unless mode is explicit `regex`

## Defaults

| Setting | Default |
|---|---|
| Auth | Hermes OAuth if present; else env API key; else regex L0 only |
| xAI distill model | **`grok-4.3`** |
| Codex distill model | **`gpt-5.5`** |
| OAuth | **on** |
| Disable OAuth | `SHIELDCORTEX_DISTILL_OAUTH=0` |
| Force stronger model | `SHIELDCORTEX_DISTILL_MODEL=grok-4.6` |
| Force regex only | `autoMemory.captureMode: "regex"` or `memory.distill.mode: "regex"` |

## What they do **not** need

- A separate distill API key
- To pick a model for capture
- To change their main Hermes chat model

## Cost posture

Distill runs on stop (~1-in-5 turns) + session-end, short JSON out, capped transcript in.  
Cheap model is the right default; main frontier models stay for interactive work.
