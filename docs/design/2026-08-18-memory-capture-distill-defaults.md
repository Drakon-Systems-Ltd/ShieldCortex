# Capture distill — zero-config defaults (all providers)

**Date:** 2026-08-18  
**PR:** #355 · Track C / epic #347

## What a normal user does

**Nothing extra**, if they already use **any** of:

- Hermes (any logged-in provider), or
- Claude Code / Claude Max OAuth, or
- standard env API keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY`)

1. ShieldCortex with capture hooks on (`setup --with-stop-hook --with-session-end` or plane flags).
2. Distill auth + cheap model resolve automatically.

## Resolution order

1. **Explicit API keys** — `SHIELDCORTEX_DISTILL_*` / `OPENAI_*` / `ANTHROPIC_*` / config
2. **On-disk auth** (OAuth + pools), first hit wins:
   1. Hermes `active_provider` (whatever they already use)
   2. Hermes OAuth: `xai-oauth`, `openai-codex`, `qwen-oauth`, `minimax-oauth`, `nous`
   3. Hermes API-key pools: `anthropic`, `openai-api`, `gemini`, `xai`, `deepseek`, `openrouter`, …
   4. **Claude Max / Claude Code OAuth** — `~/.claude/.credentials.json`
3. Else **regex L0** only (no silent pretend-distill)

## Cheap default models (background distill, not main chat)

| Provider family | Default distill model |
|---|---|
| xAI OAuth / Grok | `grok-4.3` |
| OpenAI Codex | `gpt-5.5` |
| OpenAI API | `gpt-4.1-mini` |
| Anthropic pool / Claude OAuth | `claude-haiku-4-5-20251001` |
| Gemini | `gemini-2.0-flash` |
| DeepSeek | `deepseek-chat` |
| Qwen OAuth | `qwen3-coder-flash` |
| MiniMax OAuth | `MiniMax-M2` |
| OpenRouter | `openai/gpt-4.1-mini` |

## Overrides (optional)

| Goal | How |
|---|---|
| Disable on-disk OAuth/pools | `SHIELDCORTEX_DISTILL_OAUTH=0` |
| Force provider try-order | `SHIELDCORTEX_DISTILL_OAUTH_PROVIDER=anthropic,claude-oauth,xai-oauth` |
| Stronger model | `SHIELDCORTEX_DISTILL_MODEL=grok-4.6` |
| Regex only | `autoMemory.captureMode: "regex"` |

## What users do **not** need

- A separate distill API key
- To re-login for memory
- To pick a distill model
- To change their main chat model

## Cost posture

Stop ~1-in-5 + session-end; short JSON out; cheap model default.  
Main frontier models stay for interactive work.
