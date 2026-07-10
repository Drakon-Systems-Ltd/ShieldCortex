# ShieldCortex — Hermes plugin

Brings ShieldCortex's defence pipeline to the **Hermes** agent runtime, the way
`shieldcortex-realtime` does for OpenClaw. Hermes is Python and diverges from
OpenClaw, so this is a Hermes-native plugin, not a shim.

## Phase 1 (this)

`register(ctx)` registers a **`pre_tool_call`** gate. Before every Hermes tool
execution it scans the tool + args through ShieldCortex (`POST /api/v1/scan`) and
**hard-blocks** a BLOCK/QUARANTINE verdict by returning
`{"action": "block", "message": …}` (Hermes honours first-block-wins).

- **Enforce by default (v4.47.2).** The gate blocks out of the box. To watch what
  *would* be blocked without blocking (advisory / warn-only), opt out explicitly
  with `SHIELDCORTEX_ENFORCE=0` (also accepts `false` / `no` / `off` / `advisory`).
  Earlier releases defaulted to advisory and required `SHIELDCORTEX_ENFORCE=1` to
  block — that opt-in is no longer needed.
- **Fail-open.** If the ShieldCortex API is unreachable, the gate never blocks —
  a down scanner must not wedge the agent. Every fail-open is logged. (Unchanged
  by the enforce-default flip.)

## Requires

A running ShieldCortex **API server** (the "Python via REST" surface):
`http://127.0.0.1:3001` by default — override with `SHIELDCORTEX_API_URL`.

## Install (Hermes)

Drop this folder at `~/.hermes/plugins/shieldcortex/` and enable it:
`hermes plugins enable shieldcortex` (or add to `plugins.enabled` in
`~/.hermes/config.yaml`).

## Test

Core logic is unit-tested with no Hermes SDK required:

```bash
python3 -m unittest discover -s plugins/hermes/shieldcortex/tests
```

## Roadmap (Phase 2)

- `transform_tool_result` / `transform_terminal_output` — scrub injection / leaks
  out of fetched content before the model sees it (Environment Firewall parity).
- `pre_llm_call` — inject recall / guardrail context (`{"context": …}`).
- `pre_approval_request` — attach an **Overseer Guard** report (manipulation of the
  human approver) at Hermes' approval boundary.
- `memory/shieldcortex` **MemoryProvider** — guard `on_memory_write` (admission to
  durable memory) + `prefetch` / `on_pre_compress` (recall lifecycle).

## Hermes integration reference

Plugin model and hook/memory APIs per TARS (runs native on Hermes):
`~/.hermes/hermes-agent/website/docs/{guides/build-a-hermes-plugin,user-guide/features/hooks}.md`,
`hermes_cli/plugins.py`, `agent/memory_provider.py`. Hermes hooks used:
`pre_tool_call` (block-capable), plus Phase-2 `transform_*`, `pre_llm_call`,
`pre_approval_request`, and the `MemoryProvider` lifecycle.
