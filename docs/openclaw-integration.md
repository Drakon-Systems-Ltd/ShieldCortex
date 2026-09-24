# OpenClaw Integration

ShieldCortex integrates with [OpenClaw](https://openclaw.dev) in complement mode by default:
- Real-time defence scanning is on — but on the conversation path it is
  **observe-only by default**, and it runs at all only where the operator has
  granted the plugin conversation access on that host
- The before-tool-call Action Guard is on (catastrophic operations blocked; dangerous operations enforced by default)
- Automatic memory writes are opt-in (off by default)

Context recall at session start is handled by OpenClaw's native Memory Search —
ShieldCortex stopped injecting bootstrap context in v2026.2.26 (it duplicated
what OpenClaw already recalls and ate context window).

This lets OpenClaw keep its native memory behavior while ShieldCortex adds security, auditability, and lower-noise memory extraction when enabled.

## Install

### Native OpenClaw install (preferred)

```bash
openclaw skills install shieldcortex
openclaw plugins install @drakon-systems/shieldcortex-realtime
openclaw gateway restart
```

This uses OpenClaw's native npm hook-pack and plugin-pack install flow. The
hook comes from `shieldcortex`; the real-time plugin comes from the standalone
`@drakon-systems/shieldcortex-realtime` package.

### ShieldCortex wrapper (compatibility path)

```bash
npm install -g shieldcortex
shieldcortex openclaw install
openclaw gateway restart
```

The wrapper also migrates older hook installs out of
`~/.openclaw/hooks/internal/cortex-memory` and removes duplicate legacy copies.

If the wrapper install fails with `permission denied`, use one of these:

```bash
sudo "$(command -v shieldcortex)" openclaw install
```

Or fix ownership so future installs work without `sudo`:

```bash
sudo chown -R "$USER":"$USER" ~/.openclaw ~/.claude
shieldcortex openclaw install
```

Check status:

```bash
shieldcortex openclaw status
```

## What gets installed

The native OpenClaw commands above install both components separately. Existing
wrapper-based installs can keep using `shieldcortex openclaw install`. The
wrapper also installs both components:

1. `cortex-memory` hook
- Path: `~/.openclaw/hooks/cortex-memory/`
- Handles lifecycle wiring on `agent:bootstrap` (security-warning handoff — no
  system-prompt injection since v2026.2.26) + explicit keyword saves

2. `shieldcortex-realtime` plugin
- Native `openclaw plugins install` puts it in OpenClaw's managed npm project
  tree (`~/.openclaw/npm/projects/…/node_modules/@drakon-systems/shieldcortex-realtime`,
  registered in `plugins/installs.json`); the wrapper's compatibility path
  copies it to `~/.openclaw/extensions/shieldcortex-realtime/`. Both are
  first-class installs: `shieldcortex doctor` recognises an extensions copy
  (`index.js` + `openclaw.plugin.json` present) as installed, and an empty or
  half-copied directory as not installed
- Hooks into `llm_input`, `llm_output`, `before_agent_run`, `before_tool_call`, and `session_end`
- The conversation hooks are refused by OpenClaw unless the operator grants
  conversation access on that box. `llm_input` and `llm_output` are gated that
  way on every build; `before_agent_run` joins them in 2026.5.9-beta.1, the same
  build that first declares the gate — see
  [Conversation firewall](../plugins/openclaw/README.md#conversation-firewall)

## Install-time refresh (postinstall)

Installing or updating the `shieldcortex` package globally runs
`scripts/postinstall.mjs`, and that script can write into `~/.openclaw`. It is
worth knowing before you update a box that runs OpenClaw:

- It only **refreshes an integration that is already there**. If `~/.openclaw`
  exists and a previous `cortex-memory` hook or `shieldcortex-realtime` plugin is
  on disk, it spawns `shieldcortex openclaw install` (or, for a plugin with no
  hook, re-copies the plugin files) so the file-copied hook and plugin do not go
  stale behind the new package version. That command is the **full installer**,
  not a file copy: it snapshots and edits the OpenClaw configuration to register
  the plugin and, by default, restarts the OpenClaw gateway — so a package update
  can briefly interrupt a running gateway. If the plugin-only re-copy fails, it
  falls back to the same full installer, which can add the hook that was not
  there before.
- It never wires OpenClaw for the first time. OpenClaw present but no earlier
  ShieldCortex hook or plugin means nothing under `~/.openclaw` is touched; run
  the install commands above yourself.
- It does nothing to OpenClaw for local (non-global) installs, when `CI=true`,
  or inside Docker/containers (it prints the manual command instead).
- A failed refresh is non-fatal and prints the manual command.
- Separately from OpenClaw, on macOS it restarts a ShieldCortex dashboard
  service that is still serving the previous build.
- Also separately from OpenClaw, on a machine with no
  `~/.shieldcortex/config.json` it **creates one** with
  `openclawAutoMemory: true` and `proactiveRecall: true`. An existing config file
  is never overwritten. This write is not part of the OpenClaw refresh, so it
  still happens with `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1` and inside Docker; only
  `--ignore-scripts` avoids it.

To update the package without touching OpenClaw at all (no configuration edit,
no gateway restart), set `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1` for the install, then refresh when you are
ready with `shieldcortex openclaw install`. npm's `--ignore-scripts` also skips
it, but that skips the native-module check too — prefer the variable.

## Default behavior (safe complement mode)

Enabled by default:
- Keyword triggers: saves when user explicitly says phrases like `remember this:`
- `llm_input` scanning: real-time threat detection + audit logging. This hook is
  **observation only** — it cannot stop a turn. The conversation firewall's
  enforcement point is `before_agent_run`, and its posture defaults to
  `observe`: detections are audited and sent to the operator, turns are not
  blocked until you set `interceptor.conversation.posture: "enforce"`.
  `interceptor.conversation.posture: "off"` disables **both** hooks: no scan, no
  audit row, no cloud forwarding. Neither hook's audit rows contain prompt text —
  they record a length and a content digest only
- `before_tool_call` Action Guard: catastrophic operations blocked, dangerous operations enforced (see the [plugin README](../plugins/openclaw/README.md) for `actionGuard` opt-down and allowlisting)
- `agent:bootstrap` lifecycle wiring: security-warning file handoff only — no context injection (removed v2026.2.26; OpenClaw's native Memory Search recalls context at session start)

Disabled by default:
- Auto-extract on `/new`, `/stop`, `/clear`, `/exit`
- `llm_output` auto-memory extraction

This avoids duplicate/noisy writes for users who already rely on OpenClaw memory or another primary memory store.

## Enable optional auto-memory

CLI:

```bash
shieldcortex config --openclaw-auto-memory true
```

Disable:

```bash
shieldcortex config --openclaw-auto-memory false
```

Dashboard:
- Start dashboard with `shieldcortex --dashboard`
- Open `Shield Overview -> OpenClaw Memory`
- Toggle auto-memory and dedupe settings

Config file (`~/.shieldcortex/config.json`):

```json
{
  "openclawAutoMemory": true,
  "openclawAutoMemoryDedupe": true,
  "openclawAutoMemoryNoveltyThreshold": 0.88,
  "openclawAutoMemoryMaxRecent": 300
}
```

Tuning bounds:
- `openclawAutoMemoryNoveltyThreshold`: `0.6` to `0.99`
- `openclawAutoMemoryMaxRecent`: `50` to `1000`

## Security and audit

All memory writes routed through ShieldCortex are scanned by the defence pipeline and recorded in audit logs. Threat detections from the real-time plugin can also sync to cloud when configured.

### Recalled memory is framed as data — guidance, not enforcement

The recall surfaces wrap stored memory in one untrusted-data frame before a model sees it: an opening line, a notice that imperative text inside is data and not an instruction, and a closing line carrying a per-emission random id that stored text cannot predict (#507). The surfaces that carry the frame today are:

- the MCP tools `recall`, `get_memory`, `get_related`, `get_context` (prose output; `format: "raw"` is a JSON document that carries the same notice and frame id as fields) and `start_session`;
- the MCP resources `memory://context` and `memory://important`;
- proactive recall on a `message` event (the bundled OpenClaw hook);
- the Claude Code hooks and the LangChain adapter.

Not every tool result that echoes stored text is framed yet. `export_memories` returns the stored rows as raw JSON, and the tools that echo a memory back after acting on it (`remember`, `forget`, graph, quarantine and scan results) are unframed too; that gap is tracked as #535 and stays open until those paths carry the frame. Until then, treat an `export_memories` result as you would any untrusted file.

Be clear about what that is. The frame tells the model who is speaking; it does not stop the model reading the text, and it does not make a hostile memory safe. It is advice to the model, and a model can ignore advice. The controls that actually withhold or block content are the write-time defence pipeline (a memory that scans as an injection is quarantined, never recalled) and the recall filter that drops a poisoned row before it is emitted. Treat the frame as the last line, not the first.

### PII redaction on the hook write path

Hook-captured memories go through the same write-time PII redactor as every other write: UK NI numbers, US SSNs, labelled tax ids and salary figures are stored as `[REDACTED:<kind>]`.

The same redactor also runs on **session events**: every `session_events` row the hooks write (prompt-recall, session-end, pre-compact; single and batch) is redacted at the persistence boundary in `scripts/lib/session-capture.mjs`, exactly as memory rows are.

Both hook write paths load that redactor from the installed package's compiled `dist`. If the redactor alone is missing or stale (for example straight after an upgrade), the hook **still stores the memory or event, unredacted, at CONFIDENTIAL or above** and says so on stderr: `PII redactor unavailable — storing unredacted at raised sensitivity`. Session events print that notice once per hook process; memory capture prints it once per candidate. An event already labelled RESTRICTED (or SECRET) keeps that label as written; it is never downgraded.

This fail-safe covers a missing redactor only. If any *required* defence module in `dist` is missing — the pipeline, database init or disposition module; one is enough, it does not take all three — hook memory capture is dropped and audited as `defence_pipeline_unavailable`, as it was before this change; session events are still written. This is deliberate — a packaging fault must not stop a host remembering — but it is a fail-safe, not a fail-closed redaction guarantee: raw identifiers can be stored until `dist` is fresh. Run `shieldcortex doctor` after every upgrade to confirm it is.

Hook memories that redact to the same text (two people's NI numbers) are deduplicated by a bounded rule, not by similarity: a redacted candidate is skipped when the project already holds a row with the identical redacted title and content created in the last 24 hours, or already holds 3 such rows of any age. So a hook that re-extracts the same memory every turn stores it once, two people's records captured more than 24 hours apart are both kept (up to 3), and two distinct records that redact identically within 24 hours of each other collapse to one.

Known limits: an unlabelled lowercase or lowercase-suffixed NI number (`ab123456c`, `AB123456a`) and an unlabelled undashed SSN (`078051120`) are not redacted — without a label they are indistinguishable from hex digests and ids; all three are redacted when labelled ("NI number …", "SSN …"). Names and postal addresses are not detected.

Optional cloud config example:

```json
{
  "cloudApiKey": "sc_...",
  "cloudBaseUrl": "https://api.shieldcortex.ai",
  "cloudEnabled": true
}
```

## Shared database

Memories are stored in `~/.shieldcortex/memories.db` and shared across ShieldCortex integrations (including Claude Code + OpenClaw when both use ShieldCortex memory tools).

## Troubleshooting

OpenClaw not detected:

```bash
which openclaw
```

Hook/plugin not active after install:
1. Run `shieldcortex openclaw status`
2. Restart OpenClaw gateway
3. Reinstall with `openclaw skills install shieldcortex` and `openclaw plugins install @drakon-systems/shieldcortex-realtime`
4. If `status` shows a legacy `internal/cortex-memory` path, rerun `shieldcortex openclaw install` once to migrate and clean up duplicates

Permission denied during install:
1. Check where the binary lives with `command -v shieldcortex`
2. Run `sudo "$(command -v shieldcortex)" openclaw install`
3. Or fix directory ownership with `sudo chown -R "$USER":"$USER" ~/.openclaw ~/.claude`

Auto-memory not saving:
1. Confirm `openclawAutoMemory` is enabled
2. Check `~/.shieldcortex/config.json` for expected values
3. Check plugin/hook logs for `shieldcortex` or `cortex-memory` messages

### `doctor` and a deliberately disabled plugin

`plugins.entries["shieldcortex-realtime"].enabled: false` is a sentence an
operator typed, so `shieldcortex doctor` reports it as **⚠️ warn and exits 0**.
The line still says plainly that the host is running without the memory firewall
and the Action Guard — it simply is not called a fault, because reporting a
human's own decision back as a red ❌ is how the check that catches the *real*
failure gets ignored. A **wiped** stanza (no entry at all, which is what a bad
installer run leaves behind) is a different state and still **fails**.

For CI, the enforcement route is the flag, not the severity:

```bash
shieldcortex doctor --strict   # every ⚠️ becomes exit 1
```

Use that where "disabled anywhere in the fleet" must break the build. Plain
`shieldcortex doctor` stays green for the operator who chose it.

## Uninstall

```bash
shieldcortex openclaw uninstall
```

## Related

- [README](../README.md)
- [OpenClaw plugin README](../plugins/openclaw/README.md)
- [Architecture](../ARCHITECTURE.md)
