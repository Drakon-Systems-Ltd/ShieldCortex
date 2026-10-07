# OpenClaw Integration

ShieldCortex integrates with [OpenClaw](https://openclaw.dev) in complement mode by default:
- Real-time defence scanning is on — but on the conversation path it is
  **observe-only by default**, and it runs at all only where the operator has
  granted the plugin conversation access on that host
- The before-tool-call Action Guard is **off** unless you enable it
  (`shieldcortex config --action-guard-enable`); once on, catastrophic
  operations are blocked and dangerous operations are enforced by default
- Automatic memory writes (`openclawAutoMemory`) are off when the key is not
  set, but a fresh global, non-CI npm install writes it as `true` (see
  [Default behavior](#default-behavior-safe-complement-mode))

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
  system-prompt injection since v2026.2.26) and, when `openclawAutoMemory` is
  `true`, session-end capture on `/new` and `/stop`
- Its keyword-trigger saves and per-message proactive recall are dormant: the
  hook's `events` list (`command:new`, `command:stop`, `agent:bootstrap`) has no
  `message` key, so core OpenClaw 2026.9.6 never routes those paths to it

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

- It only **refreshes an integration that is already there**, and it looks in
  exactly two places: `~/.openclaw/hooks/cortex-memory` (the hook) and
  `~/.openclaw/extensions/shieldcortex-realtime` (a file-copied plugin). If
  `~/.openclaw` exists and either is on disk, it spawns `shieldcortex openclaw
  install` (or, for a plugin with no hook, re-copies the plugin files) so the
  file-copied hook and plugin do not go stale behind the new package version.
  It does not read OpenClaw's managed plugin registry, so a plugin installed
  only through `openclaw plugins install` (with no hook) does not trigger this
  refresh; update that one with `openclaw plugins update` (see
  [Updating the plugin](#updating-the-plugin)). The rule for those two paths:
  hook and plugin present → full installer; hook only → full installer; plugin
  only → in-place copy of the plugin files, falling back to the full installer
  if that copy fails (which can add the hook that was not there before). That installer is
  the **full installer**, not a file copy: it snapshots and edits the OpenClaw
  configuration to register the plugin and, by default, restarts the OpenClaw
  gateway — so a package update can briefly interrupt a running gateway. The
  restart follows the [gateway restart consent](#gateway-restart-consent) rules
  below: it happens in a terminal, or headless with
  `SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1`, and never with
  `SHIELDCORTEX_SKIP_GATEWAY_RESTART=1`.
- It never wires OpenClaw for the first time. OpenClaw present but no earlier
  ShieldCortex hook or plugin means nothing under `~/.openclaw` is touched; run
  the install commands above yourself.
- It does nothing to OpenClaw for local (non-global) installs, when `CI=true`
  or `CONTINUOUS_INTEGRATION=true`, or inside Docker/containers (it prints the
  manual command instead).
- A failed refresh is non-fatal and prints the manual command.
- Separately from OpenClaw, on macOS it restarts a ShieldCortex dashboard
  service that is still serving the previous build.
- Also separately from OpenClaw, a global, non-CI install on a machine with no
  `~/.shieldcortex/config.json` tries to **create one**; when that write
  succeeds, `openclawAutoMemory: true` and `proactiveRecall: true` are saved.
  If the write fails, the two defaults are not saved and the install continues
  without them. An existing config file is never overwritten. The file does not
  install the OpenClaw hook or plugin and does not turn on the Action Guard.
  This write is not part of the OpenClaw refresh, so it still happens with `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1`
  and inside Docker. It is skipped for local (non-global) installs, when
  `CI=true` or `CONTINUOUS_INTEGRATION=true`, and whenever the install script
  does not run at all (for example with `--ignore-scripts`).

To update the package without touching OpenClaw at all (no configuration edit,
no gateway restart), set `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1` for the install, then refresh when you are
ready with `shieldcortex openclaw install`. npm's `--ignore-scripts` also skips
it, but that skips the native-module check too — prefer the variable.

## Updating the plugin

`shieldcortex update` refreshes an OpenClaw integration that is already on the
box. The README's [Updating](../README.md#updating) section is the short
version; this is what each step does.

- **Plugin** — `openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest`.
  The forced form is deliberate: it replaces a registration pinned to an older
  version or left half-installed, where a bare update would stay on the pin or
  refuse. It runs under the `~/.openclaw` update lock (below). A plugin install
  that did not land is reported as unfinished with that exact command as the
  re-run, and `update` exits 1; a slow install whose end state is verified is
  not a failure.
- **Skill** — an installed `shieldcortex` skill is reinstalled through
  OpenClaw's own `skills install`.
- **Hook** — a stale file-copied `cortex-memory` hook is re-copied, under the
  same lock. The gateway is a long-lived process, so the refreshed files do
  nothing until it restarts; this step does not restart it.
- **Protection check** — the plugin registration is reconciled and the gateway
  reloaded, under the consent rules below.

### Updating by hand

```bash
openclaw plugins update @drakon-systems/shieldcortex-realtime@latest
openclaw gateway restart   # if the hook was refreshed too
```

The explicit npm spec matters. OpenClaw records the selector it installed from,
so `openclaw plugins update shieldcortex-realtime` (bare plugin id) stays on a
pinned version, while the `@latest` spec moves past the pin and is recorded for
later id-based updates. On an older OpenClaw, or to recover a broken install,
use the forced form `shieldcortex update` uses itself:

```bash
openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest
```

The two do not conflict: both end with the same registration pointing at the
same version. `shieldcortex openclaw install` does plugin, hook and restart in
one go; `--no-gateway-restart` skips the restart.

### Gateway restart consent

Every OpenClaw gateway restart ShieldCortex performs — `update`'s protection
check, `shieldcortex openclaw install`, and the installer npm's postinstall
spawns — goes through one helper, which decides in this order:

| Condition | Effect |
|---|---|
| `SHIELDCORTEX_SKIP_GATEWAY_RESTART=1` | No restart, terminal or not. Checked first; wins over everything below. |
| stdin is a terminal | Restart allowed without a prompt. |
| `SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1` | Restart allowed headless (cron, CI, an agent). |
| none of the above | The restart is skipped and the output says so; restart by hand. |

`update`'s protection check has one more gate in front of the restart:
applying the reconcile plan at all needs a terminal or
`SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1`. So a headless `update` needs both
`SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1` and `SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1`
to fix and reload; with only the first it fixes and leaves the reload to you;
with only the second it computes the plan and applies nothing. `shieldcortex
openclaw install` has no reconcile gate: `SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1`
alone lets a headless install restart. `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1` is
different again: it stops npm's postinstall from touching `~/.openclaw` at all.

The macOS dashboard restart described under install-time refresh is a different
service (`com.shieldcortex.dashboard`, not the OpenClaw gateway) and is not
governed by these variables.

### The update lock

The plugin-install, wrapper-install and hook-refresh steps of `shieldcortex
update` and `shieldcortex openclaw install` take
`~/.openclaw/.shieldcortex-update.lock` first; `~/.hermes` has its own for the
Hermes plugin copy. Not every write is covered: npm postinstall's in-place
plugin copy does not take the lock, and `update` releases it before its later
OpenClaw protection check, which can restore the plugin registration or prune
directories. A second locking writer that
finds the lock held does not wait and does not take it over: `update` reports
that step as skipped and unfinished, names the re-run command, and exits 1.
Normal owners release the lock when they finish, but an abandoned lock is never
reclaimed automatically — a lock whose owner died looks the same as
one whose owner is mid-write, and a process that deletes locks by age can delete
a live one. If an interrupted run has left one behind, remove it yourself only
after confirming no `shieldcortex update` or `openclaw install` is running, then
re-run.

## Default behavior (safe complement mode)

Enabled by default:
- `llm_input` scanning: real-time threat detection + audit logging. This hook is
  **observation only** — it cannot stop a turn. The conversation firewall's
  enforcement point is `before_agent_run`, and its posture defaults to
  `observe`: detections are audited and sent to the operator, turns are not
  blocked until you set `interceptor.conversation.posture: "enforce"`.
  `interceptor.conversation.posture: "off"` disables **both** hooks: no scan, no
  audit row, no cloud forwarding. Neither hook's audit rows contain prompt text —
  they record a length and a content digest only
- `agent:bootstrap` lifecycle wiring: security-warning file handoff only — no context injection (removed v2026.2.26; OpenClaw's native Memory Search recalls context at session start)

Off unless `actionGuard.enabled` is `true`:
- `before_tool_call` Action Guard. The fresh-install defaults below do not turn it on.
  Enable it with `shieldcortex config --action-guard-enable` (a bare
  `shieldcortex protect` also turns it on); while it is on, catastrophic
  operations are blocked and dangerous operations are enforced (see the
  [plugin README](../plugins/openclaw/README.md) for `actionGuard` opt-down and allowlisting)

Off unless `openclawAutoMemory` is `true`:
- Auto-extract on `/new` and `/stop`. `/clear` and `/exit` are not core
  OpenClaw 2026.9.6 hook events and are not in the hook's `events` list, so the
  hook does not capture on them. On `/stop`, core OpenClaw does not show the
  hook's "Saved N memories" note
- `llm_output` auto-memory extraction

When the key is not set, both stay off. This avoids duplicate/noisy writes for users who already rely on OpenClaw memory or another primary memory store.

A fresh global, non-CI npm install sets it, though: on a machine with no
`~/.shieldcortex/config.json`, postinstall creates that file with
`openclawAutoMemory: true` (and `proactiveRecall: true`), so auto-memory is
**on** for that install. An existing config file is never changed, so an upgrade
keeps your current values and a config without the key stays off. See
[Install-time refresh](#install-time-refresh-postinstall) above; to turn it off,
run `shieldcortex config --openclaw-auto-memory false`. The config file only
sets the switch: it does not install the OpenClaw hook or plugin, which still
have to be installed (see [Install](#install)) before anything is extracted.

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

The recall surfaces wrap stored memory in one untrusted-data frame before a model sees it: an opening line, a notice that imperative text inside is data and not an instruction, and a closing line carrying a per-emission random id that stored text cannot predict (#507, #535). The surfaces that carry the frame today are:

- the MCP tools `recall`, `get_memory`, `get_related`, `get_context` (prose output; `format: "raw"` is a JSON document that carries the same notice and frame id as fields), `start_session`, `remember` (success), `forget` (when it lists titles), consolidation previews that list titles, contradiction listings, `quarantine_review` list, and `scan_memories` findings;
- JSON emitters `export_memories` and graph query/entities/explain success payloads, which carry `untrusted_data_notice` / `frame_id` as the first keys so the document still parses;
- the MCP resources `memory://context` and `memory://important`;
- proactive recall on a `message` event in the bundled OpenClaw hook. That code frames its output, but it is dormant: the hook does not subscribe `message` events, so core OpenClaw 2026.9.6 never calls it;
- the Claude Code hooks and the LangChain adapter.

Empty and error results with no stored text stay unframed.

Be clear about what that is. The frame tells the model who is speaking; it does not stop the model reading the text, and it does not make a hostile memory safe. It is advice to the model, and a model can ignore advice. The controls that actually withhold or block content are the write-time defence pipeline (a memory that scans as an injection is blocked or quarantined according to policy, never recalled) and the recall filter that drops a poisoned row before it is emitted. Treat the frame as the last line, not the first.

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
