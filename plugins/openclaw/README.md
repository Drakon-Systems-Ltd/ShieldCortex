# @drakon-systems/shieldcortex-realtime

OpenClaw plugin for ShieldCortex real-time defence scanning and optional memory extraction.

## Compatibility

- **Node.js** — ≥ 20 required (the `shieldcortex` peer ships `better-sqlite3` ^12, which needs Node 20+)
- **OpenClaw** — ≥ 2026.3.22 required, **≥ 2026.4.23 recommended** — 2026.4.23 added host-package linking for plugins that declare `openclaw` as a peer dependency ([#70462](https://github.com/openclaw/openclaw/pull/70462)), which lets any future `openclaw/plugin-sdk/*` imports resolve without a duplicate runtime bundle
- **OpenClaw ≥ 2026.5.12 for conversation *enforcement*** — the `before_agent_run` input gate first appears in 2026.5.9-beta.1 and first ships stable in 2026.5.12. Below that floor everything else works, but the conversation firewall is observation-only and says so (see [Conversation firewall](#conversation-firewall))
- **ShieldCortex** — ≥ 4.18.3 required (matches the declared peer dependency; ship both packages at the same version)

OpenClaw is declared as an **optional** peer dependency, so installs on older OpenClaw keep working but miss the linking benefit.

### Packaging note for OpenClaw discovery

Only the dedicated `@drakon-systems/shieldcortex-realtime` plugin declares OpenClaw plugin metadata (`openclaw.extensions` + a root `openclaw.plugin.json`). The main `shieldcortex` package keeps an `openclaw.hooks` entry — needed for the documented `openclaw hooks install` flow — but **as of v4.20.0 it no longer declares `openclaw.extensions`** so OpenClaw's npm discovery cannot mistake the bare main package for a plugin.

Why this matters. The realtime plugin's `peerDependencies.shieldcortex` causes OpenClaw to install the main package alongside in its own npm tree (`~/.openclaw/npm/node_modules/shieldcortex`). With the old contract (pre-v4.20.0) OpenClaw scanned that bare copy, found `openclaw.extensions`, registered it as a duplicate of this plugin, and emitted `duplicate plugin id detected; global plugin will be overridden by global plugin`. Functionally it dedupes — the right `dist/index.js` always wins — but the warning was noise. Removing `openclaw.extensions` from the main package makes the bare copy invisible to discovery; the warning goes away and the dedicated plugin remains the only registration target.

The defensive root `openclaw.plugin.json` is kept for one release on the main package as a shim against OpenClaw versions that might still consult it; it can be removed in a follow-up once that's confirmed clear. History: the v4.18.2 incident (Jarvis, 2026-05-16) was `plugin manifest not found` because the package declared `openclaw.extensions` *without* a root manifest. v4.18.3 added the manifest; v4.20.0 removes the declaration that required it in the first place.

### Known limitations under OpenClaw 2026.4.23

- **Forked subagent context is host-owned.** OpenClaw 2026.4.23 added `ContextEngine.prepareSubagentSpawn({ contextMode: "isolated" | "fork" })` on the plugin-sdk's `ContextEngine` interface, but the spawn itself is initiated by the host runtime — plugins can only react to the lifecycle, not call `sessions_spawn` directly. Work that would benefit from an isolated scratch transcript (e.g. batch scans) therefore still runs inline in the parent session. If upstream exposes a plugin-callable spawn API, scan offloading will be revisited.
- **No public `systemPromptAddition` seam in plugin-sdk.** Hook metadata (`{ name, description }`) is typed and stable, but the SDK does not expose a structured hook for contributing to the effective system prompt. SC's bootstrap injection was disabled in v2026.2.26 for this reason (it was using private internals), and OpenClaw's native Memory Search now handles context recall at session start.

## What it does

| Hook | Action |
|------|--------|
| `llm_input` | **Observation only.** Scans prompts and history through the ShieldCortex defence pipeline. OpenClaw classifies this hook under "conversation observation": it has no blocking contract, so a detection here cannot stop the turn. Threats are audited, alerted, and can forward to ShieldCortex Cloud. |
| `before_agent_run` | **The conversation firewall's enforcement point.** The documented input gate — it is awaited and its result decides whether the run proceeds. Behaviour is set by `interceptor.conversation.posture` (see [Conversation firewall](#conversation-firewall)). |
| `llm_output` | Extracts high-signal memories from assistant replies and writes them into ShieldCortex with novelty filtering and dedupe. |
| `before_tool_call` | Runs the Action Guard before tools execute. Catastrophic shell/file/network/git actions are always blocked. Recognised-dangerous actions are **enforced by default**: attended sessions get an approval prompt, unattended sessions fail closed per `failurePolicy`. Set `actionGuard.enforce: false` to opt down to warn-and-allow, or pre-approve specific operations with `actionGuard.autoApprove`. |
| `session_end` | Resets the interceptor's per-session caches, releases that session's scan-unavailable alert window, and (with `agent_end`) writes `action_guard_degraded` when the Action Guard denied or warned during the session. Registered even when `interceptor.enabled` is `false`, because the conversation gate keeps per-session state regardless. Neither hook can block, approve, or delay a turn. |
| `agent_end` | Same degraded-run summariser as `session_end`, idempotent with it. Present on OpenClaw 2026.5.7+; an older host warns-and-returns and `session_end` still summarises. |
| `/shieldcortex-status` | Slash command reporting the plugin's runtime state. |

The scanning and memory paths are fire-and-forget: they do not stall the OpenClaw turn loop if ShieldCortex is unavailable. The Action Guard is the deliberate exception — it gates tool calls inline, and since 4.47.5 a guard that fails to load falls back to a dependency-free scanner that still denies unambiguous catastrophic operations (fail-closed) rather than allowing everything.

## Installation

### 1. Install ShieldCortex

This plugin resolves the main `shieldcortex` package at runtime, so the CLI must also be installed somewhere the machine can reach.

```bash
npm install -g shieldcortex
```

If `shieldcortex` is not on `PATH`, set `binaryPath` in the plugin config.

### 2. Install the plugin

```bash
openclaw plugins install @drakon-systems/shieldcortex-realtime
```

If you also want the companion session hook, install it from the main package:

```bash
openclaw skills install shieldcortex
```

Restart OpenClaw after installing:

```bash
openclaw gateway restart
```

### Local development

From the monorepo root, you can link the working plugin directory directly:

```bash
openclaw plugins install --link /path/to/ShieldCortex/plugins/openclaw
```

## Configuration

The plugin reads config from `plugins.entries.shieldcortex-realtime.config` in your OpenClaw config and merges it over `~/.shieldcortex/config.json`.

Example:

```json
{
  "plugins": {
    "entries": {
      "shieldcortex-realtime": {
        "enabled": true,
        "hooks": {
          "allowConversationAccess": true
        },
        "config": {
          "binaryPath": "/usr/local/bin/shieldcortex",
          "openclawAutoMemory": true,
          "openclawAutoMemoryDedupe": true,
          "openclawAutoMemoryNoveltyThreshold": 0.88,
          "openclawAutoMemoryMaxRecent": 300
        }
      }
    }
  }
}
```

Supported plugin config keys:

- `binaryPath`: absolute path to the `shieldcortex` binary
- `cloudApiKey`: optional ShieldCortex Cloud API key for realtime threat forwarding
- `cloudBaseUrl`: optional API base URL override
- `openclawAutoMemory`: enable or disable output memory extraction
- `openclawAutoMemoryDedupe`: enable or disable duplicate suppression
- `openclawAutoMemoryNoveltyThreshold`: dedupe similarity threshold, `0.6` to `0.99`
- `openclawAutoMemoryMaxRecent`: dedupe cache size, `50` to `1000`
- `interceptor.conversation.posture`: what the conversation firewall does with a detection — `off` / `observe` (default) / `enforce`. See [Conversation firewall](#conversation-firewall).
- `interceptor.failurePolicy`: per-severity verdict when a decision can't be obtained unattended (defaults: `low`/`medium` allow, `high`/`critical` deny)

### Where the Action Guard block goes

`actionGuard` is a **top-level** key of the plugin `config` object. That is the
canonical location and the one to write:

```json
{ "config": { "actionGuard": {
  "enabled": true,
  "enforce": true,
  "notify": { "enabled": true, "webhookUrl": "https://hook.example/shieldcortex" }
} } }
```

`interceptor.actionGuard` is a **deprecated alias**, still accepted so configs
written before the top-level key existed keep their posture. Both locations
validate against the plugin's schema and the manifest's `configSchema`, and both
are read by the parser; on a conflicting key the top-level value wins, per key,
and anything the top-level block does not mention is filled in from the alias.
Everything below is relative to whichever of the two you use:

- `actionGuard.enabled`: turn the before-tool-call Action Guard on or off (default `false`; unsigned configs leave Guard off)
- `actionGuard.enforce`: enforce dangerous-operation gating (default `true` when Guard is on); `false` opts down to warn-and-allow. Catastrophic operations are blocked only while Guard is enabled.
- `actionGuard.autoApprove`: array of operation allowlist entries for unattended agents that legitimately need specific dangerous operations
- `actionGuard.auditAllows`: audit recognised (sensitive-tier) allow-decisions so "scanned & allowed" is distinguishable from "never scanned" (default `true`; benign allows are never audited)
- `actionGuard.notify`: operator-notification transport (`enabled`, `webhookUrl`, `webhookSecret`, `openclaw`, `timeoutMs`). Off unless `enabled` is exactly `true`. Used both for held tool calls and for conversation-firewall detections.

## Conversation firewall

Three postures, set at `interceptor.conversation.posture`:

| Posture | Behaviour |
|---------|-----------|
| `off` | The conversation is not scanned at all — on **either** hook. No scanner runs, no audit row is written, nothing is forwarded. |
| `observe` | **Default.** Scan, audit, and alert the operator — but never stop the turn. |
| `enforce` | Additionally block the run via `before_agent_run` when the verdict is dirty. |

`off` governs the observation hook too. It is read before any scanner, any
audit write and any cloud call on both `llm_input` and `before_agent_run`, so
switching it off costs one config read per turn and produces no record of the
conversation anywhere.

`observe` is the default deliberately: it is exactly what shipped before the posture existed, now *named* instead of implied to be protection, and the guard's false-positive rate is still unmeasured ([#182](https://github.com/drakon-systems/shieldcortex/issues/182)). An unmeasured blocker in front of every turn would be a worse incident than the one this fixes. An unrecognised value resolves **down** to `observe`, never up.

### Two things gate it, and both are reported honestly

1. **Operator consent — `hooks.allowConversationAccess`.** OpenClaw refuses *every* conversation hook for a non-bundled plugin unless the host config carries the grant. `llm_input` and `llm_output` are on that list in every build; `before_agent_run` joins it in 2026.5.9-beta.1, so on a current host the grant also gates the firewall's enforcement point. The host config needs:

   ```json
   { "plugins": { "entries": { "shieldcortex-realtime": {
     "enabled": true,
     "hooks": { "allowConversationAccess": true }
   } } } }
   ```

   This is a per-box **consent grant**: it authorises a plugin to read every conversation on the host. The plugin itself never writes it, and a plain install never adds it — `/shieldcortex-status` and `shieldcortex doctor` report its absence as *"conversation scanning INACTIVE: conversation access not granted"* rather than quietly claiming protection. Without it, registration succeeds and the hooks are dropped by the host with a diagnostic; the registration line is intent, not acceptance.

   To have the installer write it, say so explicitly:

   ```bash
   shieldcortex openclaw install --allow-conversation-access
   # or, for automation:
   SHIELDCORTEX_ALLOW_CONVERSATION_ACCESS=1 shieldcortex openclaw install
   ```

   That works for **every** install mode — the native `openclaw plugins
   install` route as well as the local-copy fallback — and the installer states
   the resulting grant state either way, read back off the config rather than
   restated from the flag. `shieldcortex repair` writes it too, but only when
   the same consent is given on that run: repairing an install is not consent to
   widen what it may read.

   `/shieldcortex-status` reports the grant as a **plugin-load snapshot**: the
   plugin reads it once, when it loads, and never re-reads it. Editing the key
   takes effect — for the gateway and for that line — only after a gateway
   restart.

2. **Host build — the gate has a floor.** `before_agent_run` first appears in OpenClaw **2026.5.9-beta.1** and first ships stable in **2026.5.12** (2026.5.7 has no such hook). Below that floor the host silently drops the registration, so the plugin reports the plane as observation-only rather than claiming enforcement. It detects this from the installed host's own shipped hook declarations first, and from its version only as a fallback; an install it cannot read is reported as *unknown*, never as supported. Everything else in this plugin still works at the base engine floor.

### When a detection fires

The order matters, and it is evidence first:

1. **The decision row is written locally, before anything leaves the box.** It
   carries the outcome (`blocked` / `observed` / `unavailable`), the posture, a
   stable `eventId`, and a content digest and length — **never the prompt text**,
   which on this path is hostile input by assumption. A hung notification
   channel, a crash, or a gateway restart mid-alert can no longer take the
   record of a block with it.
2. **Then the operator is alerted**, through the same transport the Action Guard
   uses (`actionGuard.notify`): the gateway's own channel where the runtime
   provides that seam, otherwise the configured webhook — which is what carries
   alerts today, since no OpenClaw build we have inspected exposes such a seam.
   Conversation alerts are a distinct event (`conversation_threat`) and carry
   **no Approve/Deny controls** — there is no held call behind them. The wait is
   bounded well under the hook's own timeout.
3. **Then a second row records what happened to the alert**: `type:
   "notification_delivery"`, keyed to the decision by the same `eventId`, with
   `configured` / `delivered` / `via` / `detail`. "Nobody is configured" is
   reported as such, never as delivered, and the channel is named without its
   credentials.

**Scanner failures fail open, loudly.** If the scanner cannot run, the turn
proceeds *unscanned* and is reported as `unavailable` — it is never recorded or
rendered as clean.

**The scan is bounded at 5 seconds.** `before_agent_run` is awaited by the
gateway, so the user's turn waits on it, and the scanner's fallback path boots
an MCP server through `npx`, which can take upwards of 15 s cold — on exactly
the hosts where the in-process defence module failed to load, i.e. the ones
already degraded. Past the deadline the scan is treated as unavailable: the turn
proceeds, and the audit row and alert say so. The deadline message names the
deadline and nothing else — never the prompt.

**Repeated unavailability alerts are rate limited per session; the audit is
not.** An unavailable scanner is usually a missing or broken install, so it
recurs on *every* turn. The first occurrence in a session alerts immediately;
after that, at most one alert per 5 minutes **for that session**, and the alert
that ends a quiet spell reports how many occurrences it covers. The window is
per session on purpose: a gateway multiplexes many concurrent sessions, and one
session's repeating failure must not silence the *first* report from another.
Each session's window is released at `session_end` (registered whether or not
the Action Guard interceptor is enabled), and the tracking map is bounded so a
host that never emits `session_end` cannot grow it without limit. Every
occurrence still writes its own audit row, carrying `unavailableCount`,
`alertSuppressed`, and `alertSuppressedSinceLastAlert` — so a gap in the alert
stream can never be mistaken for a gap in the failures. A suppressed occurrence
writes no delivery row, because no delivery was attempted.

**A failure detail is redacted everywhere, not just on disk.** Scanner and
transport errors are free to quote the endpoint they could not reach, and such a
URL routinely carries its credential in the path. Every http(s) URL in a reason
or detail is reduced to its origin before it is written to the audit row, sent
in the operator alert, returned as a block reason, or printed to the console —
a gateway's stdout is shipped to a log aggregator as often as the audit file is
synced, so none of the three is the "ephemeral" one.

**A shield config that will not load degrades into the same unavailable path.**
If the ShieldCortex runtime cannot be resolved or `~/.shieldcortex/config.json`
cannot be read, the plugin does not go quiet: it warns once per plugin load
(bounded and redacted, and it never claims the shield config loaded), falls back
to the `openclaw.json` plugin config so the posture still resolves, and the scan
then reports `unavailable` — producing the ordinary audit row and operator alert
above. The turn still proceeds.

**An audit write that fails is reported, never assumed.** If the decision row
cannot be persisted (unwritable audit directory, full disk), the decision itself
is unchanged, the failure is logged loudly to stderr, and the operator alert
carries `auditPersistence=failed` so it is clear the alert is the only record of
the event.

## Auto-memory

Auto-memory extraction is enabled when `openclawAutoMemory` is `true`. It complements your existing memory setup with deduplication to avoid noisy repeats.

You can manage the same settings through ShieldCortex itself:

```bash
shieldcortex config --openclaw-auto-memory true
shieldcortex config --openclaw-auto-memory false
```

Or by editing `~/.shieldcortex/config.json`:

```json
{
  "openclawAutoMemory": true,
  "openclawAutoMemoryDedupe": true,
  "openclawAutoMemoryNoveltyThreshold": 0.88,
  "openclawAutoMemoryMaxRecent": 300
}
```

## Cloud forwarding

Threat forwarding is optional. Configure it in ShieldCortex:

```json
{
  "cloudApiKey": "sc_...",
  "cloudBaseUrl": "https://api.shieldcortex.ai"
}
```

Or in the plugin entry config if you want plugin-specific overrides.

## Audit logs

Realtime events are written to:

```text
~/.shieldcortex/audit/realtime-YYYY-MM-DD.jsonl
```

Each line is a JSON object with input-scan, threat, and output-memory activity.

**No row on the conversation path carries prompt text.** That holds for the
`llm_input` observation rows as well as the `before_agent_run` gate rows: both
record `chars` and a `contentSha256` prefix instead, which is enough to
correlate the two rows for the same message without storing the message. (Up to
4.47.35 the `llm_input` threat row carried a 100-character `preview` of the
prompt — the exact text that had just tripped an injection detector — into a log
that syncs.)

A conversation-firewall detection writes **two** rows, both tagged
`hook: "before_agent_run"` and joined by a shared `eventId`:

| Row | Fields |
|-----|--------|
| the decision (`type: "threat"` or `"scan_unavailable"`) | `outcome` (`blocked` / `observed` / `unavailable`), `posture`, the scanner `verdict`, `chars`, a `contentSha256` prefix, and `notifyPending` |
| the delivery (`type: "notification_delivery"`) | `configured`, `delivered`, `via` (channel name only), `detail` |

The decision row is written **before** any notification is attempted, so a
transport that hangs or a process that dies cannot erase the record of a block.
The delivery row is appended afterwards, when its outcome is actually known —
there is no field anywhere that claims an alert was delivered before a transport
said so. A row where `type` is `scan_unavailable` means the turn ran **without
being scanned**; it is not a clean verdict.

Set `SHIELDCORTEX_AUDIT_DIR` to write these rows somewhere other than
`~/.shieldcortex/audit` (used by the test suite so a test run can never append
to a real host's security log).
