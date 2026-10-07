<p align="center">
  <img src="https://raw.githubusercontent.com/Drakon-Systems-Ltd/ShieldCortex/main/assets/shieldcortex-logo.png" alt="ShieldCortex" width="160" height="160" />
</p>

<p align="center">
  <b>A door on your agent's native memory.</b><br>
  Scan what it stores. Gate what it does. Inspect what was kept.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/shieldcortex"><img src="https://img.shields.io/npm/v/shieldcortex.svg" alt="npm version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

ShieldCortex does **not** replace OpenClaw, Hermes, or Claude memory. Native memory stays the brain. This package is the door.

> [!WARNING]
> **ShieldCortex 5.x requires Node 22.14+ or Node 24+**: Node 22.14 or later within 22.x, or Node 24 or later. Node 20 is no longer supported, and neither is Node 23. npm normally warns on unsupported versions (`EBADENGINE`) and installs anyway; with engine-strict enabled it refuses. On an unsupported Node the database engine fails to load and `shieldcortex doctor` fails. Coming from 4.x? Read [Upgrading to 5](docs/UPGRADING-5.md) **before** you update. Action Guard stays off by default; enable it deliberately.

```bash
npm install -g shieldcortex
shieldcortex setup
```

Walkthrough, dashboard, and Cloud live on the site — not in this file:

- [shieldcortex.ai](https://shieldcortex.ai)
- [Docs](https://shieldcortex.ai/docs)
- [Dashboard guide](https://shieldcortex.ai/guide)

## What it is

Trusted task → let it work. Hijack → a plain-English card. Catastrophe → hard stop. Guard stays **off** until you turn it on (a bare `shieldcortex protect` turns it on too — see Policy lock).

| Surface | Job |
|---|---|
| **Memory firewall** | Scan writes that go through ShieldCortex before they stick |
| **Tool gate** | Bound only on Claude Code, OpenClaw, and Hermes. MCP hosts are a scanner, not a deny |
| **Inspect** | Local dashboard: Overview, Memory, Protection, X-Ray, Settings |

**Where it can actually say no**

| Host | Memory scan | Tool gate |
|---|---|---|
| Claude Code | yes | bound (PreToolUse) |
| OpenClaw | yes | bound (`before_tool_call`) |
| Hermes | via local API | bound (`pre_tool_call`) |
| Codex / Cursor / Copilot / MCP | if the agent calls the tools | **unbound** |
| LangChain / Python SDK | if you call `scan` / `save` | **unbound** |

`shieldcortex doctor` prints the same host table — `memory + tool gate` or `memory only — not a gate` per host. It shows the live Guard posture for Claude Code and OpenClaw; for Hermes it only reports whether the plugin copy is present. It will not print “protected” for a host that cannot deny.

## 🚀 Quick Start

### Requirements

- **Node 22.14+ (22.14 or later within 22.x) or Node 24+ (24 or later).** Node 20 is not supported, and neither is Node 23. npm normally warns on unsupported versions; with engine-strict enabled it refuses. Check `node -v` before you install.
- Upgrade notes, including how to stay on 4.x: [Upgrading to 5](docs/UPGRADING-5.md).

```bash
npm install -g shieldcortex
shieldcortex setup
shieldcortex doctor
```

`setup` (alias `quickstart`) prints one host table and asks before wiring. Claude Code and OpenClaw get hooks that can **deny**. Hermes gets the plugin copy, which gates tool calls once you run `hermes plugins enable shieldcortex` with the local API up. Codex / Cursor / VS Code get an MCP memory server — a scanner the model may call, not a tool gate.

For Claude Code PreToolUse, a hook load failure still blocks recognised catastrophic commands through a bounded fallback scan, even with the guard off (with the guard on, unparseable input gets the same scan). The patterns are blunt text matches, so while the hook is broken they also stop routine recursive force-deletes, such as clearing a build folder; `shieldcortex doctor` shows the repair. Calls that don't match keep the fail-open behaviour so an unavailable guard does not stop other unattended work.

```bash
shieldcortex dashboard
```

Local UI: **Overview · Memory · Protection · X-Ray · Settings**. Memory has Library / Graph / Recall / Review / Timeline. Prompt-time recall into Claude Code needs two things: the Claude Code `UserPromptSubmit` hook, which `shieldcortex setup` adds once you agree to wire Claude Code (or `shieldcortex install`), and `proactiveRecall: true` in `~/.shieldcortex/config.json`. A fresh global, non-CI `npm install -g` with no config file writes one with `proactiveRecall: true` when that write succeeds; local and CI installs do not, an existing config is never changed, and when the key is not set, recall is off. The npm install does not wire Claude Code's `UserPromptSubmit` hook; npm's postinstall can still refresh an existing OpenClaw integration (see [Updating by hand](#updating-by-hand)). Turn it off under Settings → Integrations or with `shieldcortex config --proactive-recall false`.

## What's new in 5.4

- **Action Guard: enforce when ready.** A third posture beside off and enforce. `shieldcortex config --action-guard-enforce-when-ready` (or the new setup question) runs the dangerous tier in shadow, logging what it would have held or blocked while the call proceeds. It enforces only once this install's own audit log shows the guard is operable (low intervention rate, approvals reliably answered through a configured channel) and reviewed effectiveness evidence for the running version exists. No such evidence ships yet, so today this posture stays in shadow and says so. The Claude Code hook and the OpenClaw plugin each measure and promote on their own calls; the Hermes plugin ignores the gate and enforces. (#509)
- **`shieldcortex guard readiness`** shows each surface's posture, mode, thresholds, samples and what is missing. `shieldcortex guard test-approval` sends a labelled synthetic request to prove your approval channel works.
- **Loud demotions.** Falling back from enforcing to shadow prints to stderr, writes an audit row, sends a webhook notice and makes `shieldcortex doctor` fail. Promotions are announced on the same webhook.
- **Guard self-protection floor, in every mode while the guard is on.** Calls that touch the guard's own state, config, lease ledger or policy lock are held or denied even in watch-only and shadow, and only a human answer releases them. This changes behaviour for watch-only installs.

Full detail: [CHANGELOG](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md).

## What's new in 5.3

- **The injection scanner catches more.** Spoofed authority lines inside tool results (`ADMIN: you must …`, `SYSTEM OVERRIDE:`), “repeat everything above” extraction requests, explicit injection phrases in ten languages, and ROT13-encoded instructions. Content that passed before can now be quarantined by the memory firewall. It is a detection floor: reworded attacks in any language still pass. (#506)
- **Chained audit ledger and `shieldcortex ledger verify`.** New audit rows are hash-chained; existing rows are kept as unchained pre-chain history. A `Chained ledger` doctor row fails, naming `ledger verify`, when a chained row is edited or deleted mid-history. The chain is local with no external anchor: it cannot show completeness, or detect a chain rewritten as a whole or cut at the tail. (#617)
- **`shieldcortex update` reports OpenClaw plugin installs honestly.** A slow install is no longer called a failure; a plugin or skill step left unresolved is listed in the footer with its exact re-run command, and a native plugin install that failed and did not land exits 1. (#604, #583)
- **Releases ship with npm provenance.** `npm audit signatures` can verify both packages were built by this repository's release workflow. (#608)
- **5.3.1 — Action Guard on OpenClaw's Codex harness.** `gateway_exec` / `gateway_process` calls now resolve to the native exec/process contracts instead of being rejected as unknown tools and cancelled. (#622)

Full detail: [CHANGELOG](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md).

## Updating

Coming from 4.x: back up `~/.shieldcortex` and read [Upgrading to 5](docs/UPGRADING-5.md) first. Within 5.x:

```bash
shieldcortex update
shieldcortex doctor
```

`update` upgrades the package and refreshes the integrations already installed on this box: OpenClaw plugin, skill and hook, Hermes plugin copy, Claude Code hooks, state permissions. It **may restart the OpenClaw gateway**, and on macOS a ShieldCortex dashboard service still serving the old build; running it in a terminal counts as consent, with no further prompt. It asks before wiring hosts that are present but not yet wired; headless runs only list them. Read the final summary even when the command exits 0.

Warnings and re-run commands do not by themselves set the exit code. An npm failure, a failed OpenClaw protection check, or a plugin, hook or Hermes refresh marked unfinished exits 1. Other warnings can exit 0, so read the summary and run `shieldcortex doctor`.

### Restart controls

- `SHIELDCORTEX_SKIP_GATEWAY_RESTART=1` — ShieldCortex never restarts the OpenClaw gateway: not from `update`, not from `shieldcortex openclaw install`, not from npm's postinstall, in a terminal or not. It is checked before any consent. Restart by hand when ready.
- `SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1` and `SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1` — a headless `update` (cron, CI, an agent) needs both to apply the OpenClaw protection fix-up and reload the gateway afterwards. Without the first it only reports what it would change; without the second it applies the fix-up but skips the reload.
- `SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1` alone — enough for a headless `shieldcortex openclaw install` to restart the gateway, including the one npm's postinstall runs to refresh an existing OpenClaw integration; that path does not read the reconcile variable.
- `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1` — set on `npm install -g shieldcortex` to keep postinstall away from `~/.openclaw` entirely: no refresh, no installer, no restart.

### Updating by hand

1. **Package** — `npm install -g shieldcortex@latest`. On a box with an earlier OpenClaw hook or plugin, npm's postinstall refreshes it and can restart the gateway (see Restart controls). How it decides what to refresh: [install-time refresh](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/docs/openclaw-integration.md#install-time-refresh-postinstall).
2. **Claude Code** — `shieldcortex install` re-runs the hook setup in `~/.claude/settings.json`: missing hooks added, old `npx` entries migrated, timeouts fixed. Existing Stop / SessionEnd opt-ins are left as they are.
3. **OpenClaw** — `openclaw plugins update @drakon-systems/shieldcortex-realtime@latest`, then `openclaw gateway restart` if the hook was refreshed too. `shieldcortex openclaw install` does plugin, hook and restart in one go (`--no-gateway-restart` to skip the restart). Pinned versions, forced reinstall and the update lock: [updating the plugin](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/docs/openclaw-integration.md#updating-the-plugin).
4. **Hermes** — `shieldcortex hermes install` copies the plugin into `~/.hermes/plugins/shieldcortex`; it gates tool calls once `hermes plugins enable shieldcortex` has run and the local API (`shieldcortex api`) is up. Restart the Hermes gateway after a refresh. `shieldcortex hermes status` reports presence, not enforcement.
5. **Background service** — if you ran `shieldcortex service install`, check `shieldcortex service status`. On `Healthy: no (repair recommended)`, run `shieldcortex service repair` with the mode flag you installed with (`--api`, `--headless` or `--dashboard`). Linux and macOS restart the service; Windows schedules it for the next login.
6. **Doctor** — `shieldcortex doctor` warns when the OpenClaw plugin or Hermes copy is behind the package and names the command to run. It exits 1 on a failure (`--strict` also fails on warnings). Repairs are opt-in flags: `--fix-project-keys`, `--fix-action-guard`, `--fix-hermes-plugin-copies`.

## Dashboard and Cloud

Two different apps.

- **Local** (`shieldcortex dashboard`) — the npm package UI above. Runs on your machine. X-Ray lives here.
- **Cloud** — fleet view: Shield, Capture, Recall, Library, Graph, Replay, Review, Quarantine, Dome, Devices, Keys. Default chrome is glass (Shield), not the CIC terminal. Cloud does not ship X-Ray.

Connect a box:

```bash
shieldcortex config --cloud-api-key <key>
shieldcortex config --cloud-enable
shieldcortex service install --headless   # always-on servers
```

Free cloud: 500 scans/month, 7-day retention, 1 member. Enterprise (fleets, SSO, full replica): sales@drakonsystems.com.

## Policy lock

```bash
sudo shieldcortex protect
shieldcortex config --policy-status
```

Root, once. A bare `protect` reads nothing from `config.json`: it pins the safe posture — Action Guard **enabled and enforcing**, empty auto-approve and reviewed-script lists, broker off — so this is also the moment Guard turns on. `sudo shieldcortex protect --from-config` pins your current protected settings instead — the Action Guard block, plus defence mode and memory posture where `config.json` sets them — including a Guard that is off. Either way an agent cannot quietly loosen the pinned keys afterwards. There is no `unprotect` command. Recovery is a human at a root shell — [runbook](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/docs/design/2026-09-16-501-policy-lock.md).

## Integrations

| Platform | Command | Bound? |
|---|---|---|
| Claude Code | `shieldcortex setup` | tool gate |
| OpenClaw | `shieldcortex setup` / plugin `@drakon-systems/shieldcortex-realtime` | tool gate |
| Hermes | `shieldcortex hermes install` + `hermes plugins enable shieldcortex` | tool gate (needs the local API) |
| Codex / VS Code / Cursor | `shieldcortex setup` | MCP only |
| JS | `import … from 'shieldcortex'` | ESM only |
| Python | `pip install shieldcortex` | Cloud `scan()` |

### ESM only

`shieldcortex` ships as ESM only (`"type": "module"`, no CommonJS build). Every entry point works with:

```js
import { runDefencePipeline } from 'shieldcortex';
const shieldcortex = await import('shieldcortex');
```

A bare `require('shieldcortex')` fails on purpose with a fix in the error ([#134](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/134)).

## CLI

```bash
shieldcortex setup
shieldcortex doctor
shieldcortex update
shieldcortex dashboard
shieldcortex scan "text"
shieldcortex env scan <url>
shieldcortex xray <path>
shieldcortex ledger verify
shieldcortex guard readiness
shieldcortex protect
shieldcortex config --policy-status
```

`shieldcortex --help` is the live list. Config lives in `~/.shieldcortex/config.json` — use `shieldcortex config`. Do not hand-edit signed Guard flags.

## Licence

MIT. Every local feature is free. [Security reports](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/SECURITY.md) → security@drakonsystems.com. [Contributing](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CONTRIBUTING.md).

<p align="center">
  <a href="https://shieldcortex.ai">Website</a> ·
  <a href="https://shieldcortex.ai/docs">Docs</a> ·
  <a href="https://www.npmjs.com/package/shieldcortex">npm</a> ·
  <a href="https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md">Changelog</a>
  <br>
  Built by <a href="https://drakonsystems.com">Drakon Systems</a>
</p>
