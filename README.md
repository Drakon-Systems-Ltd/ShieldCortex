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
> **ShieldCortex 5.x requires Node 22.14+ or Node 24.** Node 20 is no longer supported — `npm install` will refuse. Coming from 4.x? Read [Upgrading to 5](docs/UPGRADING-5.md) **before** you update. Action Guard stays off by default; enable it deliberately.

```bash
npm install -g shieldcortex
shieldcortex setup
```

Walkthrough, dashboard, and Cloud live on the site — not in this file:

- [shieldcortex.ai](https://shieldcortex.ai)
- [Docs](https://shieldcortex.ai/docs)
- [Dashboard guide](https://shieldcortex.ai/guide)

## What it is

Trusted task → let it work. Hijack → a plain-English card. Catastrophe → hard stop. Guard stays **off** until you turn it on.

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

`shieldcortex doctor` prints the same host table — `memory + tool gate` or `memory only — not a gate` per host, with the live Guard posture for the bound ones. It will not print “protected” for a host that cannot deny.

## 🚀 Quick Start

### Requirements

- **Node 22.14+ LTS, or Node 24.** Node 20 is not supported. Check with `node -v` before you install.
- Upgrade notes, including how to stay on 4.x: [Upgrading to 5](docs/UPGRADING-5.md).

```bash
npm install -g shieldcortex
shieldcortex setup
shieldcortex doctor
```

`setup` (alias `quickstart`) prints one host table and asks before wiring. Claude Code and OpenClaw get hooks that can **deny**. Hermes gets a tool gate. Codex / Cursor / VS Code get an MCP memory server — a scanner the model may call, not a tool gate.

```bash
shieldcortex dashboard
```

Local UI: **Overview · Memory · Protection · X-Ray · Settings**. Memory has Library / Graph / Recall / Review / Timeline. Prompt-time recall into Claude Code is a config switch, not a dashboard setting: the npm postinstall creates a missing `~/.shieldcortex/config.json` with `proactiveRecall: true`; turn it off with `shieldcortex config --proactive-recall false`.

## What's new in 5.3

- **The injection scanner catches more.** Spoofed authority lines inside tool results (`ADMIN: you must …`, `SYSTEM OVERRIDE:`), “repeat everything above” extraction requests, explicit injection phrases in ten languages, and ROT13-encoded instructions. Content that passed before can now be quarantined by the memory firewall. It is a detection floor: reworded attacks in any language still pass. (#506)
- **Chained audit ledger and `shieldcortex ledger verify`.** New audit rows are hash-chained; existing rows are kept as pre-chain history. A `Chained ledger` doctor row fails, naming `ledger verify`, if the audit history is edited or rows are removed. (#617)
- **`shieldcortex update` reports OpenClaw plugin installs honestly.** A slow install is no longer called a failure, and an install that did not land exits 1 with the exact re-run command instead of a green footer. (#604, #583)
- **Releases ship with npm provenance.** `npm audit signatures` can verify both packages were built by this repository's release workflow. (#608)
- **5.3.1 — Action Guard on OpenClaw's Codex harness.** `gateway_exec` / `gateway_process` calls now resolve to the native exec/process contracts instead of being rejected as unknown tools and cancelled. (#622)

Full detail: [CHANGELOG](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md).

## Updating

Coming from 4.x: back up `~/.shieldcortex` and read [Upgrading to 5](docs/UPGRADING-5.md) first. Within 5.x, one command upgrades the package and refreshes every host that is already wired on this box:

```bash
shieldcortex update
shieldcortex doctor
```

`update` installs `shieldcortex@latest` globally, verifies the database engine, then refreshes what is already installed: the OpenClaw plugin and skill, the file-copied OpenClaw hook and Hermes plugin copies, Claude Code hooks, and state permissions. It never wires a host for the first time and never reinstalls anything you removed. A refreshed hook or plugin copy only takes effect when its gateway restarts, which `update` leaves to you. When a step did not land it exits non-zero and names the exact re-run command. `shieldcortex update --help` lists its flags. A leftover `.shieldcortex-update.lock` from an interrupted run is never cleared automatically — remove it only after confirming no update or install is running.

Doing it by hand, or re-checking one host:

1. **Package** — `npm install -g shieldcortex@latest`. npm's postinstall refreshes an OpenClaw hook or plugin that is already on disk (via `shieldcortex openclaw install`, which can restart the OpenClaw gateway). Set `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1` on the install to leave OpenClaw alone.
2. **Claude Code** — `shieldcortex install` re-runs the hook setup in `~/.claude/settings.json`: missing hooks are added, old `npx` entries migrated, timeouts fixed. Existing Stop / SessionEnd opt-ins are left as they are.
3. **OpenClaw** — the plugin is `@drakon-systems/shieldcortex-realtime` (plugin id `shieldcortex-realtime`), managed by OpenClaw's own plugin registry. Refresh it with `openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest` — a plain `openclaw plugins update shieldcortex-realtime` does nothing when OpenClaw recorded a pinned version — then `openclaw gateway restart`. `shieldcortex openclaw install` does plugin, hook and restart in one go (`--no-gateway-restart` to skip the restart).
4. **Hermes** — `shieldcortex hermes install` re-copies the plugin into `~/.hermes/plugins/shieldcortex`; then restart the Hermes gateway, because plugin discovery only runs at start-up. `shieldcortex hermes status` shows whether the copy is installed.
5. **Background service** — if you ran `shieldcortex service install`, run `shieldcortex service status`. `Healthy: no (repair recommended)` means the unit points at a stale entry point: `shieldcortex service repair` removes the unit, reinstalls it against the current install and restarts the service.
6. **Doctor** — `shieldcortex doctor` warns when the OpenClaw plugin or the Hermes copy is behind the package and names the command to run. It exits 1 on a failure (`--strict` also fails on warnings). Its repairs are opt-in flags: `--fix-project-keys`, `--fix-action-guard`, `--fix-hermes-plugin-copies`.

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

Root, once. Pins the security-critical config so an agent cannot quietly turn Guard off. There is no `unprotect` command. Recovery is a human at a root shell — [runbook](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/docs/design/2026-09-16-501-policy-lock.md).

## Integrations

| Platform | Command | Bound? |
|---|---|---|
| Claude Code | `shieldcortex setup` | tool gate |
| OpenClaw | `shieldcortex setup` / plugin `@drakon-systems/shieldcortex-realtime` | tool gate |
| Hermes | `shieldcortex hermes install` | tool gate |
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
