<p align="center">
  <img src="assets/shieldcortex-logo.png" alt="ShieldCortex" width="160" height="160" />
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
> **ShieldCortex 5.0 requires Node 22.14+ or Node 24.** Node 20 is no longer supported — `npm install` will refuse. Read [Upgrading to 5.0](docs/UPGRADING-5.md) **before** you update. Action Guard stays off by default; enable it deliberately.

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

`shieldcortex doctor` reports bound / not-bound / unknown. It will not print “protected” for a host that cannot deny.

## 🚀 Quick Start

### Requirements

- **Node 22.14+ LTS, or Node 24.** Node 20 is not supported. Check with `node -v` before you install.
- Upgrade notes, including how to stay on 4.x: [Upgrading to 5.0](docs/UPGRADING-5.md).

```bash
npm install -g shieldcortex
shieldcortex setup
shieldcortex doctor
```

`setup` (alias `quickstart`) prints one host table and asks before wiring. Claude Code and OpenClaw get hooks that can **deny**. Hermes gets a tool gate. Codex / Cursor / VS Code get an MCP memory server — a scanner the model may call, not a tool gate.

```bash
shieldcortex dashboard
```

Local UI (npm 5.0.6): **Overview · Memory · Protection · X-Ray · Settings**. Memory has Library / Graph / Recall / Review / Timeline. There is no 3D brain and no Constellation nebula. Automatic inject into every conversation is **off**.

## Dashboard and Cloud

Two different apps. Old README screenshots (Command Centre, Constellation Graph) are v1 and were removed.

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

Root, once. Pins the security-critical config so an agent cannot quietly turn Guard off. There is no `unprotect` command. Recovery is a human at a root shell — [runbook](docs/design/2026-09-16-501-policy-lock.md).

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
import shieldcortex from 'shieldcortex';
const shieldcortex = await import('shieldcortex');
```

A bare `require('shieldcortex')` fails on purpose with a fix in the error ([#134](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/134)).

## CLI

```bash
shieldcortex setup
shieldcortex doctor
shieldcortex dashboard
shieldcortex scan "text"
shieldcortex env scan <url>
shieldcortex xray <path>
shieldcortex protect
shieldcortex config --policy-status
```

`shieldcortex --help` is the live list. Config lives in `~/.shieldcortex/config.json` — use `shieldcortex config`. Do not hand-edit signed Guard flags.

## Licence

MIT. Every local feature is free. [Security reports](SECURITY.md) → security@drakonsystems.com. [Contributing](CONTRIBUTING.md).

<p align="center">
  <a href="https://shieldcortex.ai">Website</a> ·
  <a href="https://shieldcortex.ai/docs">Docs</a> ·
  <a href="https://www.npmjs.com/package/shieldcortex">npm</a> ·
  <a href="CHANGELOG.md">Changelog</a>
  <br>
  Built by <a href="https://drakonsystems.com">Drakon Systems</a>
</p>
