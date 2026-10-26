<p align="center">
  <img src="https://raw.githubusercontent.com/Drakon-Systems-Ltd/ShieldCortex/main/assets/shieldcortex-logo.png" alt="ShieldCortex" width="160" height="160" />
</p>

<p align="center">
  <b>Limits what a hijacked AI agent can do, and spots tampering with its tools and memory.</b>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/shieldcortex"><img src="https://img.shields.io/npm/v/shieldcortex.svg" alt="npm version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

<p align="center">
  <b>Trusted task: let it work. Hijack: a plain-English card. Catastrophe: a hard stop.</b>
</p>

<!-- TODO: demo recording. Uncomment when assets/demo.gif exists.
![ShieldCortex catching an injection scan](assets/demo.gif)
-->

## Why now

- AI agents now read untrusted text and act on it with real tools, so one poisoned page, file or tool description can steer them.
- Attacks on agents increasingly target what they rely on: their tools, their memory, their settings and their keys.
- ShieldCortex sits between the agent and those things. It does not replace your agent, and it is not antivirus.

## What it does

<table>
<tr>
<td width="33%" valign="top">

**Memory firewall**

Writes that go through ShieldCortex are scanned before they stick. Recognised injection and leaked credentials are quarantined or blocked.

</td>
<td width="33%" valign="top">

**Tool gate (Action Guard)**

On Claude Code, OpenClaw and Hermes, once Action Guard is on, a trusted task runs, a suspicious call gets a plain-English card, and a catastrophic command is a hard stop.

</td>
<td width="33%" valign="top">

**Tamper watch**

At each Claude Code session start, ShieldCortex checks the descriptions of your local MCP tools in the background. If one changed, or looks suspicious, it sends one plain notification. ([details](docs/README-DETAILS.md#tamper-watch-mcp-tool-description-check))

</td>
</tr>
</table>

`shieldcortex dashboard` gives you a local view of what it caught and held. [Dashboard and recall details](docs/README-DETAILS.md#dashboard-inspect-and-recall-lanes).

## Quick start

Requires Node 22.14+ or 24+. Upgrading from 4.x? Read [Upgrading to 5](docs/UPGRADING-5.md) first. [Node 20, Node 23, and what npm does](docs/UPDATING.md#node-requirement).

```bash
npm install -g shieldcortex
shieldcortex setup
shieldcortex doctor
```

[Full install notes](docs/README-DETAILS.md#install-notes): what `setup` writes, `maintain`, and skipped lifecycle scripts.

## Where it can block

Action Guard stays off until you turn it on. That shared setting is the tool gate for Claude Code and OpenClaw. A bare `sudo shieldcortex protect` turns it on and pins that posture. [Policy lock](docs/UPDATING.md#policy-lock). The Hermes plugin does not read the shared setting; it has its own ([host notes](docs/README-DETAILS.md#where-it-can-block-host-notes)).

| Host | Memory scan | Tool gate |
|---|---|---|
| Claude Code | yes | bound (PreToolUse) |
| OpenClaw | yes | bound (`before_tool_call`) |
| Hermes | via the local API | bound (`pre_tool_call`) |
| Codex, Cursor, Copilot, MCP | if the agent calls the tools | not a gate |
| LangChain, Python SDK | if you call `scan` or `save` | not a gate |
| Claude SDK browser / computer toolsets (TypeScript) | no | observe by default; `mode: 'enforce'` refuses or holds for approval (`shieldcortex/toolsets`, 5.8+) |

`shieldcortex doctor` prints the same split and will not print "protected" for a host that cannot deny. [Host notes and edge cases](docs/README-DETAILS.md#where-it-can-block-host-notes).

## What a catch looks like

```bash
shieldcortex scan "ignore previous instructions"
```

```
ShieldCortex Scan Result
──────────────────────────────────────────────────
  Result:      QUARANTINE
  Source:      cli:shieldcortex-scan (attested)
  Provenance:  cli (trusted, L2 not applied)
  Trust:       0.90
  Sensitivity: PUBLIC
  Anomaly:     0.00
  Reason:      Quarantined: Instruction injection detected (confidence: 0.8)
  Threats:     instruction_injection
  Patterns:    hidden_instruction
```

That string was caught and quarantined. Nothing was stored as a memory, and the exit code is non-zero so a script or CI job can act on it. [How scan results work](docs/SCAN.md).

## Free and Cloud

- **Local** (`shieldcortex dashboard`) runs on your machine, and every local feature is free. The Skill & package scanner (formerly X-Ray) lives here, under Protection.
- **Cloud** is the fleet view: Shield, Capture, Recall, Library, Graph, Replay, Review, Quarantine, Dome, Devices, Keys. Cloud does not ship X-Ray.

Free cloud: 500 scans/month, 7-day retention, 1 member. Enterprise (fleets, SSO, full replica): sales@drakonsystems.com. [How to connect a box](docs/UPDATING.md#connect-a-box).

## Links

- [Docs](https://shieldcortex.ai/docs)
- [Dashboard guide](https://shieldcortex.ai/guide)
- [Changelog](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md)
- [Updating](docs/UPDATING.md)
- [Security](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/SECURITY.md) (security@drakonsystems.com)
- [Contributing](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CONTRIBUTING.md)
- Licence: MIT. Every local feature is free.

<p align="center">
  <a href="https://shieldcortex.ai">Website</a> ·
  <a href="https://shieldcortex.ai/docs">Docs</a> ·
  <a href="https://www.npmjs.com/package/shieldcortex">npm</a> ·
  <a href="https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md">Changelog</a>
  <br>
  Built by <a href="https://drakonsystems.com">Drakon Systems</a>
</p>
