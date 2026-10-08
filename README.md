<p align="center">
  <img src="https://raw.githubusercontent.com/Drakon-Systems-Ltd/ShieldCortex/main/assets/shieldcortex-logo.png" alt="ShieldCortex" width="160" height="160" />
</p>

<p align="center">
  <b>Stops a hijacked or prompt-injected AI agent from running destructive commands, leaking secrets, or poisoning memory it writes through ShieldCortex.</b>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/shieldcortex"><img src="https://img.shields.io/npm/v/shieldcortex.svg" alt="npm version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

**Trusted task: let it work. Hijack: a plain-English card. Catastrophe: a hard stop.**

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

<!-- TODO: demo recording. Uncomment when assets/demo.gif exists.
![ShieldCortex catching an injection scan](assets/demo.gif)
-->

## What you get

- **Memory firewall.** ShieldCortex does not replace OpenClaw, Hermes, or Claude memory. Writes that go through it are scanned before they stick. Recognised injection and leaked credentials are quarantined or blocked.
- **Tool gate.** On Claude Code, OpenClaw, and Hermes, once Action Guard is on, a trusted task runs, a suspicious call gets a plain-English card, and a catastrophic command is a hard stop.
- **Inspect.** `shieldcortex dashboard` is a local view: Overview, Memory, Protection, X-Ray, Settings. Memory has Library, Graph, Recall, Review, and Timeline. Prompt-time recall into Claude Code is not automatic. [What it needs](docs/UPDATING.md#dashboard-recall-and-cloud).

## Install

Requires Node 22.14+ or 24+. Upgrading from 4.x? Read [Upgrading to 5](docs/UPGRADING-5.md) first. [Node 20, Node 23, and what npm does](docs/UPDATING.md#node-requirement).

```bash
npm install -g shieldcortex
shieldcortex setup
shieldcortex doctor
```

`setup` (also `quickstart`) prints one host table and asks before wiring. Within 5.x, update with [`shieldcortex update`](docs/UPDATING.md#updating).

## Where it can block

Action Guard stays off until you turn it on. A bare `sudo shieldcortex protect` turns it on and pins that posture. [Policy lock](docs/UPDATING.md#policy-lock).

| Host | Memory scan | Tool gate |
|---|---|---|
| Claude Code | yes | bound (PreToolUse) |
| OpenClaw | yes | bound (`before_tool_call`) |
| Hermes | via the local API | bound (`pre_tool_call`) |
| Codex, Cursor, Copilot, MCP | if the agent calls the tools | not a gate |
| LangChain, Python SDK | if you call `scan` or `save` | not a gate |

`shieldcortex doctor` prints the same split: `memory + tool gate` for a host that can deny, and memory only, not a gate, for one that cannot. It shows the live Guard posture for Claude Code and OpenClaw. For Hermes it only reports whether the plugin copy is present. It will not print "protected" for a host that cannot deny.

Hermes gates tool calls once you run `hermes plugins enable shieldcortex` and the local API (`shieldcortex api`) is up. Codex, Cursor, VS Code, and other MCP hosts get a memory server the model may call. That server is a scanner, not a deny.

If the Claude Code PreToolUse hook fails to load, a bounded fallback still blocks recognised catastrophic commands, even with the guard off. While the hook is broken those patterns also stop routine recursive force-deletes. Calls that do not match stay fail-open. [Full note](docs/UPDATING.md#claude-code-hook-fallback).

The optional enforce-when-ready posture runs the dangerous tier in shadow until this install's own audit shows the guard is operable and reviewed evidence for the running version exists. No such evidence ships yet, so today it stays in shadow and says so. [What's new in 5.4](docs/UPDATING.md#whats-new-in-54).

`shieldcortex policy-evidence` (5.5+) reports what each runtime's own self-report says it is enforcing, as local self-reports rather than attestation. [What's new in 5.5](docs/UPDATING.md#whats-new-in-55).

Approval cards (5.6+) say what a held action does, why it was held and who asked, in plain English, without the raw command. [What's new in 5.6](docs/UPDATING.md#whats-new-in-56).

## Free and Cloud

Two different apps.

- **Local** (`shieldcortex dashboard`) runs on your machine. X-Ray lives here.
- **Cloud** is the fleet view: Shield, Capture, Recall, Library, Graph, Replay, Review, Quarantine, Dome, Devices, Keys. Default chrome is glass (Shield). Cloud does not ship X-Ray.

Free cloud: 500 scans/month, 7-day retention, 1 member. Enterprise (fleets, SSO, full replica): sales@drakonsystems.com.

[How to connect a box](docs/UPDATING.md#connect-a-box).

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
