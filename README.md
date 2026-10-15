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
- **Inspect.** `shieldcortex dashboard` is a local view: Home, Needs you, Memory, Protection, Settings. The Skill & package scanner (formerly X-Ray) is a Protection tab. Memory has Search & browse, Map, Recall, Needs a check, Timeline, Replay, and Files. Prompt-time recall into Claude Code is not automatic. [What it needs](docs/UPDATING.md#dashboard-recall-and-cloud). In prompt-time recall (the `UserPromptSubmit` hook), turns detected as a cron job, subagent or liveness probe, or pinned to one of those lanes, get narrower recall than the owner's chat, and rows labelled PERSONAL (private-life notes the classifier recognised or a backfill raised) are withheld from them. This is not universal isolation: a private note the classifier missed and labelled `PUBLIC` can still reach those lanes, and SessionStart context, MCP tool reads and dashboard previews are not lane-scoped. [Recall lanes](docs/UPDATING.md#recall-lanes).

## Install

Requires Node 22.14+ or 24+. Upgrading from 4.x? Read [Upgrading to 5](docs/UPGRADING-5.md) first. [Node 20, Node 23, and what npm does](docs/UPDATING.md#node-requirement).

```bash
npm install -g shieldcortex
shieldcortex setup
shieldcortex doctor
```

For manual storage and memory hygiene, run `shieldcortex maintain`. It consolidates STM above its cap (applied by default: this is the first phase of `shieldcortex consolidate`, not Dream Mode; it promotes, deletes decayed STM, evicts older unpinned memories from an over-limit tier, and deletes or downvotes near-identical long-term copies, so run `--dry-run` first), backfills missing vectors when the embedding model is cached, vacuums a database with enough free pages, then runs doctor's Memories, Semantic coverage and Disk checks and sends any remaining FAIL to the configured Action Guard webhook (the same FAIL set at most once a day). A database lock held by another live ShieldCortex process, whether seen before opening or at lock acquisition, skips consolidation, embedding and vacuum. It exits 1 while a FAIL remains. Use `--dry-run` to preview without changing database contents or config; SQLite may create shared-memory sidecar files. Use `--json` for a structured report. Audit-log retention is not part of `maintain` yet (#579), and nothing schedules it yet.

`setup` is the onboarding command: it prints one host table and asks before wiring each host. `shieldcortex setup claude` skips the table and runs the Claude Code install (CLAUDE.md, MCP entry, hooks, plus the OpenClaw hook when OpenClaw is present). Two older names still work. `quickstart` takes the same targets as `setup`'s guided path, without hook flags or `uninstall`. `install` is not the wizard: it runs that same Claude Code install as `setup claude`, and is kept for existing scripts and the `--without-*` hook opt-outs. Within 5.x, update with [`shieldcortex update`](docs/UPDATING.md#updating).

If npm skipped the package's lifecycle scripts (for example `--ignore-scripts`, or `ignore-scripts=true` in an npm config), ShieldCortex's postinstall did not run. On a global install that step wires no host. It prints the next step, checks that the database engine loads, writes a default `~/.shieldcortex/config.json` when none exists, refreshes an OpenClaw integration that is already present, and on macOS restarts a dashboard service still running an older build. Skipping it does not skip onboarding: run `shieldcortex setup`, then `shieldcortex doctor`. Without that config file, prompt-time recall stays off until you turn it on. [What postinstall does](docs/openclaw-integration.md#install-time-refresh-postinstall).

## Where it can block

Action Guard stays off until you turn it on. A bare `sudo shieldcortex protect` turns it on and pins that posture. [Policy lock](docs/UPDATING.md#policy-lock).

| Host | Memory scan | Tool gate |
|---|---|---|
| Claude Code | yes | bound (PreToolUse) |
| OpenClaw | yes | bound (`before_tool_call`) |
| Hermes | via the local API | bound (`pre_tool_call`) |
| Codex, Cursor, Copilot, MCP | if the agent calls the tools | not a gate |
| LangChain, Python SDK | if you call `scan` or `save` | not a gate |
| Claude SDK browser / computer toolsets (TypeScript) | no | observe by default; `mode: 'enforce'` refuses or holds for approval (`shieldcortex/toolsets`, 5.8+) |

`shieldcortex doctor` prints the same split: `memory + tool gate` for a host that can deny, and memory only, not a gate, for one that cannot. It shows the live Guard posture for Claude Code and OpenClaw. For Hermes it only reports whether the plugin copy is present. It will not print "protected" for a host that cannot deny.

Hermes gates tool calls once you run `hermes plugins enable shieldcortex` and the local API (`shieldcortex api`) is up. Codex, Cursor, VS Code, and other MCP hosts get a memory server the model may call. That server is a scanner, not a deny.

If the Claude Code PreToolUse hook fails to load, a bounded fallback still blocks recognised catastrophic commands, even with the guard off. While the hook is broken those patterns also stop routine recursive force-deletes. Calls that do not match stay fail-open. [Full note](docs/UPDATING.md#claude-code-hook-fallback).

The optional enforce-when-ready posture runs the dangerous tier in shadow until this install's own audit shows the guard is operable and reviewed evidence for the running version exists. No such evidence ships yet, so today it stays in shadow and says so. [What's new in 5.4](docs/UPDATING.md#whats-new-in-54).

`shieldcortex policy-evidence` (5.5+) reports what each runtime's own self-report says it is enforcing, as local self-reports rather than attestation. [What's new in 5.5](docs/UPDATING.md#whats-new-in-55).

Approval cards (5.6+) say what a held action does, why it was held and who asked, in plain English, without the raw command. Database, cluster and cloud teardown commands now ask for approval (5.6+). [What's new in 5.6](docs/UPDATING.md#whats-new-in-56).

`shieldcortex/toolsets` (5.8+) sits in front of a Claude SDK browser-use or computer-use driver and by default records what each click, keystroke, navigation and page read would trigger without changing what runs; `mode: 'enforce'` refuses the riskiest calls outright, holds risky ones (such as irreversible clicks after a page read) for your approval, and lets the rest run. [Quickstart](docs/quickstarts/claude-sdk-toolsets.md).

## Free and Cloud

Two different apps.

- **Local** (`shieldcortex dashboard`) runs on your machine. The Skill & package scanner (formerly X-Ray) lives here, under Protection.
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
