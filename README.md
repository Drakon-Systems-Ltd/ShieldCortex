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

Gates tool calls on Claude Code, OpenClaw and Hermes. Scans memory for Codex, Cursor, Copilot and any MCP host that calls it.

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

## What it does

Every line below is backed by shipped code. Each link goes to the detail and the limits. [Full capability notes](docs/CAPABILITIES.md).

**Stop hijacked agents**

- **Tool gate.** On Claude Code and OpenClaw once Action Guard is on, and on Hermes from the plugin's own switch, a trusted call runs, a suspicious call gets a plain-English approval card, and a catastrophic command is a hard stop. [Where it can block](#where-it-can-block)
- **Headless approvals.** When nobody is at a prompt, the denial or held request goes to your webhook as a readable card: what, why, who and the exact `shieldcortex approve` command, never the raw command or a credential (5.18+). [Detail](docs/CAPABILITIES.md#approval-cards-and-webhooks)
- **Conversation firewall for OpenClaw.** With conversation access granted, the plugin scans what reaches the model and records which pattern an injection hit matched (5.18.2). It observes by default; the `enforce` posture blocks the run on OpenClaw builds that have the `before_agent_run` gate. [Detail and limits](docs/CAPABILITIES.md#conversation-firewall-openclaw)
- **Tool-output scan.** `scan_tool_response` checks a tool result you pass it for injection, leaked credentials and markdown-image exfiltration, and ShieldCortex's own MCP tools run it on their output. It is a scanner the agent calls, not an interceptor of other tools. Advisory by default; enforce mode hands the agent a sanitised copy. [Detail](docs/CAPABILITIES.md#tool-output-scan)
- **Claude SDK browser and computer toolsets.** `shieldcortex/toolsets` records what each click, keystroke and page read would trigger; `mode: 'enforce'` refuses the riskiest calls and holds risky ones for approval (5.8+). [Quickstart](docs/quickstarts/claude-sdk-toolsets.md)
- **Iron Dome.** The behaviour-protection layer behind the gate, with its own `status`, `scan`, `audit` and emergency stop. [Detail](docs/CAPABILITIES.md#iron-dome)

**Protect memory**

- **Memory firewall.** Writes that go through ShieldCortex are scanned before they stick; recognised injection and leaked credentials are quarantined or blocked. It does not replace OpenClaw, Hermes or Claude memory. [How scan results work](docs/SCAN.md)
- **Memory for agents.** `remember`, `recall`, `get_context`, a knowledge graph (`graph_query`, `graph_entities`), contradiction detection and `consolidate` with Dream Mode, served over MCP and the Claude Code and OpenClaw hooks. Prompt-time recall into Claude Code is not automatic; it needs the hook and a config switch. [What it needs](docs/UPDATING.md#dashboard-recall-and-cloud), [detail](docs/CAPABILITIES.md#memory-recall-and-the-knowledge-graph)
- **Memory-file scan.** `shieldcortex audit` reads persistent agent memory files for poisoned instructions and credential leaks. [Detail](docs/CAPABILITIES.md#audit)
- **Recall lanes.** Cron, subagent and liveness turns get narrower prompt-time recall than the owner's chat, with bounded coverage. [Limits](#known-limits)

**Catch supply-chain and config tampering**

- **MCP tool-description poisoning.** `shieldcortex mcp scan` checks MCP server tool descriptions for poisoning and rug-pull drift. At each Claude Code session start it also runs in the background against your user-level MCP configs and sends one `mcp_tool_change` webhook notification when a description changed or looks suspicious (5.14+). [Detail](docs/CAPABILITIES.md#mcp-tool-description-scan)
- **Skill and instruction files.** `scan-skill <path>` and `scan-skills` read SKILL.md, hook and rules files for hidden instructions; `--accept` records a reviewed file. [Detail](docs/CAPABILITIES.md#skill-and-instruction-file-scan)
- **Packages.** `xray` scans an npm package, file or directory for risky code, `xray-preinstall` can block an install, and both `xray` and `audit` emit SARIF for GitHub Code Scanning. [Detail](docs/CAPABILITIES.md#package-scan-x-ray)
- **Agent config watch.** At each fresh Claude Code startup, the hooks, MCP servers and similar settings in Claude Code, OpenClaw, Cursor, Codex and Gemini CLI configs, and instruction files planted in drop folders such as `~/Downloads`, are checked against a signed baseline; one webhook notification when something changed outside ShieldCortex. It detects and reports; it does not block, and it is not live between startups. [Limits](docs/security/agent-config-watch.md)
- **Signed config and policy lock.** `~/.shieldcortex/config.json` is signed: a hand edit fails its check and `doctor` says so; `config --resign` previews the file and writes nothing until you pass `--confirm <sha256>`. `sudo shieldcortex protect` pins the security posture in a root-owned lock that an agent running as its own non-root user cannot write. [Policy lock](docs/UPDATING.md#policy-lock)
- **Script allowlist.** `allowlist add` pins a human-reviewed script by path and content hash, so the guard stops reading the script's contents into every scan of a call that runs it; any edit to the file re-gates it. [Detail](docs/CAPABILITIES.md#script-allowlist)

**See and audit**

- **Security audit.** `shieldcortex audit` runs the memory-file, MCP config, environment-file, rules-file and dependency scanners in one pass, as terminal, JSON or SARIF output. [Detail](docs/CAPABILITIES.md#audit)
- **Doctor.** `shieldcortex doctor` checks the install, the Guard posture on each plane (Claude Code hook, OpenClaw plugin, Hermes self-report), stale Hermes plugin copies and the agent config watch. These are configured postures, not a check of running processes. `guard posture` prints the same reading and changes nothing. [Doctor and the host table](docs/UPDATING.md#doctor-and-the-host-table)
- **Chained audit ledger.** `ledger verify` walks the chained audit rows and exits 1 if they are inconsistent; `policy-evidence` reports each runtime's own posture self-report. [Detail](docs/CAPABILITIES.md#ledger-and-policy-evidence)
- **Cortex mistake learning.** `cortex capture` records a mistake, `cortex preflight` checks a task against the record before you repeat it, and a rule can graduate once the record supports it. [Detail](docs/CAPABILITIES.md#cortex)
- **Dashboard.** `shieldcortex dashboard` is a local view: Home, Needs you, Memory, Protection, Settings. It is not an approval inbox. [What it needs](docs/UPDATING.md#dashboard-recall-and-cloud)
- **Claims with proof.** The core memory, recall, gate, environment-firewall and ledger claims each map to a test that fires the real attack and asserts the block, redaction or quarantine. The matrix was written against 4.47 and does not yet cover the detect-only features above. [Claims proof matrix](docs/CLAIMS-PROOF.md)

## Install

Requires Node 22.14+ or 24+. Upgrading from 4.x? Read [Upgrading to 5](docs/UPGRADING-5.md) first. [Node 20, Node 23, and what npm does](docs/UPDATING.md#node-requirement).

```bash
npm install -g shieldcortex
shieldcortex setup
shieldcortex doctor
```

`setup` prints one host table and asks before wiring each host. What it writes, what postinstall does, storage maintenance and the offline embedding cache: [Install details](docs/INSTALL.md). Within 5.x, update with [`shieldcortex update`](docs/UPDATING.md#updating).

## Where it can block

Action Guard stays off until you turn it on. That shared setting is the tool gate for Claude Code and OpenClaw. A bare `sudo shieldcortex protect` turns it on and pins that posture. [Policy lock](docs/UPDATING.md#policy-lock). The Hermes plugin does not read the shared setting; it has its own. [Hermes](docs/CAPABILITIES.md#hermes)

| Host | Memory scan | Tool gate |
|---|---|---|
| Claude Code | yes | bound (PreToolUse) |
| OpenClaw | yes | bound (`before_tool_call`) |
| Hermes | via the local API | bound (`pre_tool_call`) |
| Codex, Cursor, Copilot, MCP | if the agent calls the tools | not a gate |
| LangChain, Python SDK | if you call `scan` or `save` | not a gate |
| Claude SDK browser / computer toolsets (TypeScript) | no | observe by default; `mode: 'enforce'` refuses or holds for approval (`shieldcortex/toolsets`, 5.8+) |

`shieldcortex doctor` prints the same split: `memory + tool gate` for a host that can deny, and memory only, not a gate, for one that cannot. It will not print "protected" for a host that cannot deny. Codex, Cursor, VS Code and other MCP hosts get a memory server the model may call; that server is a scanner, not a deny. [Hosts in detail](docs/CAPABILITIES.md#hosts-and-fallbacks)

## Known limits

- **Recall lanes.** In prompt-time recall (the `UserPromptSubmit` hook), turns detected as a cron job, subagent or liveness probe, or pinned to one of those lanes, get narrower recall than the owner's chat, and rows labelled PERSONAL (private-life notes the classifier recognised or a backfill raised) are withheld from them. This is not universal isolation: a private note the classifier missed and labelled `PUBLIC` can still reach those lanes, and SessionStart context, MCP tool reads and dashboard previews are not lane-scoped. [Recall lanes](docs/UPDATING.md#recall-lanes).
- **Hermes has no approval prompt.** A call Action Guard would hold for approval is blocked while the Hermes plugin enforces. [Hermes](docs/CAPABILITIES.md#hermes)
- **Hook fallback.** If the Claude Code hook fails to load, a bounded fallback still blocks recognised catastrophic commands; calls that do not match stay fail-open. [Full note](docs/UPDATING.md#claude-code-hook-fallback)
- **Enforce-when-ready stays in shadow.** It needs reviewed evidence for the running version, and no such evidence ships yet. [What's new in 5.4](docs/UPDATING.md#whats-new-in-54)
- **One-tap approve is half-shipped.** The 5.18 card and the loopback-only `guard approve-tap` endpoint (off by default) do not yet complete a Telegram tap end to end; approvals still go through `shieldcortex approve`. [Detail](docs/CAPABILITIES.md#approval-cards-and-webhooks)
- **Dashboard counts are partial where labelled.** Memory-pair counts stop at 20 of each kind, the disagreement check compares only the 200 most important memories, and scanner findings cover the whole computer even when a project is selected. [Detail](docs/CAPABILITIES.md#dashboard)

## Free, licensed and Cloud

- **Licence: MIT. Every local feature is free and needs no key.** That includes the memory firewall, Action Guard, all scanners, `audit`, Cortex, Iron Dome, deep X-Ray scans, review-copilot and the local dashboard.
- **Enterprise licence key.** Four cloud and team features need one: full two-way cloud sync of memories, graph and quarantine content; team management; shared patterns and policies; team memory scopes. Activate with `shieldcortex license activate <key>`. [What is gated](docs/CAPABILITIES.md#what-needs-a-licence)
- **Cloud is a second app**, the fleet view: Shield, Capture, Recall, Library, Graph, Replay, Review, Quarantine, Dome, Devices, Keys. Cloud does not ship X-Ray. Free cloud: 500 scans/month, 7-day retention, 1 member, audit metadata only. Enterprise (fleets, SSO, full replica): sales@drakonsystems.com. [How to connect a box](docs/UPDATING.md#connect-a-box)

## Links

- [Docs](https://shieldcortex.ai/docs)
- [Dashboard guide](https://shieldcortex.ai/guide)
- [Capability notes and limits](docs/CAPABILITIES.md)
- [Install details](docs/INSTALL.md)
- [Updating](docs/UPDATING.md)
- [Changelog](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md)
- [Security](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/SECURITY.md) (security@drakonsystems.com)
- [Contributing](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CONTRIBUTING.md)

<p align="center">
  <a href="https://shieldcortex.ai">Website</a> ·
  <a href="https://shieldcortex.ai/docs">Docs</a> ·
  <a href="https://www.npmjs.com/package/shieldcortex">npm</a> ·
  <a href="https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md">Changelog</a>
  <br>
  Built by <a href="https://drakonsystems.com">Drakon Systems</a>
</p>
