<p align="center">
  <img src="https://raw.githubusercontent.com/Drakon-Systems-Ltd/ShieldCortex/main/assets/shieldcortex-logo.png" alt="ShieldCortex" width="160" height="160" />
</p>

<p align="center">
  <b>Holds a hijacked AI agent's recognised dangerous tool calls for a human, hard-stops the catastrophic ones, and keeps poisoned instructions out of the memory it writes through ShieldCortex.</b>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/shieldcortex"><img src="https://img.shields.io/npm/v/shieldcortex.svg" alt="npm version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

**Trusted task: let it work. Suspicious call: hold it for a human. Catastrophe: a hard stop.**

- **Stops recognised dangerous and catastrophic tool calls from a hijacked agent.** Once Action Guard is enforcing, a trusted call runs, a call the guard recognises as dangerous is held for your approval, and a catastrophic command is a hard stop. [Tool gate](docs/CAPABILITIES.md#tool-gate-action-guard)
- **Keeps poisoned instructions out of memory.** Writes that go through ShieldCortex are scanned first; recognised injection and leaked credentials are quarantined before they stick. [How scan results work](docs/SCAN.md)
- **Catches tampering you would not see.** MCP tool descriptions, skill files and packages are scanned for poisoning and drift, and your agents' own config files are checked against a signed baseline at each fresh Claude Code startup, with one webhook notification when something changed. [Limits](docs/CAPABILITIES.md#agent-config-watch)

Action Guard is off by default on Claude Code and OpenClaw; Hermes enforces once its plugin is enabled, and blocks rather than holds. Claude Code, OpenClaw and Hermes get the tool gate and the memory scan. Codex, Cursor, Copilot and other MCP hosts get the memory scan only: a memory server the model may call, not a gate. The Claude SDK browser and computer toolsets get a gate with no memory scan. [Where it can block](#where-it-can-block)

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

## Install

Requires Node 22.14+ or 24+. Upgrading from 4.x? Read [Upgrading to 5](docs/UPGRADING-5.md) first. [Node 20, Node 23, and what npm does](docs/UPDATING.md#node-requirement).

```bash
npm install -g shieldcortex
shieldcortex setup
shieldcortex doctor
```

`setup` prints one host table and asks before wiring each host. What it writes, what postinstall does, storage maintenance and the offline embedding cache: [Install details](docs/INSTALL.md). Within 5.x, update with [`shieldcortex update`](docs/UPDATING.md#updating).

## Where it can block

Action Guard stays off until you turn it on. `sudo shieldcortex protect` turns it on for Claude Code and OpenClaw and pins that posture in a root-owned lock. [Policy lock](docs/UPDATING.md#policy-lock). The Hermes plugin has its own switch. [Hermes](docs/CAPABILITIES.md#hermes)

| Host | Memory scan | Tool gate |
|---|---|---|
| Claude Code | yes | bound (PreToolUse) |
| OpenClaw | yes | bound (`before_tool_call`) |
| Hermes | via the local API | bound (`pre_tool_call`) |
| Codex, Cursor, Copilot, MCP | if the agent calls the tools | not a gate |
| LangChain, Python SDK | if you call `scan` or `save` | not a gate |
| Claude SDK browser / computer toolsets (TypeScript) | no | observe by default; `mode: 'enforce'` refuses or holds for approval (`shieldcortex/toolsets`, 5.8+) |

`shieldcortex doctor` prints the same split and will not print "protected" for a host that cannot deny. [Hosts in detail](docs/CAPABILITIES.md#hosts-and-fallbacks)

## Everything it does

Each line links to the detail, the limits and the source file or changelog entry that carries it. [Full capability notes](docs/CAPABILITIES.md).

**Stop hijacked agents**

- **Tool gate.** On Claude Code and OpenClaw with Action Guard enforcing, a trusted call runs, a recognised dangerous call is held for your approval, and a catastrophic command is a hard stop. Watch-only and enforce-when-ready let the ordinary dangerous tier proceed and record it; catastrophic calls and calls that touch the guard's own state stay strict in every posture. Hermes blocks instead of holding. [Postures and limits](docs/CAPABILITIES.md#tool-gate-action-guard), [Hermes](docs/CAPABILITIES.md#hermes)
- **Headless approvals (Claude Code).** With a notify webhook configured, a held or headless-denied call reaches you as a plain-English card with the `shieldcortex approve` command that releases it; the raw command and any credential stay out of the message (5.18+). OpenClaw uses its own approval flow; Hermes has no prompt. [Detail](docs/CAPABILITIES.md#approval-cards-and-webhooks)
- **Conversation firewall for OpenClaw.** With conversation access granted, the plugin scans what reaches the model and names the pattern an injection hit matched (5.18.2). It observes by default; its `enforce` posture can block a turn on OpenClaw builds that support the gate. [Detail and limits](docs/CAPABILITIES.md#conversation-firewall-openclaw)
- **Tool-output scan.** `scan_tool_response` checks a tool result you pass it for injection, leaked credentials and markdown-image exfiltration, and ShieldCortex's own MCP tools run it on their output. It is a scanner the agent calls, not an interceptor of other tools. [Detail](docs/CAPABILITIES.md#tool-output-scan)
- **Claude SDK browser and computer toolsets.** `shieldcortex/toolsets` records what each click, keystroke and page read would trigger; `mode: 'enforce'` refuses the riskiest calls and holds risky ones for approval (5.8+). [Quickstart](docs/quickstarts/claude-sdk-toolsets.md)
- **Iron Dome.** The behaviour-protection layer behind the gate, with its own `status`, `scan`, `audit` and emergency stop. [Detail](docs/CAPABILITIES.md#iron-dome)

**Protect memory**

- **Memory firewall.** Writes that go through ShieldCortex are scanned before they stick; recognised injection and leaked credentials are quarantined or blocked. It does not replace OpenClaw, Hermes or Claude memory. [How scan results work](docs/SCAN.md)
- **Memory for agents.** `remember`, `recall`, `get_context`, a knowledge graph, contradiction detection and `consolidate` with Dream Mode, served over MCP and the Claude Code and OpenClaw hooks. Prompt-time recall into Claude Code is not automatic; it needs the hook and a config switch. [What it needs](docs/UPDATING.md#dashboard-recall-and-cloud), [detail](docs/CAPABILITIES.md#memory-recall-and-the-knowledge-graph)
- **Memory-file scan.** `shieldcortex audit` reads persistent agent memory files for poisoned instructions and credential leaks. [Detail](docs/CAPABILITIES.md#audit)
- **Recall lanes.** Cron, subagent and liveness turns get narrower prompt-time recall than the owner's chat. [Limits](#known-limits)

**Catch supply-chain and config tampering**

- **MCP tool-description poisoning.** `shieldcortex mcp scan` checks MCP server tool descriptions for poisoning and rug-pull drift, and a background check at each Claude Code session start sends one webhook notification when a description changed or looks suspicious (5.14+). [Scope and limits](docs/CAPABILITIES.md#mcp-tool-description-scan)
- **Skill and instruction files.** `scan-skill <path>` and `scan-skills` read SKILL.md, hook and rules files for hidden instructions; `--accept` records a reviewed file. [Detail](docs/CAPABILITIES.md#skill-and-instruction-file-scan)
- **Packages.** `xray` scans an npm package, file or directory for risky code, `xray-preinstall` can block an install, and both `xray` and `audit` emit SARIF for GitHub Code Scanning. [Detail](docs/CAPABILITIES.md#package-scan-x-ray)
- **Agent config watch.** At each fresh Claude Code startup, the hooks, MCP servers and similar settings in Claude Code, OpenClaw, Cursor, Codex and Gemini CLI configs, and instruction files planted in drop folders such as `~/Downloads`, are checked against a signed baseline, with one webhook notification when something changed outside ShieldCortex. It detects and reports; it does not block. [Limits](docs/security/agent-config-watch.md)
- **Signed config and policy lock.** `~/.shieldcortex/config.json` is signed, so a hand edit is detected and `doctor` reports it; `config --resign` previews a re-sign and `--resign --confirm <sha256>` applies it after review. `sudo shieldcortex protect` pins the security posture in a root-owned lock. [What the signature does and does not guarantee](docs/CAPABILITIES.md#signed-config-and-policy-lock), [Policy lock](docs/UPDATING.md#policy-lock)
- **Script allowlist.** `allowlist add` pins a human-reviewed script by path and content hash; any edit to the file re-gates it. [Detail](docs/CAPABILITIES.md#script-allowlist)

**See and audit**

- **Security audit.** `shieldcortex audit` runs the memory-file, MCP config, environment-file, rules-file and dependency scanners in one pass, as terminal, JSON or SARIF output. [Detail](docs/CAPABILITIES.md#audit)
- **Doctor.** `shieldcortex doctor` checks the install and the configured Guard posture on each plane (Claude Code hook, OpenClaw plugin, Hermes self-report); it fails when the hook and plugin disagree or Hermes reports a looser posture. `guard posture` prints the same reading and changes nothing. [Doctor and the host table](docs/UPDATING.md#doctor-and-the-host-table)
- **Chained audit ledger.** Audit rows form a tamper-evident chain you can verify with `ledger verify`, which exits 1 if the chain is inconsistent; `policy-evidence` reports each runtime's own posture self-report. [What the chain does and does not show](docs/CAPABILITIES.md#ledger-and-policy-evidence)
- **Cortex mistake learning.** `cortex capture` records a mistake, `cortex preflight` checks a task against the record before you repeat it, and a rule can graduate once the record supports it. [Detail](docs/CAPABILITIES.md#cortex)
- **Dashboard.** `shieldcortex dashboard` is a local view: Home, Needs you, Memory, Protection, Settings. It is not an approval inbox. [What it needs](docs/UPDATING.md#dashboard-recall-and-cloud)
- **Claims with proof.** The core memory, recall, gate, environment-firewall and ledger claims each map to a test that fires the real attack and asserts the block, redaction or quarantine. The matrix was written against 4.47 and does not yet cover the detect-only features above. [Claims proof matrix](docs/CLAIMS-PROOF.md)

## Known limits

- **Recall lanes.** In prompt-time recall (the `UserPromptSubmit` hook), turns detected as a cron job, subagent or liveness probe, or pinned to one of those lanes, get narrower recall than the owner's chat, and rows labelled PERSONAL (private-life notes the classifier recognised or a backfill raised) are withheld from them. This is not universal isolation: the stored label is what keeps a note out, so a private note labelled `PUBLIC` can still reach those lanes, and SessionStart context, MCP tool reads and dashboard previews are not lane-scoped. [Recall lanes](docs/UPDATING.md#recall-lanes).
- **Hermes has no approval prompt.** A call Action Guard would hold for approval is blocked while the Hermes plugin enforces. [Hermes](docs/CAPABILITIES.md#hermes)
- **Hook fallback.** If the Claude Code hook fails to load, a bounded fallback still blocks recognised catastrophic commands; nothing else is gated until the hook is repaired. [Full note](docs/UPDATING.md#claude-code-hook-fallback)
- **Enforce-when-ready stays in shadow.** It needs reviewed evidence for the running version, and no such evidence ships yet. [What's new in 5.4](docs/UPDATING.md#whats-new-in-54)
- **One-tap approve is half-shipped.** The 5.18 card and the loopback-only `guard approve-tap` endpoint (off by default) do not yet complete a Telegram tap end to end; approvals still go through `shieldcortex approve`. [Detail](docs/CAPABILITIES.md#approval-cards-and-webhooks)
- **Dashboard counts are partial where labelled.** Memory-pair counts stop at 20 of each kind, the disagreement check compares only the 200 most important memories, and scanner findings cover the whole computer even when a project is selected. [Detail](docs/CAPABILITIES.md#dashboard)

## Free, licensed and Cloud

- **Licence: MIT. Every local feature is free and needs no key.** That includes the memory firewall, Action Guard, all scanners, `audit`, Cortex, Iron Dome, deep X-Ray scans, review-copilot and the local dashboard.
- **Enterprise licence key.** Four cloud and team features need one: full two-way cloud sync of memories, graph and quarantine content; team management; sharing custom patterns across a team; team memory scopes. Writing custom patterns, Iron Dome policies and firewall rules is free and local; only the sharing is gated. Activate with `shieldcortex license activate <key>`. [What is gated](docs/CAPABILITIES.md#what-needs-a-licence)
- **Cloud is a second app**, the fleet view: Shield, Capture, Recall, Library, Graph, Replay, Review, Quarantine, Dome, Devices, Keys. Cloud does not ship X-Ray. Free cloud: 500 scans/month, 7-day retention, 1 member, audit metadata only. Enterprise: sales@drakonsystems.com. [How to connect a box](docs/UPDATING.md#connect-a-box)

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
