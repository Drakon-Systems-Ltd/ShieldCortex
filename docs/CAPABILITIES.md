# Capabilities, limits and where each one lives

This page is the depth behind the README's feature list. Each section says what the feature does, what it does not do, the command or hook that carries it, and where in the source and the [CHANGELOG](../CHANGELOG.md) it is recorded. If a sentence here and a sentence in the README disagree, this page wins and the README needs a fix.

Version numbers are the release that first shipped the behaviour as described. `shieldcortex --help` is the live command list.

## Stop hijacked agents

### Tool gate (Action Guard)

On Claude Code (PreToolUse hook), OpenClaw (`before_tool_call`) and Hermes (`pre_tool_call`), each tool call is evaluated before it runs. Claude Code and OpenClaw gate once the shared Action Guard setting is on; the Hermes plugin enforces from its own switch (see [Hermes](#hermes)). What happens to a verdict depends on the host and the posture:

- **Claude Code and OpenClaw, enforcing.** A trusted call runs. A dangerous-tier call is held for approval: on Claude Code through the host's own permission prompt, on OpenClaw through the host's approval flow when an approver is present, where a plain-English card says what the call does, why it was held and who asked, without the raw command (5.6+); an unattended OpenClaw call, with no approver, falls to the failure policy, which denies high and critical and allows low and medium by default. A catastrophic command is a hard stop and is never approvable. Database, cluster and cloud teardown commands ask for approval (5.6+). The Claude Code webhook card is a separate feature that needs a notify webhook; see [Approval cards and webhooks](#approval-cards-and-webhooks).
- **Claude Code and OpenClaw, watch-only (`enforce: false`).** The ordinary dangerous tier proceeds with a warning and an audit row (5.18.1, #999).
- **Claude Code and OpenClaw, enforce-when-ready shadow.** The ordinary dangerous tier is recorded as `would_hold` or `would_block` and proceeds.
- **What stays strict in every posture.** Catastrophic calls are a hard stop. Calls that touch the guard's own state or config (the self-protection floor) are held or blocked, and the session-lease floor (#227) is enforced alongside it. A call the guard could not scan in full, the #436 class (a tool input the schema rejected, or a command whose evidence walk ran out of budget), skips the watch-only and shadow exits: on OpenClaw it goes to a human, or with no approver to the failure policy, which denies unless `interceptor.failurePolicy.high` is explicitly `allow`; on Claude Code it takes the ask-or-deny door. Other partial-scan findings follow the ordinary dangerous tier in watch-only and shadow (5.18.1, 5.18.2 notes).
- **Hermes.** No approval prompt exists, so a call Action Guard would hold is blocked while the plugin enforces; advisory mode warns on the dangerous tier and still blocks catastrophic and self-protection verdicts. There is no card on Hermes.

Action Guard stays off until you turn it on. The shared setting is the gate for Claude Code and OpenClaw; `sudo shieldcortex protect` turns it on and pins that posture in a root-owned policy lock ([Policy lock](UPDATING.md#policy-lock)). Hermes does not read the shared setting; see [Hermes](#hermes).

- Source: `src/guard/`, `src/defence/iron-dome/`, `scripts/pre-tool-hook.mjs` (verdict-to-decision mapping in the header: catastrophic always `deny`, dangerous `ask` or, with `enforce: false`, a warning and no decision; the header also names the three floors enforced in every posture; `isSchemaInvalid` and `unscannedBlock` keep the #436 class out of the shadow and advisory exits), `plugins/openclaw/index.ts`, `plugins/openclaw/interceptor.ts` (`isSchemaInvalid`, `unscannedBlock`, the shadow and watch-only exits, `failurePolicy` default `high: 'deny'`, `evaluateToolCallLease`), `plugins/hermes/shieldcortex/policy.py`
- CHANGELOG: 5.6.0 (approval cards, teardown approvals), 5.15.0 (#922 guard posture), 5.18.1 (#999 watch-only and shadow on a tainted session)

### Approval cards and webhooks

The card is a Claude Code hook feature and needs a configured notify webhook (`actionGuard.notify` with `enabled: true` and a `webhookUrl`). When that hook sends a headless denial (`action_guard_denial` with outcome `denied_no_prompt_surface`) or a held approval request (`approval_requested`) to the webhook, the body ends with a `card` block (5.18+, version 1): a plain-English what, why and who, the exact `shieldcortex approve` command (for a held call it releases that one call once; for a headless denial it authorises one retry of a call that is already gone), and, for a headless denial only, Approve/Deny choices that carry only the action id. A held approval card has no action id and no choices: it carries `approve` and `deny` commands bound to the short hash (and the attempt id where there is one). Only a retryable headless denial carries `approve --denial <actionId>` and the action-id choices; any other denial is explained with no command and no choice. The card never carries the raw command or a credential. Other denials, advisory warnings and the OpenClaw plugin's webhook messages carry no card; OpenClaw approvals go through the host's own approval flow. With no webhook configured, `doctor` says in plain terms that nobody is told when Action Guard blocks something while nobody is at a prompt.

The guard half of one-tap approve from Telegram also ships in 5.18, as a loopback-only `shieldcortex guard approve-tap` endpoint that is off by default. The chat half is not in this release, so a tap cannot be completed end to end yet; approvals still go through `shieldcortex approve`.

- Commands: `shieldcortex approve <hash>` (held call), `shieldcortex approve --denial <actionId>` (headless denial), `shieldcortex deny [hash]`, `shieldcortex guard approve-tap`, `shieldcortex guard test-approval`
- Source: `src/cli/approve.ts`, `src/cli/deny.ts`, `src/cli/approve-tap.ts`, `src/cli/guard.ts`
- CHANGELOG: [What's new in 5.18](UPDATING.md#whats-new-in-518), 5.6.0

### Conversation firewall (OpenClaw)

The OpenClaw plugin scans the conversation that reaches the model on the `llm_input` hook and records what it finds. `llm_input` is an observation hook: it has no blocking contract, so a detection there is audited and sent to the operator but cannot stop the turn. Blocking is a separate posture: `observe` (the default) scans, audits and notifies and never blocks; `enforce` additionally blocks the run through the `before_agent_run` gate, which exists only on OpenClaw builds that declare it. `doctor` and the plugin's own status say which of the three states the host is in. The `llm_output` hook does not scan the reply: its handler (`captureLlmOutput` in `plugins/openclaw/index.ts`) extracts memory candidates from the assistant text, screens each candidate before the write and saves the survivors through `remember`; the plugin's own status line describes it as `llm_output (memory)`. The header comment at the top of that file still says `llm_input/llm_output scanning`; that comment is stale and the handler is what ships.

From 5.18.2, an in-process injection hit on `llm_input` records `injectionPatterns`, closed-set `category:pattern` ids, so a false positive can be traced to a rule. The matched text is still not stored.

Limits: the hooks are only live when the host grants conversation access (`plugins.entries.shieldcortex-realtime.hooks.allowConversationAccess=true` in `openclaw.json`); without it, `doctor` and the plugin's own status report the scanning as inactive. A detection on `llm_input` cannot stop the turn; `enforce` blocks only through `before_agent_run`. A scan that did not complete is never recorded as clean. `observe` stays the default. The MCP fallback path has no local pattern names.

- Source: `plugins/openclaw/index.ts`, `plugins/openclaw/conversation-access.ts`
- CHANGELOG: 5.18.2 (#1010); the firewall itself: 4.47.39
- See also: [OpenClaw integration](openclaw-integration.md), [Conversation provenance](security/conversation-provenance-911.md)

### Tool-output scan

The `scan_tool_response` MCP tool, and the `withResponseScan` wrapper around ShieldCortex's own MCP tools, scan tool output on the read path for injection, encoded or obfuscated instructions, markdown-image exfiltration and leaked credentials, using the same detectors as the memory write path.

Limits: it is a scanner the agent or the integration calls, not an interceptor. It runs on the output of ShieldCortex's own MCP tools (through `withResponseScan`) and on any tool result the agent passes to `scan_tool_response`; it does not see the output of other tools unless something hands it over. Advisory by default, which logs threats and leaves the response untouched. In enforce mode the scanner also computes a sanitised copy (injection withheld, secrets redacted, exfiltration links stripped) that the caller swaps in. It never blocks tool execution, only the threatening output.

- Source: `src/defence/tool-response-scanner.ts` (`mode: 'advisory' | 'enforce'`; the enforce branch computes `sanitisedContent`), `src/server.ts` (ten `withResponseScan(` wraps: `recall`, `get_context`, `get_memory`, `export_memories`, `get_related`, `detect_contradictions`, `graph_query`, `threat_graph`, `graph_entities`, `graph_explain`; the `scan_tool_response` tool calls the scanner directly)
- CHANGELOG: 4.37.0 (`scan_tool_response` surfaces the sanitised payload), later parity work; 5.3.0 (#506 injection floor: authority spoofing inside tool results, verbatim extraction asks, ten languages, ROT13)

### Claude SDK browser and computer toolsets

`shieldcortex/toolsets` (5.8+) sits in front of a Claude SDK browser-use or computer-use driver and by default records what each click, keystroke, navigation and page read would trigger without changing what runs. `mode: 'enforce'` refuses the riskiest calls outright, holds risky ones (such as irreversible clicks after a page read) for your approval, and lets the rest run. It does no memory scan.

- Source: `src/integrations/claude-toolsets.ts`, package export `./toolsets`
- Docs: [Quickstart](quickstarts/claude-sdk-toolsets.md), [What's new in 5.8](UPDATING.md#whats-new-in-58)

### Iron Dome

Iron Dome is the behaviour-protection layer that Action Guard's verdicts come from. The CLI exposes `iron-dome status`, `scan --text "..."` or `scan --file <path>`, `audit`, `activate`, `deactivate` and `confirmation`; the MCP server exposes `iron_dome_status`, `iron_dome_scan`, `iron_dome_check`, `iron_dome_activate`, `iron_dome_resume` and `iron_dome_emergency_stop`. Custom Iron Dome policies are a free local feature.

- Source: `src/defence/iron-dome/`, `src/cli/iron-dome.ts`, `src/server.ts`
- CHANGELOG: 2.14.0 (introduced)

## Protect memory

### Memory firewall

Writes that go through ShieldCortex (`remember`, the hooks, the plugins, `shieldcortex scan`) run through the defence pipeline before they are stored. Recognised injection and leaked credentials are quarantined or blocked, and the exit code of `scan` is non-zero on a catch. ShieldCortex does not replace OpenClaw, Hermes or Claude memory: writes that bypass it are not scanned.

- Source: `src/defence/pipeline.ts`, `src/defence/firewall/`, `src/defence/credential-leak/`
- Docs: [How scan results work](SCAN.md), [Claims proof matrix](CLAIMS-PROOF.md)

### Memory, recall and the knowledge graph

The MCP server (`shieldcortex` with no arguments, or `--mode mcp`) serves `remember`, `recall`, `get_context`, `get_memory`, `get_related`, `link_memories`, `forget`, `export_memories`, `import_memories`, `scan_memories`, `detect_contradictions`, `consolidate`, `graph_query`, `graph_entities`, `graph_explain`, `threat_graph`, `quarantine_review`, `audit_query`, `defence_stats`, `memory_stats`, session tools and project tools. `graph_query` traverses the knowledge graph from an entity (breadth-first, each reachable entity once); `graph_entities` lists known entities by type.

`shieldcortex consolidate` runs memory maintenance and then Dream Mode consolidation (merge duplicates, archive stale, detect contradictions). Typed memories, Dream Mode and LLM reranking are free local features.

Prompt-time recall into Claude Code (the `UserPromptSubmit` hook) is not automatic: it needs the hook that `setup` wires and a config switch; see [Dashboard, recall and Cloud](UPDATING.md#dashboard-recall-and-cloud) and [Recall lanes](UPDATING.md#recall-lanes) for what is injected and when.

- Source: `src/server.ts`, `src/memory/`, `src/graph/`, `src/memory/consolidate.ts`
- CHANGELOG: 1.13.0 (`graph_query`), 4.47.0 (every local feature free)

### Recall lanes

In prompt-time recall (the `UserPromptSubmit` hook), turns detected as a cron job, subagent or liveness probe, or pinned to one of those lanes, get narrower recall than the owner's chat, and rows labelled PERSONAL are withheld from them. This is not universal isolation: the stored label is what keeps a note out, so a private note labelled `PUBLIC` can still reach those lanes, and SessionStart context, MCP tool reads and dashboard previews are not lane-scoped. [Recall lanes and the PERSONAL tier](UPDATING.md#recall-lanes).

## Catch supply-chain and config tampering

### MCP tool-description scan

`shieldcortex mcp scan [server]` starts the local (stdio) MCP servers found in your configs, reads their tool lists and checks each description for poisoning and for rug-pull drift against the previous reading. The manual scan reads user-level configs (Claude Code, Claude Desktop, OpenClaw, VS Code, Cursor, Windsurf, Codex) and the project-local ones under the current directory (`.claude/mcp.json`, `.claude.json`, `.vscode/mcp.json`, `.cursor/mcp.json`); a server name defined in both keeps a separate baseline per config file (5.14.0). `--json` and `--ci` are for pipelines.

From 5.14.0 (#915), the Claude Code session-start hook also launches this check detached in the background, at most once per 6 hours per server unless that server's launch command, arguments or environment changed. When a description changed or looks suspicious it sends one plain notification to the `actionGuard.notify` webhook as an `mcp_tool_change` event and records the finding in the `mcp_tool_findings` table.

Limits of the automatic check: user-level configs only, never a project-local one (a repository-controlled config must not start its commands without approval). Alerts go only to the `actionGuard.notify` webhook; it does not need Action Guard on. With no webhook configured, or when delivery fails, the finding is kept as a pending row and retried at the next session start, and nothing is shown in the session. It fails open. Turn it off with `"sessionStart": { "mcpToolCheck": false }` in `~/.shieldcortex/config.json` (a hand edit makes the file fail its signature check; see `shieldcortex config --resign`).

- Source: `src/cli/mcp.ts`, `src/audit/mcp-config-scanner.ts` (`discoverMcpServers`, `includeProject` defaults to true for the manual scan), `src/audit/mcp-tools-autocheck-runner.ts` (passes `includeProject: false`)
- CHANGELOG: 4.32.0 (`mcp scan`), [What's new in 5.14](UPDATING.md#whats-new-in-514) (#915)

### Skill and instruction file scan

`shieldcortex scan-skill <path>` scans one agent instruction file (SKILL.md, hook, rules file) for hidden instructions and threat patterns; `--accept` records a reviewed file so it stops being flagged and `--forget` undoes that. `shieldcortex scan-skills` discovers and scans all installed skills and hooks. The same detection runs at memory-write time, so a skill-shaped payload is also caught when an agent tries to remember it. The MCP server exposes `scan_skill`.

- Source: `src/index.ts` (`scan-skill`, `scan-skills`), `src/xray/`
- CHANGELOG: 2.4.24 (introduced), 4.x (format-aware density cap, #121)

### Package scan (X-Ray)

`shieldcortex xray <target>` scans an npm package, file or directory for risky code. `--deep` adds npm registry analysis, binary file inspection, dependency-graph risk and AI-directive detection in metadata and filenames; it is free. `--sarif` emits SARIF 2.1.0 for GitHub Code Scanning, `--ci` exits non-zero on findings, `--watch` re-scans on change. `shieldcortex xray-preinstall` checks `./package.json` scripts before an install and exits 1 to block it. The local dashboard shows the same scanner under Protection as "Skill & package scanner".

Note: `xray` report output still labels deep mode "Deep Scan (Pro)". That label is stale; the gate in `src/license/gate.ts` marks `xray_deep` free and no key is checked.

- Source: `src/xray/index.ts`, `src/xray/sarif.ts`, `src/xray/report.ts`

### Agent config watch

At each fresh Claude Code startup (`source=startup`; not on resume, compact or clear), a detached background process hashes the security-relevant keys of the agent and editor config files that decide what an agent runs on its own (hooks, MCP servers, environment, tasks, plugin registrations, the Codex sandbox, trust and provider settings) in Claude Code, OpenClaw, Cursor, Codex and (5.17+) Gemini CLI, plus agent instruction files planted in drop folders such as `~/Downloads`. It compares them with a signed baseline and sends one `agent_config_change` notification to the Action Guard webhook when something changed outside ShieldCortex. `doctor` has an `Agent config watch` row.

Limits: it detects and reports; it does not block, and it is not live between startups. It runs only on `source=startup`, not on resume, compact or clear. Startup checks compare against an established baseline and report changes rather than prevent them; the first run records that baseline.

- Source: `src/cli/doctor.ts` (`Agent config watch`), session-start hook
- CHANGELOG: 5.16.0 (#916), 5.17.0 (#965 Gemini CLI)
- Docs: [Agent config watch](security/agent-config-watch.md)

### Signed config and policy lock

`~/.shieldcortex/config.json` is signed. What the signature guarantees:

- **Tampering is detected and reported.** A hand edit fails the check. `doctor` reports it and writes nothing; its posture row says `Guard unknown` rather than `off` while the signed posture depends on a signature not yet adopted, and it names no posture command in that state.
- **ShieldCortex never re-signs a tampered file on its own.** Explicit setters refuse and automatic writers skip. `shieldcortex config --resign` prints the verdict, the sha256 of the current bytes and the settings that would leave the strict posture, and writes nothing; only `--resign --confirm <sha256>` re-signs, and only the exact bytes previewed (5.11, #647).
- **A file the runtime cannot authenticate is held strict, not guessed.** In the OpenClaw runtime, a `config.json` that is a link, or whose metadata cannot be read, is accepted only with a valid signature, and a valid signature is honoured even when it turns Guard off; unsigned or mis-signed, it is held at the strict posture (Guard on and enforcing, no auto-approve, broker off, no readiness gate) (5.17.2, #878, PR #984). The CLI applies the same strict view on a normal read to a file whose signature check says it was tampered with, and to an unsigned or mis-signed file behind a link. `doctor` is a read-only caller: it enforces nothing, and for an unsigned file behind a link it reports the posture as unknown. The Claude Code hook checks only symlinked config; if it cannot read a file's metadata it uses the bytes it parsed, not the strict posture.
- **An established posture survives a file that breaks underneath it.** Once a process has read a posture, a file that turns blank, corrupt or unreadable keeps that posture and config writes are refused. A deliberate signed change, including turning Guard off, takes effect.

The Claude Code hook and the OpenClaw runtime do not verify a plain regular `config.json`; the CLI applies a strict view to a tampered file, or to an unverified file behind a link, before the policy lock is applied; and a signature alone is not a same-user boundary. Enforcement is the policy lock's job: `sudo shieldcortex protect`, run once by a human as root, pins the security-critical settings in a root-owned lock.

- Source: `src/cli/dispatch-help.ts` (`--resign` grammar), `src/cloud/config.ts` (`readRawConfigState`: strict view on `tampered`, and on `unverified` for a non-read-only caller), `src/guard/posture-switch.ts` (`runtimeBase`, `gradedPosture`, `UNKNOWN_FIX`), `src/cli/protect.ts`, `src/cli/doctor.ts`, `src/setup/host-table.ts` (`Guard unknown`)
- CHANGELOG: [What's new in 5.11](UPDATING.md#whats-new-in-511) (#647), 5.17.2 (#878), [Policy lock](UPDATING.md#policy-lock)

### Script allowlist

`shieldcortex allowlist add|remove|verify|scan` pins a human-reviewed script by path and content hash. Normally, when a call runs a script, the guard reads the script's contents into the scan of that call; a pinned script is skipped as already reviewed. Any edit to the file changes the hash and re-gates it. `allowlist scan` discovers cron-referenced scripts and batch-reviews new or changed ones in the terminal.

- Source: `src/cli/allowlist.ts`, `src/cli/allowlist-scan.ts`
- CHANGELOG: 4.13.0 (introduced), 5.10.1 (#786 JSON escaping)

## See and audit

### Audit

`shieldcortex audit` runs four scanners in one pass: persistent agent memory files (poisoned instructions, credential leaks), MCP configs, environment files and rules files. Project dependencies are scanned only when you add `--deps`, which makes it five. Output is terminal, `--json`, markdown or `--sarif` (SARIF 2.1.0 for GitHub Code Scanning); `--ci` is for pipelines. Dependency quarantine, clean and auto-protect are free local features. Findings link to live `shieldcortex.ai/docs` anchors: `#audit` for the environment, MCP config, MCP tool and rules-file scanners and the report footer, `#attack-vectors` for the memory scanner, and `#dependency-scanner` for the dependency scanner (5.17.2, PR #975).

- Source: `src/cli/audit.ts`, `src/audit/env-scanner.ts`, `src/audit/mcp-config-scanner.ts`, `src/audit/mcp-tools-scanner.ts`, `src/audit/report-formatter.ts` (`#audit`), `src/audit/memory-scanner.ts` (`#attack-vectors`), `src/audit/dependency-scanner.ts` (`#dependency-scanner`)
- CHANGELOG: 2.9.0 (introduced), 5.17.2 (PR #975 learn-more links)
- Docs: [Audit waivers](security/audit-waivers.md)

### Doctor and guard posture

`shieldcortex doctor` diagnoses the install and exits 1 on a failure (`--strict` also fails on a warning). Its `Action guard posture` row shows the configured posture of each gate plane: the Claude Code hook, the OpenClaw plugin (its `openclaw.json` entry merged over the shared setting, then the policy lock) and Hermes (from the Hermes process's own self-report only). It fails when the hook and the plugin disagree, or when Hermes reports a looser posture than they hold; Hermes reporting a tighter one is shown, not failed. These are configured postures, not a check of running processes. Other rows cover stale Hermes plugin copies (`--fix-hermes-plugin-copies`), the agent config watch, memories, semantic coverage, disk, and the host table. `shieldcortex guard posture` prints the posture reading and changes nothing; `guard readiness` shows the enforce-when-ready state per surface.

- Source: `src/cli/doctor.ts`, `src/cli/guard.ts`
- Docs: [Doctor and the host table](UPDATING.md#doctor-and-the-host-table), [Doctor severity notes](openclaw-integration.md#doctor-severity-notes-651)

### Ledger and policy evidence

`shieldcortex ledger verify [--json]` opens the database read-only, walks the chained audit ledger and reports whether it is internally consistent: the first bad row if not, and unchained history from older builds as "unchained". It exits 1 if inconsistent. A consistent result shows the chain is internally consistent; it does not show that the history is complete or that the whole chain was not replaced, which would need a head retained outside the database, and the report says so each time. `shieldcortex policy-evidence` (5.5+) reports what each runtime's own self-report says it is enforcing, as local self-reports rather than attestation.

- Source: `src/cli/ledger.ts`, `src/cli/policy-evidence.ts`
- CHANGELOG: [What's new in 5.5](UPDATING.md#whats-new-in-55), [Older copies sharing a chained database](UPDATING.md#mixed-version-ledger)

### Cortex

`shieldcortex cortex capture` records a mistake with its context; `cortex preflight` checks a task description against the recorded mistakes and active rules before you repeat the work; `cortex review`, `graduate`, `list`, `stats` and `search` manage the store, and `cortex confirm` / `confirmations` record what worked. `cortex review` lists rules that are ready to graduate and `cortex graduate` promotes them. Cortex is a free local feature.

Note: `shieldcortex --help` still labels `cortex` and `review-copilot` "(Pro)". Those labels are stale; `src/license/gate.ts` marks `cortex_learning`, `review_copilot` and `local_ai_explainer` free and no key is checked.

- Source: `src/cortex/cli.ts`
- CHANGELOG: 1.3.1 (introduced), 4.47.0 (free)

### Dashboard

`shieldcortex dashboard` is a local view: Home, Needs you, Memory, Protection, Settings. The Skill & package scanner (formerly X-Ray) is a Protection tab. Memory has Search & browse, Map, Recall, Needs a check, Timeline, Replay and Files. Needs you lists held-back items, memory pairs that disagree or look duplicated, and new scanner findings. It is not an approval inbox: held actions are still answered in Telegram or OpenClaw.

Its counts are labelled when they are partial: pair counts stop at 20 of each kind and the disagreement check compares only the 200 most important memories, a list that failed to refresh shows its last known count, and scanner findings cover the whole computer even when a project is selected.

- Source: `dashboard/`, `src/api/`
- Docs: [What it needs](UPDATING.md#dashboard-recall-and-cloud)

## Hosts and fallbacks

### Hermes

Hermes gates tool calls once you run `hermes plugins enable shieldcortex` and the local API (`shieldcortex api`) is up. The enabled plugin enforces by default, whatever the shared Action Guard setting says: it blocks unless `SHIELDCORTEX_ENFORCE` opts it out (`0`, `false`, `no`, `off` or `advisory`). Hermes has no approval prompt, so a call Action Guard would hold for approval is blocked while enforcing. Advisory mode still blocks Action Guard's hard-block verdicts and recognised calls that would change the guard's own state or config. Reading that config is not such a call when it is a plain read-only command with plain arguments. The guard keeps treating it as one when the read is wrapped in an environment prefix, carries an option it cannot prove harmless, is redirected, nests another command, or runs through an interpreter (5.14.0, #920). While the API is unreachable, its bounded fallback scan blocks the self-protection and catastrophic shapes it recognises in every mode, and recognised dangerous shapes while enforcing (the default). In advisory mode, only the recognised self-protection and catastrophic shapes are blocked by the fallback.

- Source: `plugins/hermes/shieldcortex/policy.py` (enforce by default; `require_approval` becomes a block while enforcing or on the self-protection floor), `src/defence/iron-dome/tool-action-guard.ts` (`GUARD_CONFIG_READONLY_VERB_RE`)
- CHANGELOG: 4.47.2 (enforce by default), 5.14.0 (#920 plain reads)
- Docs: [Hermes plugin](../plugins/hermes/shieldcortex/README.md)

### Claude Code hook fallback

If the Claude Code PreToolUse hook fails to load, a bounded fallback still blocks recognised catastrophic commands, even with the guard off. While the hook is broken those patterns also stop routine recursive force-deletes. Calls that do not match stay fail-open. [Full note](UPDATING.md#claude-code-hook-fallback).

### Enforce-when-ready

The optional enforce-when-ready posture runs the dangerous tier in shadow until this install's own audit shows the guard is operable and reviewed evidence for the running version exists. No such evidence ships yet, so today it stays in shadow and says so. [What's new in 5.4](UPDATING.md#whats-new-in-54).

### MCP hosts

Codex, Cursor, VS Code and other MCP hosts get a memory server the model may call. That server is a scanner, not a deny: it scans what the agent sends through it and cannot stop a tool call the host makes on its own.

## What needs a licence

The gate is `src/license/gate.ts`. Every feature it lists is `free` except four, which need a licence at team rank or above (an Enterprise key, or a grandfathered Team key):

| Feature | Gate name | What it is |
|---|---|---|
| Full cloud sync | `cloud_sync` | Two-way sync of memories, knowledge graph and quarantine content to ShieldCortex Cloud |
| Team management | `team_management` | Members, invites and shared security policies |
| Shared patterns | `shared_patterns` | Share your custom patterns across a team. Writing custom patterns and Iron Dome policies is free (`custom_iron_dome_policies: 'free'`); only the sharing is gated |
| Team memory scopes | `memory_scopes` | Private versus team memory scopes for multi-agent deployments |

Everything else, including custom injection patterns, custom Iron Dome policies, custom firewall rules, audit export, deep skill scanning, the dependency scanner, typed memories, Dream Mode, LLM reranking, the local AI explainer, memory-file scan, review-copilot and deep X-Ray, is free and checks no key. Audit-metadata sync to the Free cloud tier (`cloud_audit_sync`) is also free.

Activate a key with `shieldcortex license activate <key>`; `shieldcortex license status` shows the current tier. Enterprise: sales@drakonsystems.com.

- Source: `src/license/gate.ts`, `src/license/__tests__/feature-gating.test.ts`
- CHANGELOG: 4.47.0 ("Every local feature is now Free")
