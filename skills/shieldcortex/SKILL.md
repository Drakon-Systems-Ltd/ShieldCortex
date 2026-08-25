---
name: shieldcortex
description: "Memory and defence for AI agents: semantic recall, knowledge graph and decay, plus a memory firewall that scans and enforces against prompt injection, credential leaks and poisoning."
license: MIT-0
metadata:
  author: Drakon Systems
  version: 4.54.13
  mcp-server: shieldcortex
  category: memory-and-security
  tags: [memory, security, knowledge-graph, mcp, iron-dome, openclaw-plugin, audit]
  source: https://github.com/Drakon-Systems-Ltd/ShieldCortex
  homepage: https://shieldcortex.ai
  npm: https://www.npmjs.com/package/shieldcortex
  verified_publisher: Drakon Systems Ltd
  publisher_github: https://github.com/Drakon-Systems-Ltd
  npm_audit: clean
  snyk: no-known-vulnerabilities
  downloads: 11K+/month
install:
  command: shieldcortex quickstart
  runtime: node
  minVersion: "20"
  note: >
    Run the installed `shieldcortex` binary directly. The quickstart command
    detects your environment. Claude Code and OpenClaw get hooks that can deny;
    Codex/Cursor/VS Code get an MCP memory server only (not a tool gate).
    All data stays local in ~/.shieldcortex/. No account or API key needed
    for local use.
permissions:
  filesystem: readwrite
  network: optional
  credentials: optional
  justification: >
    Filesystem read: scans agent instruction files for prompt injection threats
    (same files the agent already reads). Filesystem write: stores memory DB
    and config in ~/.shieldcortex/. Network: off by default, only used when
    Cloud sync is explicitly enabled by the user. Credentials: optional Cloud
    API key for team sync (not required for local use).
  paths_read:
    - ~/.shieldcortex/ (own config and memory database)
    - ~/.claude/ (project memory files, MCP config)
    - ~/.openclaw/ (MCP config, extensions)
    - ~/.cursor/ (rules, memories, MCP config)
    - ~/.windsurf/ (memories, rules)
    - ~/.codex/ (MCP config)
    - $CWD/.claude/, $CWD/.cursor/ (project-level configs)
    - $CWD/.cursorrules, $CWD/.windsurfrules, $CWD/.clinerules
    - $CWD/CLAUDE.md, $CWD/copilot-instructions.md
    - $CWD/.aider.conf.yml, $CWD/.continue/config.json
    - $CWD/.env (env-scanner checks for leaked secrets — reads, never writes)
  paths_write:
    - ~/.shieldcortex/ (memory DB, config, cortex log, licence, audit cache)
    - ~/.openclaw/extensions/shieldcortex-realtime/ (OpenClaw plugin via the wrapper install only; native `openclaw plugins install` uses OpenClaw's managed npm tree instead)
    - ~/.claude/mcp.json, ~/.cursor/mcp.json (MCP server registration, when user runs setup)
  network_endpoints:
    - https://api.shieldcortex.ai (Cloud sync, licence validation — only when Cloud is enabled by user)
    - http://localhost:3001 (local REST API + WebSocket — loopback only)
    - http://localhost:3030 (local dashboard UI; also the worker health check — loopback only)
  env:
    - SHIELDCORTEX_CONFIG_DIR: Override config directory (default ~/.shieldcortex/)
    - SHIELDCORTEX_API_KEY: Cloud sync API key (optional; only used when Cloud is enabled)
    - SHIELDCORTEX_LICENSE_TIER: Override licence tier (development use)
    - SHIELDCORTEX_SKIP_EMBEDDINGS: Disable embedding generation
    - SHIELDCORTEX_SKIP_SELF_HEAL: Set to 1 to make the cortex-memory hook's bootstrap self-heal warn-only (writes nothing)
    - SHIELDCORTEX_HOST: Override dashboard/API bind host
    - PORT: Override dashboard/API port
---

# ShieldCortex — Persistent Memory & Security for AI Agents

Memory system with built-in security. Gives agents persistent memory (semantic search, knowledge graphs, decay, contradiction detection) and protects it with a 6-layer defence pipeline (input sanitisation → trust scoring → firewall → sensitivity classification → fragmentation detection → credential-leak detection). Skill threat patterns (tool injection, scope escalation, data exfiltration, persistence, supply-chain, agent manipulation, stealth instructions) block at memory-write time, not just on skill-file scans.

This is an enforcing memory boundary, not a passive scanner. Across the read/write boundary it actively: **quarantines or blocks** poisoned/credential-bearing writes; **trust/ACL-filters recalled memory** (RESTRICTED isolation, own-only for low-trust callers) before it reaches the agent, on both the prompt hooks and the MCP read tools; runs a **tool-output firewall** that, in enforce mode, redacts or withholds malicious tool results before the model sees them (advisory by default); and keeps a **provenance ledger** recording read/write/delete operations with content hashes for forensics. Enforcement that could surprise is opt-in (the tool-output firewall defaults to advisory; `shieldcortex config --tool-firewall-enforce` turns on blocking).

## Provenance & Trust

| Signal | Value |
|--------|-------|
| **Publisher** | [Drakon Systems Ltd](https://github.com/Drakon-Systems-Ltd) (UK company) |
| **Source code** | [github.com/Drakon-Systems-Ltd/ShieldCortex](https://github.com/Drakon-Systems-Ltd/ShieldCortex) — fully open, **MIT** licence (this skill file itself is published MIT-0, per the frontmatter) |
| **npm package** | [npmjs.com/package/shieldcortex](https://www.npmjs.com/package/shieldcortex) — every release git-tagged with a matching GitHub release |
| **npm audit** | Clean — `npm audit` returns 0 vulnerabilities |
| **Downloads** | 11,000+/month (July 2026) |
| **CI/CD** | CI lint/test on every push; the maintainer manually tags each release, and the tag push triggers an automated CI publish to npm |
| **Postinstall script** | Declared and bounded: prints setup instructions; on **global** installs it also smoke-tests the native SQLite binding, seeds default config on first install, and refreshes an OpenClaw hook/plugin that a previous setup already installed. It never adds integrations to a machine that had none, and it is a no-op for CI and local dependency installs. `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1` skips the refresh. |
| **Dependencies** | 8 runtime deps: `better-sqlite3`, `zod`, `@modelcontextprotocol/sdk`, `express`, `ws`, `cors`, `safe-regex2`, `semver`. `express`/`ws`/`cors` serve the bundled localhost-only dashboard/API; nothing dials out unless Cloud sync is explicitly enabled. |

## Safety & Scope

This section explains every privileged operation the tool performs and why.

- **Active interception, not scan-only — on hosts that can deny.** Writes failing the pipeline are quarantined/blocked; recalled memory is trust/ACL-filtered before the agent sees it. Tool-call denial is **bound** on Claude Code (PreToolUse), OpenClaw (`before_tool_call`), and Hermes (`pre_tool_call`, enforce by default). Codex, Cursor, Copilot, and generic MCP get a memory server / scanner the model may ignore — they are **not bound**. Tool-output firewall defaults to advisory. `shieldcortex doctor` and `shieldcortex lease` report bound / not-bound / unknown per plane.
- **Setup is user-initiated, with one bounded exception.** Installing hooks, registering the MCP server, and migrating data are manual steps the user runs in their terminal, and `quickstart` asks before each action. The npm postinstall script (disclosed in the trust table above) never adds integrations that weren't already present — on global installs it only prints instructions, checks the native binding, seeds default config on first install, and refreshes an existing OpenClaw hook/plugin install. The exception: the bundled cortex-memory hook performs a small automatic self-heal at gateway bootstrap, documented in full under **"Automatic self-heal at gateway bootstrap"** below.
- **Setup migrates legacy data.** The first `quickstart`/`setup` run may move or remove legacy config/memory directories (e.g. `~/.claude-cortex/`, `~/.claude-memory/`) into `~/.shieldcortex/` and copy hook files into place. This happens only on the user-run setup command — never on `npm install` (the postinstall script does not touch memory or config data beyond seeding defaults on a first-ever global install).
- **Destructive `forget` is bounded and gated.** Per-memory and filtered bulk deletes go through a delete ACL (own-only) and are recorded in the audit ledger. Revoke-by-source (`forget --fromSource`, bulk-delete every memory from one source — for purging a poisoned agent) is **disabled by default** and only enabled by an out-of-band human action (`shieldcortex config --allow-revoke-by-source`); even then it is bounded by a trust-hierarchy ACL (you must own the source or out-rank it) and a per-call row cap. A compromised agent cannot mass-delete your memory.
- **The bundled dashboard never renders RESTRICTED content.** The local visualization API and its WebSocket feed redact credential-class (`RESTRICTED`) memory content before it reaches the browser — the row stays visible (title/metadata) so you can manage it, but the secret is withheld (view full content via the CLI). Credential patterns in titles/metadata are masked too. This is a display-surface safeguard on top of the on-disk store; it does not weaken the firewall.
- **No credentials required for local use.** Memory, scanning, and audit work fully offline. Cloud sync is opt-in and requires a user-provided API key via `shieldcortex config --cloud-enable --cloud-api-key <key>`.
- **File access is declared and scoped.** Security scans read agent config directories listed in the permissions block above — the same directories the agent itself already has access to. They do not traverse arbitrary directories.
- **Writes are contained.** All data goes to `~/.shieldcortex/`. MCP config edits (`setup`, `copilot`, `codex` commands) modify specific JSON files and confirm before writing.
- **Network is off by default.** No outbound connections unless Cloud sync is explicitly enabled by the user. The dashboard and worker bind to localhost only.
- **Bundled source code.** The OpenClaw plugin and cortex-memory handler are shipped in the package for inspection before use.
- **Lifecycle event handlers.** ShieldCortex registers lifecycle handlers that auto-extract important context from conversations. These are registered in `~/.claude/settings.json` during setup and can be removed at any time. They run locally, never phone home.
- **Proactive recall.** The UserPromptSubmit handler queries local memory on each prompt (<100ms) and surfaces relevant context. Fully local, configurable: `shieldcortex config --proactive-recall false`.

### Automatic self-heal at gateway bootstrap

The cortex-memory hook registers for the `agent:bootstrap` event. On the first
bootstrap after each OpenClaw gateway start (once per gateway process), it runs
a self-check that can write without a prompt. In the interest of full
disclosure, this is exactly what it does:

1. **Removes stale legacy hook copies.** If the hook is running from its
   expected home (`~/.openclaw/hooks/internal/cortex-memory` or
   `~/.openclaw/hooks/cortex-memory`), it recursively deletes the pre-rename
   leftovers `~/.clawdbot/hooks/cortex-memory` and
   `~/.clawdbot/hooks/internal/cortex-memory` — and only those two
   directories. It skips this entirely when `~/.clawdbot` is a symlink (i.e.
   still pointing at a live install). No backup is taken before deletion;
   these directories are assumed to be dead copies of this hook's own files,
   not your data.
2. **Copies itself to the expected hook path.** If the hook finds itself
   running from anywhere else (for example, from inside this skill's
   `bundled/` folder after a skills-only install), it creates
   `~/.openclaw/hooks/internal/cortex-memory/` and copies its full file set
   (`HOOK.md`, `handler.ts`, `runtime.mjs`) there so the gateway loads it from
   the canonical location on the next restart, and surfaces a
   `SHIELDCORTEX_HOOK_MIGRATED.md` notice into the session's bootstrap context.
   If any file in that set fails to copy, the migration is reported as
   incomplete rather than as a success — a partially-copied hook cannot load.
3. **Checks for staleness (read-only).** It compares the running hook files
   against the installed npm package's copies and warns if they differ. This
   step never writes.

**Scope limits:** the self-heal writes only inside `~/.openclaw/hooks/**` and
deletes only the two `~/.clawdbot` hook directories named above. It does not
modify `openclaw.json`, `~/.claude/settings.json`, MCP config, shell configs,
or any other file; it makes no network calls; failures are swallowed so it can
never block agent startup.

**Opting out (since v4.47.12):** either of these downgrades steps 1 and 2 to
warn-only — the hook logs exactly what it would have deleted or copied and
touches nothing:

```bash
shieldcortex config --self-heal false     # writes "selfHeal": false to ~/.shieldcortex/config.json
export SHIELDCORTEX_SKIP_SELF_HEAL=1      # or set the env var for the gateway process
```

Restart the gateway for either to take effect. Step 3 (the read-only staleness
check) still runs, and `shieldcortex openclaw install` performs the same
migration on demand. Disabling the cortex-memory hook in your hooks config also
disables the self-heal entirely, since it only runs inside the hook.

## Data handling, privacy & consent

ShieldCortex is **local-first**: memory, scanning, and audit run entirely on your machine — no account, no network, no telemetry by default. Because the tool can auto-capture conversation content, here is exactly what it reads, stores, and (only if you opt in) transmits.

- **What it reads.** With the lifecycle handlers enabled (opt-in at setup), ShieldCortex reads your agent **session transcripts — both your prompts and the assistant's replies** — to auto-extract memorable context. PreCompact (before context compaction) reads the recent transcript; the SessionEnd and Stop handlers are **off by default**; the OpenClaw integration extracts from assistant output and explicit keyword triggers. SessionStart does **not** read transcripts (it only loads existing local memory and scans project rule files).
- **What it stores, and for how long.** Saved and auto-extracted memories are written to a **local SQLite database at `~/.shieldcortex/memories.db`** — title and content verbatim — and **persist across sessions** until you remove them (decay/consolidation prune low-value entries over time). Nothing is stored remotely unless you enable Cloud sync. Delete a memory with the `forget` tool, or remove the database to wipe everything.
- **Secrets & credentials.** Every write — manual or auto-extracted — passes the defence pipeline first; high-confidence credential patterns (49 patterns across 25 providers) and content classified RESTRICTED are **blocked or quarantined before storage**, not saved as live memory. This is a strong filter, not a guarantee: low-confidence or low-entropy secrets can still be stored. On sensitive work, **review what auto-memory captures** and disable auto-extraction (`shieldcortex config --openclaw-auto-memory false`; the Claude Code handlers can be removed from `~/.claude/settings.json`).
- **Triggers capture surrounding context.** Keyword auto-save triggers (e.g. "remember this", "don't forget") capture the *nearby* text, which may include more than you intend — treat them as "save the recent context," not "save exactly this line." They're capped (auto-extracts never outrank explicit saves) and run through the same credential/injection scan.
- **Subprocess execution.** The OpenClaw integration spawns short-lived `npx mcporter` subprocesses (via `execFile`, argv-array, no shell) to talk to your **local** ShieldCortex MCP server over stdio. One caveat for completeness: when ShieldCortex is not installed locally, the hook's fallback server command is `npx -y shieldcortex`, and `npx -y` will download the package from the npm registry on first use before executing it. Install `shieldcortex` globally (or set `binaryPath` in `~/.shieldcortex/config.json`) to guarantee no network fetch on that path.
- **Cloud sync — off by default, opt-in, explicit.** No data leaves your machine unless you run `shieldcortex config --cloud-enable --cloud-api-key <key>`. When enabled:
  - **Audit telemetry** (`/v1/audit/ingest`): scan **metadata only** — trust scores, threat indicators, categories, timings, device name. **No memory content.**
  - **Memory sync** (`/v1/sync/memories`, Enterprise licence — grandfathered Team keys also unlock it): transmits **full memory title + content** of PUBLIC/INTERNAL memories so they sync across your team. CONFIDENTIAL/RESTRICTED memories are **excluded by default**; switch to metadata-only with the `contentMode` control.
  - **Quarantine sync** (Enterprise licence): flagged content is sent with **detected credentials redacted**.
  - **OpenClaw realtime plugin** (optional): scans live input and output **locally**. When it flags something, only **threat metadata** (type, scores, timestamps — **never the input text itself**) is forwarded, and only when Cloud sync is enabled. Flagged-content previews are kept in your **local** audit log; they are never transmitted.

  Raw conversation/input text is never transmitted by the audit, threat, or interceptor paths — they carry metadata only. The single exception is **Memory sync** above, which uploads the content of memories you chose to store (PUBLIC/INTERNAL, off by default, Enterprise licence). You can disable any of the above at any time, and the realtime plugin and lifecycle handlers can be removed entirely.

## What it does NOT do

- Does **not** read SSH keys, AWS credentials, GPG keys, or /etc/ files
- Does **not** send data to external servers (unless Cloud sync is explicitly enabled)
- Does **not** modify .bashrc, .zshrc, .profile, or shell configs
- Does **not** use eval(), child_process.exec(), or dynamic code execution
- Does **not** bypass, disable, or override any agent safety mechanisms
- Does **not** auto-approve actions or skip verification prompts
- Does **not** mine cryptocurrency, trade tokens, manage wallets, or initiate purchases
- Does **not** make purchases, place orders, or move money on the user's behalf

## CLI Reference

### Getting Started
```bash
shieldcortex quickstart          # Detect integrations, guide setup
shieldcortex setup               # Register MCP server for current project
shieldcortex doctor              # Diagnose registration issues
shieldcortex status              # Show protection status
shieldcortex uninstall           # Remove from project
```

### Memory
```bash
# Memory is typically used via the MCP server, not the CLI directly. The tools are:
#   remember · recall · forget · get_context · get_memory · get_related
#   consolidate · graph_query · graph_entities · scan_memories · memory_stats
#   start_session · end_session
# (there is no `store`, `search` or bare `graph` tool — use remember/recall/graph_query)
shieldcortex graph backfill      # Build knowledge graph from stored memories
shieldcortex stats               # Memory statistics
```

### Security Scanning
```bash
shieldcortex scan "text"                    # Scan text through defence pipeline
shieldcortex scan-skill path/to/SKILL.md    # Scan one instruction file for threats
shieldcortex scan-skills                    # Scan all discovered agent instruction files
shieldcortex audit                          # Full security audit (memory, env, MCP configs, rules files)
shieldcortex iron-dome status               # Iron Dome behavioural protection status
```

### Cortex — Mistake Learning
```bash
# capture requires all four flags: --category --what --why --rule
shieldcortex cortex capture --category code --what "Guessed API endpoints" \
  --why "Didn't check the docs" --rule "Verify endpoints in API docs before calling"
shieldcortex cortex preflight --task "deploy to production"           # Pre-task check
shieldcortex cortex review                                            # Pattern analysis
shieldcortex cortex list                                              # View mistake log
shieldcortex cortex search "<query>"                                  # Full-text search
shieldcortex cortex stats                                             # Category breakdown
shieldcortex cortex confirm --category code --what "..." \
  --why-worked "..." --when-repeat "..."                              # Capture what worked
shieldcortex cortex graduate                                          # Archive mastered rules
```

### Dashboard & Services
```bash
shieldcortex dashboard           # Dashboard on localhost:3030 (starts the API on :3001 too)
shieldcortex api                 # Start the API server only (localhost:3001)
shieldcortex worker              # Background sync + heartbeat worker
shieldcortex service start|stop|status  # Manage background service
```

### Integrations
```bash
# subcommand is `install`, not `setup` (also: status, uninstall; openclaw adds repair, skill)
shieldcortex openclaw install    # Hook + realtime plugin — tool gate BOUND
shieldcortex copilot install     # VS Code / Cursor MCP memory server — NOT a tool gate
shieldcortex codex install       # Codex CLI MCP memory server — NOT a tool gate
shieldcortex config --openclaw-auto-memory true   # Enable auto-memory in OpenClaw
shieldcortex config --proactive-recall true|false  # Enable/disable proactive recall
```

### Cloud & Licensing
```bash
shieldcortex config --cloud-enable --cloud-api-key <key>  # Enable cloud sync
shieldcortex cloud sync --full    # Backfill memories + graph to cloud
shieldcortex license activate <key>  # Activate an Enterprise (or legacy) licence key
shieldcortex license status       # Check licence tier
```

### Maintenance
```bash
shieldcortex update              # Self-update (npm package + OpenClaw plugin + skill)
```

## What Gets Scanned

### `scan-skills` discovers and scans:
- SKILL.md, HOOK.md, handler.js (Claude Code / OpenClaw skills)
- .cursorrules, .windsurfrules, .clinerules (editor rules)
- CLAUDE.md, copilot-instructions.md (agent instructions)
- .aider.conf.yml, .continue/config.json (tool configs)
- Searches: ~/.claude/skills/, ~/.openclaw/skills/, ~/.openclaw/hooks/, project directories

### `audit` checks:
- **Memory files** — ~/.claude/projects/, ~/.cursor/memories/, ~/.windsurf/memories/
- **Environment** — .env files for leaked credentials (read-only check, never writes)
- **MCP configs** — ~/.claude/mcp.json, ~/.openclaw/mcp.json, ~/.cursor/mcp.json, project-level equivalents
- **Rules files** — CLAUDE.md, .cursorrules, copilot-instructions.md for injection patterns

## What Gets Uploaded to Cloud

Cloud sync is **off by default**. Audit metadata sync is included on the cloud free tier; full memory/graph replication requires an Enterprise licence (grandfathered Team keys keep working).

- **Uploaded when Cloud sync is enabled by the user:** selected memory records, related embeddings/metadata, and knowledge-graph entities/relationships required for sync.
- **Not uploaded by default:** local agent configs, MCP configs, raw rules files, shell configs, SSH keys, secrets, `.env` contents, or arbitrary project files.
- **Security scan results stay local** unless the user explicitly exports or syncs data through a Cloud-enabled workflow.
- **No cloud traffic at all** occurs unless the user explicitly enables Cloud sync and provides a valid API key.

## Licence Tiers

Public tiers are **Free** and **Enterprise** (sales@drakonsystems.com). Every local feature is Free; grandfathered Pro/Team keys keep working.

| Feature | Free | Enterprise |
|---------|------|------------|
| Memory (store/recall/search/graph) | ✅ | ✅ |
| Proactive recall (auto-inject on prompts) | ✅ | ✅ |
| Defence pipeline (scan, Iron Dome) | ✅ | ✅ |
| Audit & scan-skills | ✅ | ✅ |
| Dashboard | ✅ | ✅ |
| Custom injection patterns | ✅ | ✅ |
| Custom Iron Dome policies | ✅ | ✅ |
| Custom firewall rules | ✅ | ✅ |
| Audit export | ✅ | ✅ |
| Deep skill scanning | ✅ | ✅ |
| Cortex (mistake learning) | ✅ | ✅ |
| Cloud audit sync (metadata, 500 scans/mo, 7-day retention) | ✅ | ✅ |
| Cloud memory/graph sync | ❌ | ✅ |
| Team management | ❌ | ✅ |
| Shared patterns | ❌ | ✅ |

## Links

- **Docs:** https://shieldcortex.ai/docs
- **Source:** https://github.com/Drakon-Systems-Ltd/ShieldCortex
- **npm:** https://www.npmjs.com/package/shieldcortex
- **Issues:** https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues
- **Changelog:** https://shieldcortex.ai/changelog

## API bind (#411)
- Default bind is loopback (`127.0.0.1`).
- Non-loopback requires `SHIELDCORTEX_ALLOW_NON_LOOPBACK=1` **and** `SHIELDCORTEX_API_TOKEN` (≥32 chars).
- Public `/api/auth/session-token` is loopback-only.

