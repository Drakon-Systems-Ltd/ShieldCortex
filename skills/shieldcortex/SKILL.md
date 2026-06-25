---
name: shieldcortex
description: "Memory and defence for AI agents: semantic recall, knowledge graph and decay, plus a memory firewall that scans and enforces against prompt injection, credential leaks and poisoning."
license: MIT-0
metadata:
  author: Drakon Systems
  version: 4.42.4
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
  downloads: 9700+
install:
  command: shieldcortex quickstart
  runtime: node
  minVersion: "20"
  note: >
    Run the installed `shieldcortex` binary directly. The quickstart command
    detects your environment and guides MCP server registration. All data stays
    local in ~/.shieldcortex/. No account or API key needed for local use.
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
    - ~/.openclaw/extensions/shieldcortex-realtime/ (OpenClaw plugin, when user opts in)
    - ~/.claude/mcp.json, ~/.cursor/mcp.json (MCP server registration, when user runs setup)
  network_endpoints:
    - https://api.shieldcortex.ai (Cloud sync, licence validation — only when Cloud is enabled by user)
    - http://localhost:3001 (local dashboard server — loopback only)
    - http://localhost:3030 (local worker health check — loopback only)
  env:
    - SHIELDCORTEX_CONFIG_DIR: Override config directory (default ~/.shieldcortex/)
    - SHIELDCORTEX_API_KEY: Cloud sync API key (team tier only, optional)
    - SHIELDCORTEX_LICENSE_TIER: Override licence tier (development use)
    - SHIELDCORTEX_SKIP_EMBEDDINGS: Disable embedding generation
    - SHIELDCORTEX_HOST: Override dashboard/API bind host
    - PORT: Override dashboard/API port
---

# ShieldCortex — Persistent Memory & Security for AI Agents

Memory system with built-in security. Gives agents persistent memory (semantic search, knowledge graphs, decay, contradiction detection) and protects it with a 6-layer defence pipeline (prompt injection, credential leaks, poisoning, privilege escalation, PII filtering, behavioural analysis). Skill threat patterns (tool injection, scope escalation, data exfiltration, persistence, supply-chain, agent manipulation, stealth instructions) block at memory-write time, not just on skill-file scans.

This is an enforcing memory boundary, not a passive scanner. Across the read/write boundary it actively: **quarantines or blocks** poisoned/credential-bearing writes; **trust/ACL-filters recalled memory** (RESTRICTED isolation, own-only for low-trust callers) before it reaches the agent, on both the prompt hooks and the MCP read tools; runs a **tool-output firewall** that, in enforce mode, redacts or withholds malicious tool results before the model sees them (advisory by default); and keeps a **provenance ledger** recording read/write/delete operations with content hashes for forensics. Enforcement that could surprise is opt-in (the tool-output firewall defaults to advisory; `shieldcortex config --tool-firewall-enforce` turns on blocking).

## Provenance & Trust

| Signal | Value |
|--------|-------|
| **Publisher** | [Drakon Systems Ltd](https://github.com/Drakon-Systems-Ltd) (UK company) |
| **Source code** | [github.com/Drakon-Systems-Ltd/ShieldCortex](https://github.com/Drakon-Systems-Ltd/ShieldCortex) — fully open, MIT-0 licence |
| **npm package** | [npmjs.com/package/shieldcortex](https://www.npmjs.com/package/shieldcortex) — published via GitHub Actions CI |
| **npm audit** | Clean — `npm audit` returns 0 vulnerabilities |
| **Downloads** | 9,700+ total (April 2026) |
| **CI/CD** | Automated: push to main → CI lint/test → version tag → npm publish |
| **No postinstall scripts** | Package has no lifecycle scripts that auto-execute on install |
| **Dependencies** | 3 runtime deps: `better-sqlite3`, `zod`, `hono`. No transitive network libs. |

## Safety & Scope

This section explains every privileged operation the tool performs and why.

- **Active interception, not scan-only.** Beyond read-only scans, ShieldCortex *enforces* at the boundary: writes failing the pipeline are quarantined/blocked; recalled memory is trust/ACL-filtered before the agent sees it; in enforce mode the tool-output firewall redacts/withholds malicious tool results; and the OpenClaw `before_tool_call` interceptor + Iron Dome kill-switch can block operations. Surprising enforcement is opt-in (tool-output firewall defaults to advisory). `shieldcortex status` and `iron-dome status` report which controls are active.
- **User-initiated only.** Setup is a manual step the user runs in their terminal. Nothing auto-executes on install. The `quickstart` command asks before each action.
- **Setup migrates legacy data.** The first `quickstart`/`setup` run may move or remove legacy config/memory directories (e.g. `~/.claude-cortex/`, `~/.claude-memory/`) into `~/.shieldcortex/` and copy hook files into place. This happens only on the user-run setup command — never on `npm install` (no lifecycle scripts).
- **Destructive `forget` is bounded and gated.** Per-memory and filtered bulk deletes go through a delete ACL (own-only) and are recorded in the audit ledger. Revoke-by-source (`forget --fromSource`, bulk-delete every memory from one source — for purging a poisoned agent) is **disabled by default** and only enabled by an out-of-band human action (`shieldcortex config --allow-revoke-by-source`); even then it is bounded by a trust-hierarchy ACL (you must own the source or out-rank it) and a per-call row cap. A compromised agent cannot mass-delete your memory.
- **The bundled dashboard never renders RESTRICTED content.** The local visualization API and its WebSocket feed redact credential-class (`RESTRICTED`) memory content before it reaches the browser — the row stays visible (title/metadata) so you can manage it, but the secret is withheld (view full content via the CLI). Credential patterns in titles/metadata are masked too. This is a display-surface safeguard on top of the on-disk store; it does not weaken the firewall.
- **No credentials required for local use.** Memory, scanning, and audit work fully offline. Cloud sync (team tier) requires a user-provided API key via `shieldcortex config --cloud-enable --cloud-api-key <key>`.
- **File access is declared and scoped.** Security scans read agent config directories listed in the permissions block above — the same directories the agent itself already has access to. They do not traverse arbitrary directories.
- **Writes are contained.** All data goes to `~/.shieldcortex/`. MCP config edits (`setup`, `copilot`, `codex` commands) modify specific JSON files and confirm before writing.
- **Network is off by default.** No outbound connections unless Cloud sync is explicitly enabled by the user. The dashboard and worker bind to localhost only.
- **Bundled source code.** The OpenClaw plugin and cortex-memory handler are shipped in the package for inspection before use.
- **Lifecycle event handlers.** ShieldCortex registers lifecycle handlers that auto-extract important context from conversations. These are registered in `~/.claude/settings.json` during setup and can be removed at any time. They run locally, never phone home.
- **Proactive recall.** The UserPromptSubmit handler queries local memory on each prompt (<100ms) and surfaces relevant context. Fully local, configurable: `shieldcortex config --proactive-recall false`.

## Data handling, privacy & consent

ShieldCortex is **local-first**: memory, scanning, and audit run entirely on your machine — no account, no network, no telemetry by default. Because the tool can auto-capture conversation content, here is exactly what it reads, stores, and (only if you opt in) transmits.

- **What it reads.** With the lifecycle handlers enabled (opt-in at setup), ShieldCortex reads your agent **session transcripts — both your prompts and the assistant's replies** — to auto-extract memorable context. PreCompact (before context compaction) reads the recent transcript; the SessionEnd and Stop handlers are **off by default**; the OpenClaw integration extracts from assistant output and explicit keyword triggers. SessionStart does **not** read transcripts (it only loads existing local memory and scans project rule files).
- **What it stores, and for how long.** Saved and auto-extracted memories are written to a **local SQLite database at `~/.shieldcortex/memories.db`** — title and content verbatim — and **persist across sessions** until you remove them (decay/consolidation prune low-value entries over time). Nothing is stored remotely unless you enable Cloud sync. Delete a memory with the `forget` tool, or remove the database to wipe everything.
- **Secrets & credentials.** Every write — manual or auto-extracted — passes the defence pipeline first; high-confidence credential patterns (keys/tokens across 11+ providers) and content classified RESTRICTED are **blocked or quarantined before storage**, not saved as live memory. This is a strong filter, not a guarantee: low-confidence or low-entropy secrets can still be stored. On sensitive work, **review what auto-memory captures** and disable auto-extraction (`shieldcortex config --openclaw-auto-memory false`; the Claude Code handlers can be removed from `~/.claude/settings.json`).
- **Triggers capture surrounding context.** Keyword auto-save triggers (e.g. "remember this", "don't forget") capture the *nearby* text, which may include more than you intend — treat them as "save the recent context," not "save exactly this line." They're capped (auto-extracts never outrank explicit saves) and run through the same credential/injection scan.
- **Subprocess execution.** The OpenClaw integration spawns short-lived `npx mcporter` subprocesses (via `execFile`, no shell) to talk to your **local** ShieldCortex MCP server over stdio. No remote code is fetched or executed.
- **Cloud sync — off by default, opt-in, explicit.** No data leaves your machine unless you run `shieldcortex config --cloud-enable --cloud-api-key <key>`. When enabled:
  - **Audit telemetry** (`/v1/audit/ingest`): scan **metadata only** — trust scores, threat indicators, categories, timings, device name. **No memory content.**
  - **Memory sync** (`/v1/sync/memories`, Team tier): transmits **full memory title + content** of PUBLIC/INTERNAL memories so they sync across your team. CONFIDENTIAL/RESTRICTED memories are **excluded by default**; switch to metadata-only with the `contentMode` control.
  - **Quarantine sync** (Team tier): flagged content is sent with **detected credentials redacted**.
  - **OpenClaw realtime plugin** (optional): scans live input and output **locally**. When it flags something, only **threat metadata** (type, scores, timestamps — **never the input text itself**) is forwarded, and only when Cloud sync is enabled. Flagged-content previews are kept in your **local** audit log; they are never transmitted.

  Raw conversation/input text is never transmitted by the audit, threat, or interceptor paths — they carry metadata only. The single exception is **Memory sync** above, which uploads the content of memories you chose to store (PUBLIC/INTERNAL, off by default, Team tier). You can disable any of the above at any time, and the realtime plugin and lifecycle handlers can be removed entirely.

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
# Memory is typically used via MCP server, not CLI directly.
# The MCP server exposes: store, recall, search, forget, consolidate, graph.
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

### Cortex — Mistake Learning (Pro)
```bash
shieldcortex cortex capture --task "..." --mistake "..." --fix "..."  # Log a mistake
shieldcortex cortex preflight --task "deploy to production"           # Pre-task check
shieldcortex cortex review                                            # Pattern analysis
shieldcortex cortex list                                              # View mistake log
shieldcortex cortex stats                                             # Category breakdown
```

### Dashboard & Services
```bash
shieldcortex dashboard           # Open local web dashboard (localhost:3001)
shieldcortex api                 # Start API server
shieldcortex worker              # Background sync + heartbeat worker
shieldcortex service start|stop|status  # Manage background service
```

### Integrations
```bash
shieldcortex openclaw setup      # Set up OpenClaw realtime plugin
shieldcortex copilot setup       # Set up VS Code / Cursor MCP server
shieldcortex codex setup         # Set up Codex CLI MCP server
shieldcortex config --openclaw-auto-memory true   # Enable auto-memory in OpenClaw
shieldcortex config --proactive-recall true|false  # Enable/disable proactive recall
```

### Cloud & Licensing
```bash
shieldcortex config --cloud-enable --cloud-api-key <key>  # Enable cloud sync
shieldcortex cloud sync --full    # Backfill memories + graph to cloud
shieldcortex license activate sc_pro_...  # Activate Pro/Team licence
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

Cloud sync is **Team tier only** and **off by default**.

- **Uploaded when Cloud sync is enabled by the user:** selected memory records, related embeddings/metadata, and knowledge-graph entities/relationships required for sync.
- **Not uploaded by default:** local agent configs, MCP configs, raw rules files, shell configs, SSH keys, secrets, `.env` contents, or arbitrary project files.
- **Security scan results stay local** unless the user explicitly exports or syncs data through a Cloud-enabled workflow.
- **No cloud traffic at all** occurs unless the user explicitly enables Cloud sync and provides a valid API key.

## Licence Tiers

| Feature | Free | Pro | Team |
|---------|------|-----|------|
| Memory (store/recall/search/graph) | ✅ | ✅ | ✅ |
| Proactive recall (auto-inject on prompts) | ✅ | ✅ | ✅ |
| Defence pipeline (scan, Iron Dome) | ✅ | ✅ | ✅ |
| Audit & scan-skills | ✅ | ✅ | ✅ |
| Dashboard | ✅ | ✅ | ✅ |
| Custom injection patterns | ❌ | ✅ | ✅ |
| Custom Iron Dome policies | ❌ | ✅ | ✅ |
| Custom firewall rules | ❌ | ✅ | ✅ |
| Audit export | ❌ | ✅ | ✅ |
| Deep skill scanning | ❌ | ✅ | ✅ |
| Cortex (mistake learning) | ❌ | ✅ | ✅ |
| Cloud sync | ❌ | ❌ | ✅ |
| Team management | ❌ | ❌ | ✅ |
| Shared patterns | ❌ | ❌ | ✅ |

## Links

- **Docs:** https://shieldcortex.ai/docs
- **Source:** https://github.com/Drakon-Systems-Ltd/ShieldCortex
- **npm:** https://www.npmjs.com/package/shieldcortex
- **Issues:** https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues
- **Changelog:** https://shieldcortex.ai/changelog
