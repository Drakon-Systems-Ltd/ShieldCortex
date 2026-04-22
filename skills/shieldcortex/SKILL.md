---
name: shieldcortex
description: >
  Persistent memory and security system for AI agents. Stores memories with
  semantic search, knowledge graphs, and decay. Scans agent inputs/outputs for
  prompt injection, credential leaks, and poisoning. Audits agent instruction
  files and MCP configs. Includes Cortex mistake-learning module (Pro tier).
license: MIT-0
metadata:
  author: Drakon Systems
  version: 4.10.7
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
  minVersion: "18"
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

Memory system with built-in security. Gives agents persistent memory (semantic search, knowledge graphs, decay, contradiction detection) and protects it with a 6-layer defence pipeline (prompt injection, credential leaks, poisoning, privilege escalation, PII filtering, behavioural analysis). Skill threat patterns (tool injection, scope escalation, data exfiltration, persistence, supply-chain, agent manipulation, stealth instructions) now also block at memory-write time, not just on skill-file scans.

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

- **User-initiated only.** Setup is a manual step the user runs in their terminal. Nothing auto-executes on install. The `quickstart` command asks before each action.
- **No credentials required for local use.** Memory, scanning, and audit work fully offline. Cloud sync (team tier) requires a user-provided API key via `shieldcortex config --cloud-enable --cloud-api-key <key>`.
- **File access is declared and scoped.** Security scans read agent config directories listed in the permissions block above — the same directories the agent itself already has access to. They do not traverse arbitrary directories.
- **Writes are contained.** All data goes to `~/.shieldcortex/`. MCP config edits (`setup`, `copilot`, `codex` commands) modify specific JSON files and confirm before writing.
- **Network is off by default.** No outbound connections unless Cloud sync is explicitly enabled by the user. The dashboard and worker bind to localhost only.
- **Bundled source code.** The OpenClaw plugin and cortex-memory handler are shipped in the package for inspection before use.
- **Lifecycle event handlers.** ShieldCortex registers lifecycle handlers that auto-extract important context from conversations. These are registered in `~/.claude/settings.json` during setup and can be removed at any time. They run locally, never phone home.
- **Proactive recall.** The UserPromptSubmit handler queries local memory on each prompt (<100ms) and surfaces relevant context. Fully local, configurable: `shieldcortex config --proactive-recall false`.

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
