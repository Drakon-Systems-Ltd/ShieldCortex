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
  version: 3.5.0
  mcp-server: shieldcortex
  category: memory-and-security
  tags: [memory, security, knowledge-graph, mcp, iron-dome, openclaw-plugin, audit]
  source: https://github.com/Drakon-Systems-Ltd/ShieldCortex
  homepage: https://shieldcortex.ai
  npm: https://www.npmjs.com/package/shieldcortex
install:
  command: npm install -g shieldcortex
  runtime: node
  minVersion: "18"
permissions:
  filesystem: readwrite
  network: optional
  credentials: optional
  paths_read:
    - ~/.claude/ (project memory files, MCP config, commands)
    - ~/.openclaw/ (MCP config, extensions)
    - ~/.cursor/ (rules, memories, MCP config)
    - ~/.windsurf/ (memories, rules)
    - ~/.codex/ (MCP config)
    - $CWD/.claude/, $CWD/.cursor/ (project-level configs)
    - $CWD/.cursorrules, $CWD/.windsurfrules, $CWD/.clinerules
    - $CWD/CLAUDE.md, $CWD/copilot-instructions.md
    - $CWD/.aider.conf.yml, $CWD/.continue/config.json
    - $CWD/.env (env-scanner checks for leaked secrets)
  paths_write:
    - ~/.shieldcortex/ (memory DB, config, cortex log, licence, audit cache)
    - ~/.openclaw/extensions/shieldcortex-realtime/ (OpenClaw plugin, if installed)
    - ~/.claude/mcp.json, ~/.cursor/mcp.json (MCP server registration, if set up)
  network_endpoints:
    - https://api.shieldcortex.ai (Cloud sync, licence validation — only when Cloud is enabled)
    - http://localhost:3001 (local dashboard server)
    - http://localhost:3030 (local worker health check)
  env:
    - SHIELDCORTEX_CONFIG_DIR: Override config directory (default ~/.shieldcortex/)
    - SHIELDCORTEX_API_KEY: Cloud sync API key (team tier only, optional)
    - SHIELDCORTEX_LICENSE_TIER: Override licence tier (development use)
    - SHIELDCORTEX_SKIP_EMBEDDINGS: Disable embedding generation
    - SHIELDCORTEX_HOST: Override dashboard/API bind host
    - PORT: Override dashboard/API port
---

# ShieldCortex — Persistent Memory & Security for AI Agents

Memory system with built-in security. Gives agents persistent memory (semantic search, knowledge graphs, decay, contradiction detection) and protects it with a 6-layer defence pipeline (prompt injection, credential leaks, poisoning, privilege escalation, PII filtering, behavioural analysis).

## Safety & Scope

- **Manual install only.** `npm install -g shieldcortex` is a user-approved step. Nothing auto-executes.
- **No credentials required for local use.** Memory, scanning, and audit work fully offline. Cloud sync (team tier) requires a user-provided API key via `shieldcortex config --cloud-enable --cloud-api-key <key>`.
- **File access is scoped.** Security scans and audits read agent config directories listed in the permissions block above. They do not traverse arbitrary directories. The full list of scanned paths is declared in the `paths_read` section.
- **Writes are contained.** All data goes to `~/.shieldcortex/`. MCP config edits (`setup`, `copilot`, `codex` commands) modify specific JSON files and ask before writing.
- **Network is off by default.** No outbound connections unless Cloud sync is explicitly enabled. The dashboard and worker run on localhost only.
- **Bundled source code.** The OpenClaw plugin and cortex-memory hook are shipped in `bundled/` for inspection before installation.
- **Provenance.** Source: [github.com/Drakon-Systems-Ltd/ShieldCortex](https://github.com/Drakon-Systems-Ltd/ShieldCortex). npm: [npmjs.com/package/shieldcortex](https://www.npmjs.com/package/shieldcortex). Publisher: [@jarvis-drakon](https://github.com/jarvis-drakon).

## CLI Reference

### Getting Started
```bash
shieldcortex quickstart          # Detect integrations, guide setup
shieldcortex setup               # Install into current project
shieldcortex doctor              # Diagnose installation issues
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
shieldcortex hook start|stop|status     # Manage hooks
```

### Integrations
```bash
shieldcortex openclaw install    # Install OpenClaw realtime plugin
shieldcortex copilot install     # Set up VS Code / Cursor MCP server
shieldcortex codex install       # Set up Codex CLI MCP server
shieldcortex config --openclaw-auto-memory  # Enable auto-memory in OpenClaw
```

### Cloud & Licensing
```bash
shieldcortex config --cloud-enable --cloud-api-key <key>  # Enable cloud sync
shieldcortex cloud sync --full    # Backfill memories + graph to cloud
shieldcortex license activate sc_pro_...  # Activate Pro/Team licence
shieldcortex license status       # Check licence tier
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
- **Environment** — .env files for leaked credentials
- **MCP configs** — ~/.claude/mcp.json, ~/.openclaw/mcp.json, ~/.cursor/mcp.json, project-level equivalents
- **Rules files** — CLAUDE.md, .cursorrules, copilot-instructions.md for injection patterns

## Licence Tiers

| Feature | Free | Pro | Team |
|---------|------|-----|------|
| Memory (store/recall/search/graph) | ✅ | ✅ | ✅ |
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
