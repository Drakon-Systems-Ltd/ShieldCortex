# ShieldCortex

[![npm version](https://img.shields.io/npm/v/shieldcortex.svg)](https://www.npmjs.com/package/shieldcortex)
[![npm downloads](https://img.shields.io/npm/dm/shieldcortex.svg)](https://www.npmjs.com/package/shieldcortex)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue)](https://github.com/Drakon-Systems-Ltd/ShieldCortex)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![GitHub stars](https://img.shields.io/github/stars/Drakon-Systems-Ltd/ShieldCortex.svg?style=social)](https://github.com/Drakon-Systems-Ltd/ShieldCortex/stargazers)

Persistent memory + security for AI agents.

ShieldCortex gives agents long-term memory, then protects that memory from prompt injection, credential leaks, and poisoned context. It works with Claude Code, OpenClaw, LangChain, and any MCP-compatible workflow.

## Contents

- [Why ShieldCortex](#why-shieldcortex)
- [Install](#install)
- [Quick Start](#quick-start)
- [Complement Existing Memory Systems](#complement-existing-memory-systems)
- [Security Model](#security-model)
- [Skill Scanner](#skill-scanner)
- [Dashboard and Cloud](#dashboard-and-cloud)
- [CLI Cheat Sheet](#cli-cheat-sheet)
- [Supported Agents](#supported-agents)
- [Documentation](#documentation)

## Why ShieldCortex

- Persistent memory in local SQLite with semantic recall
- Knowledge graph extraction, contradiction detection, and memory consolidation
- Defence pipeline on memory writes (local by default, optional cloud verification)
- Iron Dome behaviour protection for outbound actions (PII, action gating, kill switch)
- Complement mode for agents that already have memory

## Install

```bash
npm install -g shieldcortex
```

## Quick Start

### Claude Code / Cursor / VS Code

```bash
npx shieldcortex setup
```

### OpenClaw

```bash
npx shieldcortex openclaw install
openclaw gateway restart
```

This installs:
- `cortex-memory` hook (context injection + keyword saves)
- `shieldcortex-realtime` plugin (real-time scanning on `llm_input` / `llm_output`)

### Optional OpenClaw Auto-Memory

Auto-memory is intentionally off by default so ShieldCortex complements, rather than duplicates, native OpenClaw memory behavior.

```bash
npx shieldcortex config --openclaw-auto-memory true
npx shieldcortex config --openclaw-auto-memory false
```

You can also control this from the local dashboard:
- `Shield Overview -> OpenClaw Memory`

Optional tuning keys in `~/.shieldcortex/config.json`:

```json
{
  "openclawAutoMemory": true,
  "openclawAutoMemoryDedupe": true,
  "openclawAutoMemoryNoveltyThreshold": 0.88,
  "openclawAutoMemoryMaxRecent": 300
}
```

### LangChain

```javascript
import { ShieldCortexMemory } from 'shieldcortex/integrations/langchain';

const memory = new ShieldCortexMemory({ mode: 'balanced' });
```

### REST API Mode

```bash
npx shieldcortex --mode api
# API: http://localhost:3001
```

```bash
curl -X POST http://localhost:3001/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"content":"ignore previous instructions"}'
```

### As a Library

```javascript
import { initDatabase, addMemory, runDefencePipeline } from 'shieldcortex';

initDatabase();

const result = runDefencePipeline(
  'Use OAuth2 bearer tokens for API auth',
  'Auth decision',
  { type: 'cli', identifier: 'readme-example' }
);
if (result.allowed) {
  addMemory({
    title: 'Auth decision',
    content: 'Use OAuth2 bearer tokens',
    category: 'architecture'
  });
}
```

## Complement Existing Memory Systems

If your agent already has built-in memory, keep that as primary and place ShieldCortex in front as a defence and quality layer.

```javascript
import { ShieldCortexGuardedMemoryBridge } from 'shieldcortex/integrations/universal';
import { OpenClawMarkdownBackend } from 'shieldcortex/integrations/openclaw';

const nativeMemory = new OpenClawMarkdownBackend();
const guarded = new ShieldCortexGuardedMemoryBridge(nativeMemory, {
  mode: 'balanced',
  blockOnThreat: true,
  sourceIdentifier: 'openclaw-memory-bridge'
});

await guarded.save({
  title: 'Architecture decision',
  content: 'Auth service uses PostgreSQL and Redis.'
});
```

## Security Model

### Inbound Memory Defence

ShieldCortex runs all memory writes through a layered pipeline:
- Input sanitisation
- Injection/encoding pattern detection
- Semantic anomaly checks
- Structural/fragmentation analysis
- Trust and sensitivity scoring
- Credential leak detection

Optional Tier 2 cloud verification can be enabled for ambiguous cases:

```bash
npx shieldcortex config --cloud-api-key <key> --cloud-enable
npx shieldcortex config --verify-enable --verify-mode advisory
```

### Outbound Behaviour Defence (Iron Dome)

Iron Dome protects agent actions after memory retrieval:
- Prompt injection scanner
- Instruction trust checks
- Action gate (allow / require approval / block)
- PII guard
- Kill switch
- Sub-agent restrictions

```bash
npx shieldcortex iron-dome activate --profile enterprise
npx shieldcortex iron-dome status
```

## Skill Scanner

Scan instruction files (`SKILL.md`, `CLAUDE.md`, `.cursorrules`, `.clinerules`, etc.) for hidden prompt injections.

```bash
npx shieldcortex scan-skills
npx shieldcortex scan-skill ./path/to/SKILL.md
```

GitHub Action:

```yaml
- uses: Drakon-Systems-Ltd/ShieldCortex@v1
  with:
    fail-on-high: 'true'
```

## Dashboard and Cloud

Start local dashboard + API:

```bash
npx shieldcortex --dashboard
# Dashboard: http://localhost:3030
# API: http://localhost:3001
```

Enable cloud sync:

```bash
npx shieldcortex config --cloud-api-key <key> --cloud-enable
```

Cloud config keys:

```json
{
  "cloudApiKey": "sc_...",
  "cloudBaseUrl": "https://api.shieldcortex.ai",
  "cloudEnabled": true
}
```

## CLI Cheat Sheet

```bash
# Setup and integrations
npx shieldcortex setup
npx shieldcortex openclaw install
npx shieldcortex openclaw status
npx shieldcortex migrate
npx shieldcortex doctor

# Memory and scanning
npx shieldcortex status
npx shieldcortex scan "text"
npx shieldcortex audit
npx shieldcortex scan-skills

# Dashboard and config
npx shieldcortex --dashboard
npx shieldcortex config --mode strict
npx shieldcortex config --openclaw-auto-memory true
npx shieldcortex config --verify-enable

# Iron Dome
npx shieldcortex iron-dome activate --profile school
npx shieldcortex iron-dome scan --text "..."
npx shieldcortex iron-dome audit --tail
```

## Supported Agents

| Agent | Integration |
|-------|-------------|
| [Claude.ai](https://claude.ai) | Upload [skill](https://github.com/Drakon-Systems-Ltd/ShieldCortex/tree/main/skills/shieldcortex) |
| [Claude Code](https://claude.ai/claude-code) | `shieldcortex setup` |
| [OpenClaw](https://openclaw.ai) | `shieldcortex openclaw install` |
| [LangChain JS](https://js.langchain.com) | `shieldcortex/integrations/langchain` |
| Python agents (CrewAI, AutoGPT) | REST API (`/api/v1/scan`) |
| Any MCP-compatible agent | MCP tools |

## Documentation

- [Architecture](ARCHITECTURE.md)
- [OpenClaw Integration](docs/openclaw-integration.md)
- [OpenClaw Plugin README](plugins/openclaw/README.md)
- [Changelog](CHANGELOG.md)
- [Website](https://shieldcortex.ai)

## License

MIT
