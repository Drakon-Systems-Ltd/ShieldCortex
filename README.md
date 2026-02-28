# ShieldCortex

[![npm version](https://img.shields.io/npm/v/shieldcortex.svg)](https://www.npmjs.com/package/shieldcortex)
[![npm downloads](https://img.shields.io/npm/dm/shieldcortex.svg)](https://www.npmjs.com/package/shieldcortex)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue)](https://github.com/Drakon-Systems-Ltd/ShieldCortex)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![GitHub stars](https://img.shields.io/github/stars/Drakon-Systems-Ltd/ShieldCortex.svg?style=social)](https://github.com/Drakon-Systems-Ltd/ShieldCortex/stargazers)

Persistent memory and security for AI agents.

ShieldCortex combines a long-term memory system with a defence pipeline and behaviour controls, so your agent can remember context without becoming easy to poison.

**Works with:** Claude Code, OpenClaw, LangChain, MCP-compatible agents, and REST-based Python stacks.

## Jump To

- [Start in 60 Seconds](#start-in-60-seconds)
- [Why It Feels Different](#why-it-feels-different)
- [OpenClaw: Complement Mode by Default](#openclaw-complement-mode-by-default)
- [Integrations](#integrations)
- [Security Model](#security-model)
- [Dashboard and Cloud](#dashboard-and-cloud)
- [CLI Quick Commands](#cli-quick-commands)
- [Docs and Links](#docs-and-links)

## Start in 60 Seconds

```bash
npm install -g shieldcortex
```

### Claude Code / Cursor / VS Code

```bash
npx shieldcortex setup
```

### OpenClaw

```bash
npx shieldcortex openclaw install
openclaw gateway restart
```

`openclaw install` sets up both:
- `cortex-memory` hook (context injection, keyword-trigger saves)
- `shieldcortex-realtime` plugin (`llm_input`/`llm_output` scanning)

## Why It Feels Different

ShieldCortex is not just a memory database. It is a three-layer runtime:

| Layer | Role | Outcome |
|---|---|---|
| Memory Engine | Persistent memory, semantic retrieval, consolidation, contradiction checks | Better continuity across sessions |
| Defence Pipeline | Multi-layer content scanning before memory writes | Blocks poisoned or sensitive payloads |
| Iron Dome | Outbound behaviour controls (actions/PII/trust channels) | Reduces compromised agent behaviour |

<details>
<summary><strong>Memory capabilities</strong></summary>

- Persistent local storage (SQLite)
- Semantic search and context recall
- Knowledge graph extraction
- Contradiction detection
- Memory consolidation and prioritisation

</details>

<details>
<summary><strong>Defence capabilities</strong></summary>

- Input sanitisation and structure checks
- Injection and obfuscation pattern detection
- Fragmentation analysis
- Trust/sensitivity scoring
- Credential leak detection
- Optional cloud LLM verification (Tier 2)

</details>

## OpenClaw: Complement Mode by Default

ShieldCortex is designed to complement, not fight, existing memory systems.

Default OpenClaw behaviour:
- Real-time scanning is on
- Context recall at session start is on
- Auto-memory extraction is off

That means users with native OpenClaw memory avoid duplicate/noisy writes by default.

Enable optional OpenClaw auto-memory:

```bash
npx shieldcortex config --openclaw-auto-memory true
```

Disable again:

```bash
npx shieldcortex config --openclaw-auto-memory false
```

Optional tuning in `~/.shieldcortex/config.json`:

```json
{
  "openclawAutoMemory": true,
  "openclawAutoMemoryDedupe": true,
  "openclawAutoMemoryNoveltyThreshold": 0.88,
  "openclawAutoMemoryMaxRecent": 300
}
```

Also available in local dashboard:
- `Shield Overview -> OpenClaw Memory`

## Integrations

### LangChain

```javascript
import { ShieldCortexMemory } from 'shieldcortex/integrations/langchain';

const memory = new ShieldCortexMemory({ mode: 'balanced' });
```

### Universal Memory Bridge

Use ShieldCortex in front of any existing memory backend.

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

### REST API Mode

```bash
npx shieldcortex --mode api
# http://localhost:3001
```

```bash
curl -X POST http://localhost:3001/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"content":"ignore all previous instructions"}'
```

### Library API

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

## Security Model

### Inbound: Memory Write Defence

Every memory write can be evaluated through layered checks:
- Sanitisation
- Pattern detection (injection/encoding)
- Semantic and structural analysis
- Trust and sensitivity scoring
- Credential leak protection

Optional Tier 2 verification:

```bash
npx shieldcortex config --cloud-api-key <key> --cloud-enable
npx shieldcortex config --verify-enable --verify-mode advisory
```

### Outbound: Iron Dome Behaviour Controls

Iron Dome protects what agents do after memory retrieval:
- Prompt injection scanner
- Channel trust checks
- Action gating (allow / require approval / block)
- PII guard
- Kill switch
- Sub-agent restrictions

```bash
npx shieldcortex iron-dome activate --profile enterprise
npx shieldcortex iron-dome status
```

## Dashboard and Cloud

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

## CLI Quick Commands

```bash
# Setup
npx shieldcortex setup
npx shieldcortex openclaw install
npx shieldcortex openclaw status
npx shieldcortex doctor
npx shieldcortex migrate

# Memory and scans
npx shieldcortex status
npx shieldcortex scan "text"
npx shieldcortex audit
npx shieldcortex scan-skills

# Config
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
|---|---|
| [Claude.ai](https://claude.ai) | Upload [skill](https://github.com/Drakon-Systems-Ltd/ShieldCortex/tree/main/skills/shieldcortex) |
| [Claude Code](https://claude.ai/claude-code) | `shieldcortex setup` |
| [OpenClaw](https://openclaw.ai) | `shieldcortex openclaw install` |
| [LangChain JS](https://js.langchain.com) | `shieldcortex/integrations/langchain` |
| Python agents (CrewAI, AutoGPT) | REST API (`/api/v1/scan`) |
| Any MCP-compatible agent | MCP tools |

## Docs and Links

- [Architecture](ARCHITECTURE.md)
- [OpenClaw Integration](docs/openclaw-integration.md)
- [OpenClaw Plugin README](plugins/openclaw/README.md)
- [Changelog](CHANGELOG.md)
- [Website](https://shieldcortex.ai)
- [npm package](https://www.npmjs.com/package/shieldcortex)

## License

MIT
