# CLAUDE.md — ShieldCortex Development Guide

## What This Project Is

ShieldCortex is a persistent memory system + security layer for AI agents. npm package (`shieldcortex`), MIT licensed, built by Drakon Systems.

**Positioning:** Memory-first. "Your AI agent forgets everything. Fix that." Security is the differentiator, not the hook.

## Architecture

- **Language:** TypeScript (ESM, `"type": "module"`)
- **Entry points:**
  - `src/index.ts` — CLI entry point (gated behind `isCLI` check)
  - `src/lib.ts` — Library entry point (70 named exports, no side effects)
  - `src/server.ts` — MCP server
- **Build:** `npm run build` → `tsc` → `dist/`
- **Database:** SQLite via better-sqlite3 (`~/.shieldcortex/memories.db`)
- **Dashboard:** Next.js app in `dashboard/` (standalone build ships with npm package)
- **Hooks:** `hooks/openclaw/cortex-memory/` — OpenClaw integration hook

## Key Directories

```
src/
├── memory/       # Store, decay, consolidation, contradiction, activation, salience, similarity
├── graph/        # Knowledge graph: extract, resolve, backfill
├── defence/      # Firewall, trust, sensitivity, credential-leak, skill-scanner, audit
├── api/          # Visualization server (REST API)
├── cli/          # CLI-only commands (audit)
├── setup/        # Install/uninstall for Claude Code, OpenClaw, Copilot
├── cloud/        # Cloud sync, config
├── integrations/ # LangChain adapter
├── worker/       # Brain worker (link discovery, predictive consolidation)
└── tools/        # MCP tool handlers (remember, recall, forget, graph)
```

## Release Process (IMPORTANT)

Every release has **three** publish targets. Don't forget any:

### 1. npm publish
```bash
npm version patch|minor|major   # bumps package.json
npm run build
npm publish
```

### 2. GitHub tag + push
```bash
git tag v$(node -p "require('./package.json').version")
git push origin main --tags
```

### 3. ClawHub skill publish
```bash
clawhub publish ./skills/shieldcortex-skill \
  --slug shieldcortex \
  --name "ShieldCortex" \
  --version $(node -p "require('./package.json').version") \
  --changelog "Brief description of changes" \
  --tags latest \
  --no-input
```

If `clawhub` CLI isn't authenticated: `clawhub login --token <token>` (token from ClawHub Settings → API tokens, account: jarvis-drakon).

**The ClawHub skill SKILL.md lives at:** The workspace skill folder that was published. If the SKILL.md needs updating, update it and re-publish with the new version.

### Quick one-liner for releases:
```bash
npm run build && npm publish && git tag v$(node -p "require('./package.json').version") && git push origin main --tags && clawhub publish ./skills/shieldcortex-skill --slug shieldcortex --name "ShieldCortex" --version $(node -p "require('./package.json').version") --tags latest --no-input
```

## ClawHub Skill

- **Slug:** `shieldcortex`
- **URL:** https://clawhub.ai/k977rg07zt1erv2r2d9833yvmn812c89/shieldcortex
- **SKILL.md location:** `skills/shieldcortex-skill/SKILL.md` (in this repo)
- **Install:** `clawhub install shieldcortex`
- Users install the skill to get the SKILL.md that teaches their agent how to use ShieldCortex

## Dev.to Articles

- **Account:** CyborgNinja1 (mkdelta221)
- **Series:** "ShieldCortex"
- **Published articles:** Check https://dev.to/mkdelta221
- **API:** Use Dev.to API with key from 1Password "Dev.to API Key"
- Post new articles on major feature releases to drive npm downloads

## Key Design Decisions

- **`index.ts` is CLI + library:** The `main()` function only runs when executed directly (via `isCLI` guard). Library exports come from `lib.ts` re-exported through `index.ts`.
- **No side effects on import:** `import('shieldcortex')` must never start servers, consume stdin, or spawn workers.
- **Memory-first messaging:** README, npm description, articles all lead with memory features. Security is positioned as "And it can't be poisoned" — a differentiator, not the headline.
- **Competitor positioning:** We have 8 features nobody else has (knowledge graph, decay, contradiction detection, consolidation, activation scoring, salience scoring, memory poisoning defence, credential leak detection).

## Testing

```bash
npm test                    # Run all tests
npm run build              # Must build cleanly with no errors
```

Verify library import works after changes:
```bash
node -e "import('./dist/index.js').then(m => { console.log('Exports:', Object.keys(m).length); process.exit(0); })"
```
Should output `Exports: 70` (or more) and exit cleanly — no SIGKILL, no hanging.

## Repos & Social Proof

### Two GitHub repos — one active, one redirect:
- **`Drakon-Systems-Ltd/ShieldCortex`** (active) — all development happens here. npm publishes from here.
- **`mkdelta221/claude-cortex`** (redirect, 46 ⭐) — the original project before the rebrand. README redirects to ShieldCortex. DO NOT archive this repo — the 46 stars are valuable social proof. No code updates needed, just keep the redirect README.

### Why two repos?
Stars don't transfer on rename/move. The 46 stars on claude-cortex are used for awesome-list submissions (require 10+ stars). ShieldCortex repo has 7 stars independently.

### awesome-claude-skills
- **PR:** https://github.com/travisvn/awesome-claude-skills/pull/139
- **Submitted from:** mkdelta221 (not jarvis-drakon — they reject AI-submitted PRs)
- **Links to:** mkdelta221/claude-cortex (46 stars, passes their 10-star threshold)
- **Rules:** https://github.com/travisvn/awesome-claude-skills/blob/main/CONTRIBUTING.md
  - Need 10+ GitHub stars
  - No AI-automated submissions
  - No SaaS wrappers / commercial segues
  - Must provide standalone value

### Marketing channels:
- **Dev.to:** mkdelta221 / CyborgNinja1 — 7 articles in "ShieldCortex: AI Agent Security" series
- **npm:** shieldcortex (2,300+ downloads)
- **Reddit:** Draft posts ready for r/LocalLLaMA (memory angle) and r/cybersecurity (attack vector angle)
- **Website:** shieldcortex.ai (Squarespace)

### SaaS (ShieldCortex Cloud):
- **Repo:** `Drakon-Systems-Ltd/ShieldCortex-internal` (PRIVATE)
- **Live at:** api.shieldcortex.ai (Fly.io, 2 machines LHR)
- **Database:** shieldcortex-db (Fly Postgres 17.2)
- **Stripe:** Pro/Team/Enterprise prices configured, webhook active
- **Dashboard:** Served alongside API, includes devices, audit, alerts, skills, webhooks, firewall rules

## Don't Break These

- [ ] `npx shieldcortex scan "text"` — must work as CLI
- [ ] `npx shieldcortex status` — must show DB stats
- [ ] `npx shieldcortex openclaw install` — must install hook to `~/.openclaw/hooks/`
- [ ] `import('shieldcortex')` — must return exports, not crash
- [ ] `import('shieldcortex/defence')` — must export defence pipeline
- [ ] `import('shieldcortex/lib')` — must export all APIs
