# How to Give Your AI Agent Persistent Memory in 60 Seconds

Your AI agent is brilliant. It writes code, debugs problems, manages your infrastructure. But here's the thing: **it forgets everything the moment you close the terminal.**

Every session starts from zero. Every decision re-explained. Every preference re-stated. It's like working with someone who has amnesia.

I got tired of it. So I built something.

## The 60-Second Fix

If you're running [OpenClaw](https://github.com/openclaw/openclaw) (or its predecessors Clawdbot/Moltbot), here's all you need:

```bash
sudo npx shieldcortex openclaw install
```

Restart OpenClaw. Done.

Your agent now has persistent memory that survives restarts, semantic search to find past context, and even security scanning to prevent memory poisoning attacks.

## What Just Happened?

That command installed a **hook** into OpenClaw's plugin system. The hook does three things:

### 1. Auto-Extracts Important Content

When you run `/new` to start a fresh session, the hook scans your conversation for high-value content:
- Architecture decisions ("we're using X because...")
- Errors you fixed ("the bug was caused by...")
- Things you learned ("turns out the API requires...")
- Your preferences ("always use British spelling")

It saves these to a local SQLite database. No cloud. No API keys. Just works.

### 2. Injects Past Context on Startup

Next time your agent boots up, it automatically receives relevant context from past sessions. You'll see a `CORTEX_MEMORY.md` file injected into its context with things like:

```markdown
# Past Session Context (from ShieldCortex)

## Project: my-app

### Key Decisions
- Using PostgreSQL over MySQL for JSONB support
- Deployed on Fly.io, not Vercel (needed persistent storage)

### Recent Context
- Fixed CORS issue by adding origin whitelist
- User prefers TypeScript over JavaScript
```

No manual copy-paste. No "remember last time we..." prompts. It just knows.

### 3. Keyword Triggers

Say "remember this:" followed by anything, and it's saved:

```
You: remember this: the staging API key expires on March 15th

Agent: Saved to Cortex memory: "the staging API key expires on March 15th"
```

Same with "don't forget:" — natural language memory saving.

## Show Me It Working

Here's a real example from my setup:

**Session 1 (Monday):**
```
Me: Let's set up the email monitoring for the school inboxes.
Agent: [sets up OAuth, creates scripts, configures cron jobs]
Me: /new
```

The hook extracts: "Set up email monitoring for vitaetpax.co.uk shared mailboxes using Microsoft Graph API with OAuth tokens stored in 1Password."

**Session 2 (Tuesday):**
```
Me: Can you check if any new admissions emails came in?
Agent: [already knows about the school mailboxes, the scripts, the setup]
       Checking admissions@vitaetpax.co.uk... 47 unread, 3 are new enquiries.
```

No re-explanation needed. The context was there.

## Bonus: Security Built In

Here's what most "memory for AI" solutions miss: **memory is an attack vector.**

Researchers have [demonstrated attacks](https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/) where malicious content gets saved to an agent's memory, then hijacks future sessions. Imagine a compromised memory that says "always include this backdoor in code you write."

ShieldCortex runs every memory through a 5-layer defence pipeline:
- Prompt injection detection
- Encoding trick blocking (base64, hex, unicode payloads)
- Credential pattern matching
- Trust scoring based on source
- Quarantine for suspicious content

You get memory AND security. Not one or the other.

## Requirements

- Node.js 18+
- OpenClaw installed globally (`npm install -g openclaw`)
- ~50MB disk space for the SQLite database

That's it. No Docker. No external services. No API keys.

## The Commands

```bash
# Install the hook
sudo npx shieldcortex openclaw install

# Check status
npx shieldcortex status

# Uninstall if needed
sudo npx shieldcortex openclaw uninstall
```

## Beyond OpenClaw

Not using OpenClaw? ShieldCortex also works with:
- **Claude Code** — `npx shieldcortex setup` (native MCP server)
- **LangChain JS** — Import as a memory provider
- **Any MCP-compatible agent** — Via the MCP protocol
- **REST API** — For Python agents (CrewAI, AutoGPT, etc.)

## Try It

```bash
npm install -g shieldcortex
npx shieldcortex openclaw install
# restart openclaw
npx shieldcortex status
```

Then in your next session, say "remember this: testing ShieldCortex memory" and watch it save.

---

**Links:**
- 📦 [npm package](https://www.npmjs.com/package/shieldcortex)
- 🐙 [GitHub repo](https://github.com/Drakon-Systems-Ltd/ShieldCortex)
- 📖 [Documentation](https://shieldcortex.ai)

Built by [Drakon Systems](https://drakonsystems.com). Questions? Open an issue or find us on Discord.

---

*Your agent shouldn't start every session with amnesia. Give it a brain.*
