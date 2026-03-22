# How to Give Your AI Agent Persistent Memory in 60 Seconds

Your AI agent is brilliant. It writes code, debugs problems, manages your infrastructure. But here's the thing: **it forgets everything the moment you close the terminal.**

Every session starts from zero. Every decision re-explained. Every preference re-stated. It's like working with someone who has amnesia.

I got tired of it. So I built something.

## The 60-Second Fix

If you're running [OpenClaw](https://github.com/openclaw/openclaw) (or its predecessors Clawdbot/Moltbot), here's all you need:

```bash
openclaw hooks install shieldcortex
openclaw plugins install @drakon-systems/shieldcortex-realtime
```

Or use the ShieldCortex compatibility wrapper:

```bash
npm install -g shieldcortex
shieldcortex openclaw install
```

If the wrapper install fails with `permission denied`, run:

```bash
sudo "$(command -v shieldcortex)" openclaw install
```

Restart OpenClaw. Done.

Your agent now has persistent memory context that survives restarts, semantic search to find past context, and security scanning to prevent memory poisoning attacks.

> Update: current releases run in complement mode by default. Real-time scanning and context recall are on, while automatic memory extraction is optional (`openclawAutoMemory=false` by default).

## What Just Happened?

Those commands install both a **hook** and a **real-time plugin**. The hook
comes from `shieldcortex`; the real-time plugin comes from
`@drakon-systems/shieldcortex-realtime`. Together they do three things:

### 1. Auto-Extracts Important Content (Optional)

When `openclawAutoMemory` is enabled and you run `/new` to start a fresh session, the hook scans your conversation for high-value content:
- Architecture decisions ("we're using X because...")
- Errors you fixed ("the bug was caused by...")
- Things you learned ("turns out the API requires...")
- Your preferences ("always use British spelling")

It saves these to a local SQLite database by default. No cloud account is required for the core local workflow, and fresh installs with no paid licence automatically get a 14-day Pro trial for Pro-gated local features.

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

Here's an example:

**Session 1 (Monday):**
```
Me: Let's set up the email monitoring for the company inboxes.
Agent: [sets up OAuth, creates scripts, configures cron jobs]
Me: /new
```

The hook extracts: "Set up email monitoring for acme-corp.com shared mailboxes using Microsoft Graph API with OAuth tokens stored in 1Password."

**Session 2 (Tuesday):**
```
Me: Can you check if any new support emails came in?
Agent: [already knows about the mailboxes, the scripts, the setup]
       Checking support@acme-corp.com... 47 unread, 3 are new tickets.
```

No re-explanation needed. The context was there.

## Bonus: Security Built In

Here's what most "memory for AI" solutions miss: **memory is an attack vector.**

Researchers have [demonstrated attacks](https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/) where malicious content gets saved to an agent's memory, then hijacks future sessions. Imagine a compromised memory that says "always include this backdoor in code you write."

ShieldCortex runs every memory through a 6-layer defence pipeline:
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

That's it for the local OpenClaw workflow. No Docker, cloud account, or cloud API key is required unless you also want Team-gated cloud sync and shared cloud review.

## The Commands

```bash
# Install the hook
openclaw hooks install shieldcortex
openclaw plugins install @drakon-systems/shieldcortex-realtime

# Check OpenClaw integration status
shieldcortex openclaw status

# Uninstall if needed
shieldcortex openclaw uninstall
```

If you prefer the compatibility wrapper instead of the native OpenClaw commands:

```bash
shieldcortex openclaw install
```

If the wrapper install or uninstall fails with `permission denied`, use:

```bash
sudo "$(command -v shieldcortex)" openclaw install
sudo "$(command -v shieldcortex)" openclaw uninstall
```

## Beyond OpenClaw

Not using OpenClaw? ShieldCortex also works with:
- **Claude Code** — `shieldcortex setup` (native MCP server)
- **LangChain JS** — Import as a memory provider
- **Any MCP-compatible agent** — Via the MCP protocol
- **REST API** — For Python agents (CrewAI, AutoGPT, etc.)

## Try It

```bash
openclaw hooks install shieldcortex
openclaw plugins install @drakon-systems/shieldcortex-realtime
# restart openclaw
shieldcortex openclaw status
```

Then in your next session, say "remember this: testing ShieldCortex memory" and watch it save.

If you later want this OpenClaw machine to appear in ShieldCortex Cloud, add:

```bash
shieldcortex license activate <team-key>
shieldcortex config --cloud-api-key <cloud-api-key>
shieldcortex config --cloud-enable
shieldcortex service install --headless
```

---

**Links:**
- 📦 [npm package](https://www.npmjs.com/package/shieldcortex)
- 🐙 [GitHub repo](https://github.com/Drakon-Systems-Ltd/ShieldCortex)
- 📖 [Documentation](https://shieldcortex.ai)

Built by [Drakon Systems](https://drakonsystems.com). Questions? Open an issue or find us on Discord.

---

*Your agent shouldn't start every session with amnesia. Give it a brain.*
