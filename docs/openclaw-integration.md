# OpenClaw Integration

ShieldCortex provides native hook integration for [OpenClaw](https://openclaw.dev) (and its variants Moltbot, Clawdbot). One command gives your OpenClaw sessions persistent memory with security protection.

## Why ShieldCortex + OpenClaw?

OpenClaw is a powerful AI coding assistant, but like most agents, it forgets everything between sessions. ShieldCortex fixes that:

| Problem | Solution |
|---------|----------|
| Sessions start from scratch | Past context auto-injected on startup |
| Important decisions get lost | Auto-extracted and saved on `/new` |
| Manual note-taking required | "Remember this..." keyword triggers |
| Memory can be poisoned | 6-layer defence pipeline scans all content |

**The result:** Your OpenClaw sessions build on each other. Decisions persist. Context accumulates. And it's all protected from prompt injection attacks.

---

## Installation

```bash
# Install the hook (requires sudo for global npm installs)
sudo npx shieldcortex openclaw install
```

**Why sudo?** OpenClaw is typically installed globally (`npm install -g openclaw`), so its hooks directory (`/usr/lib/node_modules/openclaw/dist/hooks/bundled/`) requires root access.

If you installed OpenClaw locally or have write access to the hooks directory, you can omit `sudo`.

### Verify Installation

```bash
npx shieldcortex openclaw status
```

Output:
```
OpenClaw: installed
Hooks directory:  /usr/lib/node_modules/openclaw/dist/hooks/bundled
cortex-memory:    installed
```

---

## What Gets Installed

The installer copies the `cortex-memory` hook to OpenClaw's bundled hooks directory:

```
<openclaw-install>/dist/hooks/bundled/cortex-memory/
  ├── HOOK.md      # Hook metadata and documentation
  └── handler.js   # Event handler implementation
```

The hook registers for three OpenClaw events:
- `command:new` - Session end
- `agent:bootstrap` - Session start
- `command` - All commands (for keyword triggers)

---

## How It Works

### Session Lifecycle

```
┌──────────────────────────────────────────────────────────────────┐
│                    OpenClaw Session Lifecycle                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐       │
│  │   START     │ ───▶ │   WORKING   │ ───▶ │    /new     │       │
│  │             │      │             │      │             │       │
│  └──────┬──────┘      └──────┬──────┘      └──────┬──────┘       │
│         │                    │                    │               │
│         ▼                    ▼                    ▼               │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐       │
│  │ get_context │      │ "remember   │      │  Extract    │       │
│  │ → inject    │      │  this: ..." │      │  memories   │       │
│  │   past      │      │  → save     │      │  → save     │       │
│  └─────────────┘      └─────────────┘      └─────────────┘       │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### 1. Session Start (Bootstrap)

When OpenClaw starts a new session, the hook:

1. Calls ShieldCortex `get_context` to retrieve relevant past memories
2. Formats them as a `CORTEX_MEMORY.md` file
3. Injects into the agent's bootstrap context

**What the agent sees:**

```markdown
# Past Session Context (from ShieldCortex)

## Architecture
- Using PostgreSQL with Drizzle ORM (decided Jan 15)
- API routes follow /api/v1/{resource} pattern

## Preferences
- Always use TypeScript strict mode
- Prefer async/await over callbacks

## Recent Work
- Fixed authentication bug in login flow
- Added rate limiting to API endpoints
```

### 2. During Session (Keyword Triggers)

Say any of these phrases followed by content:
- **"remember this:"**
- **"don't forget:"**

Example:
```
User: remember this: the API key for production is rotated monthly
```

The hook:
1. Detects the keyword trigger
2. Extracts the content after the trigger phrase
3. Saves to ShieldCortex with `critical` importance
4. Confirms: `Saved to Cortex memory: "the API key for production is rotated monthly"`

### 3. Session End (`/new`)

When you run `/new` to start a fresh session, the hook:

1. Reads the last 30 messages from the ending session
2. Pattern-matches for high-value content:
   - **Architecture decisions** ("decided to use...", "structured as...")
   - **Bug fixes** ("fixed by...", "root cause was...")
   - **Learnings** ("discovered that...", "turns out...")
   - **Preferences** ("always...", "never...", "prefer...")
   - **Important notes** ("important:", "key point:")
3. Saves up to 5 memories with `high` importance
4. Logs: `[cortex-memory] Saved 3/5 memories from session`

---

## Configuration

The hook works out of the box with sensible defaults. Currently there are no user-configurable options.

**Default behaviour:**
- Project scope: `openclaw` (shared across all OpenClaw sessions)
- Memory scope: `global` (accessible from Claude Code too)
- Auto-extract limit: 5 memories per session
- Keyword trigger importance: `critical`
- Auto-extract importance: `high`

---

## Database & Sharing

Memories are stored in `~/.shieldcortex/memories.db` (SQLite).

**Key point:** This database is shared with Claude Code. Memories created in OpenClaw are immediately available in Claude Code sessions, and vice versa.

```
┌──────────────┐     ┌──────────────────────┐     ┌──────────────┐
│   OpenClaw   │ ──▶ │ ~/.shieldcortex/     │ ◀── │  Claude Code │
│   Sessions   │     │   memories.db        │     │   Sessions   │
└──────────────┘     └──────────────────────┘     └──────────────┘
```

---

## Security

All content saved through the hook passes through ShieldCortex's 6-layer defence pipeline:

1. **Memory Firewall** - Blocks prompt injection, encoding tricks
2. **Audit Logger** - Full trail of every memory operation
3. **Trust Scorer** - Rates memories by source reliability
4. **Sensitivity Classifier** - Detects credentials/PII (Pro)
5. **Fragmentation Detector** - Catches multi-part attacks (Pro)

Malicious content is automatically quarantined for human review.

---

## Troubleshooting

### "OpenClaw is not installed on this system"

The installer couldn't find OpenClaw. Check:

```bash
which openclaw    # or: which moltbot, which clawdbot
```

If not found, install OpenClaw first:
```bash
npm install -g openclaw
```

### "Hook source files not found"

Your ShieldCortex installation may be corrupted. Reinstall:
```bash
npm install -g shieldcortex
```

### Hook not triggering

1. Check the hook is installed:
   ```bash
   npx shieldcortex openclaw status
   ```

2. Restart OpenClaw after installing the hook

3. Check OpenClaw logs for `[cortex-memory]` messages

### Permission denied during install

The hooks directory requires root access:
```bash
sudo npx shieldcortex openclaw install
```

### Memories not appearing in Claude Code

Ensure both tools are using the same database path (`~/.shieldcortex/memories.db`). Check with:
```bash
npx shieldcortex status
```

---

## Uninstalling

```bash
sudo npx shieldcortex openclaw uninstall
```

Or disable without removing (in OpenClaw config):

```json
{
  "hooks": {
    "internal": {
      "entries": {
        "cortex-memory": { "enabled": false }
      }
    }
  }
}
```

---

## How It Compares

| Feature | Raw OpenClaw | + ShieldCortex |
|---------|--------------|----------------|
| Session memory | None | Full persistence |
| Cross-session context | Manual copy/paste | Automatic injection |
| Decision tracking | Lost on `/new` | Auto-extracted |
| Security | None | 6-layer defence |
| Claude Code sharing | N/A | Same database |

---

## Related

- [ShieldCortex README](../README.md) - Full documentation
- [Architecture](../ARCHITECTURE.md) - How ShieldCortex works internally
- [LangChain Integration](./langchain-integration.md) - For LangChain users

---

**Questions?** [Open an issue](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues)
