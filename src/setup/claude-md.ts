/**
 * Full setup for ShieldCortex.
 *
 * 1. Injects proactive memory instructions into ~/.claude/CLAUDE.md (Claude Code)
 * 2. Creates global MCP server config at ~/.claude.json (user scope)
 * 3. Installs hooks into ~/.claude/settings.json
 * 4. Installs cortex-memory hook into OpenClaw if detected
 *
 * Both steps are idempotent.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { installOpenClawHook, findAllHooksDirs } from './openclaw.js';
import { setupHooks } from './settings-hooks.js';

const MARKER = '# ShieldCortex — Memory System';

const INSTRUCTIONS = `
${MARKER}

ShieldCortex provides persistent, project-scoped memory for this session.

**Automatic capture** — no tool calls required. ShieldCortex hooks fire at key
moments and extract high-signal content without the model having to do anything:

- **PreCompact** auto-extracts decisions, bug fixes, learnings, preferences,
  and architecture notes before compaction, tagged and scored for recall.
- **UserPromptSubmit** queries memory on every turn and injects relevant prior
  context into the conversation before the model responds.
- **SessionStart** surfaces a brief project-context preamble on fresh starts
  (silent on resume / compact).

**Manual capture** — *only if* MCP memory tools appear in this session's tool
surface. Typical names are \`mcp__memory__remember\`, \`mcp__memory__recall\`,
\`mcp__memory__get_context\`. If they show up, you may call them directly for
high-signal moments that the hooks might miss.

**If those tools are not in the tool surface for this session** (e.g. OpenClaw-only
installs, or any install where the \`shieldcortex\` MCP server is not wired), the
automatic capture above is sufficient. Do not nag yourself to call tools that do
not appear — it produces silent failures and user-visible amnesia.
`;

// A signature substring unique to the current INSTRUCTIONS. Presence of this
// string means the block is up to date. If the marker is present but this
// signature is missing, an older (potentially stale/incorrect) block is
// installed and should be replaced. Prior versions told the model to call
// bare `remember`/`recall` tools, which don't exist in OpenClaw-only installs
// and produced silent failures.
const CONTENT_SIGNATURE = '**Automatic capture** — no tool calls required.';

function stripExistingBlock(content: string): string {
  const markerIndex = content.indexOf(MARKER);
  if (markerIndex === -1) return content;
  // Drop from MARKER to end of file. Users do not add content after this
  // auto-injected block — it sits at the very end of CLAUDE.md.
  return content.slice(0, markerIndex).trimEnd();
}

function setupClaudeCode(): void {
  const claudeDir = path.join(os.homedir(), '.claude');
  const claudeMdPath = path.join(claudeDir, 'CLAUDE.md');

  fs.mkdirSync(claudeDir, { recursive: true });

  let existing = '';
  if (fs.existsSync(claudeMdPath)) {
    existing = fs.readFileSync(claudeMdPath, 'utf-8');
  }

  const hasMarker = existing.includes(MARKER);
  const hasCurrentContent = existing.includes(CONTENT_SIGNATURE);

  if (hasMarker && hasCurrentContent) {
    console.log('✓ Claude Code: instructions up to date in ~/.claude/CLAUDE.md');
    return;
  }

  const base = hasMarker ? stripExistingBlock(existing) : existing.trimEnd();
  const newContent = (base ? base + '\n' : '') + INSTRUCTIONS;
  fs.writeFileSync(claudeMdPath, newContent, 'utf-8');

  if (hasMarker) {
    console.log('✓ Claude Code: refreshed stale memory instructions in ~/.claude/CLAUDE.md');
  } else {
    console.log('✓ Claude Code: added memory instructions to ~/.claude/CLAUDE.md');
  }
}

function setupGlobalMcp(): void {
  // Claude Code reads user-scope MCP servers from ~/.claude.json
  const mcpPath = path.join(os.homedir(), '.claude.json');

  // Check if already configured
  if (fs.existsSync(mcpPath)) {
    try {
      const existing = JSON.parse(fs.readFileSync(mcpPath, 'utf-8'));
      const servers = existing.mcpServers || {};
      if (servers.memory?.command?.includes?.('shieldcortex') ||
          servers.memory?.args?.some?.((a: string) => a.includes('shieldcortex'))) {
        console.log('✓ MCP: global server already configured in ~/.claude.json');
        return;
      }
      // File exists but no shieldcortex entry — merge it in
      existing.mcpServers = servers;
      existing.mcpServers.memory = {
        type: 'stdio',
        command: 'npx',
        args: ['-y', 'shieldcortex'],
      };
      fs.writeFileSync(mcpPath, JSON.stringify(existing, null, 2) + '\n', 'utf-8');
      console.log('✓ MCP: added shieldcortex server to ~/.claude.json');
      return;
    } catch {
      // Parse error — create fresh
    }
  }

  const config = {
    mcpServers: {
      memory: {
        type: 'stdio',
        command: 'npx',
        args: ['-y', 'shieldcortex'],
      },
    },
  };
  fs.writeFileSync(mcpPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
  console.log('✓ MCP: created global server config at ~/.claude.json');
}

export async function setupClaudeMd(options?: { stopHook?: boolean }): Promise<void> {
  console.log('Setting up ShieldCortex...\n');

  // 1. Claude Code CLAUDE.md — always
  setupClaudeCode();

  // 2. Global MCP server config
  setupGlobalMcp();

  // 3. Hooks in settings.json
  setupHooks(options);

  // 4. OpenClaw — if detected
  const hooksDirs = findAllHooksDirs();
  if (hooksDirs.length > 0) {
    const hookExists = hooksDirs.some(d => fs.existsSync(path.join(d, 'cortex-memory')));
    if (hookExists) {
      console.log('✓ OpenClaw: cortex-memory hook already installed');
    } else {
      await installOpenClawHook();
    }
  } else {
    console.log('- OpenClaw: not detected (skipped)');
  }

  console.log('\nSetup complete.');
}
