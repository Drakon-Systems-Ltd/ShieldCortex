/**
 * Full setup for ShieldCortex.
 *
 * 1. Injects proactive memory instructions into ~/.claude/CLAUDE.md (Claude Code)
 * 2. Creates global MCP server config at ~/.claude.json (user scope)
 * 3. Installs hooks into ~/.claude/settings.json
 * 4. Installs cortex-memory hook into OpenClaw/Clawdbot if detected
 *
 * Both steps are idempotent.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { installClawdbotHook, findClawdbotHooksDir } from './clawdbot.js';
import { setupHooks } from './settings-hooks.js';

const MARKER = '# ShieldCortex — Memory System';

const INSTRUCTIONS = `
${MARKER}

You have access to a persistent memory system via MCP tools (\`remember\`, \`recall\`, \`get_context\`, \`forget\`).

**MUST use \`remember\` immediately when any of these occur:**
- A decision is made (architecture, library choice, approach)
- A bug is fixed (capture root cause + solution)
- Something new is learned about the codebase
- User states a preference
- A significant feature is completed

Do not wait until the end of the session. Call \`remember\` right after the event happens.
`;

function setupClaudeCode(): void {
  const claudeDir = path.join(os.homedir(), '.claude');
  const claudeMdPath = path.join(claudeDir, 'CLAUDE.md');

  fs.mkdirSync(claudeDir, { recursive: true });

  let existing = '';
  if (fs.existsSync(claudeMdPath)) {
    existing = fs.readFileSync(claudeMdPath, 'utf-8');
  }

  if (existing.includes(MARKER)) {
    console.log('✓ Claude Code: instructions already present in ~/.claude/CLAUDE.md');
  } else {
    const newContent = existing.trimEnd() + '\n' + INSTRUCTIONS;
    fs.writeFileSync(claudeMdPath, newContent, 'utf-8');
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

  // 4. OpenClaw/Clawdbot — if detected
  const hooksDir = findClawdbotHooksDir();
  if (hooksDir) {
    const hookExists = fs.existsSync(path.join(hooksDir, 'cortex-memory'));
    if (hookExists) {
      console.log('✓ OpenClaw: cortex-memory hook already installed');
    } else {
      await installClawdbotHook();
    }
  } else {
    console.log('- OpenClaw/Clawdbot: not detected (skipped)');
  }

  console.log('\nSetup complete.');
}
