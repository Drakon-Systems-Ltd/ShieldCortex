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
import { fileURLToPath } from 'url';
import { installOpenClawHook, findAllHooksDirs } from './openclaw.js';
import { setupHooks } from './settings-hooks.js';
import { readJsonConfigOrAbort, writeJsonConfigWithBackup, looksLikeShieldcortex, resolveMcpServerCommand } from './json-config.js';

// MCP entry point: dist/index.js — one level up from dist/setup/ (this module).
const MCP_ENTRY = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'index.js');

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

interface McpCommand {
  command: string;
  args: string[];
}

/**
 * Resolve the shieldcortex command for the MCP stdio registration.
 *
 * PATH-immune (issue #76): delegates to the shared resolver so the entry is an
 * ABSOLUTE node binary (`process.execPath`) + the ABSOLUTE `dist/index.js` — it
 * never emits the `shieldcortex` shebang bin (which relies on `#!/usr/bin/env
 * node` finding node on PATH; GUI/launchd spawns often lack it, killing the
 * server before the MCP handshake with a bare -32000).
 *
 * Also never `npx -y shieldcortex`: `npx` re-resolves on every spawn, so a cache
 * shift changes the effective command; Claude Code / OpenClaw hash the MCP
 * config and reset the active CLI session on any change, wiping conversation
 * context mid-flight (TARS, 2026-04-22 fleet "Fresh session" bug). Two absolute
 * paths never drift.
 */
export function resolveMcpCommand(): McpCommand {
  return resolveMcpServerCommand(MCP_ENTRY);
}

function isIdealMcpEntry(entry: unknown, ideal: McpCommand): boolean {
  if (!entry || typeof entry !== 'object') return false;
  const e = entry as { command?: unknown; args?: unknown };
  if (e.command !== ideal.command) return false;
  if (!Array.isArray(e.args) || e.args.length !== ideal.args.length) return false;
  return e.args.every((v, i) => v === ideal.args[i]);
}

export function setupGlobalMcp(): void {
  // Claude Code reads user-scope MCP servers from ~/.claude.json
  const mcpPath = path.join(os.homedir(), '.claude.json');
  const ideal = resolveMcpCommand();
  const idealEntry = {
    type: 'stdio' as const,
    command: ideal.command,
    args: ideal.args,
  };
  const isStablePath = ideal.command !== 'npx';

  // ~/.claude.json is Claude Code's PRIMARY state file. A parse failure on an
  // EXISTING file MUST abort (readJsonConfigOrAbort throws) — never overwrite
  // it with a `{ mcpServers: { memory } }` stub, which would wipe the user's
  // entire Claude Code state. A missing file legitimately yields {}.
  const existing = readJsonConfigOrAbort(mcpPath);
  const fileExisted = fs.existsSync(mcpPath);
  const servers = existing.mcpServers || {};
  const current = servers.memory;

  if (isIdealMcpEntry(current, idealEntry)) {
    console.log(
      `✓ MCP: global server already configured in ~/.claude.json (stable binary: ${isStablePath ? ideal.command : 'npx'})`
    );
    return;
  }

  // Ownership guard (mirrors uninstall.ts): `memory` is a generic key the
  // upstream @modelcontextprotocol/server-memory also uses. If an existing
  // entry is NOT ShieldCortex-owned, leave it alone rather than clobber it.
  if (current && !looksLikeShieldcortex(current)) {
    console.warn(
      '⚠ MCP: ~/.claude.json mcpServers.memory does not look ShieldCortex-owned — leaving it alone.'
    );
    console.warn('  Remove or rename that entry if you want ShieldCortex to register under `memory`.');
    return;
  }

  // Detect whether this is a fresh add or an upgrade from the old
  // `npx -y shieldcortex` form so we log the right message.
  const currentIsShieldCortex = !!current && looksLikeShieldcortex(current);

  existing.mcpServers = servers;
  existing.mcpServers.memory = idealEntry;
  writeJsonConfigWithBackup(mcpPath, existing);

  if (!fileExisted) {
    console.log(`✓ MCP: created global server config at ~/.claude.json (${ideal.command})`);
  } else if (currentIsShieldCortex && isStablePath) {
    console.log(`✓ MCP: upgraded shieldcortex server to stable binary path (${ideal.command})`);
    console.log('  Reason: `npx -y` resolution drift was causing periodic CLI session resets.');
  } else if (currentIsShieldCortex) {
    console.log('✓ MCP: refreshed shieldcortex server registration');
  } else {
    console.log(`✓ MCP: added shieldcortex server to ~/.claude.json (${ideal.command})`);
  }
}

export async function setupClaudeMd(options?: { stopHook?: boolean; sessionEnd?: boolean }): Promise<void> {
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
