/**
 * Uninstall utilities for ShieldCortex.
 *
 * Removes hooks from settings.json, CLAUDE.md block, service, and OpenClaw hook.
 *
 * SECURITY: Requires --confirm flag or interactive TTY confirmation.
 * This prevents automated/bot-initiated uninstalls.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import readline from 'readline';
import { uninstallService } from '../service/install.js';
import { uninstallOpenClawHook } from './openclaw.js';
import { uninstallCodex } from './codex.js';
import { looksLikeShieldcortex } from './json-config.js';
import { formatKeptSummary } from './uninstall-manifest.js';

/**
 * Check if the current process is running in an agent context.
 * Agents (sub-agents) should not be able to uninstall ShieldCortex.
 */
function isAgentContext(): boolean {
  // Common agent environment indicators
  return !!(
    process.env.CLAUDE_AGENT_CONTEXT ||
    process.env.SHIELDCORTEX_AGENT_SOURCE ||
    (process.env.CLAUDE_CODE_ENTRYPOINT === 'subagent')
  );
}

/**
 * Block uninstall attempts from agent contexts.
 * Returns true if blocked (caller should abort).
 */
function blockAgentUninstall(): boolean {
  if (isAgentContext()) {
    console.error('\n[ShieldCortex] BLOCKED: Uninstall attempted from agent context.');
    console.error('Sub-agents cannot uninstall ShieldCortex.');
    console.error('Only human operators can uninstall via interactive TTY.\n');
    return true;
  }
  return false;
}

/**
 * Require explicit confirmation before uninstall.
 * Returns true if confirmed, false otherwise.
 */
export async function requireConfirmation(action: string): Promise<boolean> {
  // Allow --confirm flag to skip interactive prompt
  if (process.argv.includes('--confirm')) {
    return true;
  }

  // Non-interactive (piped, no TTY) → reject
  if (!process.stdin.isTTY) {
    console.error(`\nUninstall blocked: no interactive terminal detected.`);
    console.error(`Use --confirm flag for non-interactive uninstall:`);
    console.error(`  shieldcortex ${action} --confirm\n`);
    return false;
  }

  // Interactive TTY prompt
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise<boolean>((resolve) => {
    rl.question(
      `\nAre you sure you want to ${action}? Type "yes" to confirm: `,
      (answer) => {
        rl.close();
        resolve(answer.trim().toLowerCase() === 'yes');
      },
    );
  });
}

const SETTINGS_PATH = path.join(os.homedir(), '.claude', 'settings.json');
const CLAUDE_MD_PATH = path.join(os.homedir(), '.claude', 'CLAUDE.md');
const MARKER = '# ShieldCortex — Memory System';

export function removeHooks(): void {
  if (!fs.existsSync(SETTINGS_PATH)) {
    console.log('No settings.json found — nothing to remove.');
    return;
  }

  let settings: Record<string, any>;
  try {
    settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf-8'));
  } catch (err) {
    console.error('Failed to parse settings.json — aborting hook removal to avoid corruption.');
    return;
  }

  if (!settings.hooks || typeof settings.hooks !== 'object') {
    console.log('No hooks found in settings.json.');
    return;
  }

  let removed = 0;

  for (const category of Object.keys(settings.hooks)) {
    const entries = settings.hooks[category];
    if (!Array.isArray(entries)) continue;

    const filtered = entries.filter(
      (entry: any) =>
        !entry.hooks?.some(
          (h: any) =>
            typeof h.command === 'string' &&
            (h.command.includes('shieldcortex') || h.command.includes('shield-cortex'))
        )
    );

    const diff = entries.length - filtered.length;
    if (diff > 0) {
      settings.hooks[category] = filtered;
      removed += diff;
      console.log(`  - Removed ${diff} hook(s) from ${category}`);
    }
  }

  if (removed > 0) {
    fs.writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2) + '\n', 'utf-8');
    console.log(`Hooks: removed ${removed} hook(s) from ~/.claude/settings.json`);
  } else {
    console.log('Hooks: no ShieldCortex hooks found in settings.json.');
  }
}

export function removeClaudeMdBlock(): void {
  if (!fs.existsSync(CLAUDE_MD_PATH)) {
    console.log('No ~/.claude/CLAUDE.md found — nothing to remove.');
    return;
  }

  const content = fs.readFileSync(CLAUDE_MD_PATH, 'utf-8');
  const markerIndex = content.indexOf(MARKER);

  if (markerIndex === -1) {
    console.log('CLAUDE.md: no ShieldCortex block found.');
    return;
  }

  // Find the end of the block: next heading at same or higher level, or EOF
  const afterMarker = content.substring(markerIndex + MARKER.length);
  const nextHeadingMatch = afterMarker.match(/\n#(?= )/);

  let before = content.substring(0, markerIndex).trimEnd();
  let after = '';

  if (nextHeadingMatch) {
    after = afterMarker.substring(nextHeadingMatch.index!);
  }

  const newContent = (before + after).trimEnd() + '\n';
  fs.writeFileSync(CLAUDE_MD_PATH, newContent, 'utf-8');
  console.log('CLAUDE.md: removed ShieldCortex memory instructions block.');
}

/**
 * Remove the ShieldCortex MCP server entry from ~/.claude.json.
 *
 * Pre-v4.12.11 uninstall left this entry in place. Every Claude Code
 * session then tried to spawn the now-missing shieldcortex binary, and
 * the failure cascaded into fleet-wide context loss — confirmed by a
 * peer agent (Edith) who saw an affected host stabilise within minutes
 * after manually removing the entry.
 *
 * Safe: only deletes entries that look ShieldCortex-owned. No-op if the
 * file is missing, JSON is malformed, the entry is absent, or the entry
 * belongs to another MCP server.
 */
export function removeMcpEntry(): void {
  const mcpPath = path.join(os.homedir(), '.claude.json');
  if (!fs.existsSync(mcpPath)) return;

  let config: any;
  try {
    config = JSON.parse(fs.readFileSync(mcpPath, 'utf-8'));
  } catch (err: any) {
    console.warn(`MCP: could not parse ~/.claude.json — leaving it untouched: ${err.message}`);
    return;
  }

  const entry = config?.mcpServers?.memory;
  if (!entry) {
    console.log('MCP: no shieldcortex entry found in ~/.claude.json.');
    return;
  }

  if (!looksLikeShieldcortex(entry)) {
    console.warn('MCP: ~/.claude.json mcpServers.memory does not look ShieldCortex-owned — leaving it alone.');
    return;
  }

  delete config.mcpServers.memory;
  fs.writeFileSync(mcpPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
  console.log('MCP: removed shieldcortex entry from ~/.claude.json.');
}

export async function uninstallSetup(): Promise<void> {
  if (blockAgentUninstall()) return;

  const confirmed = await requireConfirmation('remove ShieldCortex setup');
  if (!confirmed) {
    console.log('Uninstall cancelled.');
    return;
  }

  console.log('Removing ShieldCortex setup...\n');

  try {
    removeHooks();
  } catch (err: any) {
    console.error(`Failed to remove hooks: ${err.message}`);
  }

  try {
    removeClaudeMdBlock();
  } catch (err: any) {
    console.error(`Failed to remove CLAUDE.md block: ${err.message}`);
  }

  try {
    removeMcpEntry();
  } catch (err: any) {
    console.error(`Failed to remove MCP entry: ${err.message}`);
  }

  console.log('\nSetup removal complete.');
}

export async function uninstallAll(options?: {
  keepLogs?: boolean;
  deep?: boolean;
  restartGateway?: boolean;
}): Promise<void> {
  if (blockAgentUninstall()) return;

  const action = options?.deep
    ? 'fully uninstall ShieldCortex and purge OpenClaw residue'
    : 'fully uninstall ShieldCortex';
  const confirmed = await requireConfirmation(action);
  if (!confirmed) {
    console.log('Uninstall cancelled.');
    return;
  }

  console.log('Uninstalling ShieldCortex completely...\n');

  // 1. Uninstall service
  try {
    await uninstallService(options?.keepLogs ? undefined : { cleanLogs: true });
  } catch (err: any) {
    console.error(`Failed to uninstall service: ${err.message}`);
  }

  // 2. Uninstall OpenClaw hook
  try {
    await uninstallOpenClawHook();
  } catch (err: any) {
    console.error(`Failed to uninstall OpenClaw hook: ${err.message}`);
  }

  // 3. Remove hooks from settings.json
  try {
    removeHooks();
  } catch (err: any) {
    console.error(`Failed to remove hooks: ${err.message}`);
  }

  // 4. Remove CLAUDE.md block
  try {
    removeClaudeMdBlock();
  } catch (err: any) {
    console.error(`Failed to remove CLAUDE.md block: ${err.message}`);
  }

  // 5. Remove the MCP entry from ~/.claude.json. This is THE
  //    pre-v4.12.11 context-killer — every Claude Code session loaded
  //    the orphaned entry, tried to spawn the missing binary, and the
  //    failure cascaded into context loss across the fleet.
  try {
    removeMcpEntry();
  } catch (err: any) {
    console.error(`Failed to remove MCP entry: ${err.message}`);
  }

  // 5b. Codex MCP block in ~/.codex/config.toml (#452). The standalone
  //     `shieldcortex codex uninstall` verb already did this; full uninstall
  //     did not, so Codex kept a dead `shieldcortex-memory` server after the
  //     package was gone.
  try {
    await uninstallCodex();
  } catch (err: any) {
    console.error(`Failed to remove Codex MCP entry: ${err.message}`);
  }

  // 6. Deep clean: purge all known OpenClaw residue locations that the
  //    version-specific uninstall paths miss, then (best-effort) restart
  //    the gateway so the purged config takes effect immediately.
  if (options?.deep) {
    try {
      const { runDeepClean } = await import('./deep-clean.js');
      const { report, result, gateway } = await runDeepClean({
        restartGateway: options?.restartGateway !== false,
      });
      if (result.removed.length > 0) {
        console.log(`\nDeep clean: removed ${result.removed.length} residue reference(s):`);
        for (const r of result.removed) {
          console.log(`  - ${r}`);
        }
      } else if (report.dirtyCount === 0) {
        console.log('\nDeep clean: no OpenClaw residue detected.');
      }
      if (result.errors.length > 0) {
        console.warn(`\nDeep clean: ${result.errors.length} error(s):`);
        for (const e of result.errors) {
          console.warn(`  - ${e.description}: ${e.error}`);
        }
      }
      if (gateway) {
        if (gateway.restarted) {
          console.log(`\nOpenClaw gateway restarted via ${gateway.method}.`);
        } else if (gateway.attempted) {
          console.warn(`\nOpenClaw gateway restart via ${gateway.method} failed: ${gateway.detail ?? 'unknown'}`);
          console.warn('Restart it manually for the cleanup to take effect.');
        }
      }
    } catch (err: any) {
      console.error(`Deep clean failed: ${err.message}`);
    }
  }

  // The last thing on screen is what we deliberately did NOT remove, and why
  // (#197). Silence about a kept artifact reads as coverage.
  console.log('\nUninstall complete.\n');
  console.log(formatKeptSummary());
  console.log('\nTo clear the npx cache:');
  console.log('  npx cache clean shieldcortex  (npm 9+)');
  console.log('  rm -rf ~/.npm/_npx             (older npm)\n');
}
