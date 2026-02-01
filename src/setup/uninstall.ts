/**
 * Uninstall utilities for ShieldCortex.
 *
 * Removes hooks from settings.json, CLAUDE.md block, service, and Clawdbot hook.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { uninstallService } from '../service/install.js';
import { uninstallClawdbotHook } from './clawdbot.js';

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

export async function uninstallSetup(): Promise<void> {
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

  console.log('\nSetup removal complete.');
}

export async function uninstallAll(options?: { keepLogs?: boolean }): Promise<void> {
  console.log('Uninstalling ShieldCortex completely...\n');

  // 1. Uninstall service
  try {
    await uninstallService(options?.keepLogs ? undefined : { cleanLogs: true });
  } catch (err: any) {
    console.error(`Failed to uninstall service: ${err.message}`);
  }

  // 2. Uninstall Clawdbot hook
  try {
    await uninstallClawdbotHook();
  } catch (err: any) {
    console.error(`Failed to uninstall Clawdbot hook: ${err.message}`);
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

  console.log('\nDatabase preserved at ~/.shieldcortex/memories.db — delete manually if desired.');
  console.log('Uninstall complete.');
}
