/**
 * Auto-configure Claude Code hooks in ~/.claude/settings.json.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';

const SETTINGS_PATH = path.join(os.homedir(), '.claude', 'settings.json');

interface HookEntry {
  hooks: Array<{ type: string; command?: string; prompt?: string; timeout?: number }>;
  matcher?: string;
}

const CORTEX_HOOKS: Record<string, HookEntry> = {
  PreCompact: {
    hooks: [{ type: 'command', command: 'npx claude-cortex hook pre-compact', timeout: 10 }],
  },
  SessionStart: {
    hooks: [{ type: 'command', command: 'npx claude-cortex hook session-start', timeout: 5 }],
  },
  SessionEnd: {
    hooks: [{ type: 'command', command: 'npx claude-cortex hook session-end', timeout: 10 }],
  },
};

const STOP_HOOK: HookEntry = {
  hooks: [{ type: 'command', command: 'npx claude-cortex hook stop', timeout: 10 }],
};

function hasCortexHook(entries: HookEntry[]): boolean {
  return entries.some((e) =>
    e.hooks?.some((h) => typeof h.command === 'string' && h.command.includes('claude-cortex'))
  );
}

function readSettings(): Record<string, any> {
  if (!fs.existsSync(SETTINGS_PATH)) {
    return {};
  }
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf-8'));
  } catch {
    return {};
  }
}

function writeSettings(settings: Record<string, any>): void {
  const dir = path.dirname(SETTINGS_PATH);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2) + '\n', 'utf-8');
}

export function setupHooks(options?: { stopHook?: boolean }): void {
  const settings = readSettings();
  if (!settings.hooks) {
    settings.hooks = {};
  }

  let added = 0;

  // Install command hooks (PreCompact, SessionStart, SessionEnd)
  for (const [name, entry] of Object.entries(CORTEX_HOOKS)) {
    if (!Array.isArray(settings.hooks[name])) {
      settings.hooks[name] = [];
    }
    if (!hasCortexHook(settings.hooks[name])) {
      settings.hooks[name].push(entry);
      added++;
      console.log(`  + Hook: ${name}`);
    } else {
      console.log(`  = Hook: ${name} (already configured)`);
    }
  }

  // Optionally install Stop hook
  if (options?.stopHook) {
    if (!Array.isArray(settings.hooks.Stop)) {
      settings.hooks.Stop = [];
    }
    if (!hasCortexHook(settings.hooks.Stop)) {
      settings.hooks.Stop.push(STOP_HOOK);
      added++;
      console.log(`  + Hook: Stop (opt-in)`);
    } else {
      console.log(`  = Hook: Stop (already configured)`);
    }
  }

  if (added > 0) {
    writeSettings(settings);
    console.log(`Hooks: ${added} hook(s) added to ~/.claude/settings.json`);
  } else {
    console.log('Hooks: all hooks already configured in ~/.claude/settings.json');
  }
}
