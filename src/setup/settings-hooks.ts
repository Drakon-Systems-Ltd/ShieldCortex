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
    hooks: [{ type: 'command', command: 'shieldcortex hook pre-compact', timeout: 10 }],
  },
  SessionStart: {
    hooks: [{ type: 'command', command: 'shieldcortex hook session-start', timeout: 5 }],
  },
  // SessionEnd removed from defaults — it causes fatal failures in OpenClaw
  // agents when the session is already gone. PreCompact handles memory
  // extraction. The cortex-memory hook handles session-end for OpenClaw.
  UserPromptSubmit: {
    hooks: [{ type: 'command', command: 'shieldcortex hook prompt-recall', timeout: 2 }],
  },
};

/**
 * Canonical list of Claude Code hook names that ShieldCortex installs.
 * Source of truth for `shieldcortex doctor` so doctor and install agree.
 * Keep this alongside CORTEX_HOOKS — drift between the two is what caused #23.
 */
export const REQUIRED_HOOK_NAMES: readonly string[] = Object.freeze(Object.keys(CORTEX_HOOKS));

const STOP_HOOK: HookEntry = {
  hooks: [{ type: 'command', command: 'shieldcortex hook stop', timeout: 10 }],
};

// SessionEnd is opt-in. The hook script gates execution behind
// `autoMemory.enableSessionEnd` in ~/.shieldcortex/config.json AND a
// process.env-based OpenClaw context detector, so wiring it via this flag
// does NOT regress the v4.10 OpenClaw-crash class on its own.
const SESSION_END_HOOK: HookEntry = {
  hooks: [{ type: 'command', command: 'shieldcortex hook session-end', timeout: 10 }],
};

function hasCortexHook(entries: HookEntry[]): boolean {
  return entries.some((e) =>
    e.hooks?.some((h) => typeof h.command === 'string' && h.command.includes('shieldcortex'))
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

/**
 * Migrate stale `npx shieldcortex hook ...` commands to `shieldcortex hook ...`.
 * The npx variant hits a stale cache and can crash OpenClaw agents.
 */
function migrateNpxHooks(settings: Record<string, any>): number {
  let migrated = 0;
  if (!settings.hooks) return 0;

  for (const [eventName, entries] of Object.entries(settings.hooks)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries as HookEntry[]) {
      if (!entry.hooks || !Array.isArray(entry.hooks)) continue;
      for (const hook of entry.hooks) {
        if (typeof hook.command === 'string' && hook.command.startsWith('npx shieldcortex hook')) {
          hook.command = hook.command.replace('npx shieldcortex hook', 'shieldcortex hook');
          migrated++;
          console.log(`  ↑ Hook: ${eventName} (migrated from npx to global binary)`);
        }
      }
    }
  }
  return migrated;
}

export function setupHooks(options?: { stopHook?: boolean; sessionEnd?: boolean }): void {
  const settings = readSettings();
  if (!settings.hooks) {
    settings.hooks = {};
  }

  // First: migrate any stale npx commands to direct binary
  const migrated = migrateNpxHooks(settings);

  // SessionEnd handling is now bidirectional:
  //   - if --with-session-end was passed, install it (the .mjs gates execution
  //     by config + OpenClaw env so it's safe to wire here);
  //   - otherwise, remove any existing ShieldCortex SessionEnd entry to keep
  //     the OpenClaw-safe default for users who don't explicitly opt in.
  if (!options?.sessionEnd && settings.hooks.SessionEnd) {
    const hadCortex = hasCortexHook(settings.hooks.SessionEnd);
    if (hadCortex) {
      settings.hooks.SessionEnd = settings.hooks.SessionEnd.filter(
        (e: HookEntry) => !e.hooks?.some((h) => typeof h.command === 'string' && h.command.includes('shieldcortex'))
      );
      if (settings.hooks.SessionEnd.length === 0) delete settings.hooks.SessionEnd;
      console.log('  - Hook: SessionEnd (removed — opt in with `--with-session-end`)');
    }
  }

  let added = 0;

  // Install command hooks (PreCompact, SessionStart, UserPromptSubmit)
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

  // Optionally install SessionEnd hook
  if (options?.sessionEnd) {
    if (!Array.isArray(settings.hooks.SessionEnd)) {
      settings.hooks.SessionEnd = [];
    }
    if (!hasCortexHook(settings.hooks.SessionEnd)) {
      settings.hooks.SessionEnd.push(SESSION_END_HOOK);
      added++;
      console.log(`  + Hook: SessionEnd (opt-in — gated by autoMemory.enableSessionEnd)`);
    } else {
      console.log(`  = Hook: SessionEnd (already configured)`);
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
      console.log(`  + Hook: Stop (opt-in — gated by autoMemory.enableStop)`);
    } else {
      console.log(`  = Hook: Stop (already configured)`);
    }
  }

  const changed = added + migrated;
  if (changed > 0) {
    writeSettings(settings);
    console.log(`Hooks: ${added} added, ${migrated} migrated in ~/.claude/settings.json`);
  } else {
    console.log('Hooks: all hooks already configured in ~/.claude/settings.json');
  }
}
