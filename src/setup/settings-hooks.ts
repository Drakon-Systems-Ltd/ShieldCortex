/**
 * Auto-configure Claude Code hooks in ~/.claude/settings.json.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { setAutoMemoryEnableConfig } from '../cloud/config.js';

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
    // Cold-spawn floor for the recall hook is ~1.5 s (Node + better-sqlite3 +
    // FTS query). The previous 2 s ceiling SIGKILLed the hook silently under
    // any IO pressure, dropping recall context with no user-visible error
    // (#43). 5 s leaves ~3 s headroom on a busy host.
    hooks: [{ type: 'command', command: 'shieldcortex hook prompt-recall', timeout: 5 }],
  },
};

/**
 * Canonical list of Claude Code hook names that ShieldCortex installs.
 * Source of truth for `shieldcortex doctor` so doctor and install agree.
 * Keep this alongside CORTEX_HOOKS — drift between the two is what caused #23.
 */
export const REQUIRED_HOOK_NAMES: readonly string[] = Object.freeze(Object.keys(CORTEX_HOOKS));

/**
 * Canonical timeout (seconds) for each ShieldCortex hook. Used by
 * `shieldcortex doctor` to flag drift in hand-edited settings.json files —
 * a too-tight UserPromptSubmit timeout silently dropped recall pre-#43.
 */
export const CANONICAL_HOOK_TIMEOUTS: Readonly<Record<string, number>> = Object.freeze(
  Object.fromEntries(
    Object.entries(CORTEX_HOOKS).map(([name, entry]) => [
      name,
      entry.hooks?.[0]?.timeout ?? 0,
    ]),
  ),
);

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

/**
 * Reconcile timeouts on existing ShieldCortex hook entries. Doctor warns
 * users when an existing settings.json has a timeout below canonical (e.g.
 * pre-#43 hand-edited 2 s UserPromptSubmit) and tells them to re-run
 * `shieldcortex install` to fix it. Without this reconciliation the install
 * step was a lie — it only added missing hooks. Now it also bumps timeouts
 * on existing shieldcortex entries to match the canonical values declared
 * alongside CORTEX_HOOKS.
 */
function reconcileHookTimeouts(settings: Record<string, any>): number {
  let updated = 0;
  if (!settings.hooks) return 0;

  for (const [eventName, expectedTimeout] of Object.entries(CANONICAL_HOOK_TIMEOUTS)) {
    if (!expectedTimeout) continue;
    const entries = settings.hooks[eventName];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries as HookEntry[]) {
      if (!entry.hooks || !Array.isArray(entry.hooks)) continue;
      for (const hook of entry.hooks) {
        if (typeof hook.command !== 'string' || !hook.command.includes('shieldcortex')) continue;
        if (typeof hook.timeout === 'number' && hook.timeout < expectedTimeout) {
          const previous = hook.timeout;
          hook.timeout = expectedTimeout;
          updated++;
          console.log(`  ↑ Hook: ${eventName} (timeout ${previous}s → ${expectedTimeout}s)`);
        }
      }
    }
  }
  return updated;
}

export function setupHooks(options?: { stopHook?: boolean; sessionEnd?: boolean }): void {
  const settings = readSettings();
  if (!settings.hooks) {
    settings.hooks = {};
  }

  // First: migrate any stale npx commands to direct binary
  const migrated = migrateNpxHooks(settings);

  // Second: reconcile timeouts on existing shieldcortex entries so doctor's
  // "re-run install to restore canonical timeouts" suggestion actually works.
  const timeoutsUpdated = reconcileHookTimeouts(settings);

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
      console.log(`  + Hook: SessionEnd (opt-in — flipping autoMemory.enableSessionEnd=true)`);
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
      console.log(`  + Hook: Stop (opt-in — flipping autoMemory.enableStop=true)`);
    } else {
      console.log(`  = Hook: Stop (already configured)`);
    }
  }

  const changed = added + migrated + timeoutsUpdated;
  if (changed > 0) {
    writeSettings(settings);
    const parts = [`${added} added`, `${migrated} migrated`];
    if (timeoutsUpdated > 0) parts.push(`${timeoutsUpdated} timeout${timeoutsUpdated === 1 ? '' : 's'} updated`);
    console.log(`Hooks: ${parts.join(', ')} in ~/.claude/settings.json`);
  } else {
    console.log('Hooks: all hooks already configured in ~/.claude/settings.json');
  }

  // Single source of truth: the install flag IS the runtime gate. Wiring the
  // hook in settings.json without flipping autoMemory.enable* was the
  // silent-amnesia failure mode in #41 — passing --with-stop-hook wrote the
  // hook but the runtime gate (default false) made it bail on every fire.
  // Always sync gate to install flag — including the false case, so removing
  // a hook by re-running install without the flag also disables the gate.
  if (options?.stopHook !== undefined || options?.sessionEnd !== undefined) {
    const updates: { enableStop?: boolean; enableSessionEnd?: boolean } = {};
    if (options.stopHook !== undefined) updates.enableStop = options.stopHook;
    if (options.sessionEnd !== undefined) updates.enableSessionEnd = options.sessionEnd;
    try {
      setAutoMemoryEnableConfig(updates);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`Hooks: could not update autoMemory enable config — ${msg}`);
    }
  }
}
