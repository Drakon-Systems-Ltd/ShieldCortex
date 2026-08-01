/**
 * Auto-configure Claude Code hooks in ~/.claude/settings.json.
 */

import path from 'path';
import os from 'os';
import { getAutoMemoryEnableConfig, setAutoMemoryEnableConfig } from '../cloud/config.js';
import { readJsonConfigOrAbort, writeJsonConfigWithBackup } from './json-config.js';
import {
  resolveHookBinary,
  needsAbsolutePathRepair,
  repairHookCommand,
} from './hook-command-resolution.js';

// Resolved per call, not at import: an import-time constant freezes whichever
// home os.homedir() saw when the module FIRST loaded, so any later redirection
// (an os.homedir mock in a cached-module test, a future homedir override)
// silently writes to the wrong settings.json. Call-time resolution keeps the
// target honest no matter when this module was imported.
function settingsPath(): string {
  return path.join(os.homedir(), '.claude', 'settings.json');
}

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
  PreToolUse: {
    // Action guard (P1/WS1 carried over from the OpenClaw plugin): catastrophic
    // ops deny, dangerous ops route through Claude Code's native "ask" dialog.
    // Enforce-by-default — the runtime opt-down lives in ~/.shieldcortex/
    // config.json (`actionGuard.enforce:false` → advisory, `enabled:false` →
    // off) so posture changes never require re-editing settings.json.
    matcher: '*',
    hooks: [{ type: 'command', command: 'shieldcortex hook pre-tool', timeout: 10 }],
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

/**
 * Rewrite every ShieldCortex hook command to an absolute path (#146).
 *
 * Runs on EVERY install and upgrade, not just fresh installs. That is the whole
 * point: fixing the template alone would leave every already-broken box broken
 * forever, and those boxes cannot tell — a bare command that does not resolve
 * fails silently and `doctor` used to report it green.
 *
 * Idempotent and conservative: an already-absolute command is untouched, a
 * command that is not ours is untouched, and if no binary can be located
 * nothing changes at all rather than writing a path that does not exist.
 */
function absolutiseHookCommands(settings: Record<string, any>): number {
  const binary = resolveHookBinary();
  if (!binary) return 0;
  let repaired = 0;
  for (const entries of Object.values(settings.hooks ?? {})) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      for (const hook of entry?.hooks ?? []) {
        const cmd = hook?.command;
        if (typeof cmd === 'string' && needsAbsolutePathRepair(cmd)) {
          hook.command = repairHookCommand(cmd, binary);
          repaired++;
        }
      }
    }
  }
  return repaired;
}

/** A copy of a hook template with its command bound to an absolute path. */
function withAbsoluteCommand(entry: HookEntry, binary: string | null): HookEntry {
  if (!binary) return entry;
  return {
    ...entry,
    hooks: entry.hooks.map(h =>
      typeof h.command === 'string' && needsAbsolutePathRepair(h.command)
        ? { ...h, command: repairHookCommand(h.command, binary) }
        : { ...h },
    ),
  };
}

function hasCortexHook(entries: HookEntry[]): boolean {
  return entries.some((e) =>
    e.hooks?.some((h) => typeof h.command === 'string' && h.command.includes('shieldcortex'))
  );
}

// Reads settings.json. A missing file yields {} (fresh install); a file that
// EXISTS but won't parse THROWS — setupHooks() must surface that and abort
// rather than write a hooks-only file over the user's permissions/env/model
// settings. Mirrors uninstall.ts's "aborting to avoid corruption" discipline.
function readSettings(): Record<string, any> {
  return readJsonConfigOrAbort(settingsPath());
}

// Backs up an existing settings.json before overwriting it.
function writeSettings(settings: Record<string, any>): void {
  writeJsonConfigWithBackup(settingsPath(), settings);
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

export interface HookOptInOptions {
  stopHook?: boolean;
  sessionEnd?: boolean;
}

/**
 * CLI flag → opt-in option mapping. An absent flag MUST map to undefined
 * ("leave as-is"), never false: `process.argv.includes()` returning false for
 * an absent flag is exactly how `setup --with-session-end` used to silently
 * flip enableStop off (and vice versa). Disabling is its own explicit flag.
 */
export function parseHookOptInFlags(argv: string[]): HookOptInOptions {
  const opts: HookOptInOptions = {};
  if (argv.includes('--with-stop-hook')) opts.stopHook = true;
  else if (argv.includes('--without-stop-hook')) opts.stopHook = false;
  if (argv.includes('--with-session-end')) opts.sessionEnd = true;
  else if (argv.includes('--without-session-end')) opts.sessionEnd = false;
  return opts;
}

function removeCortexEntries(entries: HookEntry[]): HookEntry[] {
  return entries.filter(
    (e) => !e.hooks?.some((h) => typeof h.command === 'string' && h.command.includes('shieldcortex'))
  );
}

export function setupHooks(options?: HookOptInOptions): void {
  const settings = readSettings();
  if (!settings.hooks) {
    settings.hooks = {};
  }

  // First: migrate any stale npx commands to direct binary
  const migrated = migrateNpxHooks(settings);

  // Second: reconcile timeouts on existing shieldcortex entries so doctor's
  // "re-run install to restore canonical timeouts" suggestion actually works.
  const timeoutsUpdated = reconcileHookTimeouts(settings);

  // SessionEnd handling:
  //   - sessionEnd === true  → install below (the .mjs gates execution by
  //     config + OpenClaw env so it's safe to wire);
  //   - sessionEnd === false → explicit opt-out (--without-session-end):
  //     remove the wiring; the gate sync below turns the gate off too;
  //   - undefined            → PRESERVE an opted-in hook (runtime gate on).
  //     Residue with the gate off is still cleaned up — that keeps the
  //     OpenClaw-safe default for users who never opted in, without letting
  //     an unrelated run (update.ts calls setupHooks() bare; `setup
  //     --with-stop-hook` passes no sessionEnd) silently drop an opt-in.
  let removed = 0;
  let dropSessionEnd = options?.sessionEnd === false;
  if (options?.sessionEnd === undefined && settings.hooks.SessionEnd) {
    try {
      dropSessionEnd = getAutoMemoryEnableConfig().enableSessionEnd !== true;
    } catch {
      // Unreadable config — don't destroy wiring on a guess.
    }
  }
  if (dropSessionEnd && settings.hooks.SessionEnd && hasCortexHook(settings.hooks.SessionEnd)) {
    settings.hooks.SessionEnd = removeCortexEntries(settings.hooks.SessionEnd);
    if (settings.hooks.SessionEnd.length === 0) delete settings.hooks.SessionEnd;
    removed++;
    console.log('  - Hook: SessionEnd (removed — opt in with `--with-session-end`)');
  }

  // Explicit Stop opt-out (--without-stop-hook) removes the wiring too —
  // gating off while leaving the hook wired is the "wired but runtime gate
  // is off" warn state doctor exists to catch.
  if (options?.stopHook === false && Array.isArray(settings.hooks.Stop) && hasCortexHook(settings.hooks.Stop)) {
    settings.hooks.Stop = removeCortexEntries(settings.hooks.Stop);
    if (settings.hooks.Stop.length === 0) delete settings.hooks.Stop;
    removed++;
    console.log('  - Hook: Stop (removed — opt in with `--with-stop-hook`)');
  }

  let added = 0;

  // Absolute path, resolved now (#146). A bare command name makes enforcement
  // depend on the operator's shell config; three of four fleet boxes could not
  // resolve one from the subprocess a harness spawns hooks in.
  const hookBinary = resolveHookBinary();

  // Repair hooks written by an EARLIER version before doing anything else —
  // upgrade has to fix installs that are already wrong, or they stay wrong.
  const repairedExisting = absolutiseHookCommands(settings);
  if (repairedExisting > 0) {
    console.log(`  ~ Hooks: repaired ${repairedExisting} bare command(s) to an absolute path (#146)`);
  }

  // Install command hooks (PreCompact, SessionStart, UserPromptSubmit)
  for (const [name, entry] of Object.entries(CORTEX_HOOKS)) {
    if (!Array.isArray(settings.hooks[name])) {
      settings.hooks[name] = [];
    }
    if (!hasCortexHook(settings.hooks[name])) {
      settings.hooks[name].push(withAbsoluteCommand(entry, hookBinary));
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
      settings.hooks.SessionEnd.push(withAbsoluteCommand(SESSION_END_HOOK, hookBinary));
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
      settings.hooks.Stop.push(withAbsoluteCommand(STOP_HOOK, hookBinary));
      added++;
      console.log(`  + Hook: Stop (opt-in — flipping autoMemory.enableStop=true)`);
    } else {
      console.log(`  = Hook: Stop (already configured)`);
    }
  }

  // `removed` MUST be in this sum: removing a stale SessionEnd entry mutates
  // `settings` but adds nothing, so omitting it meant a removal-only run (every
  // other hook already configured) computed the removal, printed "removed", then
  // took the else-branch and never wrote the file — the entry stayed wired on
  // disk while setup claimed it was gone.
  const changed = added + removed + migrated + timeoutsUpdated;
  if (changed > 0) {
    writeSettings(settings);
    const parts = [`${added} added`, `${migrated} migrated`];
    if (removed > 0) parts.push(`${removed} removed`);
    if (timeoutsUpdated > 0) parts.push(`${timeoutsUpdated} timeout${timeoutsUpdated === 1 ? '' : 's'} updated`);
    console.log(`Hooks: ${parts.join(', ')} in ~/.claude/settings.json`);
  } else {
    console.log('Hooks: all hooks already configured in ~/.claude/settings.json');
  }

  // Single source of truth: the install flag IS the runtime gate. Wiring the
  // hook in settings.json without flipping autoMemory.enable* was the
  // silent-amnesia failure mode in #41 — passing --with-stop-hook wrote the
  // hook but the runtime gate (default false) made it bail on every fire.
  // Explicit true/false syncs the gate; undefined leaves it alone — callers
  // must never coerce an absent CLI flag to false (use parseHookOptInFlags).
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
