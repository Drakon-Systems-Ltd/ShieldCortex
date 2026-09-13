/**
 * Best-effort sync of signed Action Guard core switches onto the OpenClaw
 * plugin entry (`plugins.entries.shieldcortex-realtime.config.actionGuard`).
 *
 * Signed `~/.shieldcortex/config.json` is the source of truth. The running
 * interceptor reads the plugin entry. Jarvis 5.0.3 proved the two can lie:
 * signed Enforce, plugin `enforce: false`, live Guard off. This writer updates
 * only `enabled` / `enforce` on an EXISTING object-valued plugin entry.
 *
 * Fail closed: missing/malformed/unreadable config does not invent an entry,
 * does not grant conversation access, does not flip `entries.*.enabled`,
 * does not restart the gateway.
 */
import { existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';

import { openClawConfigPath } from './openclaw.js';

const PLUGIN_ID = 'shieldcortex-realtime';

export type OpenClawPluginGuardSyncSkip =
  | 'noop'
  | 'missing-config'
  | 'no-entry'
  | 'malformed'
  | 'unreadable'
  | 'unwritable';

export type OpenClawPluginGuardSync =
  | { status: 'applied'; path: string }
  | { status: 'skipped'; reason: OpenClawPluginGuardSyncSkip };

export function syncOpenClawPluginActionGuard(updates: {
  enabled?: boolean;
  enforce?: boolean;
}): OpenClawPluginGuardSync {
  if (updates.enabled === undefined && updates.enforce === undefined) {
    return { status: 'skipped', reason: 'noop' };
  }

  let configPath: string;
  try {
    configPath = openClawConfigPath();
  } catch {
    return { status: 'skipped', reason: 'unreadable' };
  }

  if (!existsSync(configPath)) {
    return { status: 'skipped', reason: 'missing-config' };
  }

  let raw: string;
  try {
    raw = readFileSync(configPath, 'utf8');
  } catch {
    return { status: 'skipped', reason: 'unreadable' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { status: 'skipped', reason: 'malformed' };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { status: 'skipped', reason: 'malformed' };
  }

  const root = parsed as Record<string, unknown>;
  const plugins = root.plugins;
  if (!plugins || typeof plugins !== 'object' || Array.isArray(plugins)) {
    return { status: 'skipped', reason: 'no-entry' };
  }
  const entries = (plugins as Record<string, unknown>).entries;
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) {
    return { status: 'skipped', reason: 'no-entry' };
  }
  const entry = (entries as Record<string, unknown>)[PLUGIN_ID];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return { status: 'skipped', reason: 'no-entry' };
  }

  const entryObj = { ...(entry as Record<string, unknown>) };
  const existingConfig =
    entryObj.config && typeof entryObj.config === 'object' && !Array.isArray(entryObj.config)
      ? { ...(entryObj.config as Record<string, unknown>) }
      : {};
  const existingGuard =
    existingConfig.actionGuard && typeof existingConfig.actionGuard === 'object' && !Array.isArray(existingConfig.actionGuard)
      ? { ...(existingConfig.actionGuard as Record<string, unknown>) }
      : {};

  if (updates.enabled !== undefined) existingGuard.enabled = updates.enabled;
  if (updates.enforce !== undefined) existingGuard.enforce = updates.enforce;
  existingConfig.actionGuard = existingGuard;
  entryObj.config = existingConfig;
  (entries as Record<string, unknown>)[PLUGIN_ID] = entryObj;

  const tmp = `${configPath}.${process.pid}.tmp`;
  try {
    writeFileSync(tmp, `${JSON.stringify(root, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    renameSync(tmp, configPath);
  } catch {
    try { unlinkSync(tmp); } catch { /* leftover tmp is owner-only */ }
    return { status: 'skipped', reason: 'unwritable' };
  }
  return { status: 'applied', path: configPath };
}
