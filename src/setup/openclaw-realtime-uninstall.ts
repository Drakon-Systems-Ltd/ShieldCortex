/**
 * Managed-npm realtime plugin uninstall (#1115).
 *
 * One spawn primitive, two callers. Repair uses only the spawn (same argv,
 * same child env, same binary resolver). It must not share this function's
 * postcondition: repair uninstalls and then reinstalls, and it treats CLI
 * exit 0 as "continue", not as "the selected copy is gone". Applying that
 * postcondition there would abort a repair whose selected copy is supposed
 * to remain until the reinstall. The honesty check — do not report success,
 * and do not strip config, while a selected or indexed copy remains — lives
 * here, on plain uninstall.
 *
 * This file does not delete ~/.openclaw/npm/projects, installs.json, or the
 * SQLite install index. A leftover project directory is printed and left.
 */

import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';
import { withOwnConfigWrite } from '../audit/agent-config-watch-own-write.js';
import {
  identifyPluginDir,
  readLinkedRealtimeInstall,
  readSelectedRealtimeInstall,
} from '../integrations/openclaw-realtime-install.js';
import {
  readPluginInstallIndexState,
  type PluginIndexRow,
} from '../integrations/openclaw-plugin-index.js';
import type { LockResult } from './host-swap.js';
import { openClawEffectiveHome } from './openclaw-effective-home.js';

export const REALTIME_PLUGIN_ID = 'shieldcortex-realtime';

/** The only argv for `openclaw plugins uninstall`. Do not invent a --yes. */
export const PLUGINS_UNINSTALL_ARGV = ['plugins', 'uninstall', REALTIME_PLUGIN_ID] as const;

export const PLUGINS_UNINSTALL_TIMEOUT_MS = 60_000;
export const PLUGINS_UNINSTALL_STDIN = 'y\n';

export type RealtimeUninstallStatus = 'absent' | 'removed' | 'refused' | 'failed' | 'unverified';

export interface RealtimeUninstallResult {
  status: RealtimeUninstallStatus;
  detail: string;
  /** Unreferenced project dirs still on disk. Not a failure, and not deleted. */
  leftovers?: string[];
}

export interface PluginsUninstallChild {
  status: number | null;
  signal?: NodeJS.Signals | null;
  stdout?: string | Buffer | null;
  stderr?: string | Buffer | null;
  error?: NodeJS.ErrnoException | null;
}

export type PluginsUninstallSpawn = (
  command: string,
  args: readonly string[],
  options: {
    encoding: 'utf-8';
    env: NodeJS.ProcessEnv;
    input: string;
    timeout: number;
    shell: false;
  },
) => PluginsUninstallChild;

export interface RealtimeUninstallDeps {
  home: string;
  spawn: PluginsUninstallSpawn;
  resolveBinary: (home: string) => string | null;
  childEnv: (home: string) => NodeJS.ProcessEnv;
  acquireLock: (root: string) => LockResult;
}

export function spawnOpenClawPluginsUninstall(
  bin: string,
  env: NodeJS.ProcessEnv,
  spawn: typeof spawnSync = spawnSync,
): PluginsUninstallChild {
  return spawn(bin, [...PLUGINS_UNINSTALL_ARGV], {
    encoding: 'utf-8',
    env,
    input: PLUGINS_UNINSTALL_STDIN,
    timeout: PLUGINS_UNINSTALL_TIMEOUT_MS,
    shell: false,
  });
}

function text(value: string | Buffer | null | undefined): string {
  if (typeof value === 'string') return value.trim();
  if (value) return value.toString('utf-8').trim();
  return '';
}

function childFailureDetail(result: PluginsUninstallChild): string {
  const timedOut = result.error?.code === 'ETIMEDOUT';
  const how = timedOut
    ? 'timed out'
    : result.error
      ? result.error.message
      : result.signal
        ? `killed by ${result.signal}`
        : `exited ${result.status}`;
  const extra = [text(result.stderr), text(result.stdout)].filter(Boolean).join('\n').slice(0, 500);
  // The child may have deleted files or records before a nonzero exit, signal,
  // or timeout. This process did not continue, and it did not strip config.
  return `openclaw plugins uninstall ${REALTIME_PLUGIN_ID} ${how}${extra ? `: ${extra}` : ''}. ShieldCortex did not delete anything further and did not strip config; the child may already have changed files.`;
}

function childFailed(result: PluginsUninstallChild): boolean {
  return Boolean(result.error) || Boolean(result.signal) || result.status !== 0;
}

/**
 * Direct children of npm/projects whose package copy identifies as ours.
 * Symlinks are not followed. A name that merely contains the plugin id is
 * not enough — identity is package.json name or openclaw.plugin.json id.
 */
export function listManagedRealtimeProjectCopies(home: string): string[] {
  const projects = path.join(home, '.openclaw', 'npm', 'projects');
  let st: fs.Stats;
  try {
    st = fs.lstatSync(projects);
  } catch {
    return [];
  }
  if (st.isSymbolicLink() || !st.isDirectory()) return [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(projects, { withFileTypes: true });
  } catch {
    return [];
  }
  const found: string[] = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink() || !entry.isDirectory()) continue;
    const pkgDir = path.join(projects, entry.name, 'node_modules', '@drakon-systems', REALTIME_PLUGIN_ID);
    let pkgStat: fs.Stats;
    try {
      pkgStat = fs.lstatSync(pkgDir);
    } catch {
      continue;
    }
    if (pkgStat.isSymbolicLink() || !pkgStat.isDirectory()) continue;
    const id = identifyPluginDir(pkgDir);
    if (id.state === 'ours') found.push(pkgDir);
  }
  return found;
}

function legacyDir(home: string): string {
  return path.join(home, '.openclaw', 'extensions', REALTIME_PLUGIN_ID);
}

type LegacyInspect =
  | { kind: 'absent' }
  | { kind: 'symlink' }
  | { kind: 'unknown'; why: string }
  | { kind: 'ours' }
  | { kind: 'not-ours' };

function inspectLegacy(home: string): LegacyInspect {
  const dir = legacyDir(home);
  let st: fs.Stats;
  try {
    st = fs.lstatSync(dir);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return { kind: 'absent' };
    return { kind: 'unknown', why: `cannot lstat ${dir}: ${(err as Error).message}` };
  }
  if (st.isSymbolicLink()) return { kind: 'symlink' };
  if (!st.isDirectory()) return { kind: 'not-ours' };
  const id = identifyPluginDir(dir);
  if (id.state === 'ours') return { kind: 'ours' };
  if (id.state === 'unknown') return { kind: 'unknown', why: id.why };
  return { kind: 'not-ours' };
}

function indexNamesPlugin(row: PluginIndexRow): boolean {
  if (row.installRecords && Object.prototype.hasOwnProperty.call(row.installRecords, REALTIME_PLUGIN_ID)) return true;
  return row.plugins?.some((p) => p && p.pluginId === REALTIME_PLUGIN_ID) ?? false;
}

type InstallsRead = 'missing' | 'unreadable' | 'names' | 'no-record';

function readInstallsRecord(home: string): InstallsRead {
  const file = path.join(home, '.openclaw', 'plugins', 'installs.json');
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return 'missing';
    return 'unreadable';
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return 'unreadable';
    const records = (parsed as { installRecords?: unknown }).installRecords;
    if (!records || typeof records !== 'object' || Array.isArray(records)) return 'no-record';
    return Object.prototype.hasOwnProperty.call(records, REALTIME_PLUGIN_ID) ? 'names' : 'no-record';
  } catch {
    return 'unreadable';
  }
}

/**
 * Doctor's resolveUserPath, inlined so uninstall does not import doctor
 * (doctor imports this tree). Relative and ~user are unresolvable — never
 * path.resolve'd against this process's cwd.
 */
function resolveOverridePath(raw: string, home: string): { path: string } | { unresolvable: string } {
  const trimmed = raw.trim();
  if (/^~($|[\\/])/.test(trimmed)) {
    return { path: path.resolve(trimmed.replace(/^~(?=$|[\\/])/, home)) };
  }
  if (trimmed.startsWith('~')) {
    return { unresolvable: 'OpenClaw does not expand ~user paths — they resolve against its process cwd, which this CLI cannot know' };
  }
  if (!path.isAbsolute(trimmed)) {
    return { unresolvable: 'a relative path resolves against the OpenClaw process cwd, which this CLI cannot know' };
  }
  return { path: path.resolve(trimmed) };
}

/**
 * Unsupported targeting is an honest refusal, not a second tree walker.
 * The install-index reader is bound to <home>/.openclaw/state. A child would
 * honour STATE_DIR / CONFIG_PATH / PROFILE from the inherited env, so a
 * different or unresolvable target must not be declared clean from the
 * default tree, and must not be spawned.
 *
 * An explicit OPENCLAW_HOME that openClawEffectiveHome cannot resolve
 * (relative, `~user`) is the same refusal. openClawUserHome ignores that
 * value and falls back to another home; acting there would uninstall the
 * fallback. A supported absolute or `~/` override must be the home we are
 * about to act on, not a different tree.
 */
export function realtimeUninstallTargetingRefusal(home: string): string | null {
  const explicitHome = process.env.OPENCLAW_HOME?.trim();
  if (explicitHome) {
    const effective = openClawEffectiveHome();
    if ('unresolvable' in effective) {
      return `OPENCLAW_HOME="${explicitHome}" is unresolvable: ${effective.unresolvable}. Refusing rather than uninstalling another home. Nothing was changed.`;
    }
    if (path.resolve(effective.home) !== path.resolve(home)) {
      return `OPENCLAW_HOME resolves to ${effective.home}, not ${path.resolve(home)}. Refusing rather than acting on another home. Nothing was changed.`;
    }
  }
  const statePrimary = process.env.OPENCLAW_STATE_DIR?.trim();
  const stateOverride = statePrimary || process.env.CLAWDBOT_STATE_DIR?.trim();
  if (stateOverride) {
    const name = statePrimary ? 'OPENCLAW_STATE_DIR' : 'CLAWDBOT_STATE_DIR';
    const resolved = resolveOverridePath(stateOverride, home);
    if ('unresolvable' in resolved) {
      return `${name}="${stateOverride}" is unresolvable: ${resolved.unresolvable}. Nothing was changed.`;
    }
    const expected = path.resolve(home, '.openclaw');
    if (resolved.path !== expected) {
      return `${name} resolves to ${resolved.path}, not ${expected}. Refusing: uninstall cannot verify that tree, and will not declare ${expected} clean. Nothing was changed.`;
    }
  }
  const cfgPrimary = process.env.OPENCLAW_CONFIG_PATH?.trim();
  const cfgOverride = cfgPrimary || process.env.CLAWDBOT_CONFIG_PATH?.trim();
  if (cfgOverride) {
    const name = cfgPrimary ? 'OPENCLAW_CONFIG_PATH' : 'CLAWDBOT_CONFIG_PATH';
    const resolved = resolveOverridePath(cfgOverride, home);
    if ('unresolvable' in resolved) {
      return `${name}="${cfgOverride}" is unresolvable: ${resolved.unresolvable}. Nothing was changed.`;
    }
    const expected = path.resolve(home, '.openclaw', 'openclaw.json');
    if (resolved.path !== expected) {
      return `${name} resolves to ${resolved.path}, not ${expected}. Refusing rather than verifying a different config. Nothing was changed.`;
    }
  }
  const profile = process.env.OPENCLAW_PROFILE?.trim();
  if (profile && profile.toLowerCase() !== 'default') {
    return `OPENCLAW_PROFILE="${profile}" is set. Uninstall does not know which tree that profile selects, so it will not guess. Nothing was changed.`;
  }
  return null;
}

function isLegacySelected(home: string, dir: string): boolean {
  return path.resolve(dir) === path.resolve(legacyDir(home));
}

function configNeedsCleanup(config: Record<string, unknown>): boolean {
  const plugins = config.plugins as { allow?: unknown; entries?: unknown; installs?: unknown } | undefined;
  if (plugins && typeof plugins === 'object') {
    if (Array.isArray(plugins.allow) && plugins.allow.some((e) => typeof e === 'string' && e.includes(REALTIME_PLUGIN_ID))) return true;
    if (plugins.entries && typeof plugins.entries === 'object' && REALTIME_PLUGIN_ID in (plugins.entries as object)) return true;
    if (plugins.installs && typeof plugins.installs === 'object' && REALTIME_PLUGIN_ID in (plugins.installs as object)) return true;
  }
  const hooks = config.hooks as { internal?: { installs?: unknown } } | undefined;
  const hookInstalls = hooks?.internal?.installs;
  return Boolean(hookInstalls && typeof hookInstalls === 'object' && REALTIME_PLUGIN_ID in (hookInstalls as object));
}

/**
 * Strict JSON only, and only keys OpenClaw's CLI is already known to leave
 * (plugins.allow / entries / installs in openclaw.json, and the hook-pack pin
 * repair clears itself). Does not author plugins.installs, and does not
 * write installs.json or the SQLite index.
 */
function stripVerifiedConfig(home: string): { ok: true } | { ok: false; detail: string } {
  const configPath = path.join(home, '.openclaw', 'openclaw.json');
  let raw: string;
  try {
    raw = fs.readFileSync(configPath, 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return { ok: true };
    return { ok: false, detail: `cannot read ${configPath}: ${(err as Error).message}. Not rewritten.` };
  }
  let config: Record<string, unknown>;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, detail: `${configPath} is not strict JSON. Not rewritten.` };
    }
    config = parsed as Record<string, unknown>;
  } catch {
    return { ok: false, detail: `${configPath} is not strict JSON. Not rewritten.` };
  }
  if (!configNeedsCleanup(config)) return { ok: true };
  const plugins = config.plugins as {
    allow?: unknown;
    entries?: Record<string, unknown>;
    installs?: Record<string, unknown>;
  } | undefined;
  if (plugins && typeof plugins === 'object') {
    if (Array.isArray(plugins.allow)) {
      plugins.allow = plugins.allow.filter((entry) => typeof entry !== 'string' || !entry.includes(REALTIME_PLUGIN_ID));
    }
    if (plugins.entries && REALTIME_PLUGIN_ID in plugins.entries) delete plugins.entries[REALTIME_PLUGIN_ID];
    if (plugins.installs && REALTIME_PLUGIN_ID in plugins.installs) delete plugins.installs[REALTIME_PLUGIN_ID];
  }
  const hooks = config.hooks as { internal?: { installs?: Record<string, unknown> } } | undefined;
  if (hooks?.internal?.installs && REALTIME_PLUGIN_ID in hooks.internal.installs) {
    delete hooks.internal.installs[REALTIME_PLUGIN_ID];
  }
  try {
    const out = JSON.stringify(config, null, 2) + '\n';
    withOwnConfigWrite(configPath, () => {
      fs.writeFileSync(configPath, out, 'utf-8');
      return out;
    });
  } catch (err) {
    return { ok: false, detail: `could not update ${configPath}: ${(err as Error).message}. Not reported as removed.` };
  }
  return { ok: true };
}

/**
 * installs.json presence is what sent a pathless record down the CLI path.
 * The selected-copy reader skips a record with no installPath, so a re-read
 * of that reader is not a re-read of the registration. A retained or
 * unreadable key is not absence. This does not edit the file.
 */
function retainedRegistration(home: string): RealtimeUninstallResult | null {
  const installs = readInstallsRecord(home);
  if (installs === 'unreadable') {
    return {
      status: 'unverified',
      detail: `${path.join(home, '.openclaw', 'plugins', 'installs.json')} could not be read after uninstall. Unknown is not absent. Config was not stripped.`,
    };
  }
  if (installs === 'names') {
    return {
      status: 'failed',
      detail: `OpenClaw's installs.json still names ${REALTIME_PLUGIN_ID}. The install record is still there. Config was not stripped.`,
    };
  }
  return null;
}

/**
 * openclaw.json plugins.installs[id] that names the legacy extensions dir
 * (no installPath means that dir), and nothing else is registered. That
 * record is config this process strips after it removes the directory it
 * just identified. It is not an installs.json or SQLite registration, and
 * it is not a path/link. A record that names any other path is not owned.
 */
function legacyConfigRecordIsOwned(home: string): boolean {
  const installs = readInstallsRecord(home);
  if (installs !== 'missing' && installs !== 'no-record') return false;
  const index = readPluginInstallIndexState(home);
  if (index.state === 'unreadable') return false;
  if (index.state === 'ok' && indexNamesPlugin(index.row)) return false;
  const configPath = path.join(home, '.openclaw', 'openclaw.json');
  let raw: string;
  try {
    raw = fs.readFileSync(configPath, 'utf-8');
  } catch {
    return false;
  }
  let config: unknown;
  try {
    config = JSON.parse(raw) as unknown;
  } catch {
    return false;
  }
  if (!config || typeof config !== 'object' || Array.isArray(config)) return false;
  const plugins = (config as { plugins?: unknown }).plugins;
  if (!plugins || typeof plugins !== 'object' || Array.isArray(plugins)) return false;
  const records = (plugins as { installs?: unknown }).installs;
  if (!records || typeof records !== 'object' || Array.isArray(records)) return false;
  if (!Object.prototype.hasOwnProperty.call(records, REALTIME_PLUGIN_ID)) return false;
  const rec = (records as Record<string, unknown>)[REALTIME_PLUGIN_ID];
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) return false;
  const r = rec as { source?: unknown; installPath?: unknown };
  if (r.source === 'path') return false;
  const named = typeof r.installPath === 'string' && r.installPath ? r.installPath : null;
  if (!named) return true;
  const openclawDir = path.join(home, '.openclaw');
  const expanded = named === '~' ? home : named.startsWith('~/') ? path.join(home, named.slice(2)) : named;
  return path.resolve(openclawDir, expanded) === path.resolve(legacyDir(home));
}

function verifiedGone(home: string, opts?: { ownedLegacyConfig?: boolean }): RealtimeUninstallResult | null {
  const index = readPluginInstallIndexState(home);
  if (index.state === 'unreadable') {
    return { status: 'unverified', detail: `OpenClaw's plugin install index could not be read after uninstall (${index.why}). Not reported as removed.` };
  }
  if (index.state === 'ok' && indexNamesPlugin(index.row)) {
    return { status: 'failed', detail: `OpenClaw's install index still names ${REALTIME_PLUGIN_ID}. Config was not stripped.` };
  }
  const retained = retainedRegistration(home);
  if (retained) return retained;
  const selected = readSelectedRealtimeInstall(home);
  if (selected.state === 'unknown') {
    return { status: 'unverified', detail: `${selected.why} Not reported as removed.` };
  }
  if (selected.state === 'selected') {
    return { status: 'failed', detail: `OpenClaw still has a loadable copy at ${selected.dir}. Config was not stripped.` };
  }
  // Deleting the legacy dir makes the openclaw.json record that named it
  // look dangling. That record is the config strip below, not a managed
  // registration that outlived the child. Any other dangling record still fails.
  if (selected.dangling && !(opts?.ownedLegacyConfig && legacyConfigRecordIsOwned(home))) {
    return { status: 'failed', detail: `${selected.dangling}. The record is still there. Config was not stripped.` };
  }
  const legacy = inspectLegacy(home);
  if (legacy.kind === 'symlink') {
    return { status: 'refused', detail: `${legacyDir(home)} is a symlink. Refusing to follow it. Nothing further was changed.` };
  }
  if (legacy.kind === 'unknown') {
    return { status: 'unverified', detail: `${legacy.why} Not reported as removed.` };
  }
  if (legacy.kind === 'ours') {
    return { status: 'failed', detail: `the extensions copy at ${legacyDir(home)} is still present. Config was not stripped.` };
  }
  return null;
}

function finishRemoved(home: string, detail: string, opts?: { ownedLegacyConfig?: boolean }): RealtimeUninstallResult {
  const still = verifiedGone(home, opts);
  if (still) return still;
  const cleaned = stripVerifiedConfig(home);
  if (!cleaned.ok) return { status: 'failed', detail: cleaned.detail };
  if (opts?.ownedLegacyConfig) {
    const after = verifiedGone(home);
    if (after) return after;
  }
  const leftovers = listManagedRealtimeProjectCopies(home);
  const leftoverNote = leftovers.length
    ? ` Left in place (not an install, not removed): ${leftovers.join(', ')}.`
    : '';
  return { status: 'removed', detail: `${detail}${leftoverNote}`, ...(leftovers.length ? { leftovers } : {}) };
}

function removeLegacyDir(home: string): RealtimeUninstallResult {
  const ownedLegacyConfig = legacyConfigRecordIsOwned(home);
  const dir = legacyDir(home);
  try {
    fs.rmSync(dir, { recursive: true });
  } catch (err) {
    return { status: 'failed', detail: `could not remove ${dir}: ${(err as Error).message}. Config was not stripped.` };
  }
  return finishRemoved(home, `Removed real-time plugin from ${dir}.`, { ownedLegacyConfig });
}

/**
 * Remove the realtime plugin, or say exactly why that did not happen.
 * Reads first. No mkdir of extensions/. No deletion of a managed project.
 */
export function uninstallManagedRealtimePlugin(deps: RealtimeUninstallDeps): RealtimeUninstallResult {
  const { home } = deps;
  if (!path.isAbsolute(home)) {
    return { status: 'refused', detail: `home ${JSON.stringify(home)} is not absolute, so it was not resolved against the process cwd. Nothing was changed.` };
  }

  const targeting = realtimeUninstallTargetingRefusal(home);
  if (targeting) return { status: 'refused', detail: targeting };

  const linked = readLinkedRealtimeInstall(home);
  if (linked.state === 'linked') {
    return { status: 'refused', detail: `refusing to uninstall a linked/path install at ${linked.at}. Nothing was changed.` };
  }
  if (linked.state === 'unknown') {
    return { status: 'refused', detail: `cannot tell whether the plugin is linked (${linked.why}). Nothing was changed.` };
  }

  const index = readPluginInstallIndexState(home);
  if (index.state === 'unreadable') {
    return { status: 'refused', detail: `OpenClaw's plugin install index could not be read (${index.why}). Nothing was changed.` };
  }
  const selected = readSelectedRealtimeInstall(home);
  if (selected.state === 'unknown') {
    return { status: 'refused', detail: `${selected.why} Nothing was changed.` };
  }

  const legacy = inspectLegacy(home);
  if (legacy.kind === 'symlink') {
    return { status: 'refused', detail: `${legacyDir(home)} is a symlink. Refusing to follow it. Nothing was changed.` };
  }
  if (legacy.kind === 'unknown') {
    return { status: 'refused', detail: `${legacy.why} Nothing was changed.` };
  }

  const installs = readInstallsRecord(home);
  if (installs === 'unreadable') {
    return { status: 'refused', detail: `${path.join(home, '.openclaw', 'plugins', 'installs.json')} could not be read. Unknown is not absent. Nothing was changed.` };
  }

  const indexRecord = index.state === 'ok' && indexNamesPlugin(index.row);
  const installsRecord = installs === 'names';
  const selectedLegacy = selected.state === 'selected' && isLegacySelected(home, selected.dir);
  const selectedOther = selected.state === 'selected' && !selectedLegacy;
  const dangling = selected.state === 'none' && Boolean(selected.dangling);
  const legacyOurs = legacy.kind === 'ours';
  const needsCli = indexRecord || installsRecord || selectedOther || dangling;
  const needsLegacyRm = legacyOurs && (selectedLegacy || (!indexRecord && !installsRecord && !selectedOther));

  if (!needsCli && !needsLegacyRm) {
    return { status: 'absent', detail: `${REALTIME_PLUGIN_ID} plugin is not installed.` };
  }

  if (needsCli) {
    const bin = deps.resolveBinary(home);
    if (!bin) {
      return {
        status: 'failed',
        detail: `openclaw binary not found. Run: openclaw plugins uninstall ${REALTIME_PLUGIN_ID} (home: ${home}). Nothing was deleted.`,
      };
    }
    const root = path.join(home, '.openclaw');
    const lock = deps.acquireLock(root);
    if (!('lock' in lock)) {
      return { status: 'failed', detail: `${lock.busy} Nothing was changed.` };
    }
    try {
      let child: PluginsUninstallChild;
      try {
        child = spawnOpenClawPluginsUninstall(bin, deps.childEnv(home), deps.spawn as typeof spawnSync);
      } catch (err) {
        return { status: 'failed', detail: `openclaw plugins uninstall could not be started: ${(err as Error).message}. Nothing was deleted.` };
      }
      if (childFailed(child)) return { status: 'failed', detail: childFailureDetail(child) };
      const indexAfter = readPluginInstallIndexState(home);
      if (indexAfter.state === 'unreadable') {
        return { status: 'unverified', detail: `OpenClaw's plugin install index could not be read after uninstall (${indexAfter.why}). Config was not stripped.` };
      }
      if (indexAfter.state === 'ok' && indexNamesPlugin(indexAfter.row)) {
        return { status: 'failed', detail: `OpenClaw's install index still names ${REALTIME_PLUGIN_ID}. Config was not stripped.` };
      }
      const retained = retainedRegistration(home);
      if (retained) return retained;
      const selectedAfter = readSelectedRealtimeInstall(home);
      if (selectedAfter.state === 'unknown') {
        return { status: 'unverified', detail: `${selectedAfter.why} Config was not stripped.` };
      }
      if (selectedAfter.state === 'none' && selectedAfter.dangling) {
        return { status: 'failed', detail: `${selectedAfter.dangling}. The record is still there. Config was not stripped.` };
      }
      if (selectedAfter.state === 'selected' && !isLegacySelected(home, selectedAfter.dir)) {
        return { status: 'failed', detail: `OpenClaw still has a loadable copy at ${selectedAfter.dir}. Config was not stripped.` };
      }
      const legacyAfter = inspectLegacy(home);
      if (legacyAfter.kind === 'symlink') {
        return { status: 'refused', detail: `${legacyDir(home)} is a symlink. Refusing to follow it. Config was not stripped.` };
      }
      if (legacyAfter.kind === 'unknown') {
        return { status: 'unverified', detail: `${legacyAfter.why} Config was not stripped.` };
      }
      if (legacyAfter.kind === 'ours') return removeLegacyDir(home);
      if (selectedAfter.state === 'selected') {
        return { status: 'failed', detail: `OpenClaw still has a loadable copy at ${selectedAfter.dir}. Config was not stripped.` };
      }
      return finishRemoved(home, `openclaw plugins uninstall ${REALTIME_PLUGIN_ID} finished and the install record is gone.`);
    } finally {
      lock.lock.release();
    }
  }

  const root = path.join(home, '.openclaw');
  const lock = deps.acquireLock(root);
  if (!('lock' in lock)) {
    return { status: 'failed', detail: `${lock.busy} Nothing was changed.` };
  }
  try {
    return removeLegacyDir(home);
  } finally {
    lock.lock.release();
  }
}
