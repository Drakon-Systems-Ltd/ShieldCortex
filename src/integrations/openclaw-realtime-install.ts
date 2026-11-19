import fs from 'fs';
import path from 'path';
import semver from 'semver';
import { REALTIME_PLUGIN_PACKAGE } from '../setup/openclaw-plugin-spec.js';
import { readPluginInstallIndexState, type PluginInstallIndexState } from './openclaw-plugin-index.js';
import { resolveLocalExtensionInstall } from './openclaw-plugin-state.js';

/**
 * Two questions every forced realtime-plugin install has to answer from
 * OpenClaw's own records before and after it runs (#1109 round 2):
 *
 *  1. Is the plugin a LINKED / path install? Then it is someone's checkout, and
 *     a forced install must not replace it. Decided by what is AT each
 *     `plugins.load.paths` entry (its `package.json` name or its
 *     `openclaw.plugin.json` id), and by any install record whose source is a
 *     local path — in openclaw.json, installs.json, or OpenClaw's SQLite
 *     install index. Never by the path string: the repository's own
 *     `plugins/openclaw` directory does not carry the plugin id in its name.
 *  2. Which copy did OpenClaw SELECT, and what version is it? Not the highest
 *     version anywhere on disk: a leftover project directory at the right
 *     version can sit next to the older copy OpenClaw actually loads.
 *
 * Both answers have a third value, "unknown". A file that exists but cannot be
 * read or parsed is not evidence of absence, and unknown never authorises an
 * overwrite or a success.
 */

const REALTIME_PLUGIN_ID = 'shieldcortex-realtime';

// ── Small readers that keep "missing" and "unreadable" apart ────────────────

type JsonRead =
  | { state: 'missing' }
  | { state: 'unreadable'; why: string }
  | { state: 'ok'; value: Record<string, unknown> };

function readJsonObject(file: string): JsonRead {
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return { state: 'missing' };
    return { state: 'unreadable', why: `cannot read ${file}: ${(err as Error).message}` };
  }
  try {
    const v = JSON.parse(raw) as unknown;
    if (v && typeof v === 'object' && !Array.isArray(v)) return { state: 'ok', value: v as Record<string, unknown> };
    return { state: 'unreadable', why: `${file} is not a JSON object` };
  } catch {
    // OpenClaw itself accepts JSON5 in openclaw.json; this reader does not, so
    // such a file is "could not tell", never "says nothing".
    return { state: 'unreadable', why: `${file} is not strict JSON` };
  }
}

function tilde(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return path.join(home, p.slice(2));
  return p;
}

/** Is the directory at `entry` (or the file's directory) the realtime plugin? */
function identifyPluginDir(entry: string): { state: 'ours'; dir: string } | { state: 'not-ours' } | { state: 'unknown'; why: string } {
  let st: fs.Stats;
  try {
    st = fs.statSync(entry);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    // Nothing there: OpenClaw cannot load anything from it either.
    if (code === 'ENOENT' || code === 'ENOTDIR') return { state: 'not-ours' };
    return { state: 'unknown', why: `cannot stat ${entry}: ${(err as Error).message}` };
  }
  const dir = st.isDirectory() ? entry : path.dirname(entry);
  const pkg = readJsonObject(path.join(dir, 'package.json'));
  if (pkg.state === 'ok' && pkg.value.name === REALTIME_PLUGIN_PACKAGE) return { state: 'ours', dir };
  const manifest = readJsonObject(path.join(dir, 'openclaw.plugin.json'));
  if (manifest.state === 'ok' && manifest.value.id === REALTIME_PLUGIN_ID) return { state: 'ours', dir };
  if (pkg.state === 'unreadable') return { state: 'unknown', why: pkg.why };
  if (manifest.state === 'unreadable') return { state: 'unknown', why: manifest.why };
  return { state: 'not-ours' };
}

function pathRecordWhere(rec: unknown): string | null {
  if (!rec || typeof rec !== 'object') return null;
  const r = rec as { source?: unknown; sourcePath?: unknown; installPath?: unknown };
  if (r.source !== 'path') return null;
  return typeof r.sourcePath === 'string' ? r.sourcePath : typeof r.installPath === 'string' ? r.installPath : 'a local path';
}

// ── 1. Linked / path install ────────────────────────────────────────────────

export type LinkedRealtimeInstall =
  | { state: 'linked'; at: string }
  | { state: 'absent' }
  | { state: 'unknown'; why: string };

export interface LinkedReadOptions {
  /** Injectable index read (defaults to OpenClaw's SQLite index under `home`). */
  readIndex?: (home: string) => PluginInstallIndexState;
}

/**
 * Is the realtime plugin a linked/path install, as far as OpenClaw's own files
 * under `home` say? Linked evidence anywhere wins (the caller keeps the
 * install); otherwise any source that could not be read makes the answer
 * `unknown`; only when every source was read and none names a link is it
 * `absent`.
 */
export function readLinkedRealtimeInstall(home: string, options: LinkedReadOptions = {}): LinkedRealtimeInstall {
  const unknowns: string[] = [];
  const openclawDir = path.join(home, '.openclaw');

  const config = readJsonObject(path.join(openclawDir, 'openclaw.json'));
  if (config.state === 'unreadable') unknowns.push(config.why);
  if (config.state === 'ok') {
    const plugins = config.value.plugins as { load?: { paths?: unknown }; installs?: Record<string, unknown> } | undefined;
    const loadPaths = plugins && typeof plugins === 'object' && plugins.load && Array.isArray(plugins.load.paths)
      ? plugins.load.paths as unknown[]
      : [];
    for (const p of loadPaths) {
      if (typeof p !== 'string' || !p.trim()) continue;
      const resolved = path.resolve(openclawDir, tilde(p.trim(), home));
      const id = identifyPluginDir(resolved);
      if (id.state === 'ours') return { state: 'linked', at: p };
      if (id.state === 'unknown') unknowns.push(id.why);
    }
    const legacy = pathRecordWhere(plugins && typeof plugins === 'object' ? plugins.installs?.[REALTIME_PLUGIN_ID] : null);
    if (legacy) return { state: 'linked', at: legacy };
  }

  const installs = readJsonObject(path.join(openclawDir, 'plugins', 'installs.json'));
  if (installs.state === 'unreadable') unknowns.push(installs.why);
  if (installs.state === 'ok') {
    const records = installs.value.installRecords as Record<string, unknown> | undefined;
    const where = pathRecordWhere(records && typeof records === 'object' ? records[REALTIME_PLUGIN_ID] : null);
    if (where) return { state: 'linked', at: where };
  }

  const index = (options.readIndex ?? readPluginInstallIndexState)(home);
  if (index.state === 'unreadable') unknowns.push(`OpenClaw's plugin install index: ${index.why}`);
  if (index.state === 'ok') {
    const where = pathRecordWhere(index.row.installRecords?.[REALTIME_PLUGIN_ID]);
    if (where) return { state: 'linked', at: where };
  }

  return unknowns.length ? { state: 'unknown', why: unknowns[0] } : { state: 'absent' };
}

// ── 2. The copy OpenClaw selected ───────────────────────────────────────────

export type SelectedRealtimeInstall =
  | { state: 'selected'; dir: string; version: string; evidence: string }
  | { state: 'none' }
  | { state: 'unknown'; why: string };

type DirVersion = { state: 'ok'; version: string } | { state: 'unknown'; why: string };

/**
 * The version of the plugin build in `dir`: its package.json (the npm package
 * and a linked checkout carry one), else its openclaw.plugin.json (a
 * trusted-local copy writes a version-less package.json and versions the
 * manifest). Anything that is not an exact version is unknown.
 */
function readPluginDirVersion(dir: string): DirVersion {
  for (const file of ['package.json', 'openclaw.plugin.json']) {
    const r = readJsonObject(path.join(dir, file));
    if (r.state === 'unreadable') return { state: 'unknown', why: r.why };
    if (r.state === 'ok' && typeof r.value.version === 'string') {
      const v = semver.valid(r.value.version.trim());
      if (v) return { state: 'ok', version: v };
      return { state: 'unknown', why: `${path.join(dir, file)} has no exact version (${JSON.stringify(r.value.version)})` };
    }
  }
  return { state: 'unknown', why: `no readable plugin version in ${dir}` };
}

function sameDir(a: string, b: string): boolean {
  const real = (p: string): string => {
    try {
      return fs.realpathSync(p);
    } catch {
      return path.resolve(p);
    }
  };
  return real(a) === real(b);
}

export interface SelectedReadOptions extends LinkedReadOptions {}

/**
 * Which copy of the realtime plugin OpenClaw selected, and its version.
 *
 * Authority, in order:
 *  - OpenClaw's SQLite install index (2026.6.1+): the latest row's roster
 *    entry (`rootDir`) and its install record (`installPath`) — the install
 *    command rewrites both in one row. When both name a copy and the copies'
 *    versions differ, or the record's own version disagrees with the copy it
 *    names, the evidence conflicts and the answer is `unknown`.
 *  - installs.json's record (`installPath`), on hosts with no index.
 *  - a linked `plugins.load.paths` entry, then the trusted-local copy in
 *    `~/.openclaw/extensions` — the two installs no record names. Both at
 *    different versions is ambiguous: `unknown`.
 *
 * `none` only when every source was read and none names a copy.
 */
export function readSelectedRealtimeInstall(home: string, options: SelectedReadOptions = {}): SelectedRealtimeInstall {
  const readIndex = options.readIndex ?? readPluginInstallIndexState;
  const index = readIndex(home);
  if (index.state === 'unreadable') {
    return { state: 'unknown', why: `OpenClaw's plugin install index could not be read (${index.why})` };
  }
  if (index.state === 'ok') {
    const roster = index.row.plugins?.find((p) => p && p.pluginId === REALTIME_PLUGIN_ID)?.rootDir;
    const record = index.row.installRecords?.[REALTIME_PLUGIN_ID];
    const recordPath = record && typeof record.installPath === 'string' ? record.installPath : null;
    const named = [
      ...(typeof roster === 'string' && roster ? [{ dir: roster, evidence: 'install index roster' }] : []),
      ...(recordPath ? [{ dir: recordPath, evidence: 'install index record' }] : []),
    ];
    if (named.length > 0) {
      const read = named.map((n) => ({ ...n, v: readPluginDirVersion(n.dir) }));
      for (const r of read) {
        if (r.v.state === 'unknown') return { state: 'unknown', why: `the copy OpenClaw's ${r.evidence} names: ${r.v.why}` };
      }
      const versions = read.map((r) => (r.v as { version: string }).version);
      if (read.length === 2 && !sameDir(read[0].dir, read[1].dir) && versions[0] !== versions[1]) {
        return { state: 'unknown', why: `OpenClaw's install index names two copies (v${versions[0]} loaded, v${versions[1]} recorded)` };
      }
      const recorded = semver.valid(String(record?.resolvedVersion ?? record?.version ?? '')) ?? null;
      if (recorded && recorded !== versions[0]) {
        return { state: 'unknown', why: `OpenClaw's install record says v${recorded}, but the copy it selected is v${versions[0]}` };
      }
      return { state: 'selected', dir: read[0].dir, version: versions[0], evidence: read[0].evidence };
    }
  }

  if (index.state === 'absent') {
    const installs = readJsonObject(path.join(home, '.openclaw', 'plugins', 'installs.json'));
    if (installs.state === 'unreadable') return { state: 'unknown', why: installs.why };
    if (installs.state === 'ok') {
      const records = installs.value.installRecords as Record<string, { installPath?: unknown }> | undefined;
      const p = records && typeof records === 'object' ? records[REALTIME_PLUGIN_ID]?.installPath : undefined;
      if (typeof p === 'string' && p) {
        const v = readPluginDirVersion(p);
        if (v.state === 'unknown') return { state: 'unknown', why: `the copy installs.json names: ${v.why}` };
        return { state: 'selected', dir: p, version: v.version, evidence: 'installs.json record' };
      }
    }
  }

  // No record names a copy. What is left is what OpenClaw discovers on its own.
  const found: Array<{ dir: string; version: string; evidence: string }> = [];
  const linked = readLinkedRealtimeInstall(home, { readIndex: () => index });
  if (linked.state === 'unknown') return { state: 'unknown', why: linked.why };
  if (linked.state === 'linked') {
    const openclawDir = path.join(home, '.openclaw');
    const id = identifyPluginDir(path.resolve(openclawDir, tilde(linked.at, home)));
    if (id.state === 'ours') {
      const v = readPluginDirVersion(id.dir);
      if (v.state === 'unknown') return { state: 'unknown', why: `the linked copy: ${v.why}` };
      found.push({ dir: id.dir, version: v.version, evidence: 'plugins.load.paths' });
    }
  }
  const local = resolveLocalExtensionInstall(home);
  if (local && !found.some((f) => sameDir(f.dir, local))) {
    const v = readPluginDirVersion(local);
    if (v.state === 'unknown') return { state: 'unknown', why: `the local copy: ${v.why}` };
    found.push({ dir: local, version: v.version, evidence: 'extensions directory' });
  }
  if (found.length === 0) return { state: 'none' };
  if (found.length > 1 && found[0].version !== found[1].version) {
    return { state: 'unknown', why: `two unrecorded copies (v${found[0].version} linked, v${found[1].version} in extensions)` };
  }
  return { state: 'selected', ...found[0] };
}

/**
 * The selected copy's version for a post-install check, or why there is none.
 * `version: null` is never success.
 */
export function readSelectedRealtimePluginVersion(
  home: string,
  options: SelectedReadOptions = {},
): { version: string } | { version: null; reason: string } {
  const s = readSelectedRealtimeInstall(home, options);
  if (s.state === 'selected') return { version: s.version };
  if (s.state === 'none') return { version: null, reason: 'no install record names the copy OpenClaw loads' };
  return { version: null, reason: `could not tell which copy OpenClaw selected — ${s.why}` };
}


// ── 3. Everything a forced replacement must know (#1109 round 3) ────────────

type CopyRead =
  | { state: 'absent' }
  | { dir: string; state: 'ok'; version: string }
  | { dir: string; state: 'unknown'; why: string };

/**
 * The version of a copy the caller is about to DELETE. Nothing there — or a
 * directory with neither package.json nor openclaw.plugin.json (an
 * interrupted copy, a half-reaped uninstall) — is `absent`: there is no build
 * to lose. A file that exists but cannot be read, or carries no exact
 * version, is `unknown`.
 */
function readDoomedCopy(dir: string): CopyRead {
  let st: fs.Stats;
  try {
    st = fs.statSync(dir);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return { state: 'absent' };
    return { dir, state: 'unknown', why: `cannot stat ${dir}: ${(err as Error).message}` };
  }
  if (!st.isDirectory()) return { state: 'absent' };
  const pkg = readJsonObject(path.join(dir, 'package.json'));
  const manifest = readJsonObject(path.join(dir, 'openclaw.plugin.json'));
  if (pkg.state === 'missing' && manifest.state === 'missing') return { state: 'absent' };
  const v = readPluginDirVersion(dir);
  return v.state === 'ok' ? { dir, state: 'ok', version: v.version } : { dir, state: 'unknown', why: v.why };
}

export interface ReplacementEvidenceOptions extends SelectedReadOptions {
  /** Copies the caller will delete before or as part of the install. */
  deleting?: readonly string[];
}

/**
 * What `assessRealtimeReplacement` needs before ANY forced install or
 * deletion: the copy OpenClaw selected (not the highest version on disk — a
 * stale npm project must not hide a newer selected extension or index-only
 * install), whether it is linked, and the version of every copy the caller is
 * about to delete.
 */
export function readRealtimeReplacementEvidence(
  home: string,
  options: ReplacementEvidenceOptions = {},
): {
  selected: SelectedRealtimeInstall;
  linked: LinkedRealtimeInstall;
  deleting: Array<{ dir: string; state: 'ok'; version: string } | { dir: string; state: 'unknown'; why: string }>;
} {
  const readIndex = options.readIndex ?? readPluginInstallIndexState;
  // One index read for both answers, so they describe the same moment.
  const index = readIndex(home);
  const opts = { readIndex: () => index };
  const deleting: Array<{ dir: string; state: 'ok'; version: string } | { dir: string; state: 'unknown'; why: string }> = [];
  for (const dir of options.deleting ?? []) {
    const c = readDoomedCopy(dir);
    if (c.state !== 'absent') deleting.push(c);
  }
  return {
    selected: readSelectedRealtimeInstall(home, opts),
    linked: readLinkedRealtimeInstall(home, opts),
    deleting,
  };
}
