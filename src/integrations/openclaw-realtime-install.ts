import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import semver from 'semver';
import { REALTIME_PLUGIN_PACKAGE } from '../setup/openclaw-plugin-spec.js';
import { indexPathField, readPluginInstallIndexState, type PluginInstallIndexState } from './openclaw-plugin-index.js';
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
  const linked = readLinked(home, options);
  return linked.state === 'linked' ? { state: 'linked', at: linked.at } : linked;
}

/**
 * The linked reader, plus the plugin dir it already identified for a
 * `plugins.load.paths` entry — so the version is read from that same dir
 * rather than from a second, differently normalized look at the path
 * (#1110 round 3). `dir` is absent for a path install record, whose path was
 * not identified here.
 */
function readLinked(
  home: string,
  options: LinkedReadOptions,
): { state: 'linked'; at: string; dir?: string } | { state: 'absent' } | { state: 'unknown'; why: string } {
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
      // OpenClaw trims a load path before resolving it; so does every read here.
      const entry = typeof p === 'string' ? p.trim() : '';
      if (!entry) continue;
      const id = identifyPluginDir(path.resolve(openclawDir, tilde(entry, home)));
      if (id.state === 'ours') return { state: 'linked', at: entry, dir: id.dir };
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
  | {
    state: 'selected';
    dir: string;
    version: string;
    evidence: string;
    /**
     * Where the install record that names this copy says it came from
     * (`npm`, `clawhub`, `path`, …) — absent when no record names it, or the
     * record does not say.
     */
    source?: string;
  }
  /**
   * Nothing to load and nothing to lose. `dangling` says why when a record
   * DOES name a copy, but that copy is not on disk (#1109 round 4).
   */
  | { state: 'none'; dangling?: string }
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
 *    Then openclaw.json's own `plugins.installs` record (OpenClaw <= 2026.4.24,
 *    #1110); two records naming copies at different versions are `unknown`,
 *    and so is a record copy beside a linked `plugins.load.paths` copy at a
 *    different (or unreadable) version — OpenClaw loads the linked one.
 *  - a linked `plugins.load.paths` entry, then the copy in
 *    `~/.openclaw/extensions` (trusted-local, or the npm package's own
 *    `dist/index.js` layout) — the two installs no record names. Both at
 *    different versions is ambiguous: `unknown`.
 *
 * A copy a record names that is NOT ON DISK (the directory is gone, or holds
 * neither package.json nor openclaw.plugin.json — a manual delete, a
 * half-reaped uninstall, a cleaned-out npm project) is not "could not tell"
 * (#1109 round 4): there is nothing there to load or to lose, so the answer
 * is whatever OpenClaw would discover without that record, and `none` (with
 * `dangling` saying which record) when that is nothing. A copy that exists but
 * cannot be read (EACCES, bad JSON, no exact version) is still `unknown`.
 *
 * `none` only when every source was read and none names a copy that exists.
 */
export function readSelectedRealtimeInstall(home: string, options: SelectedReadOptions = {}): SelectedRealtimeInstall {
  const readIndex = options.readIndex ?? readPluginInstallIndexState;
  const index = readIndex(home);
  if (index.state === 'unreadable') {
    return { state: 'unknown', why: `OpenClaw's plugin install index could not be read (${index.why})` };
  }
  // Set when a record names a copy that is not on disk (see the doc above).
  let dangling: string | null = null;
  if (index.state === 'ok') {
    const entry = index.row.plugins?.find((p) => p && p.pluginId === REALTIME_PLUGIN_ID);
    // #260 (Sol finding 1): the roster entry IS the selection evidence. One
    // that names no usable copy (no rootDir, an empty or non-string one) is
    // not "names nothing" — dropping it let a record-less row fall through to
    // `none`, and `none` lets a forced install replace what is there. OpenClaw
    // requires a string rootDir on every entry; the reader enforces the type,
    // and this refuses what is left.
    const roster = indexPathField(entry?.rootDir);
    if (entry && roster.kind !== 'path') {
      return { state: 'unknown', why: `OpenClaw's install index lists the plugin with no usable rootDir${roster.kind === 'unknown' ? ` — its rootDir ${roster.why}` : ''}` };
    }
    // #260 r10 (Sol): the same rule for the record's installPath. An empty or
    // blank one was dropped as "names nothing", which allowed the replacement.
    const record = index.row.installRecords?.[REALTIME_PLUGIN_ID];
    const recordPath = indexPathField(record?.installPath);
    if (recordPath.kind === 'unknown') {
      return { state: 'unknown', why: `OpenClaw's install record's installPath ${recordPath.why}, so which copy it names is unknown` };
    }
    const named = [
      ...(roster.kind === 'path' ? [{ dir: roster.path, evidence: 'install index roster' }] : []),
      ...(recordPath.kind === 'path' ? [{ dir: recordPath.path, evidence: 'install index record' }] : []),
    ];
    if (named.length > 0) {
      const present: Array<{ dir: string; evidence: string; version: string }> = [];
      for (const n of named) {
        const copy = readCopyAt(n.dir);
        if (copy.state === 'unknown') return { state: 'unknown', why: `the copy OpenClaw's ${n.evidence} names: ${copy.why}` };
        if (copy.state === 'ok') present.push({ ...n, version: copy.version });
      }
      if (present.length === 0) {
        dangling = `the copy OpenClaw's ${named.map((n) => n.evidence).join(' and ')} name${named.length === 1 ? 's' : ''} is not on disk (${named[0].dir})`;
      } else {
        const versions = present.map((r) => r.version);
        if (present.length === 2 && !sameDir(present[0].dir, present[1].dir) && versions[0] !== versions[1]) {
          return { state: 'unknown', why: `OpenClaw's install index names two copies (v${versions[0]} loaded, v${versions[1]} recorded)` };
        }
        const recorded = semver.valid(String(record?.resolvedVersion ?? record?.version ?? '')) ?? null;
        if (recorded && recorded !== versions[0]) {
          return { state: 'unknown', why: `OpenClaw's install record says v${recorded}, but the copy it selected is v${versions[0]}` };
        }
        // The record's source describes the selected copy only when the
        // record's own copy is there (same version as the roster's, above).
        const recordPresent = present.some((r) => r.evidence === 'install index record');
        const source = recordPresent && typeof record?.source === 'string' ? record.source : undefined;
        return { state: 'selected', dir: present[0].dir, version: versions[0], evidence: present[0].evidence, ...(source ? { source } : {}) };
      }
    }
  }

  if (index.state === 'absent') {
    const openclawDir = path.join(home, '.openclaw');
    const extDir = path.join(openclawDir, 'extensions', REALTIME_PLUGIN_ID);
    const installs = readJsonObject(path.join(openclawDir, 'plugins', 'installs.json'));
    if (installs.state === 'unreadable') return { state: 'unknown', why: installs.why };
    // #1110: OpenClaw <= 2026.4.24 has no installs.json — its own install
    // record is openclaw.json `plugins.installs`, and the copy is the npm
    // package under the extensions directory (the default when the record
    // carries no path). A path record there is the linked reader's. An
    // unreadable openclaw.json is not decided here: an installs.json record
    // copy is still selected; with no such copy the answer is `unknown`, below.
    const config = readJsonObject(path.join(openclawDir, 'openclaw.json'));
    const records: Array<{ rec: unknown; evidence: string; native?: string }> = [
      { rec: installs.state === 'ok' ? (installs.value.installRecords as Record<string, unknown> | undefined)?.[REALTIME_PLUGIN_ID] : undefined, evidence: 'installs.json' },
      { rec: config.state === 'ok' ? (config.value.plugins as { installs?: Record<string, unknown> } | undefined)?.installs?.[REALTIME_PLUGIN_ID] : undefined, evidence: 'openclaw.json plugins.installs', native: extDir },
    ];
    const present: Array<{ dir: string; version: string; evidence: string; source?: string }> = [];
    for (const { rec, evidence, native } of records) {
      if (!rec || typeof rec !== 'object') continue;
      const r = rec as { installPath?: unknown; source?: unknown; version?: unknown; resolvedVersion?: unknown };
      if (native && r.source === 'path') continue;
      // #260 r10 (Sol): a present installPath that is empty, blank or not a
      // string names no folder anyone can check — unknown, never "no path".
      // (openclaw.json's own record keeps its relative/`~` resolution against
      // OpenClaw's dir, #1110; installs.json's relative one is refused below.)
      const field = indexPathField(r.installPath);
      const resolvable = native && typeof r.installPath === 'string' && r.installPath.trim() !== '';
      if (field.kind === 'unknown' && !resolvable) {
        return { state: 'unknown', why: `the copy ${evidence} names: its installPath ${field.why}` };
      }
      const named = field.kind === 'absent' ? null : (r.installPath as string);
      const p = native ? (named ? path.resolve(openclawDir, tilde(named, home)) : native) : named;
      if (!p) continue;
      const copy = readCopyAt(p);
      if (copy.state === 'unknown') return { state: 'unknown', why: `the copy ${evidence} names: ${copy.why}` };
      if (copy.state === 'absent') {
        dangling ??= `the copy ${evidence} names is not on disk (${p})`;
        continue;
      }
      const recorded = native ? semver.valid(String(r.resolvedVersion ?? r.version ?? '')) : null;
      if (recorded && recorded !== copy.version) {
        return { state: 'unknown', why: `${evidence} says v${recorded}, but the copy it names is v${copy.version}` };
      }
      present.push({ dir: p, version: copy.version, evidence: `${evidence} record`, ...(typeof r.source === 'string' ? { source: r.source } : {}) });
    }
    if (present.length === 2 && !sameDir(present[0].dir, present[1].dir) && present[0].version !== present[1].version) {
      return { state: 'unknown', why: `installs.json and openclaw.json name two copies (v${present[0].version}, v${present[1].version})` };
    }
    if (present.length > 0) {
      // #1110 round 2: OpenClaw ranks a `plugins.load.paths` copy above a
      // record-matched copy, so a record cannot claim the version while a
      // linked copy at another (or an unreadable) version is configured.
      if (config.state === 'ok') {
        const l = readLinkedCopy(home, index);
        if (l.state === 'unknown') return l;
        if (l.state === 'ok' && !sameDir(l.dir, present[0].dir) && l.version !== present[0].version) {
          return { state: 'unknown', why: `a plugins.load.paths copy (v${l.version}, ${l.dir}) and the ${present[0].evidence} copy (v${present[0].version}) disagree` };
        }
      }
      return { state: 'selected', ...present[0] };
    }
  }

  // No record names a copy that exists. What is left is what OpenClaw
  // discovers on its own.
  const found: Array<{ dir: string; version: string; evidence: string }> = [];
  const linked = readLinkedCopy(home, index);
  if (linked.state === 'unknown') return linked;
  if (linked.state === 'ok') found.push({ dir: linked.dir, version: linked.version, evidence: 'plugins.load.paths' });
  let local = resolveLocalExtensionInstall(home);
  if (!local) {
    // #1110: the npm package's own layout — `dist/index.js`, no root index.js
    // — with no record naming it. Identity from its package.json / manifest.
    const ext = path.join(home, '.openclaw', 'extensions', REALTIME_PLUGIN_ID);
    const id = fs.existsSync(path.join(ext, 'dist', 'index.js')) ? identifyPluginDir(ext) : null;
    if (id?.state === 'unknown') return { state: 'unknown', why: `the extension copy: ${id.why}` };
    if (id?.state === 'ours') local = ext;
  }
  if (local && !found.some((f) => sameDir(f.dir, local))) {
    const v = readPluginDirVersion(local);
    if (v.state === 'unknown') return { state: 'unknown', why: `the local copy: ${v.why}` };
    found.push({ dir: local, version: v.version, evidence: 'extensions directory' });
  }
  if (found.length === 0) return dangling ? { state: 'none', dangling } : { state: 'none' };
  if (found.length > 1 && found[0].version !== found[1].version) {
    return { state: 'unknown', why: `two unrecorded copies (v${found[0].version} linked, v${found[1].version} in extensions)` };
  }
  return { state: 'selected', ...found[0] };
}

/** The linked copy (a `plugins.load.paths` entry or a path record) and its version. */
function readLinkedCopy(
  home: string,
  index: PluginInstallIndexState,
): { state: 'none' } | { state: 'ok'; dir: string; version: string } | { state: 'unknown'; why: string } {
  const linked = readLinked(home, { readIndex: () => index });
  if (linked.state === 'unknown') return { state: 'unknown', why: linked.why };
  if (linked.state !== 'linked') return { state: 'none' };
  // #1110 round 3: a load path's dir is the one the linked reader identified
  // (no second look at the path). A path record's path is identified here; an
  // identity that cannot be read is unknown, never absence.
  let dir = linked.dir;
  if (dir === undefined) {
    const id = identifyPluginDir(path.resolve(path.join(home, '.openclaw'), tilde(linked.at, home)));
    if (id.state === 'unknown') return { state: 'unknown', why: `the linked copy at ${linked.at}: ${id.why}` };
    if (id.state !== 'ours') return { state: 'none' };
    dir = id.dir;
  }
  const v = readPluginDirVersion(dir);
  if (v.state === 'unknown') return { state: 'unknown', why: `the linked copy: ${v.why}` };
  return { state: 'ok', dir, version: v.version };
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
  if (s.state === 'selected') {
    // #1109 round 4 (npm provenance): OpenClaw <= 2026.4.25 resolves the bare
    // compatibility retry's plain package name on ClawHub FIRST
    // (plugins-install-command.ts → buildPreferredClawHubSpec) and records
    // where the copy came from. An equal version is not npm provenance: a copy
    // whose install record names any source but npm (or a local path — a
    // linked development install) is not the pinned npm build, never success.
    if (s.source !== undefined && !PINNED_BUILD_SOURCES.has(s.source)) {
      return { version: null, reason: `the copy OpenClaw selected (v${s.version}) was installed from ${s.source}, not npm` };
    }
    return { version: s.version };
  }
  if (s.state === 'none') return { version: null, reason: s.dangling ?? 'no install record names the copy OpenClaw loads' };
  return { version: null, reason: `could not tell which copy OpenClaw selected — ${s.why}` };
}

/** Install-record sources a post-install check may accept (see above). */
const PINNED_BUILD_SOURCES: ReadonlySet<string> = new Set(['npm', 'path']);


// ── 3. Everything a forced replacement must know (#1109 round 3) ────────────

type CopyRead =
  | { state: 'absent' }
  | { dir: string; state: 'ok'; version: string }
  | { dir: string; state: 'unknown'; why: string };

/**
 * The version of the copy at `dir` — one a record names, or one the caller is
 * about to DELETE. Nothing there — or a directory with neither package.json
 * nor openclaw.plugin.json (an interrupted copy, a half-reaped uninstall) — is
 * `absent`: there is no build to load or to lose. A file that exists but
 * cannot be read, or carries no exact version, is `unknown`.
 */
function readCopyAt(dir: string): CopyRead {
  // #260 r9 (Sol): a relative path names a folder against OpenClaw's own
  // working directory, not this process's. Stat'ing it here measured some
  // other folder, and "not there" let a forced install replace a copy no one
  // checked. Not checked is not absent.
  if (!path.isAbsolute(dir)) {
    return { dir, state: 'unknown', why: `${dir} is not an absolute path, so which folder it names is not known here` };
  }
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
    const c = readCopyAt(dir);
    if (c.state !== 'absent') deleting.push(c);
  }
  return {
    selected: readSelectedRealtimeInstall(home, opts),
    linked: readLinkedRealtimeInstall(home, opts),
    deleting,
  };
}

/**
 * #260 r11 (Sol): the managed npm project folder that physically holds the
 * copy a replacement preflight verified — the real path of the
 * `~/.openclaw/npm/projects/<dir>` the selected copy's real location sits in.
 * Null when the preflight verified no specific copy, or that copy is in no
 * managed project, or a real path cannot be read. A write whose target comes
 * from the disk resolver (`resolveRealtimeProjectDir`) goes to this folder or
 * does not happen: the resolver can choose a different copy than OpenClaw did.
 */
export function verifiedRealtimeProjectDir(
  home: string,
  evidence: { selected: SelectedRealtimeInstall },
): string | null {
  if (evidence.selected.state !== 'selected') return null;
  try {
    const projects = fs.realpathSync(path.join(home, '.openclaw', 'npm', 'projects'));
    const rel = path.relative(projects, fs.realpathSync(evidence.selected.dir));
    if (!rel || rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) return null;
    return path.join(projects, rel.split(path.sep)[0]);
  } catch {
    return null;
  }
}

/** Where a managed-pin repair may write, or why it may not. */
export type ManagedManifestTarget =
  | { ok: true; projectDir: string; manifestPath: string }
  | { ok: false; why: 'folders-disagree' | 'manifest-not-plain-file' };

/**
 * #260 r12 (Sol): the one target check for a managed-pin repair, shared by the
 * repair and by doctor's advice for it. The folder must be the one the
 * preflight verified ({@link verifiedRealtimeProjectDir}) — and so must the
 * FILE: its package.json must be a regular file, not a link, whose real path
 * is that folder's own package.json. A link into a different project passed
 * the folder check and was then written through. Any doubt refuses.
 */
export function managedManifestTarget(
  home: string,
  evidence: { selected: SelectedRealtimeInstall },
  projectDir: string | null,
): ManagedManifestTarget {
  const verified = verifiedRealtimeProjectDir(home, evidence);
  if (!verified || !projectDir) return { ok: false, why: 'folders-disagree' };
  try {
    if (fs.realpathSync(projectDir) !== verified) return { ok: false, why: 'folders-disagree' };
  } catch {
    return { ok: false, why: 'folders-disagree' };
  }
  const manifestPath = path.join(verified, 'package.json');
  try {
    const named = path.join(projectDir, 'package.json');
    const st = fs.lstatSync(named);
    if (st.isSymbolicLink() || !st.isFile() || fs.realpathSync(named) !== manifestPath) {
      return { ok: false, why: 'manifest-not-plain-file' };
    }
  } catch {
    return { ok: false, why: 'manifest-not-plain-file' };
  }
  return { ok: true, projectDir: verified, manifestPath };
}

/**
 * Re-check, right before a write, that a target {@link managedManifestTarget}
 * approved still holds: the folder's real path is unchanged and its
 * package.json is still a regular file, not a link. False on any doubt.
 */
export function managedManifestTargetStillHolds(target: { projectDir: string; manifestPath: string }): boolean {
  try {
    if (fs.realpathSync(target.projectDir) !== target.projectDir) return false;
    const st = fs.lstatSync(target.manifestPath);
    return !st.isSymbolicLink() && st.isFile();
  } catch {
    return false;
  }
}

/** A manifest read bound to the file it came from (see {@link readBoundManifest}). */
export interface BoundManifestRead {
  text: string;
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
  sha256: string;
  /** The file's owner and mode bits, for a replacement that keeps them (r15). */
  uid: number;
  gid: number;
  mode: number;
}

/**
 * #260 r13 (Sol): read `file` through ONE descriptor opened without following
 * a link (`O_NOFOLLOW`; where the platform has none, an lstat gate first),
 * and record that descriptor's identity — dev, inode, size, mtime — and a
 * sha256 of exactly the bytes read. Callers parse from `text`, so what they
 * write back derives from the file {@link boundManifestUnchanged} re-checks.
 * Throws on a link, a non-regular file, or any read error.
 */
export function readBoundManifest(file: string): BoundManifestRead {
  const noFollow = fs.constants.O_NOFOLLOW;
  if (typeof noFollow !== 'number') {
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile()) throw new Error('package.json is not a plain file');
  }
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (typeof noFollow === 'number' ? noFollow : 0));
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new Error('package.json is not a plain file');
    const bytes = fs.readFileSync(fd);
    return {
      text: bytes.toString('utf-8'),
      dev: st.dev,
      ino: st.ino,
      size: st.size,
      mtimeMs: st.mtimeMs,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      uid: st.uid,
      gid: st.gid,
      mode: st.mode,
    };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Re-check, right before a write, that `file` is still the file `read` came
 * from with the same bytes: its entry is not a link, has the same dev, inode,
 * size and mtime, and a fresh bound read has the same identity and sha256. A
 * different regular file (new inode) or the same inode rewritten fails it.
 * False on any doubt.
 */
export function boundManifestUnchanged(file: string, read: BoundManifestRead): boolean {
  try {
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile()) return false;
    if (st.dev !== read.dev || st.ino !== read.ino || st.size !== read.size || st.mtimeMs !== read.mtimeMs) return false;
    const again = readBoundManifest(file);
    return again.dev === read.dev && again.ino === read.ino && again.sha256 === read.sha256;
  } catch {
    return false;
  }
}
