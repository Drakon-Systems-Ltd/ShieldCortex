/**
 * Agent configuration watch (#916).
 *
 * Hashes only the security-relevant keys of the files that decide what an AI
 * agent or editor runs on its own (hooks, mcpServers, env, tasks), keeps a
 * per-entry baseline, and reports a change ShieldCortex did not make. The
 * October 2026 tensorlake compromise persisted by editing agent and editor
 * settings so it re-ran later; this is the tripwire for that class.
 *
 * Rules:
 *  - Values never leave this module: a notification names the file and the
 *    KIND of change plus a sanitised entry name, never a command or a path
 *    inside the entry (it may be the injected payload).
 *  - Fail open: any error becomes one ledger row; the host agent is never
 *    blocked or delayed (the runner is detached and time-budgeted). A file
 *    that cannot be read or parsed is a per-file health error (fixed category,
 *    never contents or raw error text); it keeps its baseline and the other
 *    files are still checked. Nothing is committed after the deadline.
 *  - First run records a baseline silently. A project root seen for the first
 *    time is baselined silently too (a fresh clone is not an attack); a new
 *    watched file in an already-baselined root IS reported.
 *  - ShieldCortex's own writes call `recordOwnConfigWrite` (see
 *    agent-config-watch-own-write.ts) so they never alert.
 */

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parseToml } from './toml-lite.js';

/** Entries of one section: id -> sorted list of entry hashes. */
export type SectionMap = Record<string, string[]>;
/** Snapshot of one file: section name -> entries. Absent file = {}. */
export type FileSnapshot = Record<string, SectionMap>;

export interface AgentConfigWatchState {
  version: 1;
  initialised: boolean;
  roots: string[];
  files: Record<string, FileSnapshot>;
  lastCheckAt?: string;
  /** ISO time an unexpected change was last DETECTED (delivered or not). */
  lastDetectedAt?: string;
  /** ISO time an unexpected change was last reported AND recorded (baseline advanced). */
  lastChangeAt?: string;
  /** Files whose detected change is not yet reported/recorded; retried next run. */
  pendingChanges?: number;
  /** Per-file health error category from the last run (read or parse failure). */
  fileErrors?: Record<string, string>;
}

// ── Watched set (config, not scattered paths) ───────────────────────────────

export type SectionKind = 'hooks' | 'mcpServers' | 'env' | 'tasks' | 'plugins';

export interface WatchedFileSpec {
  id: string;
  scope: 'user' | 'project';
  /** Path relative to the home (user) or the project root (project). */
  relPath: string;
  format: 'json' | 'jsonc' | 'toml';
  /** Dotted key paths to hash; the section kind decides how it is diffed. */
  sections: Array<{ keyPath: string; kind: SectionKind }>;
}

export const WATCHED_FILES: readonly WatchedFileSpec[] = Object.freeze([
  // Claude Code
  ...(['settings.json', 'settings.local.json'] as const).flatMap((f) => ([
    { id: `claude-${f}`, scope: 'user' as const, relPath: path.join('.claude', f), format: 'json' as const, sections: [{ keyPath: 'hooks', kind: 'hooks' as const }, { keyPath: 'env', kind: 'env' as const }, { keyPath: 'mcpServers', kind: 'mcpServers' as const }] },
    { id: `claude-project-${f}`, scope: 'project' as const, relPath: path.join('.claude', f), format: 'json' as const, sections: [{ keyPath: 'hooks', kind: 'hooks' as const }, { keyPath: 'env', kind: 'env' as const }, { keyPath: 'mcpServers', kind: 'mcpServers' as const }] },
  ])),
  { id: 'claude-json', scope: 'user', relPath: '.claude.json', format: 'json', sections: [{ keyPath: 'mcpServers', kind: 'mcpServers' }] },
  { id: 'claude-project-mcp', scope: 'project', relPath: '.mcp.json', format: 'json', sections: [{ keyPath: 'mcpServers', kind: 'mcpServers' }] },
  // OpenClaw
  { id: 'openclaw-config', scope: 'user', relPath: path.join('.openclaw', 'openclaw.json'), format: 'jsonc', sections: [{ keyPath: 'hooks', kind: 'hooks' }, { keyPath: 'mcp.servers', kind: 'mcpServers' }, { keyPath: 'mcpServers', kind: 'mcpServers' }, { keyPath: 'plugins.entries', kind: 'plugins' }] },
  { id: 'openclaw-mcp', scope: 'user', relPath: path.join('.openclaw', 'mcp.json'), format: 'json', sections: [{ keyPath: 'mcpServers', kind: 'mcpServers' }] },
  // Cursor
  { id: 'cursor-mcp', scope: 'user', relPath: path.join('.cursor', 'mcp.json'), format: 'json', sections: [{ keyPath: 'mcpServers', kind: 'mcpServers' }] },
  { id: 'cursor-project-mcp', scope: 'project', relPath: path.join('.cursor', 'mcp.json'), format: 'json', sections: [{ keyPath: 'mcpServers', kind: 'mcpServers' }] },
  // Codex (TOML: only [mcp_servers.*] and [hooks*] tables are read)
  { id: 'codex-config', scope: 'user', relPath: path.join('.codex', 'config.toml'), format: 'toml', sections: [{ keyPath: 'mcp_servers', kind: 'mcpServers' }, { keyPath: 'hooks', kind: 'hooks' }] },
  // Editor tasks
  { id: 'vscode-tasks', scope: 'project', relPath: path.join('.vscode', 'tasks.json'), format: 'jsonc', sections: [{ keyPath: 'tasks', kind: 'tasks' }] },
]);

// ── Parsing ─────────────────────────────────────────────────────────────────

/**
 * Strip // and block comments, then trailing commas, without touching string
 * contents. Both passes track JSON string state, so `"echo ,]"` stays
 * `"echo ,]"`. A comment becomes one space (never glues two tokens together);
 * an unterminated block comment throws so the file is reported as unparseable.
 */
export function stripJsonc(src: string): string {
  let noComments = '';
  let i = 0;
  let inStr = false;
  while (i < src.length) {
    const c = src[i];
    if (inStr) {
      noComments += c;
      if (c === '\\') { noComments += src[i + 1] ?? ''; i += 2; continue; }
      if (c === '"') inStr = false;
      i++;
      continue;
    }
    if (c === '"') { inStr = true; noComments += c; i++; continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < src.length && src[i] !== '\n') i++; noComments += ' '; continue; }
    if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      if (end === -1) throw new SyntaxError('unterminated block comment');
      i = end + 2;
      noComments += ' ';
      continue;
    }
    noComments += c;
    i++;
  }
  // Pass 2: drop a comma only when, outside a string, the next non-space is } or ].
  let out = '';
  inStr = false;
  for (let j = 0; j < noComments.length; j++) {
    const c = noComments[j];
    if (inStr) {
      out += c;
      if (c === '\\') { out += noComments[j + 1] ?? ''; j++; continue; }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === ',') {
      let k = j + 1;
      while (k < noComments.length && /\s/.test(noComments[k])) k++;
      if (noComments[k] === '}' || noComments[k] === ']') continue;
    }
    out += c;
  }
  return out;
}

function sha(s: string): string {
  return crypto.createHash('sha256').update(s).digest('hex').slice(0, 32);
}

/** Canonical JSON: sorted keys, so key order never counts as a change. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

function getPath(obj: unknown, keyPath: string): unknown {
  let cur: unknown = obj;
  for (const k of keyPath.split('.')) {
    if (!cur || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur;
}

/** Entry name for a hooks value that is an array (TOML `[[hooks]]`). */
export const HOOK_ARRAY_ENTRY = 'hooks-array';

function sectionFrom(kind: SectionKind, value: unknown): SectionMap {
  const out: SectionMap = {};
  if (value === undefined || value === null) return out;
  if (kind === 'tasks') {
    const list = Array.isArray(value) ? value : [];
    list.forEach((t, i) => {
      const label = t && typeof t === 'object' && typeof (t as Record<string, unknown>).label === 'string'
        ? String((t as Record<string, unknown>).label) : `task-${i}`;
      (out[label] ??= []).push(sha(canonical(t)));
    });
  } else if (kind === 'hooks') {
    if (Array.isArray(value)) {
      // TOML `[[hooks]]` (an array of tables): one bucket, so an added,
      // removed or edited entry still shows up in the set diff.
      if (value.length) out[HOOK_ARRAY_ENTRY] = value.map((e) => sha(canonical(e)));
    } else if (typeof value === 'object') {
      for (const [event, entries] of Object.entries(value as Record<string, unknown>)) {
        const list = Array.isArray(entries) ? entries : [entries];
        out[event] = list.map((e) => sha(canonical(e))).sort();
      }
    } else {
      out['(value)'] = [sha(canonical(value))];
    }
  } else if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const [name, entry] of Object.entries(value as Record<string, unknown>)) out[name] = [sha(canonical(entry))];
  } else {
    out['(value)'] = [sha(canonical(value))];
  }
  for (const k of Object.keys(out)) out[k].sort();
  return out;
}

/** Section key for a file whose contents could not be parsed (opaque content hash). */
export const UNPARSEABLE = '_file';

function unparseable(raw: string): FileSnapshot {
  return { [UNPARSEABLE]: { unreadable: [sha(raw)] } };
}

/** True when a snapshot is the parse-failure marker. */
export function isUnparseable(snap: FileSnapshot): boolean {
  return Object.prototype.hasOwnProperty.call(snap, UNPARSEABLE);
}

/** Largest watched config file read; a bigger one is a per-file read error (EFBIG). */
export const MAX_WATCHED_FILE_BYTES = 1024 * 1024;

function codedError(code: string, message: string): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

/**
 * Read a regular file, at most `max` bytes, without ever blocking on a special
 * file (#928 round 1, blocker 3). A blocking `readFileSync` of a FIFO or
 * /dev/zero pins the event loop, so neither the check budget nor the child
 * deadline can fire. The open is O_NONBLOCK (a FIFO open returns at once), the
 * fd is fstat'd, and only a regular file is read: a directory is EISDIR, any
 * other type (FIFO, device, socket, a symlink to one) is ENOTREG, and an
 * oversize file is EFBIG. Symlinks to regular files are followed (dotfile
 * managers symlink these configs).
 */
export function readRegularFileBounded(filePath: string, max: number = MAX_WATCHED_FILE_BYTES): string {
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const st = fs.fstatSync(fd);
    if (st.isDirectory()) throw codedError('EISDIR', 'is a directory');
    if (!st.isFile()) throw codedError('ENOTREG', 'not a regular file');
    if (st.size > max) throw codedError('EFBIG', 'file too large');
    // The size can change after fstat: read at most max+1 bytes and re-check.
    const buf = Buffer.alloc(Math.min(st.size, max) + 1);
    let total = 0;
    for (;;) {
      if (total === buf.length) break;
      const n = fs.readSync(fd, buf, total, buf.length - total, null);
      if (n === 0) break;
      total += n;
    }
    if (total > max) throw codedError('EFBIG', 'file too large');
    return buf.subarray(0, total).toString('utf-8');
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Snapshot of one file's security-relevant keys from its raw contents. Shared
 * by the check and the own-write helper (which derives the new baseline from
 * the bytes it wrote, not from a second read of the file).
 */
export function snapshotContent(raw: string, spec: WatchedFileSpec): FileSnapshot {
  let parsed: unknown;
  try {
    parsed = spec.format === 'toml' ? parseToml(raw) : JSON.parse(spec.format === 'jsonc' ? stripJsonc(raw) : raw);
  } catch {
    return unparseable(raw);
  }
  const snap: FileSnapshot = {};
  for (const s of spec.sections) {
    const m = sectionFrom(s.kind, getPath(parsed, s.keyPath));
    if (Object.keys(m).length) snap[s.keyPath] = m;
  }
  return snap;
}

/**
 * Snapshot one file's security-relevant keys. Absent file = empty snapshot.
 * A file that exists but cannot be parsed becomes the `_file` marker (its
 * contents hashed, never stored), which the check reports as a parse error.
 * A read failure other than "absent" THROWS (EISDIR, ENOTREG, EFBIG, EACCES...):
 * the caller keeps that file's baseline and reports a read error.
 */
export function snapshotFile(filePath: string, spec: WatchedFileSpec): FileSnapshot {
  let raw: string;
  try {
    raw = readRegularFileBounded(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT' || (err as NodeJS.ErrnoException).code === 'ENOTDIR') return {};
    throw err;
  }
  return snapshotContent(raw, spec);
}

// ── Diff ────────────────────────────────────────────────────────────────────

export type ChangeKind = 'added' | 'removed' | 'changed';

export interface ConfigChange {
  keyPath: string;
  section: SectionKind | 'file';
  kind: ChangeKind;
  /** Entry name (hook event, server name, task label, env var): sanitised on output. */
  name: string;
}

export function diffSnapshots(spec: WatchedFileSpec, before: FileSnapshot, after: FileSnapshot): ConfigChange[] {
  const changes: ConfigChange[] = [];
  const keyPaths = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const keyPath of keyPaths) {
    const sec = spec.sections.find((s) => s.keyPath === keyPath);
    const section: ConfigChange['section'] = sec?.kind ?? 'file';
    const b = before[keyPath] ?? {};
    const a = after[keyPath] ?? {};
    for (const name of new Set([...Object.keys(b), ...Object.keys(a)])) {
      const bi = b[name];
      const ai = a[name];
      if (!bi && ai) { changes.push({ keyPath, section, kind: 'added', name }); continue; }
      if (bi && !ai) { changes.push({ keyPath, section, kind: 'removed', name }); continue; }
      if (!bi || !ai || bi.join() === ai.join()) continue;
      const bs = new Set(bi);
      const as = new Set(ai);
      const gained = ai.some((h) => !bs.has(h));
      const lost = bi.some((h) => !as.has(h));
      changes.push({ keyPath, section, kind: gained && lost ? 'changed' : gained ? 'added' : lost ? 'removed' : 'changed', name });
    }
  }
  return changes;
}

const SECTION_LABEL: Record<ConfigChange['section'], string> = {
  hooks: 'hook',
  mcpServers: 'MCP server',
  env: 'environment variable',
  tasks: 'task',
  plugins: 'plugin registration',
  file: 'file contents',
};

/** Fixed-vocabulary label, e.g. "hook added". */
export function changeLabel(c: ConfigChange): string {
  return `${SECTION_LABEL[c.section]} ${c.kind}`;
}

// ── Display + ledger types ──────────────────────────────────────────────────

export interface AgentConfigLedgerRow {
  /** Display path (home abbreviated), never contents. */
  file: string;
  keyPath: string;
  kind: string;
  detail: string;
  outcome: 'change' | 'error';
}

export function displayPath(p: string, home: string): string {
  const rel = path.relative(home, p);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? `~/${rel}` : p;
}

// ── State ───────────────────────────────────────────────────────────────────

/**
 * The one home the watch uses everywhere: the runner, the doctor check and
 * the own-write helper (#928 round 1). OpenClaw's installer resolves its own
 * home through OPENCLAW_HOME / SUDO_USER; the watch does not, so an own write
 * and the check always read and write the SAME state file.
 */
export function agentConfigWatchHome(): string {
  return os.homedir();
}

export function agentConfigStatePath(home: string): string {
  return path.join(home, '.shieldcortex', 'state', 'agent-config-watch.json');
}

/** HMAC key for the baseline, kept apart from the state file (0700 dir, 0600 file). */
export function agentConfigKeyPath(home: string): string {
  return path.join(home, '.shieldcortex', 'keys', 'agent-config-watch.key');
}

export function emptyState(): AgentConfigWatchState {
  return { version: 1, initialised: false, roots: [], files: {} };
}

/**
 * Baseline integrity (#928 round 1, blocker 1). The state is signed with an
 * HMAC whose key lives in a separate owner-only file. This is tamper-EVIDENCE,
 * not tamper-proofing: anything running as the same user can read the key and
 * re-sign. What it does stop is the cheap attack the review reproduced, a
 * payload that rewrites the baseline JSON to hide its own config edit; that
 * now raises a "baseline untrusted" alert instead of suppressing one.
 *  - `fresh`: no state and no key (first run on this home).
 *  - `ok`: state present and its signature verifies.
 *  - `untrusted`: unsigned, bad signature, unreadable/malformed state, a
 *    symlinked state file, or a state deleted while its key remains.
 */
export type StateIntegrity = 'fresh' | 'ok' | 'untrusted';

export interface LoadedAgentConfigState {
  state: AgentConfigWatchState;
  integrity: StateIntegrity;
}

const MAX_STATE_BYTES = 8 * 1024 * 1024;
const MAC_DOMAIN = 'shieldcortex-agent-config-watch:v1:';

function macOf(key: Buffer, body: unknown): string {
  return crypto.createHmac('sha256', key).update(MAC_DOMAIN + canonical(body)).digest('hex');
}

function readKey(home: string): Buffer | null {
  try {
    const raw = readRegularFileBounded(agentConfigKeyPath(home), 1024).trim();
    return /^[0-9a-f]{64}$/i.test(raw) ? Buffer.from(raw, 'hex') : null;
  } catch {
    return null;
  }
}

function keyExists(home: string): boolean {
  try { fs.lstatSync(agentConfigKeyPath(home)); return true; } catch { return false; }
}

function isState(s: unknown): s is AgentConfigWatchState {
  const o = s as AgentConfigWatchState | null;
  return !!o && typeof o === 'object' && o.version === 1 && !!o.files && typeof o.files === 'object' && Array.isArray(o.roots);
}

export function loadAgentConfigStateChecked(home: string): LoadedAgentConfigState {
  const untrusted: LoadedAgentConfigState = { state: emptyState(), integrity: 'untrusted' };
  const p = agentConfigStatePath(home);
  let raw: string;
  try {
    if (fs.lstatSync(p).isSymbolicLink()) return untrusted;
    raw = readRegularFileBounded(p, MAX_STATE_BYTES);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return keyExists(home) ? untrusted : { state: emptyState(), integrity: 'fresh' };
    return untrusted;
  }
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { return untrusted; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return untrusted;
  const { mac, ...body } = parsed as Record<string, unknown>;
  const key = readKey(home);
  if (!key || typeof mac !== 'string' || !/^[0-9a-f]{64}$/.test(mac)) return untrusted;
  const want = Buffer.from(macOf(key, body), 'hex');
  if (!crypto.timingSafeEqual(want, Buffer.from(mac, 'hex'))) return untrusted;
  if (!isState(body)) return untrusted;
  return { state: body, integrity: 'ok' };
}

/** The verified state, or an empty one when it is absent or untrusted. */
export function loadAgentConfigState(home: string): AgentConfigWatchState {
  return loadAgentConfigStateChecked(home).state;
}

/**
 * Create (0700) and verify a directory the watcher owns: never a symlink,
 * always a real directory, owned by this user. Anything else refuses the
 * write (EUNSAFEPATH) rather than following it somewhere else.
 */
function ensureOwnedDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir);
  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  if (st.isSymbolicLink() || !st.isDirectory() || (uid !== undefined && st.uid !== uid)) {
    throw codedError('EUNSAFEPATH', 'state directory is not an owned directory');
  }
}

/**
 * Replace `target` with `content` via an exclusive, unpredictable temp file
 * in the same owned directory (#928 round 1, blocker 2): O_CREAT|O_EXCL|
 * O_NOFOLLOW so a planted temp or symlink is never written through, and a
 * target that is anything but a regular file is refused, never replaced.
 */
function writeOwnedFileAtomic(target: string, content: string): void {
  const dir = path.dirname(target);
  ensureOwnedDir(path.dirname(dir)); // ~/.shieldcortex
  ensureOwnedDir(dir);
  try {
    if (!fs.lstatSync(target).isFile()) throw codedError('EUNSAFEPATH', 'state target is not a regular file');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
  const tmp = path.join(dir, `.${path.basename(target)}.${crypto.randomBytes(12).toString('hex')}.tmp`);
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0);
  const fd = fs.openSync(tmp, flags, 0o600);
  try {
    try {
      fs.writeSync(fd, content);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, target);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch { /* already renamed or gone */ }
    throw err;
  }
}

/** The baseline key, created once (exclusive create; a racing creator wins). */
function ensureKey(home: string): Buffer {
  const existing = readKey(home);
  if (existing) return existing;
  const p = agentConfigKeyPath(home);
  ensureOwnedDir(path.dirname(path.dirname(p)));
  ensureOwnedDir(path.dirname(p));
  const key = crypto.randomBytes(32);
  try {
    const fd = fs.openSync(p, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    try { fs.writeSync(fd, `${key.toString('hex')}\n`); } finally { fs.closeSync(fd); }
    return key;
  } catch (err) {
    const raced = readKey(home);
    if (raced) return raced;
    throw err;
  }
}

export function saveAgentConfigState(home: string, state: AgentConfigWatchState): void {
  const key = ensureKey(home);
  // Sign exactly what a reader will parse back (undefined fields dropped).
  const body = JSON.parse(JSON.stringify({ ...state, mac: undefined })) as Record<string, unknown>;
  writeOwnedFileAtomic(agentConfigStatePath(home), JSON.stringify({ ...body, mac: macOf(key, body) }));
}

/** Opt-out: `sessionStart.agentConfigWatch: false` (default on). */
export function agentConfigWatchEnabled(config: unknown): boolean {
  const ss = config && typeof config === 'object' ? (config as Record<string, unknown>).sessionStart : undefined;
  return !(ss && typeof ss === 'object' && (ss as Record<string, unknown>).agentConfigWatch === false);
}

/** Candidate (path, spec) pairs for a home and a list of project roots. */
export function watchedPaths(home: string, roots: string[]): Array<{ file: string; spec: WatchedFileSpec; root?: string }> {
  const out: Array<{ file: string; spec: WatchedFileSpec; root?: string }> = [];
  for (const spec of WATCHED_FILES) {
    if (spec.scope === 'user') out.push({ file: path.join(home, spec.relPath), spec });
    else for (const root of roots) out.push({ file: path.join(root, spec.relPath), spec, root });
  }
  return out;
}

function realOrResolved(p: string): string {
  try { return path.join(fs.realpathSync(path.dirname(p)), path.basename(p)); } catch { return path.resolve(p); }
}

/**
 * Match a path against the watched set (used by the own-write helper). The
 * match is by real directory, so a writer that reached the file through a
 * different spelling (a symlinked OPENCLAW_HOME) still hits the entry, and the
 * returned `file` is the key the check itself uses in the state.
 */
export function watchedEntryForPath(filePath: string, home: string, roots: string[]): { file: string; spec: WatchedFileSpec } | undefined {
  const target = realOrResolved(filePath);
  const hit = watchedPaths(home, roots).find((w) => path.resolve(w.file) === path.resolve(filePath) || realOrResolved(w.file) === target);
  return hit ? { file: hit.file, spec: hit.spec } : undefined;
}

export function specForPath(filePath: string, home: string, roots: string[]): WatchedFileSpec | undefined {
  return watchedEntryForPath(filePath, home, roots)?.spec;
}

// ── Check ───────────────────────────────────────────────────────────────────

export interface AgentConfigNotification {
  file: string;
  changes: Array<{ label: string; name: string }>;
  changeCount: number;
}

export interface AgentConfigWatchDeps {
  home: string;
  projectRoots: string[];
  notify: (n: AgentConfigNotification) => Promise<void>;
  ledger: (row: AgentConfigLedgerRow) => boolean | void;
  now?: () => number;
  totalBudgetMs?: number;
  /** Test seam: replaces the file reader. */
  snapshot?: (file: string, spec: WatchedFileSpec) => FileSnapshot | Promise<FileSnapshot>;
}

export interface AgentConfigWatchResult {
  baselined: boolean;
  notified: number;
  errors: number;
  /** The stored baseline failed its integrity check this run. */
  untrustedBaseline?: boolean;
}

/** Notification label for a baseline that failed its integrity check. */
export const BASELINE_UNTRUSTED_LABEL = 'watch baseline untrusted';

const DEFAULT_TOTAL_BUDGET_MS = 5_000;

class DeadlineError extends Error {
  constructor(ms: number) {
    super(`timed out after ${ms}ms`);
    this.name = 'DeadlineError';
  }
}

/**
 * Fixed-vocabulary category for a thrown error. Raw error text never reaches
 * the ledger (it may carry a URL token, a path or file contents); only an
 * errno-style code such as EISDIR is kept, because that alphabet is closed.
 */
export function errorCategory(err: unknown): string {
  if (err instanceof DeadlineError) return 'timeout';
  const code = err && typeof err === 'object' ? (err as { code?: unknown }).code : undefined;
  return typeof code === 'string' && /^E[A-Z0-9_]{1,24}$/.test(code) ? code : 'unclassified';
}

/** Semantic snapshot equality, shared with the own-write helper: key order never counts. */
export function sameSnapshot(a: FileSnapshot | undefined, b: FileSnapshot | undefined): boolean {
  return canonical(a ?? {}) === canonical(b ?? {});
}

export async function runAgentConfigWatch(deps: AgentConfigWatchDeps): Promise<AgentConfigWatchResult> {
  const now = deps.now ?? Date.now;
  const result: AgentConfigWatchResult = { baselined: false, notified: 0, errors: 0 };
  /** True when the row was recorded; a `false` return or a throw both count as not recorded. */
  const safeLedger = (row: AgentConfigLedgerRow): boolean => {
    try { return deps.ledger(row) !== false; } catch { return false; }
  };
  const budget = deps.totalBudgetMs ?? DEFAULT_TOTAL_BUDGET_MS;
  const roots = [...new Set(deps.projectRoots.map((r) => path.resolve(r)))];
  const take = deps.snapshot ?? snapshotFile;
  // Commit guard: once the deadline fires (or the run fails), the abandoned body
  // must not notify, log or save anything after this function has returned.
  let expired = false;

  const body = async (): Promise<void> => {
    const loaded = loadAgentConfigStateChecked(deps.home);
    // An untrusted baseline is never diffed against and never silently
    // replaced: every file is re-baselined only after the operator has been
    // told (below); until then nothing is saved and the next run re-alerts.
    const untrusted = loaded.integrity === 'untrusted';
    const state = loaded.state;
    const firstRun = !state.initialised;
    const knownRoots = new Set(state.roots);
    const next: AgentConfigWatchState = { ...state, version: 1, initialised: true, files: { ...state.files }, roots: [...new Set([...state.roots, ...roots])] };
    const changedFiles: Array<{ file: string; spec: WatchedFileSpec; before: FileSnapshot; after: FileSnapshot }> = [];
    const health: Record<string, string> = {};

    for (const w of watchedPaths(deps.home, roots)) {
      if (expired) return;
      let after: FileSnapshot;
      try {
        after = await take(w.file, w.spec);
      } catch (err) {
        // One unreadable file (EISDIR, EACCES...) keeps ITS baseline and is
        // reported as a health error; every other file is still checked.
        health[w.file] = `read-error (${errorCategory(err)})`;
        continue;
      }
      if (expired) return;
      if (isUnparseable(after)) health[w.file] = 'parse-error';
      const known = Object.prototype.hasOwnProperty.call(state.files, w.file);
      // Baseline silently: first run, or a project root we have not seen before.
      if (firstRun || (w.root && !knownRoots.has(w.root))) { next.files[w.file] = after; continue; }
      const before = known ? state.files[w.file] : {};
      if (!sameSnapshot(before, after)) changedFiles.push({ file: w.file, spec: w.spec, before, after });
      else if (!known) next.files[w.file] = after;
    }

    // Health errors are reported on every path, first run included (a malformed
    // file baselined silently is still a disabled tripwire). One ledger row per
    // new or changed condition; result.errors counts every affected file per run.
    const prevErrors = state.fileErrors ?? {};
    const nextErrors: Record<string, string> = {};
    for (const [file, category] of Object.entries(health)) {
      if (expired) return;
      result.errors++;
      if (prevErrors[file] === category) { nextErrors[file] = category; continue; }
      if (safeLedger({ file: displayPath(file, deps.home), keyPath: '', kind: 'health-error', detail: category, outcome: 'error' })) nextErrors[file] = category;
    }
    next.fileErrors = nextErrors;

    if (firstRun) result.baselined = true;
    let pending = 0;
    for (const c of changedFiles) {
      if (expired) return;
      const changes = diffSnapshots(c.spec, c.before, c.after);
      const shown = displayPath(c.file, deps.home);
      if (changes.length === 0) { next.files[c.file] = c.after; continue; }
      next.lastDetectedAt = new Date(now()).toISOString();
      const note: AgentConfigNotification = {
        file: shown,
        changes: changes.slice(0, 3).map((x) => ({ label: changeLabel(x), name: x.name })),
        changeCount: changes.length,
      };
      try {
        await deps.notify(note);
      } catch (err) {
        if (expired) return;
        // Not delivered: keep the old baseline so the change is re-sent next session.
        result.errors++;
        pending++;
        safeLedger({ file: shown, keyPath: changes[0].keyPath, kind: 'notify-error', detail: `notification not delivered (${errorCategory(err)})`, outcome: 'error' });
        continue;
      }
      if (expired) return;
      result.notified++;
      let recorded = true;
      for (const x of changes) {
        if (!safeLedger({ file: shown, keyPath: x.keyPath, kind: changeLabel(x), detail: `entry=${safeEntryName(x.name)}`, outcome: 'change' })) recorded = false;
      }
      if (!recorded) {
        // The audit row is the durable record: without it, do not advance the
        // baseline, so the next run re-reports and re-records the change.
        result.errors++;
        pending++;
        continue;
      }
      next.files[c.file] = c.after;
      next.lastChangeAt = new Date(now()).toISOString();
    }
    next.pendingChanges = pending;
    next.lastCheckAt = new Date(now()).toISOString();
    if (untrusted) {
      result.untrustedBaseline = true;
      next.lastDetectedAt = next.lastCheckAt;
      const shown = displayPath(agentConfigStatePath(deps.home), deps.home);
      try {
        await deps.notify({ file: shown, changes: [{ label: BASELINE_UNTRUSTED_LABEL, name: 'review all agent configs' }], changeCount: 1 });
      } catch (err) {
        if (expired) return;
        result.errors++;
        safeLedger({ file: shown, keyPath: '', kind: 'notify-error', detail: `notification not delivered (${errorCategory(err)})`, outcome: 'error' });
        return; // not told: keep the untrusted state so the next run re-alerts
      }
      if (expired) return;
      result.notified++;
      if (!safeLedger({ file: shown, keyPath: '', kind: 'baseline-untrusted', detail: 'signature missing or invalid; re-baselined after notifying', outcome: 'error' })) {
        result.errors++;
        return;
      }
      next.lastChangeAt = next.lastCheckAt;
    }
    if (expired) return;
    saveAgentConfigState(deps.home, next);
  };

  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_, rej) => {
    timer = setTimeout(() => { expired = true; rej(new DeadlineError(budget)); }, budget);
    timer.unref?.();
  });
  const running = body();
  running.catch(() => undefined); // a late rejection after the deadline is not unhandled
  try {
    await Promise.race([running, deadline]);
  } catch (err) {
    // Fail open: one ledger row, no notification, baseline untouched.
    expired = true;
    result.errors++;
    safeLedger({
      file: '(agent config watch)',
      keyPath: '',
      kind: 'error',
      detail: err instanceof DeadlineError ? `timed out after ${budget}ms` : `check failed (${errorCategory(err)})`,
      outcome: 'error',
    });
  } finally {
    if (timer) clearTimeout(timer);
  }
  return result;
}

const NAME_MAX = 64;
/** Entry names are file-controlled: keep a safe charset and length. */
export function safeEntryName(raw: unknown): string {
  const cleaned = String(raw ?? '').replace(/[^A-Za-z0-9_.:\/@ -]/g, '?').trim();
  return (cleaned || 'unknown').slice(0, NAME_MAX);
}

/** Default project roots: the session's working directory plus configured roots. */
export function resolveProjectRoots(config: unknown, cwd: string = process.cwd()): string[] {
  const cfg = config && typeof config === 'object' ? (config as Record<string, unknown>).agentConfigWatch : undefined;
  const extra = cfg && typeof cfg === 'object' && Array.isArray((cfg as Record<string, unknown>).projectRoots)
    ? ((cfg as Record<string, unknown>).projectRoots as unknown[]).filter((r): r is string => typeof r === 'string' && path.isAbsolute(r))
    : [];
  return [...new Set([cwd, ...extra])];
}
