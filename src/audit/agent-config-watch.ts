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
 *    blocked or delayed (the runner is detached and time-budgeted).
 *  - First run records a baseline silently. A project root seen for the first
 *    time is baselined silently too (a fresh clone is not an attack); a new
 *    watched file in an already-baselined root IS reported.
 *  - ShieldCortex's own writes call `recordOwnConfigWrite` (see
 *    agent-config-watch-own-write.ts) so they never alert.
 */

import crypto from 'crypto';
import fs from 'fs';
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
  /** ISO time of the last detected unexpected change (doctor shows this). */
  lastChangeAt?: string;
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
function canonical(v: unknown): string {
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
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      for (const [event, entries] of Object.entries(value as Record<string, unknown>)) {
        const list = Array.isArray(entries) ? entries : [entries];
        out[event] = list.map((e) => sha(canonical(e))).sort();
      }
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

/**
 * Snapshot one file's security-relevant keys. Absent file = empty snapshot.
 * A file that exists but cannot be parsed becomes the `_file` marker (its
 * contents hashed, never stored), which the check reports as a parse error.
 * A read failure other than "absent" THROWS: the caller keeps that file's
 * baseline and reports a read error.
 */
export function snapshotFile(filePath: string, spec: WatchedFileSpec): FileSnapshot {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT' || (err as NodeJS.ErrnoException).code === 'ENOTDIR') return {};
    throw err;
  }
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

export function agentConfigStatePath(home: string): string {
  return path.join(home, '.shieldcortex', 'state', 'agent-config-watch.json');
}

export function emptyState(): AgentConfigWatchState {
  return { version: 1, initialised: false, roots: [], files: {} };
}

export function loadAgentConfigState(home: string): AgentConfigWatchState {
  try {
    const s = JSON.parse(fs.readFileSync(agentConfigStatePath(home), 'utf-8')) as AgentConfigWatchState;
    if (s && s.version === 1 && s.files && typeof s.files === 'object' && Array.isArray(s.roots)) return s;
  } catch { /* fresh */ }
  return emptyState();
}

export function saveAgentConfigState(home: string, state: AgentConfigWatchState): void {
  const p = agentConfigStatePath(home);
  fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
  const tmp = `${p}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
  fs.renameSync(tmp, p);
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

/** Match a path against the watched set (used by the own-write helper). */
export function specForPath(filePath: string, home: string, roots: string[]): WatchedFileSpec | undefined {
  const target = path.resolve(filePath);
  return watchedPaths(home, roots).find((w) => path.resolve(w.file) === target)?.spec;
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
}

const DEFAULT_TOTAL_BUDGET_MS = 5_000;

async function withDeadline<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const t = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new Error(`timed out after ${ms}ms`)), ms);
    timer.unref?.();
  });
  try { return await Promise.race([p, t]); } finally { if (timer) clearTimeout(timer); }
}

function sameSnapshot(a: FileSnapshot | undefined, b: FileSnapshot): boolean {
  return canonical(a ?? {}) === canonical(b);
}

export async function runAgentConfigWatch(deps: AgentConfigWatchDeps): Promise<AgentConfigWatchResult> {
  const now = deps.now ?? Date.now;
  const result: AgentConfigWatchResult = { baselined: false, notified: 0, errors: 0 };
  const safeLedger = (row: AgentConfigLedgerRow): void => { try { deps.ledger(row); } catch { /* ledger is best effort */ } };
  const budget = deps.totalBudgetMs ?? DEFAULT_TOTAL_BUDGET_MS;
  const roots = [...new Set(deps.projectRoots.map((r) => path.resolve(r)))];
  const take = deps.snapshot ?? snapshotFile;

  try {
    const body = async (): Promise<void> => {
      const state = loadAgentConfigState(deps.home);
      const firstRun = !state.initialised;
      const knownRoots = new Set(state.roots);
      const next: AgentConfigWatchState = { ...state, version: 1, initialised: true, files: { ...state.files }, roots: [...new Set([...state.roots, ...roots])] };
      const changedFiles: Array<{ file: string; spec: WatchedFileSpec; before: FileSnapshot; after: FileSnapshot }> = [];

      for (const w of watchedPaths(deps.home, roots)) {
        const after = await take(w.file, w.spec);
        const known = Object.prototype.hasOwnProperty.call(state.files, w.file);
        // Baseline silently: first run, or a project root we have not seen before.
        if (firstRun || (w.root && !knownRoots.has(w.root))) { next.files[w.file] = after; continue; }
        const before = known ? state.files[w.file] : {};
        if (!sameSnapshot(before, after)) changedFiles.push({ file: w.file, spec: w.spec, before, after });
        else if (!known) next.files[w.file] = after;
      }

      if (firstRun) result.baselined = true;
      for (const c of changedFiles) {
        const changes = diffSnapshots(c.spec, c.before, c.after);
        const shown = displayPath(c.file, deps.home);
        if (changes.length === 0) { next.files[c.file] = c.after; continue; }
        const note: AgentConfigNotification = {
          file: shown,
          changes: changes.slice(0, 3).map((x) => ({ label: changeLabel(x), name: x.name })),
          changeCount: changes.length,
        };
        try {
          await deps.notify(note);
        } catch (err) {
          // Not delivered: keep the old baseline so the change is re-sent next session.
          result.errors++;
          safeLedger({ file: shown, keyPath: changes[0].keyPath, kind: 'notify-error', detail: `notification not delivered: ${err instanceof Error ? err.message : String(err)}`.slice(0, 200), outcome: 'error' });
          continue;
        }
        result.notified++;
        for (const x of changes) safeLedger({ file: shown, keyPath: x.keyPath, kind: changeLabel(x), detail: `entry=${safeEntryName(x.name)}`, outcome: 'change' });
        next.files[c.file] = c.after;
        next.lastChangeAt = new Date(now()).toISOString();
      }
      next.lastCheckAt = new Date(now()).toISOString();
      saveAgentConfigState(deps.home, next);
    };
    await withDeadline(body(), budget);
  } catch (err) {
    // Fail open: one ledger row, no notification, baseline untouched.
    result.errors++;
    safeLedger({ file: '(agent config watch)', keyPath: '', kind: 'error', detail: (err instanceof Error ? err.message : String(err)).slice(0, 200), outcome: 'error' });
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
