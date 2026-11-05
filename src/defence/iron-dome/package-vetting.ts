/**
 * Pre-install package vetting (#889, phase 1).
 *
 * The Action Guard already raises an approval card for a package install, but
 * the card said nothing about the PACKAGE: a freshly poisoned version looked
 * identical to a safe one. This module recognises the install, resolves the
 * version that would actually be installed, and answers four questions about
 * it from public registries — read-only, bounded, never a verdict on its own:
 *
 *   1. Does OSV list this exact version (including `MAL-` malicious-package
 *      entries)?
 *   2. How old is this version?
 *   3. Does an npm version declare lifecycle scripts that run on install?
 *   4. Is a PyPI release source-only (setup code runs on install)?
 *
 * Posture (see {@link applyVettingToVerdict}):
 *   - a `MAL-` hit is catastrophic: blocked on every plane, even in advisory
 *     mode, like the other catastrophic signals;
 *   - everything else only adds plain-English reasons to the approval card and
 *     the audit row. Age or hooks alone never block.
 *
 * Failure posture: a lookup that cannot complete is reported as
 * `unchecked: <reason>`, never as clean, and the call proceeds (fail open) —
 * EXCEPT when a cached, unexpired `MAL-` hit for the package is on disk, which
 * still blocks while the network is away.
 *
 * Nothing here installs, downloads or executes a package: the only requests
 * are metadata GETs to the registry and one POST to OSV.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import semver from 'semver';
import { extractCommand } from './tool-action-guard.js';

// ── Types ───────────────────────────────────────────────────────────────────

export type Ecosystem = 'npm' | 'PyPI';

export interface PackageRef {
  ecosystem: Ecosystem;
  name: string;
  /** Requested version, range or dist-tag exactly as typed; null when unpinned. */
  spec: string | null;
  /** The installer form that named it (`npm install`, `uvx`, …). */
  installer: string;
  /** A non-default index/registry flag was present: public metadata would not describe it. */
  customIndex?: boolean;
}

export type FindingKind = 'malicious' | 'advisory' | 'new-version' | 'install-hook' | 'sdist-only' | 'unchecked';

export interface VettingFinding {
  kind: FindingKind;
  /** `catastrophic` only for a known-malicious hit; everything else is advisory. */
  severity: 'catastrophic' | 'advisory';
  /** Plain English, safe to put on an approval card. */
  reason: string;
}

export interface PackageVet {
  ref: PackageRef;
  status: 'checked' | 'unchecked';
  uncheckedReason?: string;
  /** The version a plain install would resolve to. */
  version?: string;
  publishedAt?: string;
  osvIds: string[];
  /** The subset of `osvIds` that are `MAL-` (known malicious) entries. */
  malicious: string[];
  /** npm lifecycle scripts present on the version manifest. */
  hooks: string[];
  /** PyPI: the release has a source distribution and no wheel. */
  sdistOnly: boolean;
  /** True when the answer came from the on-disk cache rather than the network. */
  cached?: boolean;
  findings: VettingFinding[];
}

export interface VettingResult {
  packages: PackageVet[];
  /** Any package carries a known-malicious (`MAL-`) hit. */
  malicious: boolean;
  /** Plain-English reasons across all packages, most serious first. */
  reasons: string[];
}

export interface PackageVettingConfig {
  enabled?: boolean;
  /** A version published fewer than this many days ago is a finding. Default 7. */
  minAgeDays?: number;
}

export type FetchLike = (url: string, init?: {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
}) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface VetOptions extends PackageVettingConfig {
  fetchImpl?: FetchLike;
  /** Total wall-clock budget for the whole command. Default 3000. */
  budgetMs?: number;
  nowMs?: number;
  /** Override `~/.shieldcortex/state`. */
  stateDir?: string;
  cacheTtlMs?: number;
}

export const DEFAULT_MIN_AGE_DAYS = 7;
export const DEFAULT_BUDGET_MS = 3000;
export const DEFAULT_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_PACKAGES_PER_COMMAND = 8;

// ── Command parsing ─────────────────────────────────────────────────────────

/** Split on statement separators outside quotes. */
function splitStatements(cmd: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q: '"' | "'" | null = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (q) {
      cur += c;
      if (c === '\\' && q === '"' && i + 1 < cmd.length) { cur += cmd[++i]; continue; }
      if (c === q) q = null;
      continue;
    }
    if (c === '"' || c === "'") { q = c; cur += c; continue; }
    if (c === '\\' && i + 1 < cmd.length) { cur += c + cmd[++i]; continue; }
    // An unquoted `#` at the start of a word begins a comment: not an argument.
    if (c === '#' && (cur === '' || /\s$/.test(cur))) {
      while (i + 1 < cmd.length && cmd[i + 1] !== '\n') i++;
      continue;
    }
    if (c === ';' || c === '\n' || c === '|' || c === '&') {
      out.push(cur);
      cur = '';
      while (cmd[i + 1] === c && (c === '|' || c === '&')) i++;
      continue;
    }
    cur += c;
  }
  out.push(cur);
  return out.map((s) => s.trim()).filter(Boolean);
}

/** Shell-ish word split: quotes removed, backslash escapes honoured. */
function words(stmt: string): string[] {
  const out: string[] = [];
  let cur = '';
  let has = false;
  let q: '"' | "'" | null = null;
  for (let i = 0; i < stmt.length; i++) {
    const c = stmt[i];
    if (q) {
      if (c === q) { q = null; continue; }
      if (c === '\\' && q === '"' && i + 1 < stmt.length) { cur += stmt[++i]; continue; }
      cur += c;
      continue;
    }
    if (c === '"' || c === "'") { q = c; has = true; continue; }
    if (c === '\\' && i + 1 < stmt.length) { cur += stmt[++i]; has = true; continue; }
    if (/\s/.test(c)) {
      if (has) { out.push(cur); cur = ''; has = false; }
      continue;
    }
    cur += c;
    has = true;
  }
  if (has) out.push(cur);
  return out;
}

const WRAPPERS = new Set(['sudo', 'env', 'time', 'nohup', 'command', 'exec', 'nice', 'ionice', 'setsid', 'stdbuf', 'timeout']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash']);
const NPM_FAMILY = new Set(['npm', 'pnpm', 'yarn', 'bun']);
const NPM_ADD_VERBS = new Set([
  'install', 'add', 'i', 'in', 'ins', 'inst', 'insta', 'instal', 'isntall', 'isnt',
]);
const PIP_VERBS = new Set(['install']);

/** Flags (per tool family) that consume the NEXT word as their value. */
const VALUE_FLAGS_NPM = new Set([
  '--prefix', '--registry', '--workspace', '-w', '--cache', '--userconfig', '--tag', '-C', '--dir', '--filter', '-F',
  '--cwd', '--save-prefix', '--loglevel', '--omit', '--include', '--scope', '--otp', '--before', '--store-dir',
]);
const VALUE_FLAGS_PIP = new Set([
  '-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-i', '--index-url', '--extra-index-url', '-f',
  '--find-links', '-t', '--target', '--prefix', '--root', '--python', '--platform', '--abi', '--implementation',
  '--python-version', '--only-binary', '--no-binary', '--progress-bar', '--upgrade-strategy', '--src', '--proxy',
  '--cert', '--client-cert', '--cache-dir', '--log', '--retries', '--timeout', '--trusted-host', '--exists-action',
  '--config-settings', '-C', '--default-index', '--index', '--index-strategy', '--resolution', '--with',
  '--project', '--directory', '--package', '--constraints', '--overrides',
]);
const INDEX_FLAGS_NPM = new Set(['--registry']);
const INDEX_FLAGS_PIP = new Set(['-i', '--index-url', '--extra-index-url', '--default-index', '--index', '-f', '--find-links']);

interface Positionals {
  positionals: string[];
  /** Values given to -p/--package style flags. */
  packageFlags: string[];
  customIndex: boolean;
  /** `-r file` style inputs the vetting cannot resolve. */
  fileInputs: boolean;
}

function collectArgs(args: readonly string[], valueFlags: ReadonlySet<string>, indexFlags: ReadonlySet<string>, pkgFlags: ReadonlySet<string>): Positionals {
  const out: Positionals = { positionals: [], packageFlags: [], customIndex: false, fileInputs: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { out.positionals.push(...args.slice(i + 1)); break; }
    if (a.startsWith('-') && a !== '-') {
      const eq = a.indexOf('=');
      const flag = eq > 0 ? a.slice(0, eq) : a;
      const inlineValue = eq > 0 ? a.slice(eq + 1) : undefined;
      if (indexFlags.has(flag)) out.customIndex = true;
      if (flag === '-r' || flag === '--requirement' || flag === '-e' || flag === '--editable') out.fileInputs = true;
      if (pkgFlags.has(flag)) {
        const v = inlineValue ?? args[i + 1];
        if (v !== undefined) out.packageFlags.push(v);
        if (inlineValue === undefined) i++;
        continue;
      }
      // Short flag with attached value: -wfoo / -rreq.txt (only for the value-taking shorts).
      if (inlineValue === undefined && valueFlags.has(flag)) i++;
      continue;
    }
    out.positionals.push(a);
  }
  return out;
}

/** A positional that is not a registry name: path, URL, git, tarball, workspace/alias protocol. */
function isNonRegistrySpec(s: string): boolean {
  return (
    s === '.' || s === '..' || s.startsWith('./') || s.startsWith('../') || s.startsWith('/') || s.startsWith('~')
    || /^[a-z][a-z0-9+.-]*:/i.test(s) // file:, git+https:, github:, http(s):, npm:, workspace:, link:
    || /\.(?:tgz|tar\.gz|zip|whl|tar)$/i.test(s)
    || (/^[^@][^/]*\/[^/]+$/.test(s) && !s.startsWith('@')) // user/repo github shorthand
  );
}

const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i;

/** `name@spec`, scoped-aware. Null when the token is not a registry package. */
export function parseNpmSpecifier(token: string): { name: string; spec: string | null } | null {
  if (!token || isNonRegistrySpec(token)) return null;
  const at = token.lastIndexOf('@');
  let name = token;
  let spec: string | null = null;
  if (at > 0) { name = token.slice(0, at); spec = token.slice(at + 1) || null; }
  if (!NPM_NAME.test(name) || name.length > 214) return null;
  return { name: name.toLowerCase(), spec };
}

const PY_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

/** PEP 508-ish requirement: `name[extras]<op>version[,<op>version]`, env markers dropped. */
export function parsePythonRequirement(token: string): { name: string; spec: string | null } | null {
  if (!token || isNonRegistrySpec(token) || token.includes('@')) return null;
  const noMarker = token.split(';')[0].trim();
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$/.exec(noMarker);
  if (!m || !PY_NAME.test(m[1])) return null;
  const rest = m[2].replace(/\s+/g, '');
  if (rest && !/^(?:(?:===|==|~=|!=|<=|>=|<|>)[A-Za-z0-9.*+!_-]+,?)+$/.test(rest)) return null;
  return { name: m[1].toLowerCase().replace(/[._]+/g, '-'), spec: rest ? rest.replace(/,$/, '') : null };
}

/** uvx / uv tool run use `name@version` (and `name==1.0`). */
function parseUvxSpecifier(token: string): { name: string; spec: string | null } | null {
  if (!token || isNonRegistrySpec(token)) return null;
  const at = token.indexOf('@');
  if (at > 0) {
    const base = parsePythonRequirement(token.slice(0, at));
    const ver = token.slice(at + 1);
    if (!base || !ver) return null;
    return { name: base.name, spec: ver === 'latest' ? null : `==${ver}` };
  }
  return parsePythonRequirement(token);
}

const MAX_DEPTH = 3;

/**
 * Package installs named by a shell command: npm/pnpm/yarn/bun add or install,
 * npx/bunx/pnpm dlx/yarn dlx/npm exec, pip/pip3 install (also `python -m pip`),
 * uv add / uv pip install / uvx / uv tool run|install, pipx install|run.
 *
 * Deliberately conservative: only registry-name arguments yield a ref. Paths,
 * URLs, git specs and tarballs are skipped (nothing to look up by name), and a
 * bare `npm install` (no packages) yields nothing.
 */
export function parseInstallCommands(command: string, depth = 0): PackageRef[] {
  if (typeof command !== 'string' || !command || depth > MAX_DEPTH) return [];
  const refs: PackageRef[] = [];
  for (const stmt of splitStatements(command)) {
    let w = words(stmt);
    // Leading VAR=value assignments and transparent wrappers.
    for (;;) {
      if (w.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(w[0])) { w = w.slice(1); continue; }
      if (w.length && WRAPPERS.has(path.basename(w[0]))) {
        w = w.slice(1);
        while (w.length && (w[0].startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w[0]) || /^\d+[smhd]?$/.test(w[0]))) w = w.slice(1);
        continue;
      }
      break;
    }
    if (!w.length) continue;
    const bin = path.basename(w[0]);
    const rest = w.slice(1);

    if (SHELLS.has(bin)) {
      const ci = rest.findIndex((x) => /^-[a-z]*c$/.test(x));
      if (ci >= 0 && rest[ci + 1]) refs.push(...parseInstallCommands(rest[ci + 1], depth + 1));
      continue;
    }

    if (NPM_FAMILY.has(bin)) {
      refs.push(...parseNpmFamily(bin, rest));
    } else if (bin === 'npx' || bin === 'bunx') {
      refs.push(...parseNpx(bin, rest));
    } else if (/^pip\d*(?:\.\d+)?$/.test(bin)) {
      refs.push(...parsePip(bin, rest));
    } else if (/^python[\d.]*$/.test(bin) && rest[0] === '-m' && /^pip\d*$/.test(rest[1] ?? '')) {
      refs.push(...parsePip('pip', rest.slice(2)));
    } else if (bin === 'uv') {
      refs.push(...parseUv(rest));
    } else if (bin === 'uvx') {
      refs.push(...parseUvx('uvx', rest));
    } else if (bin === 'pipx') {
      refs.push(...parsePipx(rest));
    }
  }
  return refs;
}

function npmRefs(installer: string, tokens: readonly string[], customIndex: boolean): PackageRef[] {
  const out: PackageRef[] = [];
  for (const t of tokens) {
    const p = parseNpmSpecifier(t);
    if (p) out.push({ ecosystem: 'npm', name: p.name, spec: p.spec, installer, ...(customIndex ? { customIndex } : {}) });
  }
  return out;
}

function pyRefs(installer: string, tokens: readonly string[], customIndex: boolean, uvStyle = false): PackageRef[] {
  const out: PackageRef[] = [];
  for (const t of tokens) {
    const p = uvStyle ? parseUvxSpecifier(t) : parsePythonRequirement(t);
    if (p) out.push({ ecosystem: 'PyPI', name: p.name, spec: p.spec, installer, ...(customIndex ? { customIndex } : {}) });
  }
  return out;
}

function parseNpmFamily(bin: string, rest: string[]): PackageRef[] {
  // Find the subcommand: first non-flag word (yarn/pnpm `global add` tolerated).
  let i = 0;
  while (i < rest.length && rest[i].startsWith('-')) {
    i += VALUE_FLAGS_NPM.has(rest[i]) && !rest[i].includes('=') ? 2 : 1;
  }
  let verb = rest[i];
  if (verb === undefined) return [];
  if (bin === 'yarn' && verb === 'global') { i++; verb = rest[i]; }
  const after = rest.slice(i + 1);
  if (verb === 'dlx') {
    return parseNpx(`${bin} dlx`, after);
  }
  if (bin === 'npm' && (verb === 'exec' || verb === 'x')) return parseNpx('npm exec', after);
  if (!NPM_ADD_VERBS.has(verb)) return [];
  // `yarn install` / `pnpm install` / `npm ci` take no packages; `yarn add` does.
  if (bin === 'yarn' && verb !== 'add') return [];
  const a = collectArgs(after, VALUE_FLAGS_NPM, INDEX_FLAGS_NPM, new Set());
  return npmRefs(`${bin} ${verb}`, a.positionals, a.customIndex);
}

function parseNpx(installer: string, rest: string[]): PackageRef[] {
  const a = collectArgs(rest, VALUE_FLAGS_NPM, INDEX_FLAGS_NPM, new Set(['-p', '--package']));
  // With -p/--package the positionals are the command to run, not packages.
  if (a.packageFlags.length) return npmRefs(installer, a.packageFlags, a.customIndex);
  // Everything after the first positional belongs to the executed command.
  return a.positionals.length ? npmRefs(installer, [a.positionals[0]], a.customIndex) : [];
}

function parsePip(bin: string, rest: string[]): PackageRef[] {
  let i = 0;
  while (i < rest.length && rest[i].startsWith('-')) i += VALUE_FLAGS_PIP.has(rest[i]) && !rest[i].includes('=') ? 2 : 1;
  if (!PIP_VERBS.has(rest[i] ?? '')) return [];
  const a = collectArgs(rest.slice(i + 1), VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set());
  return pyRefs(`${bin} install`, a.positionals, a.customIndex);
}

function parseUv(rest: string[]): PackageRef[] {
  const sub = rest.findIndex((x) => !x.startsWith('-'));
  if (sub < 0) return [];
  const verb = rest[sub];
  const after = rest.slice(sub + 1);
  if (verb === 'add') {
    const a = collectArgs(after, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set());
    return pyRefs('uv add', a.positionals, a.customIndex);
  }
  if (verb === 'pip') {
    const j = after.findIndex((x) => !x.startsWith('-'));
    if (j >= 0 && after[j] === 'install') {
      const a = collectArgs(after.slice(j + 1), VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set());
      return pyRefs('uv pip install', a.positionals, a.customIndex);
    }
    return [];
  }
  if (verb === 'tool') {
    const j = after.findIndex((x) => !x.startsWith('-'));
    if (j >= 0 && after[j] === 'run') return parseUvx('uv tool run', after.slice(j + 1));
    if (j >= 0 && after[j] === 'install') {
      const a = collectArgs(after.slice(j + 1), VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set());
      return pyRefs('uv tool install', a.positionals, a.customIndex, true);
    }
  }
  return [];
}

function parseUvx(installer: string, rest: string[]): PackageRef[] {
  const a = collectArgs(rest, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set(['--from']));
  if (a.packageFlags.length) return pyRefs(installer, a.packageFlags, a.customIndex, true);
  return a.positionals.length ? pyRefs(installer, [a.positionals[0]], a.customIndex, true) : [];
}

function parsePipx(rest: string[]): PackageRef[] {
  const j = rest.findIndex((x) => !x.startsWith('-'));
  if (j < 0) return [];
  const verb = rest[j];
  const after = rest.slice(j + 1);
  if (verb === 'install') {
    const a = collectArgs(after, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set());
    return pyRefs('pipx install', a.positionals.slice(0, 1), a.customIndex);
  }
  if (verb === 'run') {
    const a = collectArgs(after, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set(['--spec']));
    if (a.packageFlags.length) return pyRefs('pipx run', a.packageFlags, a.customIndex);
    return a.positionals.length ? pyRefs('pipx run', [a.positionals[0]], a.customIndex) : [];
  }
  return [];
}

/**
 * An MCP server entry that launches a package (`command: npx|uvx|…`,
 * `args: ['-y', 'pkg@1']`). Reuses the command parser so the two paths cannot
 * disagree about what an invocation names.
 */
export function parseMcpServerEntry(entry: unknown): PackageRef[] {
  if (!entry || typeof entry !== 'object') return [];
  const e = entry as Record<string, unknown>;
  if (typeof e.command !== 'string') return [];
  const args = Array.isArray(e.args) ? e.args.filter((a): a is string => typeof a === 'string') : [];
  const quote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  return parseInstallCommands([e.command, ...args].map(quote).join(' '));
}

// ── Cache ───────────────────────────────────────────────────────────────────

interface CacheEntry {
  at: number;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  publishedAt?: string;
  osvIds: string[];
  hooks: string[];
  sdistOnly: boolean;
}
interface CacheFile { v: 1; entries: Record<string, CacheEntry> }

function stateDir(opts: VetOptions): string {
  return opts.stateDir ?? path.join(os.homedir(), '.shieldcortex', 'state');
}
function cachePath(opts: VetOptions): string {
  return path.join(stateDir(opts), 'package-vetting-cache.json');
}
const cacheKey = (eco: Ecosystem, name: string, version: string) => `${eco}@${name}@${version}`;

function readCache(opts: VetOptions): CacheFile {
  try {
    const st = fs.lstatSync(cachePath(opts));
    if (!st.isFile() || st.size > 4_000_000) return { v: 1, entries: {} };
    const parsed = JSON.parse(fs.readFileSync(cachePath(opts), 'utf-8')) as CacheFile;
    if (parsed?.v === 1 && parsed.entries && typeof parsed.entries === 'object') return parsed;
  } catch { /* absent or corrupt: start empty */ }
  return { v: 1, entries: {} };
}

function writeCache(opts: VetOptions, file: CacheFile, nowMs: number, ttlMs: number): void {
  try {
    const entries: Record<string, CacheEntry> = {};
    for (const [k, e] of Object.entries(file.entries)) if (nowMs - e.at < ttlMs) entries[k] = e;
    const dir = stateDir(opts);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = path.join(dir, `.package-vetting-cache.${process.pid}.${Date.now()}.tmp`);
    fs.writeFileSync(tmp, JSON.stringify({ v: 1, entries }), { mode: 0o600 });
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, cachePath(opts));
  } catch { /* the cache is an optimisation; never fail a vet over it */ }
}

/** A cached, unexpired `MAL-` hit that applies to this request, or null. */
function cachedMaliciousFor(ref: PackageRef, cache: CacheFile, nowMs: number, ttlMs: number): CacheEntry | null {
  for (const e of Object.values(cache.entries)) {
    if (e.ecosystem !== ref.ecosystem || e.name !== ref.name || nowMs - e.at >= ttlMs) continue;
    if (!e.osvIds.some((id) => id.startsWith('MAL-'))) continue;
    if (specCouldResolveTo(ref, e.version)) return e;
  }
  return null;
}

/** Whether a requested spec might resolve to this cached version when we cannot ask the registry. */
function specCouldResolveTo(ref: PackageRef, version: string): boolean {
  const spec = ref.spec;
  if (!spec) return true;
  if (ref.ecosystem === 'npm') {
    if (semver.valid(spec)) return semver.eq(spec, version);
    if (semver.validRange(spec)) return semver.satisfies(version, spec, { includePrerelease: true });
    return true; // dist-tag: cannot tell which version it points at
  }
  const exact = /^===?(.+)$/.exec(spec);
  if (exact) return exact[1] === version;
  return pySatisfies(version, spec);
}

// ── Version resolution ──────────────────────────────────────────────────────

function pyParts(v: string): number[] | null {
  const m = /^(?:\d+!)?(\d+(?:\.\d+)*)$/.exec(v.trim());
  return m ? m[1].split('.').map(Number) : null;
}
function pyCmp(a: number[], b: number[]): number {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** Minimal PEP 440 specifier check over final releases (`==`, `!=`, `>=`, `<=`, `>`, `<`, `~=`, `==x.*`). */
export function pySatisfies(version: string, spec: string): boolean {
  const v = pyParts(version);
  if (!v) return false;
  for (const clause of spec.split(',').filter(Boolean)) {
    const m = /^(===|==|~=|!=|<=|>=|<|>)(.+)$/.exec(clause);
    if (!m) return false;
    const [, op, rhs] = m;
    if (rhs.endsWith('.*')) {
      const base = pyParts(rhs.slice(0, -2));
      if (!base) return false;
      const eq = base.every((x, i) => (v[i] ?? 0) === x);
      if ((op === '==' || op === '===') && !eq) return false;
      if (op === '!=' && eq) return false;
      continue;
    }
    const r = pyParts(rhs);
    if (!r) return false;
    const c = pyCmp(v, r);
    const ok = op === '==' || op === '===' ? c === 0
      : op === '!=' ? c !== 0
      : op === '>=' ? c >= 0
      : op === '<=' ? c <= 0
      : op === '>' ? c > 0
      : op === '<' ? c < 0
      : (c >= 0 && pyCmp(v, [...r.slice(0, Math.max(1, r.length - 1))].map((x, i, arr) => (i === arr.length - 1 ? x + 1 : x))) < 0); // ~=
    if (!ok) return false;
  }
  return true;
}

// ── Registry + OSV lookups ──────────────────────────────────────────────────

class Unchecked extends Error {}

interface Facts {
  version: string;
  publishedAt?: string;
  hooks: string[];
  sdistOnly: boolean;
}

const NPM_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare'];

async function getJson(fetchImpl: FetchLike, url: string, signal: AbortSignal): Promise<unknown> {
  let res;
  try {
    res = await fetchImpl(url, { headers: { accept: 'application/json', 'user-agent': 'shieldcortex-package-vetting' }, signal });
  } catch (err) {
    throw new Unchecked(signal.aborted ? 'timed out' : `network error (${errClass(err)})`);
  }
  if (res.status === 404) throw new Unchecked('package not found in the public registry');
  if (!res.ok) throw new Unchecked(`registry answered HTTP ${res.status}`);
  try { return await res.json(); } catch { throw new Unchecked('registry answer was not valid JSON'); }
}

function errClass(err: unknown): string {
  const code = err && typeof err === 'object' ? (err as { code?: unknown }).code : undefined;
  return typeof code === 'string' && /^[A-Z0-9_]{2,30}$/.test(code) ? code : 'failed';
}

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});

async function resolveNpm(ref: PackageRef, fetchImpl: FetchLike, signal: AbortSignal): Promise<Facts> {
  const enc = ref.name.startsWith('@') ? `@${encodeURIComponent(ref.name.slice(1))}` : encodeURIComponent(ref.name);
  const doc = obj(await getJson(fetchImpl, `https://registry.npmjs.org/${enc}`, signal));
  const versions = obj(doc.versions);
  const tags = obj(doc['dist-tags']);
  const spec = ref.spec ?? 'latest';
  let version: string | undefined;
  if (typeof tags[spec] === 'string') version = tags[spec] as string;
  else if (semver.valid(spec)) version = semver.valid(spec)!;
  else if (semver.validRange(spec)) version = semver.maxSatisfying(Object.keys(versions), spec) ?? undefined;
  if (!version || !versions[version]) throw new Unchecked(`could not resolve "${ref.spec ?? 'latest'}" to a published version`);
  const manifest = obj(versions[version]);
  const scripts = obj(manifest.scripts);
  const hooks = NPM_HOOKS.filter((h) => typeof scripts[h] === 'string' && (scripts[h] as string).trim() !== '');
  // A manifest can also flag install scripts without listing them (registry-computed).
  if (!hooks.length && manifest.hasInstallScript === true) hooks.push('install');
  const published = obj(doc.time)[version];
  return { version, publishedAt: typeof published === 'string' ? published : undefined, hooks, sdistOnly: false };
}

async function resolvePyPI(ref: PackageRef, fetchImpl: FetchLike, signal: AbortSignal): Promise<Facts> {
  const name = encodeURIComponent(ref.name);
  const exact = ref.spec ? /^===?([A-Za-z0-9.!+_-]+)$/.exec(ref.spec) : null;
  let doc: Record<string, unknown>;
  let version: string;
  if (exact) {
    version = exact[1];
    doc = obj(await getJson(fetchImpl, `https://pypi.org/pypi/${name}/${encodeURIComponent(version)}/json`, signal));
  } else {
    const project = obj(await getJson(fetchImpl, `https://pypi.org/pypi/${name}/json`, signal));
    const latest = obj(project.info).version;
    if (!ref.spec) {
      if (typeof latest !== 'string') throw new Unchecked('could not read the latest version');
      version = latest;
      doc = project;
    } else {
      const candidates = Object.keys(obj(project.releases))
        .filter((v) => pyParts(v) && pySatisfies(v, ref.spec!))
        .sort((a, b) => pyCmp(pyParts(a)!, pyParts(b)!));
      const best = candidates[candidates.length - 1];
      if (!best) throw new Unchecked(`could not resolve "${ref.spec}" to a released version`);
      version = best;
      doc = { releases: project.releases, urls: obj(project.releases)[best] };
    }
  }
  const files = (Array.isArray(doc.urls) ? doc.urls : Array.isArray(obj(doc.releases)[version]) ? obj(doc.releases)[version] as unknown[] : []).map(obj);
  const types = files.map((f) => f.packagetype);
  const sdistOnly = files.length > 0 && types.includes('sdist') && !types.includes('bdist_wheel');
  const times = files.map((f) => f.upload_time_iso_8601 ?? f.upload_time).filter((t): t is string => typeof t === 'string').sort();
  return { version, publishedAt: times[0], hooks: [], sdistOnly };
}

async function queryOsv(ref: PackageRef, version: string, fetchImpl: FetchLike, signal: AbortSignal): Promise<string[]> {
  let res;
  try {
    res = await fetchImpl('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'shieldcortex-package-vetting' },
      body: JSON.stringify({ version, package: { name: ref.name, ecosystem: ref.ecosystem } }),
      signal,
    });
  } catch (err) {
    throw new Unchecked(signal.aborted ? 'timed out' : `OSV unreachable (${errClass(err)})`);
  }
  if (!res.ok) throw new Unchecked(`OSV answered HTTP ${res.status}`);
  let body: Record<string, unknown>;
  try { body = obj(await res.json()); } catch { throw new Unchecked('OSV answer was not valid JSON'); }
  const vulns = Array.isArray(body.vulns) ? body.vulns : [];
  const ids: string[] = [];
  for (const v of vulns) {
    const o = obj(v);
    if (typeof o.id === 'string' && !o.withdrawn && /^[A-Za-z0-9][A-Za-z0-9._:-]{2,60}$/.test(o.id)) ids.push(o.id);
  }
  return [...new Set(ids)];
}

// ── Findings ────────────────────────────────────────────────────────────────

/** Names reach the card, so reduce them to a registry-safe shape. */
function safeName(ref: PackageRef): string {
  return /^[A-Za-z0-9@/._~-]{1,120}$/.test(ref.name) ? ref.name : 'this package';
}

export function describeAge(hours: number): string {
  if (hours < 1) return 'less than an hour ago';
  if (hours < 48) return `${Math.floor(hours)} h ago`;
  return `${Math.floor(hours / 24)} days ago`;
}

function listIds(ids: string[], max = 3): string {
  return ids.length <= max ? ids.join(', ') : `${ids.slice(0, max).join(', ')} +${ids.length - max} more`;
}

function buildFindings(v: Omit<PackageVet, 'findings'>, minAgeDays: number, nowMs: number): VettingFinding[] {
  const out: VettingFinding[] = [];
  const label = `${safeName(v.ref)}${v.version ? `@${v.version}` : ''}`;
  if (v.status === 'unchecked') {
    out.push({ kind: 'unchecked', severity: 'advisory', reason: `unchecked: ${v.uncheckedReason ?? 'lookup failed'}` });
  }
  if (v.malicious.length) {
    out.push({ kind: 'malicious', severity: 'catastrophic', reason: `OSV lists ${label} as known malicious (${listIds(v.malicious)})` });
  }
  const advisories = v.osvIds.filter((id) => !id.startsWith('MAL-'));
  if (advisories.length) {
    out.push({ kind: 'advisory', severity: 'advisory', reason: `OSV: ${listIds(advisories)} ${advisories.length === 1 ? 'affects' : 'affect'} this version` });
  }
  if (v.publishedAt) {
    const t = Date.parse(v.publishedAt);
    if (Number.isFinite(t)) {
      const hours = Math.max(0, (nowMs - t) / 3_600_000);
      if (hours < minAgeDays * 24) out.push({ kind: 'new-version', severity: 'advisory', reason: `published ${describeAge(hours)}` });
    }
  }
  if (v.hooks.length) {
    out.push({ kind: 'install-hook', severity: 'advisory', reason: `runs ${v.hooks.length === 1 ? 'a ' : ''}${v.hooks.join(' and ')} script${v.hooks.length === 1 ? '' : 's'} on install` });
  }
  if (v.sdistOnly) {
    out.push({ kind: 'sdist-only', severity: 'advisory', reason: 'ships source only (no prebuilt wheel), so setup code runs on install' });
  }
  return out;
}

// ── Orchestration ───────────────────────────────────────────────────────────

function uncheckedVet(ref: PackageRef, reason: string, minAgeDays: number, nowMs: number): PackageVet {
  const base = { ref, status: 'unchecked' as const, uncheckedReason: reason, osvIds: [], malicious: [], hooks: [], sdistOnly: false };
  return { ...base, findings: buildFindings(base, minAgeDays, nowMs) };
}

async function vetOne(ref: PackageRef, ctx: {
  fetchImpl: FetchLike; signal: AbortSignal; minAgeDays: number; nowMs: number;
  cache: CacheFile; ttlMs: number; opts: VetOptions; dirty: { v: boolean };
}): Promise<PackageVet> {
  const { fetchImpl, signal, minAgeDays, nowMs, cache, ttlMs } = ctx;
  if (ref.customIndex) {
    return uncheckedVet(ref, 'installs from a custom package index, which public records do not describe', minAgeDays, nowMs);
  }
  try {
    const facts = ref.ecosystem === 'npm' ? await resolveNpm(ref, fetchImpl, signal) : await resolvePyPI(ref, fetchImpl, signal);
    const key = cacheKey(ref.ecosystem, ref.name, facts.version);
    const hit = cache.entries[key];
    let osvIds: string[];
    let cached = false;
    if (hit && nowMs - hit.at < ttlMs) { osvIds = hit.osvIds; cached = true; }
    else {
      osvIds = await queryOsv(ref, facts.version, fetchImpl, signal);
      cache.entries[key] = { at: nowMs, ecosystem: ref.ecosystem, name: ref.name, version: facts.version, publishedAt: facts.publishedAt, osvIds, hooks: facts.hooks, sdistOnly: facts.sdistOnly };
      ctx.dirty.v = true;
    }
    const base = {
      ref, status: 'checked' as const, version: facts.version, publishedAt: facts.publishedAt, osvIds,
      malicious: osvIds.filter((id) => id.startsWith('MAL-')), hooks: facts.hooks, sdistOnly: facts.sdistOnly, ...(cached ? { cached } : {}),
    };
    return { ...base, findings: buildFindings(base, minAgeDays, nowMs) };
  } catch (err) {
    const reason = err instanceof Unchecked ? err.message : 'lookup failed';
    const mal = cachedMaliciousFor(ref, cache, nowMs, ttlMs);
    if (mal) {
      // Offline, but a fresh record says this package is malicious: that still blocks.
      const base = {
        ref, status: 'checked' as const, version: mal.version, publishedAt: mal.publishedAt, osvIds: mal.osvIds,
        malicious: mal.osvIds.filter((id) => id.startsWith('MAL-')), hooks: mal.hooks, sdistOnly: mal.sdistOnly, cached: true,
      };
      return { ...base, findings: buildFindings(base, minAgeDays, nowMs) };
    }
    return uncheckedVet(ref, reason, minAgeDays, nowMs);
  }
}

/**
 * Vet a set of package references. Never throws; a failed lookup is an
 * `unchecked` entry, never a clean one. One shared deadline covers every
 * request, so the whole call costs at most `budgetMs` of wall clock.
 */
export async function vetPackages(refs: readonly PackageRef[], opts: VetOptions = {}): Promise<VettingResult> {
  const nowMs = opts.nowMs ?? Date.now();
  const minAgeDays = Number.isFinite(opts.minAgeDays) && (opts.minAgeDays as number) >= 0 ? (opts.minAgeDays as number) : DEFAULT_MIN_AGE_DAYS;
  const ttlMs = opts.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  const budgetMs = opts.budgetMs ?? DEFAULT_BUDGET_MS;
  const unique: PackageRef[] = [];
  const seen = new Set<string>();
  for (const r of refs) {
    const k = `${r.ecosystem}@${r.name}@${r.spec ?? ''}`;
    if (!seen.has(k)) { seen.add(k); unique.push(r); }
  }
  const fetchImpl: FetchLike = opts.fetchImpl ?? ((url, init) => (globalThis as unknown as { fetch: FetchLike }).fetch(url, init));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), budgetMs);
  timer.unref?.();
  const cache = readCache(opts);
  const dirty = { v: false };
  const packages: PackageVet[] = [];
  try {
    const head = unique.slice(0, MAX_PACKAGES_PER_COMMAND);
    const results = await Promise.all(head.map((ref) => vetOne(ref, { fetchImpl, signal: controller.signal, minAgeDays, nowMs, cache, ttlMs, opts, dirty }).catch(() => uncheckedVet(ref, 'lookup failed', minAgeDays, nowMs))));
    packages.push(...results);
    for (const ref of unique.slice(MAX_PACKAGES_PER_COMMAND)) packages.push(uncheckedVet(ref, `more than ${MAX_PACKAGES_PER_COMMAND} packages in one command`, minAgeDays, nowMs));
  } finally {
    clearTimeout(timer);
  }
  if (dirty.v) writeCache(opts, cache, nowMs, ttlMs);
  const all = packages.flatMap((p) => p.findings);
  const rank = (f: VettingFinding) => (f.kind === 'malicious' ? 0 : f.kind === 'advisory' ? 1 : f.kind === 'install-hook' || f.kind === 'sdist-only' ? 2 : f.kind === 'new-version' ? 3 : 4);
  const reasons = [...new Set(all.sort((a, b) => rank(a) - rank(b)).map((f) => f.reason))];
  return { packages, malicious: packages.some((p) => p.malicious.length > 0), reasons };
}

/** Parse a shell command and vet whatever it installs. Null when it installs nothing by name. */
export async function vetCommand(command: string, opts: VetOptions = {}): Promise<VettingResult | null> {
  if (opts.enabled === false) return null;
  if (!INSTALLER_PREFILTER.test(command)) return null;
  const refs = parseInstallCommands(command);
  if (!refs.length) return null;
  return vetPackages(refs, opts);
}

const INSTALLER_PREFILTER = /\b(?:npm|pnpm|yarn|bun|bunx|npx|pip\d*|python[\d.]*|uv|uvx|pipx)\b/;

/** What the enforcement surfaces consume: structural, so the plugin needs no compile-time import. */
export interface ToolVettingOutcome {
  malicious: boolean;
  /** Plain-English reasons, ready for the approval card and the audit row. */
  reasons: string[];
  /** Compact per-package record for the audit row (no command text). */
  audit: Array<{ ecosystem: Ecosystem; name: string; version?: string; status: 'checked' | 'unchecked'; kinds: FindingKind[]; reasons: string[] }>;
}

/** Entry point for a tool call. Never throws; null when the call installs nothing by name. */
export async function vetToolCall(
  toolName: string,
  args: Record<string, unknown>,
  opts: VetOptions = {},
): Promise<ToolVettingOutcome | null> {
  try {
    const command = extractCommand(args ?? {});
    if (!command) return null;
    const res = await vetCommand(command, opts);
    if (!res) return null;
    return {
      malicious: res.malicious,
      reasons: res.reasons,
      audit: res.packages.map((p) => ({ ecosystem: p.ref.ecosystem, name: safeName(p.ref), version: p.version, status: p.status, kinds: p.findings.map((f) => f.kind), reasons: p.findings.map((f) => f.reason) })),
    };
  } catch {
    return null;
  }
}

// ── Verdict policy ──────────────────────────────────────────────────────────

export const VETTING_SIGNAL = 'package-vetting';
export const MALICIOUS_SIGNAL = 'known-malicious-package';

interface VerdictLike {
  decision: 'allow' | 'require_approval' | 'block';
  severity: string;
  signals: string[];
  reason: string;
  [k: string]: unknown;
}

/**
 * Fold a vetting outcome into a guard verdict.
 *
 *   - known malicious → `block` / `catastrophic` (door-less on every plane,
 *     including advisory mode and shadow);
 *   - any other finding → the verdict's decision and severity are UNCHANGED;
 *     only the signals and the reason text gain the vetting reasons.
 */
export function applyVettingToVerdict<V extends VerdictLike>(v: V, outcome: ToolVettingOutcome | null): V {
  if (!outcome || outcome.reasons.length === 0) return v;
  const shown = outcome.reasons.slice(0, 4).join('; ');
  if (outcome.malicious) {
    return {
      ...v,
      decision: 'block',
      severity: 'catastrophic',
      signals: [...new Set([...v.signals, VETTING_SIGNAL, MALICIOUS_SIGNAL])],
      reason: `Package install blocked: ${shown}`,
    };
  }
  // An "unchecked" note is information about the lookup, not about the package:
  // it must not add a signal, or a network blip would stop the approval broker
  // pre-clearing an install it would otherwise clear (fail open).
  const substantive = outcome.audit.some((a) => a.kinds.some((k) => k !== 'unchecked'));
  return {
    ...v,
    signals: substantive ? [...new Set([...v.signals, VETTING_SIGNAL])] : v.signals,
    reason: `${v.reason} — package check: ${shown}`,
  };
}

/** Raw config → the vetting options the surfaces pass through. */
export function normalisePackageVettingConfig(raw: unknown): PackageVettingConfig {
  const o = obj(raw);
  const out: PackageVettingConfig = {};
  if (o.enabled === false) out.enabled = false;
  if (typeof o.minAgeDays === 'number' && Number.isFinite(o.minAgeDays) && o.minAgeDays >= 0 && o.minAgeDays <= 365) out.minAgeDays = o.minAgeDays;
  return out;
}

/** MCP server entries that launch a package: vet and return reasons (report-only). One shared budget. */
export async function vetMcpServers(
  servers: ReadonlyArray<{ name: string; entry: unknown }>,
  opts: VetOptions = {},
): Promise<Array<{ name: string; malicious: boolean; reasons: string[] }>> {
  if (opts.enabled === false) return [];
  const perServer = servers.map((s) => ({ name: s.name, refs: parseMcpServerEntry(s.entry) })).filter((s) => s.refs.length > 0);
  if (!perServer.length) return [];
  const res = await vetPackages(perServer.flatMap((s) => s.refs), opts);
  const key = (r: PackageRef) => `${r.ecosystem}@${r.name}@${r.spec ?? ''}`;
  const byRef = new Map(res.packages.map((p) => [key(p.ref), p]));
  const out: Array<{ name: string; malicious: boolean; reasons: string[] }> = [];
  for (const s of perServer) {
    const pkgs = s.refs.map((r) => byRef.get(key(r))).filter((p): p is PackageVet => !!p);
    const reasons = [...new Set(pkgs.flatMap((p) => p.findings.map((f) => f.reason)))];
    if (reasons.length) out.push({ name: s.name, malicious: pkgs.some((p) => p.malicious.length > 0), reasons });
  }
  return out;
}
