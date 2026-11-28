/**
 * FROZEN COPY. Do not edit, do not import from product code.
 *
 * The install-command parser exactly as it stood on `main` at
 * 482f30a973a0b0c32337879bf0a784bca2618998 (the merge of #1084, Part A of #1054),
 * `src/defence/iron-dome/package-vetting.ts` from the "Command parsing" banner up to
 * the "Cache" banner, byte for byte. The only additions are this header, the `path`
 * import and the `PackageRef` type as it was on that commit.
 *
 * It is the oracle of the lookup-parity test (`package-vetting-parity-1054.test.ts`):
 * for every command in the fixed list, every package this parser puts on the public
 * lookup path must also be on the public lookup path of the current parser.
 */
/* eslint-disable */
import path from 'path';

export type Ecosystem = 'npm' | 'PyPI';

export interface PackageRef {
  ecosystem: Ecosystem;
  name: string;
  spec: string | null;
  installer: string;
  customIndex?: boolean;
}

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
  if (!token) return null;
  // npm alias: `<alias>@npm:<real>[@spec]` (also a bare `npm:<real>[@spec]`).
  // The alias name is irrelevant; the target is what gets installed, so vet it.
  const alias = /^(?:(?:@[^@/\s]+\/)?[^@/\s:]+@)?npm:(.+)$/.exec(token);
  if (alias) return /^npm:/.test(alias[1]) ? null : parseNpmSpecifier(alias[1]);
  if (isNonRegistrySpec(token)) return null;
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

/** Environment variables that redirect an installer to a different registry/index. */
const INDEX_ENV = /^(?:npm_config_(?:[^=]*:)?registry|PIP_(?:EXTRA_)?INDEX_URL|PIP_FIND_LINKS|UV_(?:DEFAULT_|EXTRA_)?INDEX(?:_URL)?|UV_FIND_LINKS)=/i;

/**
 * Package installs named by a shell command: npm/pnpm/bun add or install, yarn add,
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
    let envIndex = false;
    // Leading VAR=value assignments and transparent wrappers.
    for (;;) {
      if (w.length && /^[A-Za-z_][A-Za-z0-9_@:.-]*=/.test(w[0])) { if (INDEX_ENV.test(w[0])) envIndex = true; w = w.slice(1); continue; }
      if (w.length && WRAPPERS.has(path.basename(w[0]))) {
        w = w.slice(1);
        while (w.length && (w[0].startsWith('-') || /^[A-Za-z_][A-Za-z0-9_@:.-]*=/.test(w[0]) || /^\d+[smhd]?$/.test(w[0]))) {
          if (INDEX_ENV.test(w[0])) envIndex = true;
          w = w.slice(1);
        }
        continue;
      }
      break;
    }
    if (!w.length) continue;
    const bin = path.basename(w[0]);
    const rest = w.slice(1);
    const stmtRefs: PackageRef[] = [];

    if (SHELLS.has(bin)) {
      const ci = rest.findIndex((x) => /^-[a-z]*c$/.test(x));
      if (ci >= 0 && rest[ci + 1]) stmtRefs.push(...parseInstallCommands(rest[ci + 1], depth + 1));
    } else if (NPM_FAMILY.has(bin)) {
      stmtRefs.push(...parseNpmFamily(bin, rest));
    } else if (bin === 'npx' || bin === 'bunx') {
      stmtRefs.push(...parseNpx(bin, rest));
    } else if (/^pip\d*(?:\.\d+)?$/.test(bin)) {
      stmtRefs.push(...parsePip(bin, rest));
    } else if (/^python[\d.]*$/.test(bin) && rest[0] === '-m' && /^pip\d*$/.test(rest[1] ?? '')) {
      stmtRefs.push(...parsePip('pip', rest.slice(2)));
    } else if (bin === 'uv') {
      stmtRefs.push(...parseUv(rest));
    } else if (bin === 'uvx') {
      stmtRefs.push(...parseUvx('uvx', rest));
    } else if (bin === 'pipx') {
      stmtRefs.push(...parsePipx(rest));
    }
    // An index/registry env var set for this statement applies to every package it names.
    if (envIndex) for (const r of stmtRefs) r.customIndex = true;
    refs.push(...stmtRefs);
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
  let preIndex = false;
  while (i < rest.length && rest[i].startsWith('-')) {
    if (INDEX_FLAGS_NPM.has(rest[i].split('=')[0])) preIndex = true;
    i += VALUE_FLAGS_NPM.has(rest[i]) && !rest[i].includes('=') ? 2 : 1;
  }
  let verb = rest[i];
  if (verb === undefined) return [];
  if (bin === 'yarn' && verb === 'global') { i++; verb = rest[i]; }
  const after = rest.slice(i + 1);
  if (verb === 'dlx') {
    return parseNpx(`${bin} dlx`, after, preIndex);
  }
  if (bin === 'npm' && (verb === 'exec' || verb === 'x')) return parseNpx('npm exec', after, preIndex);
  if (!NPM_ADD_VERBS.has(verb)) return [];
  // `yarn install` / `pnpm install` / `npm ci` take no packages; `yarn add` does.
  if (bin === 'yarn' && verb !== 'add') return [];
  const a = collectArgs(after, VALUE_FLAGS_NPM, INDEX_FLAGS_NPM, new Set());
  return npmRefs(`${bin} ${verb}`, a.positionals, a.customIndex || preIndex);
}

function parseNpx(installer: string, rest: string[], preIndex = false): PackageRef[] {
  const a = collectArgs(rest, VALUE_FLAGS_NPM, INDEX_FLAGS_NPM, new Set(['-p', '--package']));
  const custom = a.customIndex || preIndex;
  // With -p/--package the positionals are the command to run, not packages.
  if (a.packageFlags.length) return npmRefs(installer, a.packageFlags, custom);
  // Everything after the first positional belongs to the executed command.
  return a.positionals.length ? npmRefs(installer, [a.positionals[0]], custom) : [];
}

function parsePip(bin: string, rest: string[]): PackageRef[] {
  let i = 0;
  let preIndex = false;
  while (i < rest.length && rest[i].startsWith('-')) {
    if (INDEX_FLAGS_PIP.has(rest[i].split('=')[0])) preIndex = true;
    i += VALUE_FLAGS_PIP.has(rest[i]) && !rest[i].includes('=') ? 2 : 1;
  }
  if (!PIP_VERBS.has(rest[i] ?? '')) return [];
  const a = collectArgs(rest.slice(i + 1), VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set());
  return pyRefs(`${bin} install`, a.positionals, a.customIndex || preIndex);
}

/** Index of the first non-flag word, skipping the values of value-taking flags; also reports an index flag seen before it. */
function firstWord(args: readonly string[], valueFlags: ReadonlySet<string>, indexFlags: ReadonlySet<string>): { at: number; preIndex: boolean } {
  let i = 0;
  let preIndex = false;
  while (i < args.length && args[i].startsWith('-')) {
    if (indexFlags.has(args[i].split('=')[0])) preIndex = true;
    i += valueFlags.has(args[i]) && !args[i].includes('=') ? 2 : 1;
  }
  return { at: i < args.length ? i : -1, preIndex };
}

function parseUv(rest: string[]): PackageRef[] {
  const first = firstWord(rest, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP);
  if (first.at < 0) return [];
  const verb = rest[first.at];
  const after = rest.slice(first.at + 1);
  if (verb === 'add') {
    const a = collectArgs(after, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set());
    return pyRefs('uv add', a.positionals, a.customIndex || first.preIndex);
  }
  if (verb === 'pip') {
    const sec = firstWord(after, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP);
    if (sec.at >= 0 && after[sec.at] === 'install') {
      const a = collectArgs(after.slice(sec.at + 1), VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set());
      return pyRefs('uv pip install', a.positionals, a.customIndex || first.preIndex || sec.preIndex);
    }
    return [];
  }
  if (verb === 'tool') {
    const sec = firstWord(after, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP);
    const pre = first.preIndex || sec.preIndex;
    if (sec.at >= 0 && after[sec.at] === 'run') return parseUvx('uv tool run', after.slice(sec.at + 1), pre);
    if (sec.at >= 0 && after[sec.at] === 'install') {
      const a = collectArgs(after.slice(sec.at + 1), VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set());
      return pyRefs('uv tool install', a.positionals, a.customIndex || pre, true);
    }
  }
  return [];
}

function parseUvx(installer: string, rest: string[], preIndex = false): PackageRef[] {
  const a = collectArgs(rest, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set(['--from']));
  const custom = a.customIndex || preIndex;
  if (a.packageFlags.length) return pyRefs(installer, a.packageFlags, custom, true);
  return a.positionals.length ? pyRefs(installer, [a.positionals[0]], custom, true) : [];
}

function parsePipx(rest: string[]): PackageRef[] {
  const f = firstWord(rest, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP);
  if (f.at < 0) return [];
  const verb = rest[f.at];
  const after = rest.slice(f.at + 1);
  if (verb === 'install') {
    const a = collectArgs(after, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set());
    return pyRefs('pipx install', a.positionals.slice(0, 1), a.customIndex || f.preIndex);
  }
  if (verb === 'run') {
    const a = collectArgs(after, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set(['--spec']));
    const custom = a.customIndex || f.preIndex;
    if (a.packageFlags.length) return pyRefs('pipx run', a.packageFlags, custom);
    return a.positionals.length ? pyRefs('pipx run', [a.positionals[0]], custom) : [];
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
