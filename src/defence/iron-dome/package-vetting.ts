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
 * still blocks while the network is away. Only `MAL-` hits are ever cached: a
 * clean answer is never reused, because the window in which a report for a
 * fresh version arrives is exactly the window a cached "clean" would hide.
 *
 * The malicious-package check does not depend on registry resolution or on the
 * per-command package cap: one OSV `querybatch` covers EVERY package named in
 * the command, on its own deadline, so padding a command with decoys or
 * burning the registry budget cannot hide a `MAL-` package.
 *
 * Nothing here installs, downloads or executes a package: the only requests
 * are metadata GETs to the registry and one POST to OSV.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import semver from 'semver';
import { extractCommand } from './tool-action-guard.js';
import { npmCommand, npxArgv, parseNpmArgv, type NpmArgv } from './npm-cli-args.js';

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
  /**
   * An option or environment variable on the command that changes WHICH version
   * the installer picks (`--tag`, `--before`, `--pre`, …), from a fixed
   * vocabulary. This check does not model those rules, so unless the spec pins
   * an exact version the version this install would fetch is unconfirmed.
   */
  versionOption?: string;
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
  /**
   * `malicious` came from a name-only OSV answer (a malicious release exists under this
   * name) and the version this install would fetch could not be checked.
   */
  unconfirmedVersion?: boolean;
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
/** Extra registry + version lookups for refs past the cap that carry a name-only `MAL-` hit. */
const MAX_EXTRA_LOOKUPS = 8;
/** Chunks of the OSV batch in flight at once. */
const BATCH_CONCURRENCY = 3;

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

/**
 * Flags (per tool family) that consume the NEXT word as their value. npm itself
 * is read by {@link parseNpmArgv} with npm's own option table; this set serves
 * pnpm / yarn / bun, where `-w` / `--workspace` are switches.
 */
const VALUE_FLAGS_NPM = new Set([
  '--prefix', '--registry', '--cache', '--userconfig', '--tag', '-C', '--dir', '--filter', '-F',
  '--cwd', '--save-prefix', '--loglevel', '--omit', '--include', '--scope', '--otp', '--before', '--store-dir',
  '--resolution-mode',
  // pnpm 10's value-taking options (`pnpm add|install|dlx --help`).
  '--child-concurrency', '--filter-prod', '--hoist-pattern', '--lockfile-dir', '--modules-dir', '--network-concurrency',
  '--package-import-method', '--public-hoist-pattern', '--reporter', '--test-pattern', '--trust-policy',
  '--trust-policy-exclude', '--trust-policy-ignore-after', '--virtual-store-dir',
]);
const VALUE_FLAGS_PIP = new Set([
  '-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-i', '--index-url', '--extra-index-url', '-f',
  '--find-links', '-t', '--target', '--prefix', '--root', '--python', '--platform', '--abi', '--implementation',
  '--python-version', '--only-binary', '--no-binary', '--progress-bar', '--upgrade-strategy', '--src', '--proxy',
  '--cert', '--client-cert', '--cache-dir', '--log', '--retries', '--timeout', '--trusted-host', '--exists-action',
  '--config-settings', '-C', '--default-index', '--index', '--index-strategy', '--resolution', '--with',
  '--project', '--directory', '--package', '--constraints', '--overrides',
  // uv: `-p` is `--python`; selection options that take a value.
  '-p', '--prerelease', '--exclude-newer',
  // The rest of pip 24's and uv 0.11's value-taking options (`--help` of `pip install`,
  // `uv pip install`, `uv add`, `uv tool run|install`, `uvx`), so their values are not read as packages.
  ...('--allow-insecure-host --bounds --branch --build-constraints --color --config-file --config-setting '
    + '--config-settings-package --default-timeout --env-file --exclude-newer-package --excludes --extra --fork-strategy '
    + '--global-option --group --keyring-provider --link-mode --local-log --log-file --marker --no-binary-package '
    + '--no-build-isolation-package --no-build-package --no-editable-package --no-install-package --no-sources-package '
    + '--optional --pypi-url --python-platform --refresh-package --reinstall-package --report --requirements --rev '
    + '--root-user-action --script --source --source-dir --source-directory --tag --torch-backend --upgrade-group '
    + '--upgrade-package --use-deprecated --use-feature --with-editable --with-executables-from --with-requirements '
    + '-P -b -m -w').split(' '),
]);
/** pipx's own value-taking options (its `-f` is `--force` and its `-e` is `--editable`, both switches). */
const VALUE_FLAGS_PIPX = new Set(['--suffix', '--python', '--index-url', '-i', '--pip-args', '--spec', '--preinstall', '--backend']);
const INDEX_FLAGS_NPM = new Set(['--registry']);
const INDEX_FLAGS_PIP = new Set(['-i', '--index-url', '--extra-index-url', '--default-index', '--index', '-f', '--find-links']);
/**
 * Options that change which version the installer selects for a range, a tag or
 * an unpinned name (npm `--tag` sets the default dist-tag, `--before` picks the
 * newest version published before a date, `--userconfig` / `--globalconfig`
 * read either from a file; pnpm `--resolution-mode` can pick the lowest;
 * pip/uv `--pre`/`--prerelease` admit pre-releases, `--exclude-newer` (and
 * `--exclude-newer-package`) is uv's `--before`, `--resolution` /
 * `--fork-strategy` can pick the lowest, `--only-binary` / `--prefer-binary`
 * can pick an older release that has a wheel, `--python-version` /
 * `--platform` / `--abi` / `--implementation` / `--python-platform` resolve
 * for another interpreter; pipx `--pip-args` passes any pip option). The
 * registry lookup below follows none of these, so a ref carrying one is never
 * treated as resolved: see {@link PackageRef.versionOption}.
 */
const VERSION_FLAGS_NPM = new Set(['--tag', '--before', '--include-staged', '--resolution-mode', '--userconfig', '--globalconfig']);
const VERSION_FLAGS_PIP = new Set([
  '--pre', '--prerelease', '--exclude-newer', '--exclude-newer-package', '--resolution', '--fork-strategy', '--only-binary',
  '--prefer-binary', '--python-version', '--platform', '--abi', '--implementation', '--python-platform', '--pip-args',
]);
/** npm config keys (as {@link parseNpmArgv} canonicalises them) that select the version. */
const NPM_VERSION_KEYS = new Set([...VERSION_FLAGS_NPM].map((f) => f.slice(2)));

/**
 * The {@link PackageRef.versionOption} of an option this check does not
 * recognise. Installers accept aliases and abbreviations (npm `--bef` is
 * `--before`, pip and pipx take any unique prefix) and add options over time,
 * so an unrecognised option may select the version: never resolved as if absent.
 */
export const UNRECOGNISED_OPTION = 'an option this check does not recognise';

/**
 * Every option the pnpm / yarn / bun forms are known to take that is not an npm
 * option (npm's own are recognised through {@link parseNpmArgv}): pnpm 10
 * `add|install|dlx --help`, yarn 1/4 `add|dlx`, bun 1 `add|x`.
 */
const NPM_FAMILY_EXTRA = new Set([
  ...('--aggregate-output --allow-build --child-concurrency --fail-if-no-match --filter --filter-prod --fix-lockfile '
    + '--global-dir --hoist-pattern --ignore-pnpmfile --ignore-workspace --lockfile-dir --lockfile-only '
    + '--merge-git-branch-lockfiles --modules-dir --network-concurrency --frozen-lockfile --no-frozen-lockfile --hoist '
    + '--no-hoist --lockfile --no-lockfile --no-optional --optimistic-repeat-install --package-import-method --parallel '
    + '--prefer-frozen-lockfile --public-hoist-pattern --reporter --resolution-only --save-catalog --save-catalog-name '
    + '--shamefully-hoist --side-effects-cache --no-side-effects-cache --side-effects-cache-readonly --stream '
    + '--strict-peer-dependencies --test-pattern --trust-policy --trust-policy-exclude --trust-policy-ignore-after '
    + '--use-running-store-server --use-stderr --use-store-server --virtual-store-dir --workspace-concurrency --dir '
    + '--prod --recursive --workspace --workspace-root --shell-mode --store-dir --cwd --silent --peer --exact --tilde --caret '
    + '--interactive --cached --mode --ignore-workspace-root-check --immutable --check-cache --inline-builds '
    + '--skip-builds --no-save --no-progress --no-summary --no-verify --trust --backend --config --linker '
    + '--concurrent-scripts --cache-dir --no-cache --analyze --only-missing --bun --yarn --quiet --verbose').split(' '),
  ...'-r -F -w -W -C -D -P -O -E -T -i -g -s -c -d -p -f -a -b -y -q -v -h'.split(' '),
]);

/**
 * pip 24 `install`, uv 0.11 (`pip install`, `add`, `tool run|install`, `uvx`,
 * global options) and pipx 1 (`install`, `run`) options: anything else on a
 * Python install is unrecognised.
 */
const PY_KNOWN = new Set([
  ...('--abi --active --all-extras --allow-insecure-host --bounds --branch --break-system-packages '
    + '--build-constraints --cache-dir --cert --check-build-dependencies --client-cert --color --compile '
    + '--compile-bytecode --config-file --config-setting --config-settings --config-settings-package '
    + '--constraint --constraints --debug --default-index --default-timeout --dev --directory '
    + '--disable-pip-version-check --dry-run --editable --env-file --exact --exclude-newer '
    + '--exclude-newer-package --excludes --exists-action --extra --extra-index-url --find-links --force '
    + '--force-reinstall --fork-strategy --from --frozen --global-option --group --help --ignore-installed '
    + '--ignore-requires-python --implementation --index --index-strategy --index-url --isolated '
    + '--keyring-provider --lfs --link-mode --local-log --locked --log --log-file --managed-python '
    + '--marker --no-binary --no-binary-package --no-break-system-packages --no-build --no-build-isolation '
    + '--no-build-isolation-package --no-build-package --no-cache --no-cache-dir --no-clean --no-color '
    + '--no-compile --no-config --no-dependencies --no-deps --no-editable --no-editable-package '
    + '--no-env-file --no-index --no-input --no-install-local --no-install-package --no-install-project '
    + '--no-install-workspace --no-managed-python --no-progress --no-python-downloads '
    + '--no-python-version-warning --no-sources --no-sources-package --no-sync --no-use-pep517 --no-user '
    + '--no-verify-hashes --no-warn-conflicts --no-warn-script-location --no-workspace --offline '
    + '--only-binary --optional --overrides --package --platform --pre --prefer-binary --prefix '
    + '--prerelease --progress-bar --project --proxy --pypi-url --python --python-platform '
    + '--python-version --quiet --raw --refresh --refresh-package --reinstall --reinstall-package --report '
    + '--require-hashes --require-venv --require-virtualenv --requirement --requirements --resolution '
    + '--retries --rev --root --root-user-action --script --source --source-dir --source-directory --src '
    + '--strict --system --system-certs --tag --target --timeout --torch-backend --trusted-host --upgrade '
    + '--upgrade-group --upgrade-package --upgrade-strategy --use-deprecated --use-feature --use-pep517 '
    + '--user --verbose --version --with --with-editable --with-executables-from --with-requirements '
    + '--workspace --preview --no-preview --native-tls --python-preference --no-python-downloads').split(' '),
  // pipx
  ...('--include-deps --suffix --fetch-missing-python --system-site-packages --pip-args --preinstall --global '
    + '--backend --path --pypackages --spec').split(' '),
  ...'-C -I -P -U -V -b -c -e -f -h -i -m -n -p -q -r -t -v -w'.split(' '),
]);

/**
 * What an option word is to the check: selects the version (the canonical flag), unrecognised, or
 * neither; and whether it takes the next word as its value when it is read through npm's table.
 */
interface OptionClass { version?: string; unknown?: boolean; takesValue?: boolean }
type Classify = (word: string) => OptionClass;

/** A `-abc` cluster of single-letter options is known when each letter is (up to a value-taking one). */
function shortCluster(word: string, known: ReadonlySet<string>, valueFlags: ReadonlySet<string>): OptionClass {
  for (const c of word.slice(1)) {
    if (!known.has(`-${c}`)) return { unknown: true };
    if (valueFlags.has(`-${c}`)) return {};
  }
  return {};
}

/** pnpm / yarn / bun: their own options, else read the way npm would (aliases, prefixes), else unrecognised. */
function classifyNpmFamily(word: string): OptionClass {
  const flag = word.split('=')[0];
  if (VERSION_FLAGS_NPM.has(flag)) return { version: flag };
  if (NPM_FAMILY_EXTRA.has(flag) || VALUE_FLAGS_NPM.has(flag)) return {};
  const opts = parseNpmArgv([flag, 'x']).options;
  const takesValue = opts.at(-1)?.value === 'x';
  const version = opts.find((o) => NPM_VERSION_KEYS.has(o.key));
  if (version) return { version: `--${version.key}`, takesValue };
  if (opts.length && opts.every((o) => o.known)) return { takesValue };
  if (/^-[^-]/.test(flag)) return shortCluster(flag, NPM_FAMILY_EXTRA, new Set());
  return { unknown: true };
}

function classifyPython(word: string): OptionClass {
  const flag = word.split('=')[0];
  if (VERSION_FLAGS_PIP.has(flag)) return { version: flag };
  if (PY_KNOWN.has(flag)) return {};
  if (/^-[^-]/.test(flag)) return shortCluster(flag, PY_KNOWN, VALUE_FLAGS_PIP);
  return { unknown: true };
}

interface Positionals {
  positionals: string[];
  /** Values given to -p/--package style flags. */
  packageFlags: string[];
  customIndex: boolean;
  /** `-r file` style inputs the vetting cannot resolve. */
  fileInputs: boolean;
  /** The first version-selection option seen (see {@link PackageRef.versionOption}). */
  versionOption?: string;
}

interface CollectOptions {
  /** How an option word bears on version selection (see {@link PackageRef.versionOption}). */
  classify?: Classify;
  /**
   * Runner form (`npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `uvx`, `uv tool run`,
   * `pipx run`): the installer reads its own options only up to the first
   * positional, which names what to run; every later word, dashed or not, is an
   * argument of the program being run (npm's `npx-cli.js` inserts `--` there).
   */
  stopAtFirstPositional?: boolean;
}

function collectArgs(args: readonly string[], valueFlags: ReadonlySet<string>, indexFlags: ReadonlySet<string>, pkgFlags: ReadonlySet<string>, opts: CollectOptions = {}): Positionals {
  const out: Positionals = { positionals: [], packageFlags: [], customIndex: false, fileInputs: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { out.positionals.push(...args.slice(i + 1)); break; }
    if (a.startsWith('-') && a !== '-') {
      const eq = a.indexOf('=');
      const flag = eq > 0 ? a.slice(0, eq) : a;
      const inlineValue = eq > 0 ? a.slice(eq + 1) : undefined;
      if (indexFlags.has(flag)) out.customIndex = true;
      const cls = opts.classify?.(a);
      if (cls?.version) out.versionOption ??= cls.version;
      else if (cls?.unknown) out.versionOption ??= UNRECOGNISED_OPTION;
      if (flag === '-r' || flag === '--requirement' || flag === '-e' || flag === '--editable') out.fileInputs = true;
      if (pkgFlags.has(flag)) {
        const v = inlineValue ?? args[i + 1];
        if (v !== undefined) out.packageFlags.push(v);
        if (inlineValue === undefined) i++;
        continue;
      }
      // Short flag with attached value: -wfoo / -rreq.txt (only for the value-taking shorts).
      if (inlineValue === undefined && (valueFlags.has(flag) || cls?.takesValue)) i++;
      continue;
    }
    out.positionals.push(a);
    if (opts.stopAtFirstPositional) break;
  }
  return out;
}

/**
 * Pre-verb options (`pnpm --tag beta add x`, `uv --prerelease allow pip install x`): value-skipping scan up to the verb.
 * An unrecognised option may take a value the check does not know about: the word after it is
 * skipped as that value when it is not itself one of `verbs`.
 */
interface PreVerb { at: number; preIndex: boolean; versionOption?: string }
function scanPreVerb(args: readonly string[], valueFlags: ReadonlySet<string>, indexFlags: ReadonlySet<string>, classify: Classify, verbs: ReadonlySet<string>): PreVerb {
  let i = 0;
  const out: PreVerb = { at: -1, preIndex: false };
  while (i < args.length && args[i].startsWith('-')) {
    const flag = args[i].split('=')[0];
    if (indexFlags.has(flag)) out.preIndex = true;
    const cls = classify(args[i]);
    if (cls.version) out.versionOption ??= cls.version;
    else if (cls.unknown) out.versionOption ??= UNRECOGNISED_OPTION;
    const takesNext = !args[i].includes('=') && (valueFlags.has(args[i]) || cls.takesValue === true
      || (cls.unknown === true && i + 1 < args.length && !args[i + 1].startsWith('-') && !verbs.has(args[i + 1])));
    i += takesNext ? 2 : 1;
  }
  out.at = i < args.length ? i : -1;
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
  // `name@<url | git+… | github:… | user/repo | file:…>` installs from that source, not the
  // registry: a version, range or dist-tag never holds `/` or `:`.
  if (spec !== null && /[/:]/.test(spec)) return null;
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
/** Environment variables that change which version is selected (the {@link VERSION_FLAGS_NPM} / {@link VERSION_FLAGS_PIP} settings). */
const VERSION_ENV = /^(npm_config_(?:tag|before|include[_-]staged|resolution[_-]mode|userconfig|globalconfig)|PIP_(?:PRE|ONLY_BINARY|PREFER_BINARY|PYTHON_VERSION|PLATFORM|ABI|IMPLEMENTATION)|UV_(?:PRERELEASE|EXCLUDE_NEWER|RESOLUTION))=/i;

/** Index / version-selection variables exported earlier in the command (`export NPM_CONFIG_TAG=beta; npm i x`). */
interface CarriedEnv { index: boolean; version?: string }

/**
 * Package installs named by a shell command: npm/pnpm/bun add or install, yarn add,
 * npx/bunx/pnpm dlx/yarn dlx/npm exec, pip/pip3 install (also `python -m pip`),
 * uv add / uv pip install / uvx / uv tool run|install, pipx install|run.
 *
 * Deliberately conservative: only registry-name arguments yield a ref. Paths,
 * URLs, git specs and tarballs are skipped (nothing to look up by name), and a
 * bare `npm install` (no packages) yields nothing.
 */
export function parseInstallCommands(command: string, depth = 0, inherited: CarriedEnv = { index: false }): PackageRef[] {
  if (typeof command !== 'string' || !command || depth > MAX_DEPTH) return [];
  const refs: PackageRef[] = [];
  const carried: CarriedEnv = { ...inherited };
  const carry = (word: string) => {
    if (INDEX_ENV.test(word)) carried.index = true;
    const m = VERSION_ENV.exec(word);
    if (m) carried.version ??= m[1].toLowerCase();
  };
  for (const stmt of splitStatements(command)) {
    let w = words(stmt);
    // `export VAR=value` (or `declare -x` / `typeset -x`) sets the variable for every later
    // statement; so may a bare `VAR=value` statement when VAR is already exported.
    if (w[0] === 'export' || ((w[0] === 'declare' || w[0] === 'typeset') && w.includes('-x'))) {
      for (const x of w.slice(1)) carry(x);
      continue;
    }
    if (w.length && w.every((x) => /^[A-Za-z_][A-Za-z0-9_@:.-]*=/.test(x))) {
      for (const x of w) carry(x);
      continue;
    }
    let envIndex = carried.index;
    let envVersion: string | undefined = carried.version;
    const noteEnv = (word: string) => {
      if (INDEX_ENV.test(word)) envIndex = true;
      // The variable name, lower-cased, from the fixed alternatives above: safe to show.
      const m = VERSION_ENV.exec(word);
      if (m) envVersion ??= m[1].toLowerCase();
    };
    // Leading VAR=value assignments and transparent wrappers.
    for (;;) {
      if (w.length && /^[A-Za-z_][A-Za-z0-9_@:.-]*=/.test(w[0])) { noteEnv(w[0]); w = w.slice(1); continue; }
      if (w.length && WRAPPERS.has(path.basename(w[0]))) {
        w = w.slice(1);
        while (w.length && (w[0].startsWith('-') || /^[A-Za-z_][A-Za-z0-9_@:.-]*=/.test(w[0]) || /^\d+[smhd]?$/.test(w[0]))) {
          noteEnv(w[0]);
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
      if (ci >= 0 && rest[ci + 1]) stmtRefs.push(...parseInstallCommands(rest[ci + 1], depth + 1, { index: envIndex, version: envVersion }));
    } else if (NPM_FAMILY.has(bin)) {
      stmtRefs.push(...parseNpmFamily(bin, rest));
    } else if (bin === 'npx') {
      stmtRefs.push(...parseNpxCli(rest));
    } else if (bin === 'bunx') {
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
    // An index/registry or version-selection env var set for this statement applies to every package it names.
    if (envIndex) for (const r of stmtRefs) r.customIndex = true;
    if (envVersion) for (const r of stmtRefs) r.versionOption ??= envVersion;
    refs.push(...stmtRefs);
  }
  return refs;
}

/** What the options around a package name say about where and how it is resolved. */
interface RefContext { customIndex: boolean; versionOption?: string }

function npmRefs(installer: string, tokens: readonly string[], ctx: RefContext): PackageRef[] {
  const out: PackageRef[] = [];
  for (const t of tokens) {
    const p = parseNpmSpecifier(t);
    if (p) out.push({ ecosystem: 'npm', name: p.name, spec: p.spec, installer, ...refFlags(ctx) });
  }
  return out;
}

function pyRefs(installer: string, tokens: readonly string[], ctx: RefContext, uvStyle = false): PackageRef[] {
  const out: PackageRef[] = [];
  for (const t of tokens) {
    const p = uvStyle ? parseUvxSpecifier(t) : parsePythonRequirement(t);
    if (p) out.push({ ecosystem: 'PyPI', name: p.name, spec: p.spec, installer, ...refFlags(ctx) });
  }
  return out;
}

function refFlags(ctx: RefContext): Pick<PackageRef, 'customIndex' | 'versionOption'> {
  return { ...(ctx.customIndex ? { customIndex: true } : {}), ...(ctx.versionOption ? { versionOption: ctx.versionOption } : {}) };
}

/** Merge what was seen before the verb(s) with what the argument list itself carries. */
function ctxOf(a: Positionals, ...pre: Array<{ preIndex: boolean; versionOption?: string }>): RefContext {
  return {
    customIndex: a.customIndex || pre.some((p) => p.preIndex),
    versionOption: pre.map((p) => p.versionOption).find(Boolean) ?? a.versionOption,
  };
}

/** Index / version options on npm's own command line, and its `--package` values. */
function npmContext(p: NpmArgv): RefContext & { packages: string[] } {
  let customIndex = false;
  let selected: string | undefined;
  let unknown = false;
  const packages: string[] = [];
  for (const o of p.options) {
    if (!o.known) { unknown = true; continue; }
    if (o.key === 'registry' && !o.negated) customIndex = true;
    if (NPM_VERSION_KEYS.has(o.key)) selected ??= `--${o.key}`;
    if (o.key === 'package' && o.value) packages.push(o.value);
  }
  return { customIndex, versionOption: selected ?? (unknown ? UNRECOGNISED_OPTION : undefined), packages };
}

const NPM_RUNS = (cmd: string | undefined) => cmd === 'install' || cmd === 'install-test' || cmd === 'exec';

/**
 * `npm …`, read as npm reads it ({@link parseNpmArgv}): options anywhere before `--`, in any
 * spelling npm accepts, and the command by npm's own aliases and prefixes.
 */
function parseNpm(rest: readonly string[]): PackageRef[] {
  const p = parseNpmArgv(rest);
  let at = 0;
  let cmd = npmCommand(p.remain[0]);
  // npm 10 reads an option it does not define as a switch, so the next word is the command; an npm
  // that defines it might read that word as its value. Take the reading that names an install.
  if (!NPM_RUNS(cmd) && p.afterUnknown.has(0) && NPM_RUNS(npmCommand(p.remain[1]))) {
    at = 1;
    cmd = npmCommand(p.remain[1]);
  }
  if (!NPM_RUNS(cmd)) return [];
  const ctx = npmContext(p);
  const args = p.remain.slice(at + 1);
  // `npm exec` installs its --package values, else the command it is given.
  if (cmd === 'exec') return npmRefs('npm exec', ctx.packages.length ? ctx.packages : args.slice(0, 1), ctx);
  return npmRefs(`npm ${p.remain[at]}`, args, ctx);
}

/** `npx …`: npx-cli puts `--` before the first positional, then npm exec reads the rest (see {@link npxArgv}). */
function parseNpxCli(rest: readonly string[]): PackageRef[] {
  const p = parseNpmArgv(['exec', ...npxArgv(rest)]);
  const ctx = npmContext(p);
  return npmRefs('npx', ctx.packages.length ? ctx.packages : p.remain.slice(1, 2), ctx);
}

const NPM_FAMILY_VERBS = new Set([...NPM_ADD_VERBS, 'dlx', 'global']);

function parseNpmFamily(bin: string, rest: string[]): PackageRef[] {
  if (bin === 'npm') return parseNpm(rest);
  // Find the subcommand: first non-flag word (yarn/pnpm `global add` tolerated).
  const pre = scanPreVerb(rest, VALUE_FLAGS_NPM, INDEX_FLAGS_NPM, classifyNpmFamily, NPM_FAMILY_VERBS);
  if (pre.at < 0) return [];
  let i = pre.at;
  let verb = rest[i];
  if (bin === 'yarn' && verb === 'global') { i++; verb = rest[i]; }
  if (verb === undefined) return [];
  const after = rest.slice(i + 1);
  // `npx`-style runners stop reading their own options at the command.
  if (verb === 'dlx') return parseNpx(`${bin} dlx`, after, pre);
  if (!NPM_ADD_VERBS.has(verb)) return [];
  // `yarn install` / `pnpm install` take no packages; `yarn add` does.
  if (bin === 'yarn' && verb !== 'add') return [];
  const a = collectArgs(after, VALUE_FLAGS_NPM, INDEX_FLAGS_NPM, new Set(), { classify: classifyNpmFamily });
  return npmRefs(`${bin} ${verb}`, a.positionals, ctxOf(a, pre));
}

/** `bunx`, `pnpm dlx`, `yarn dlx`: options up to the command, then the command is the package. */
function parseNpx(installer: string, rest: string[], pre: { preIndex: boolean; versionOption?: string } = { preIndex: false }): PackageRef[] {
  const a = collectArgs(rest, VALUE_FLAGS_NPM, INDEX_FLAGS_NPM, new Set(['-p', '--package']), { classify: classifyNpmFamily, stopAtFirstPositional: true });
  const ctx = ctxOf(a, pre);
  // With -p/--package the positionals are the command to run, not packages.
  if (a.packageFlags.length) return npmRefs(installer, a.packageFlags, ctx);
  // Everything after the first positional belongs to the executed command.
  return a.positionals.length ? npmRefs(installer, [a.positionals[0]], ctx) : [];
}

function parsePip(bin: string, rest: string[]): PackageRef[] {
  const pre = scanPreVerb(rest, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, classifyPython, PIP_VERBS);
  if (pre.at < 0 || !PIP_VERBS.has(rest[pre.at])) return [];
  const a = collectArgs(rest.slice(pre.at + 1), VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set(), { classify: classifyPython });
  return pyRefs(`${bin} install`, a.positionals, ctxOf(a, pre));
}

/** Index of the first non-flag word, skipping the values of value-taking flags; also reports index / version options seen before it. */
function firstWord(args: readonly string[], verbs: ReadonlySet<string>): PreVerb {
  return scanPreVerb(args, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, classifyPython, verbs);
}

const UV_VERBS = new Set(['add', 'pip', 'tool']);
const UV_SUB_VERBS = new Set(['install', 'run']);

function parseUv(rest: string[]): PackageRef[] {
  const first = firstWord(rest, UV_VERBS);
  if (first.at < 0) return [];
  const verb = rest[first.at];
  const after = rest.slice(first.at + 1);
  const pyCollect = (args: readonly string[]) => collectArgs(args, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set(), { classify: classifyPython });
  if (verb === 'add') {
    const a = pyCollect(after);
    return pyRefs('uv add', a.positionals, ctxOf(a, first));
  }
  if (verb === 'pip') {
    const sec = firstWord(after, UV_SUB_VERBS);
    if (sec.at >= 0 && after[sec.at] === 'install') {
      const a = pyCollect(after.slice(sec.at + 1));
      return pyRefs('uv pip install', a.positionals, ctxOf(a, first, sec));
    }
    return [];
  }
  if (verb === 'tool') {
    const sec = firstWord(after, UV_SUB_VERBS);
    if (sec.at >= 0 && after[sec.at] === 'run') return parseUvx('uv tool run', after.slice(sec.at + 1), [first, sec]);
    if (sec.at >= 0 && after[sec.at] === 'install') {
      const a = pyCollect(after.slice(sec.at + 1));
      return pyRefs('uv tool install', a.positionals, ctxOf(a, first, sec), true);
    }
  }
  return [];
}

function parseUvx(installer: string, rest: string[], pre: Array<{ preIndex: boolean; versionOption?: string }> = []): PackageRef[] {
  const a = collectArgs(rest, VALUE_FLAGS_PIP, INDEX_FLAGS_PIP, new Set(['--from']), { classify: classifyPython, stopAtFirstPositional: true });
  const ctx = ctxOf(a, ...pre);
  if (a.packageFlags.length) return pyRefs(installer, a.packageFlags, ctx, true);
  return a.positionals.length ? pyRefs(installer, [a.positionals[0]], ctx, true) : [];
}

const PIPX_VERBS = new Set(['install', 'run']);
const INDEX_FLAGS_PIPX = new Set(['-i', '--index-url']);

function parsePipx(rest: string[]): PackageRef[] {
  const f = scanPreVerb(rest, VALUE_FLAGS_PIPX, INDEX_FLAGS_PIPX, classifyPython, PIPX_VERBS);
  if (f.at < 0) return [];
  const verb = rest[f.at];
  const after = rest.slice(f.at + 1);
  if (verb === 'install') {
    const a = collectArgs(after, VALUE_FLAGS_PIPX, INDEX_FLAGS_PIPX, new Set(), { classify: classifyPython });
    return pyRefs('pipx install', a.positionals.slice(0, 1), ctxOf(a, f));
  }
  if (verb === 'run') {
    const a = collectArgs(after, VALUE_FLAGS_PIPX, INDEX_FLAGS_PIPX, new Set(['--spec']), { classify: classifyPython, stopAtFirstPositional: true });
    const ctx = ctxOf(a, f);
    if (a.packageFlags.length) return pyRefs('pipx run', a.packageFlags, ctx);
    return a.positionals.length ? pyRefs('pipx run', [a.positionals[0]], ctx) : [];
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
  // The entry's `env` is the launched process's environment: a registry/index or a
  // version-selection variable there applies exactly as a `VAR=value` prefix would.
  // Only the names the parser acts on are carried (values never leave this function).
  const env = e.env && typeof e.env === 'object' && !Array.isArray(e.env)
    ? Object.entries(e.env as Record<string, unknown>)
      .filter(([k, v]) => typeof v === 'string' && /^[A-Za-z_][A-Za-z0-9_@:.-]*$/.test(k) && (INDEX_ENV.test(`${k}=`) || VERSION_ENV.test(`${k}=`)))
      .map(([k, v]) => `${k}=${v as string}`)
    : [];
  const quote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  return parseInstallCommands([...env, e.command, ...args].map(quote).join(' '));
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

/** A version string safe to show and to put in an audit row: no control characters, bounded. */
function isSafeVersion(v: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9.!+_~-]{0,63}$/.test(v);
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
  if (!version || !versions[version]) throw new Unchecked('could not resolve the requested version to a published version');
  if (!isSafeVersion(version)) throw new Unchecked('registry returned an unrecognisable version');
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
      if (!best) throw new Unchecked('could not resolve the requested version to a released version');
      version = best;
      doc = { releases: project.releases, urls: obj(project.releases)[best] };
    }
  }
  if (!isSafeVersion(version)) throw new Unchecked('registry returned an unrecognisable version');
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
  let body: unknown;
  try { body = await res.json(); } catch { throw new Unchecked('OSV answer was not valid JSON'); }
  const answer = readOsvResult(body, { aliases: true, skipWithdrawn: true });
  // A malformed answer is never a clean one (it would be final for this version and evict a
  // cached MAL- hit). It still counts when a well-formed entry in it names a MAL- id.
  if (!answer.complete && !answer.ids.some(isMalId)) throw new Unchecked('OSV answer was not in the expected shape');
  return answer.ids;
}

const OSV_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,60}$/;
const isMalId = (id: string) => id.startsWith('MAL-');
/** Top-level keys of an error body (Google API / gRPC-gateway shapes); OSV's answers carry none of them. */
const OSV_ERROR_KEYS = ['error', 'code', 'message', 'details', 'status'];

/**
 * One OSV result object, validated: `{}` or `{ vulns: [ { id, … }, … ] }`, as
 * `/v1/query` returns it and as each element of a `/v1/querybatch` `results`
 * array is. `complete` is false — the answer may not be read as clean — when
 * it is not a plain object, carries an error shape, has a `vulns` that is not
 * an array, holds an entry that is not an object with a well-formed string id
 * (or has non-array `aliases`), or says there are more pages to fetch. Ids of
 * the well-formed entries are returned either way, so a malformed answer can
 * still prove a package malicious, but never prove it clean.
 */
function readOsvResult(result: unknown, opts: { aliases: boolean; skipWithdrawn: boolean }): { ids: string[]; complete: boolean } {
  if (!result || typeof result !== 'object' || Array.isArray(result)) return { ids: [], complete: false };
  const r = result as Record<string, unknown>;
  let complete = !OSV_ERROR_KEYS.some((k) => Object.prototype.hasOwnProperty.call(r, k));
  if (r.next_page_token !== undefined && r.next_page_token !== '') complete = false;
  if (r.vulns === undefined) return { ids: [], complete };
  if (!Array.isArray(r.vulns)) return { ids: [], complete: false };
  const ids: string[] = [];
  for (const v of r.vulns) {
    if (!v || typeof v !== 'object' || Array.isArray(v)) { complete = false; continue; }
    const o = v as Record<string, unknown>;
    if (typeof o.id !== 'string' || !OSV_ID.test(o.id)) { complete = false; continue; }
    if (o.aliases !== undefined && !Array.isArray(o.aliases)) complete = false;
    if (opts.skipWithdrawn && o.withdrawn) continue;
    ids.push(o.id);
    // A record filed under another id (GHSA-…, PYSEC-…) can carry the MAL- id as an alias.
    if (opts.aliases && Array.isArray(o.aliases)) for (const a of o.aliases) if (typeof a === 'string' && isMalId(a) && OSV_ID.test(a)) ids.push(a);
  }
  return { ids: [...new Set(ids)], complete };
}

const MAX_BATCH = 500;
const MAX_ALIAS_LOOKUPS = 6;

/**
 * OSV `querybatch` for every package in the command, independent of the
 * registry and of the per-command cap, sent in chunks of at most
 * {@link MAX_BATCH} (a few in flight at a time, all on the caller's deadline).
 * A package with a known version is asked by name+version; otherwise by name
 * alone, so any `MAL-` entry for the name comes back — which includes entries
 * that only affect OTHER versions (a name-only hit is a reason to look, not a
 * verdict; `vetPackages` resolves it).
 *
 * Returns ids per query index; `null` for a query whose chunk failed, whose
 * answer did not line up with the chunk, or whose own result was malformed
 * and named no `MAL-` id (never an empty clean answer).
 *
 * The batch answer carries ids only, never aliases, so the (few) non-MAL ids it
 * returns are fetched individually to see whether one is an alias of a `MAL-`
 * record; that budget is shared by all chunks.
 */
async function queryOsvBatch(
  queries: ReadonlyArray<{ ref: PackageRef; version: string | null }>,
  fetchImpl: FetchLike,
  signal: AbortSignal,
): Promise<Array<string[] | null>> {
  const out: Array<string[] | null> = queries.map(() => null);
  if (!queries.length) return out;
  const budget = { aliasLookups: 0 };
  const chunks: number[] = [];
  for (let start = 0; start < queries.length; start += MAX_BATCH) chunks.push(start);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < chunks.length) {
      const start = chunks[next++];
      const slice = queries.slice(start, start + MAX_BATCH);
      const answer = await queryOsvChunk(slice, fetchImpl, signal, budget);
      if (answer) answer.forEach((ids, i) => { out[start + i] = ids; });
    }
  };
  await Promise.all(Array.from({ length: Math.min(BATCH_CONCURRENCY, chunks.length) }, worker));
  return out;
}

async function queryOsvChunk(
  slice: ReadonlyArray<{ ref: PackageRef; version: string | null }>,
  fetchImpl: FetchLike,
  signal: AbortSignal,
  budget: { aliasLookups: number },
): Promise<Array<string[] | null> | null> {
  try {
    const res = await fetchImpl('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'shieldcortex-package-vetting' },
      body: JSON.stringify({
        queries: slice.map((q) => ({ package: { name: q.ref.name, ecosystem: q.ref.ecosystem }, ...(q.version ? { version: q.version } : {}) })),
      }),
      signal,
    });
    if (!res.ok) return null;
    const body: unknown = await res.json();
    if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
    if (OSV_ERROR_KEYS.some((k) => Object.prototype.hasOwnProperty.call(body, k))) return null;
    const results = (body as Record<string, unknown>).results;
    if (!Array.isArray(results) || results.length !== slice.length) return null;
    const out: Array<string[] | null> = slice.map(() => null);
    for (let i = 0; i < slice.length; i++) {
      const answer = readOsvResult(results[i], { aliases: false, skipWithdrawn: false });
      const ids: string[] = [];
      for (const id of answer.ids) {
        ids.push(id);
        if (!id.startsWith('MAL-') && budget.aliasLookups < MAX_ALIAS_LOOKUPS) {
          budget.aliasLookups++;
          try {
            const r = await fetchImpl(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { headers: { accept: 'application/json', 'user-agent': 'shieldcortex-package-vetting' }, signal });
            if (r.ok) {
              const rec = obj(await r.json());
              if (Array.isArray(rec.aliases)) for (const a of rec.aliases) if (typeof a === 'string' && a.startsWith('MAL-') && OSV_ID.test(a)) ids.push(a);
            }
          } catch { /* alias enrichment is best-effort */ }
        }
      }
      // A malformed result is unavailable for this query (never clean) unless it still names a MAL- id.
      out[i] = answer.complete || ids.some(isMalId) ? [...new Set(ids)] : null;
    }
    return out;
  } catch {
    return null;
  }
}

/** The version a spec pins exactly, without asking a registry; null for tags, ranges and unpinned. */
function pinnedVersion(ref: PackageRef): string | null {
  if (!ref.spec) return null;
  if (ref.ecosystem === 'npm') {
    const v = semver.valid(ref.spec);
    return v && isSafeVersion(v) ? v : null;
  }
  const m = /^===?([A-Za-z0-9.!+_-]+)$/.exec(ref.spec);
  return m && !m[1].includes('*') && isSafeVersion(m[1]) ? m[1] : null;
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

/** Longest reason that reaches a verdict, an audit row or the hook's denial text whole. */
const MAX_REASON_CHARS = 240;
/** Longest package name shown inside a malicious reason; a longer one is clipped. */
const MAX_REASON_NAME_CHARS = 64;

function clip(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, Math.max(0, max - 3))}...`;
}

/**
 * A malicious reason whose fixed wording always fits {@link MAX_REASON_CHARS}.
 * The package name and the id list are the only variable parts, so they are
 * bounded separately (the name by the caller, the ids to the room that is
 * left) and the explanation after them, including the way through, is never
 * what a later length cap cuts off.
 */
function maliciousReason(before: string, subject: string, between: string, ids: string, after: string): string {
  const room = MAX_REASON_CHARS - before.length - subject.length - between.length - after.length;
  return `${before}${subject}${between}${clip(ids, Math.max(0, room))}${after}`;
}

function listIds(ids: string[], max = 3): string {
  return ids.length <= max ? ids.join(', ') : `${ids.slice(0, max).join(', ')} +${ids.length - max} more`;
}

function buildFindings(v: Omit<PackageVet, 'findings'>, minAgeDays: number, nowMs: number): VettingFinding[] {
  const out: VettingFinding[] = [];
  const name = clip(safeName(v.ref), MAX_REASON_NAME_CHARS);
  const label = `${name}${v.version && isSafeVersion(v.version) ? `@${v.version}` : ''}`;
  if (v.status === 'unchecked') {
    out.push({ kind: 'unchecked', severity: 'advisory', reason: `unchecked: ${v.uncheckedReason ?? 'lookup failed'}` });
  }
  if (v.malicious.length && v.unconfirmedVersion) {
    // A name-only hit: OSV lists a malicious release under this name, but the version this install
    // would fetch could not be checked. Say exactly that, and the way through.
    out.push({ kind: 'malicious', severity: 'catastrophic', reason: maliciousReason('OSV lists a malicious release of ', name, ' (', listIds(v.malicious), '); the version this install would fetch could not be checked, so it is blocked until you pin a version') });
  } else if (v.malicious.length) {
    out.push({ kind: 'malicious', severity: 'catastrophic', reason: maliciousReason('OSV lists ', label, ' as known malicious (', listIds(v.malicious), ')') });
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

interface OneResult {
  vet: PackageVet;
  /** The version the registry resolved, when it did. */
  version?: string;
  /** `osvIds` came from a version-specific OSV query (not a name-only one). */
  exact: boolean;
}

async function vetOne(ref: PackageRef, ctx: {
  fetchImpl: FetchLike; regSignal: AbortSignal; osvSignal: AbortSignal; minAgeDays: number; nowMs: number;
  cache: CacheFile; dirty: { v: boolean };
}): Promise<OneResult> {
  const { fetchImpl, regSignal, osvSignal, minAgeDays, nowMs, cache } = ctx;
  if (ref.customIndex) {
    return { vet: uncheckedVet(ref, 'installs from a custom package index, which public records do not describe', minAgeDays, nowMs), exact: false };
  }
  if (ref.versionOption && !pinnedVersion(ref)) {
    // The installer picks the version by a rule this check does not follow, so resolving the
    // spec here would vet a different version and its clean answer would wrongly be final.
    // No version-specific answer: a name-only MAL- hit stays in force (unconfirmed-version block).
    const why = ref.versionOption === UNRECOGNISED_OPTION
      ? `the install has ${UNRECOGNISED_OPTION}, which may choose the version it fetches, so that version could not be confirmed`
      : `the install chooses its version with ${ref.versionOption}, which this check does not follow, so the version it would fetch could not be confirmed`;
    return { vet: uncheckedVet(ref, why, minAgeDays, nowMs), exact: false };
  }
  let facts: Facts;
  try {
    facts = ref.ecosystem === 'npm' ? await resolveNpm(ref, fetchImpl, regSignal) : await resolvePyPI(ref, fetchImpl, regSignal);
  } catch (err) {
    return { vet: uncheckedVet(ref, err instanceof Unchecked ? err.message : 'lookup failed', minAgeDays, nowMs), exact: false };
  }
  try {
    // A clean answer is never served from the cache: always ask OSV for this version.
    const osvIds = await queryOsv(ref, facts.version, fetchImpl, osvSignal);
    rememberMalicious(cache, ctx.dirty, ref, facts, osvIds, nowMs);
    const base = {
      ref, status: 'checked' as const, version: facts.version, publishedAt: facts.publishedAt, osvIds,
      malicious: osvIds.filter((id) => id.startsWith('MAL-')), hooks: facts.hooks, sdistOnly: facts.sdistOnly,
    };
    return { vet: { ...base, findings: buildFindings(base, minAgeDays, nowMs) }, version: facts.version, exact: true };
  } catch (err) {
    return { vet: uncheckedVet(ref, err instanceof Unchecked ? err.message : 'lookup failed', minAgeDays, nowMs), version: facts.version, exact: false };
  }
}

/** Only `MAL-` hits are cached (for the offline block). A fresh clean answer evicts a stale hit for the same version. */
function rememberMalicious(cache: CacheFile, dirty: { v: boolean }, ref: PackageRef, facts: Pick<Facts, 'version' | 'publishedAt' | 'hooks' | 'sdistOnly'>, osvIds: string[], nowMs: number): void {
  const key = cacheKey(ref.ecosystem, ref.name, facts.version);
  if (osvIds.some((id) => id.startsWith('MAL-'))) {
    cache.entries[key] = { at: nowMs, ecosystem: ref.ecosystem, name: ref.name, version: facts.version, publishedAt: facts.publishedAt, osvIds, hooks: facts.hooks, sdistOnly: facts.sdistOnly };
    dirty.v = true;
  } else if (key in cache.entries) {
    delete cache.entries[key];
    dirty.v = true;
  }
}

/** Vet with the malicious-package gate applied: extra `MAL-` ids found by the batch query or the cache. */
function withMalicious(v: PackageVet, extra: string[], minAgeDays: number, nowMs: number, cached = false, unconfirmed = false): PackageVet {
  const mal = extra.filter((id) => id.startsWith('MAL-') && !v.osvIds.includes(id));
  if (!mal.length) return v;
  const base = { ...v, osvIds: [...v.osvIds, ...mal], malicious: [...v.malicious, ...mal], ...(cached ? { cached: true } : {}), ...(unconfirmed ? { unconfirmedVersion: true } : {}) } as Omit<PackageVet, 'findings'> & { findings?: VettingFinding[] };
  delete base.findings;
  return { ...base, findings: buildFindings(base, minAgeDays, nowMs) };
}

/** Dedup / lookup key. A custom-index ref and a public ref for the same package are different installs. */
function refKey(r: PackageRef): string {
  return `${r.ecosystem}@${r.name}@${r.spec ?? ''}@${r.customIndex ? 'custom' : 'public'}@${r.versionOption ?? ''}`;
}

/**
 * Vet a set of package references. Never throws; a failed lookup is an
 * `unchecked` entry, never a clean one. Registry lookups (capped at
 * {@link MAX_PACKAGES_PER_COMMAND} packages) and the OSV malicious-package
 * batch (every package) run on separate deadlines of `budgetMs` each, so
 * neither padding the command nor slow registry answers can starve the
 * malicious-package check.
 *
 * A name-only `MAL-` hit does not by itself condemn an unpinned package (the
 * report may cover other versions only): the version this install would fetch
 * is resolved and asked about, for the first eight packages and for up to
 * {@link MAX_EXTRA_LOOKUPS} more that carry such a hit. A version-specific
 * answer is final. Where the version cannot be confirmed the install stays
 * blocked, with a reason that says so.
 */
export async function vetPackages(refs: readonly PackageRef[], opts: VetOptions = {}): Promise<VettingResult> {
  const nowMs = opts.nowMs ?? Date.now();
  const minAgeDays = Number.isFinite(opts.minAgeDays) && (opts.minAgeDays as number) >= 0 ? (opts.minAgeDays as number) : DEFAULT_MIN_AGE_DAYS;
  const ttlMs = opts.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  const budgetMs = opts.budgetMs ?? DEFAULT_BUDGET_MS;
  const unique: PackageRef[] = [];
  const seen = new Set<string>();
  for (const r of refs) {
    const k = refKey(r);
    if (!seen.has(k)) { seen.add(k); unique.push(r); }
  }
  const fetchImpl: FetchLike = opts.fetchImpl ?? ((url, init) => (globalThis as unknown as { fetch: FetchLike }).fetch(url, init));
  const regCtl = new AbortController();
  const osvCtl = new AbortController();
  const regTimer = setTimeout(() => regCtl.abort(), budgetMs);
  const osvTimer = setTimeout(() => osvCtl.abort(), budgetMs);
  regTimer.unref?.();
  osvTimer.unref?.();
  const cache = readCache(opts);
  const dirty = { v: false };
  const packages: PackageVet[] = [];
  try {
    const head = unique.slice(0, MAX_PACKAGES_PER_COMMAND);
    // The malicious-package batch covers EVERY package (custom-index installs excepted: public records do not describe them).
    const batchRefs = unique.filter((r) => !r.customIndex);
    const batchP = queryOsvBatch(batchRefs.map((ref) => ({ ref, version: pinnedVersion(ref) })), fetchImpl, osvCtl.signal);
    const headP = Promise.all(head.map((ref) => vetOne(ref, { fetchImpl, regSignal: regCtl.signal, osvSignal: osvCtl.signal, minAgeDays, nowMs, cache, dirty })
      .catch((): OneResult => ({ vet: uncheckedVet(ref, 'lookup failed', minAgeDays, nowMs), exact: false }))));
    const [batch, results] = await Promise.all([batchP, headP]);
    const batchAnswer = (ref: PackageRef): string[] | null => {
      const i = batchRefs.indexOf(ref);
      return i >= 0 ? batch[i] : [];
    };
    const batchFor = (ref: PackageRef): string[] => (batchAnswer(ref) ?? []).filter((id) => id.startsWith('MAL-'));
    // Refs past the cap with a name-only MAL- hit get the same registry + version lookup as the first eight.
    const extraRefs = unique.slice(head.length)
      .filter((r) => !r.customIndex && !pinnedVersion(r) && batchFor(r).length > 0)
      .slice(0, MAX_EXTRA_LOOKUPS);
    const extraResults = await Promise.all(extraRefs.map((ref) => vetOne(ref, { fetchImpl, regSignal: regCtl.signal, osvSignal: osvCtl.signal, minAgeDays, nowMs, cache, dirty })
      .catch((): OneResult => ({ vet: uncheckedVet(ref, 'lookup failed', minAgeDays, nowMs), exact: false }))));
    const extraByRef = new Map(extraRefs.map((ref, i) => [ref, extraResults[i]] as const));
    unique.forEach((ref, idx) => {
      const pinned = pinnedVersion(ref);
      const r = idx < head.length ? results[idx] : extraByRef.get(ref);
      let vet: PackageVet;
      if (r) {
        // A version-specific OSV answer is final for this ref, pinned or not: no name-only ids are merged.
        const malIds = r.exact ? [] : batchFor(ref);
        // No version-specific answer AND this ref's batch chunk failed or did not line up: the
        // malicious-package check did not happen for it. Say so next to the lookup's own reason
        // (as the refs past the cap do); the cached-MAL check below stays in force.
        const base = !r.exact && !ref.customIndex && batchAnswer(ref) === null
          ? uncheckedVet(ref, `${r.vet.uncheckedReason ?? 'lookup failed'}, and the malicious-package check was unavailable`, minAgeDays, nowMs)
          : r.vet;
        vet = withMalicious(base, malIds, minAgeDays, nowMs, false, !pinned && malIds.length > 0);
        if (malIds.length && pinned && !r.exact) {
          rememberMalicious(cache, dirty, ref, { version: pinned, hooks: [], sdistOnly: false }, malIds, nowMs);
        }
      } else {
        const reason = batchAnswer(ref) !== null || ref.customIndex
          ? `more than ${MAX_PACKAGES_PER_COMMAND} packages in one command`
          : `more than ${MAX_PACKAGES_PER_COMMAND} packages in one command, and the malicious-package check was unavailable`;
        const hits = batchFor(ref);
        vet = withMalicious(uncheckedVet(ref, reason, minAgeDays, nowMs), hits, minAgeDays, nowMs, false, !pinned && hits.length > 0);
        if (pinned && vet.malicious.length) rememberMalicious(cache, dirty, ref, { version: pinned, hooks: [], sdistOnly: false }, vet.malicious, nowMs);
      }
      // Offline: a fresh cached MAL- record for this package still blocks.
      if (vet.status === 'unchecked' && !vet.malicious.length && !ref.customIndex) {
        const mal = cachedMaliciousFor(ref, cache, nowMs, ttlMs);
        if (mal) {
          const base = {
            ref, status: 'checked' as const, version: mal.version, publishedAt: mal.publishedAt, osvIds: mal.osvIds,
            malicious: mal.osvIds.filter((id) => id.startsWith('MAL-')), hooks: mal.hooks, sdistOnly: mal.sdistOnly, cached: true,
          };
          vet = { ...base, findings: buildFindings(base, minAgeDays, nowMs) };
        }
      }
      packages.push(vet);
    });
  } finally {
    clearTimeout(regTimer);
    clearTimeout(osvTimer);
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
    // Defence in depth: every reason is built from a fixed vocabulary plus validated names/versions,
    // but nothing that reaches an audit row or a verdict may carry a control character.
    const clean = (r: string) => r.replace(/[^\x20-\x7e]/g, '?').slice(0, MAX_REASON_CHARS);
    return {
      malicious: res.malicious,
      reasons: res.reasons.map(clean),
      audit: res.packages.map((p) => ({
        ecosystem: p.ref.ecosystem, name: safeName(p.ref), version: p.version && isSafeVersion(p.version) ? p.version : undefined,
        status: p.status, kinds: p.findings.map((f) => f.kind), reasons: p.findings.map((f) => clean(f.reason)),
      })),
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
  const key = refKey;
  const byRef = new Map(res.packages.map((p) => [key(p.ref), p]));
  const out: Array<{ name: string; malicious: boolean; reasons: string[] }> = [];
  for (const s of perServer) {
    const pkgs = s.refs.map((r) => byRef.get(key(r))).filter((p): p is PackageVet => !!p);
    const reasons = [...new Set(pkgs.flatMap((p) => p.findings.map((f) => f.reason)))];
    if (reasons.length) out.push({ name: s.name, malicious: pkgs.some((p) => p.malicious.length > 0), reasons });
  }
  return out;
}
