/**
 * How npm reads its own command line, so the package check (#889) sees the
 * options, values and positionals npm sees rather than the literal spellings.
 *
 * npm parses argv with `nopt` against the `@npmcli/config` definitions. That
 * accepts much more than the documented flags: aliases (`--enjoy-by` is
 * `--before`), shorthands (`-D`, `-e` is an abbreviation of the `enjoy-by`
 * alias), any unique prefix of an option name (`--bef`, `--befor`), `=` values,
 * `--no-` negation, and a type per option that decides whether the next word
 * is its value. Matching flags by exact string therefore missed options that
 * select the version and read their values as package names or as the verb.
 *
 * The tables below are npm 10.9's (generated from `@npmcli/config` definitions
 * and `lib/utils/cmd-list.js`); the parse mirrors `nopt-lib` and `npx-cli.js`.
 * An option missing from them (a typo, or one a later npm adds) is reported as
 * unknown so the caller can treat the selected version as unconfirmed.
 * Pure string handling: nothing is executed.
 */

const words = (...lines: string[]): string[] => lines.join(' ').split(' ');

/** Boolean options: they never take the next word (except a literal `true`/`false`). */
const BOOL = words(
  'all allow-same-version audit bin-links commit-hooks description dev diff-ignore-all-space',
  'diff-name-only diff-no-prefix diff-text dry-run engine-strict force foreground-scripts',
  'format-package-lock fund git-tag-version global global-style if-present ignore-scripts',
  'include-staged include-workspace-root install-links json legacy-bundling legacy-peer-deps link long',
  'offline omit-lockfile-registry-resolved package-lock package-lock-only parseable prefer-dedupe',
  'prefer-offline prefer-online progress provenance read-only rebuild-bundle save save-bundle save-dev',
  'save-exact save-optional save-peer save-prod shrinkwrap sign-git-commit sign-git-tag',
  'strict-peer-deps strict-ssl timing unicode update-notifier usage version versions workspaces-update',
);
/** `[null, Boolean]` options: boolean, but also take a literal `null`. */
const BOOL_OR_NULL = words('expect-results optional production workspaces yes');
/** `String` options: take the next word unless it looks like an option. */
const STRING = words(
  'call diff-dst-prefix diff-src-prefix editor git heading init-author-email init-author-name',
  'init-license init.author.email init.author.name init.license message pack-destination preid',
  'save-prefix scope searchexclude searchopts shell tag tag-version-prefix user-agent viewer',
);
/** Every other typed option (paths, URLs, dates, numbers, enums, arrays): always take the next word. */
const VALUE = words(
  '_auth access also audit-level auth-type before ca cache cache-max cache-min cafile cert cidr cpu',
  'depth diff diff-unified expect-result-count fetch-retries fetch-retry-factor fetch-retry-maxtimeout',
  'fetch-retry-mintimeout fetch-timeout globalconfig https-proxy include init-author-url init-module',
  'init-version init.author.url init.module init.version install-strategy key libc local-address',
  'location lockfile-version loglevel logs-dir logs-max maxsockets node-options noproxy omit only os',
  'otp package prefix provenance-file proxy registry replace-registry-host sbom-format sbom-type',
  'script-shell searchlimit searchstaleness umask userconfig which workspace',
);

type Kind = 'bool' | 'bool-or-null' | 'string' | 'value' | 'browser' | 'color';
const KINDS = new Map<string, Kind>([
  ...BOOL.map((k) => [k, 'bool'] as const),
  ...BOOL_OR_NULL.map((k) => [k, 'bool-or-null'] as const),
  ...STRING.map((k) => [k, 'string'] as const),
  ...VALUE.map((k) => [k, 'value'] as const),
  // `[null, Boolean, String]` and `['always', Boolean]`.
  ['browser', 'browser'],
  ['color', 'color'],
]);

/**
 * Value options whose type is a list: under `--no-` nopt reads them as booleans
 * but still takes the next word when the list admits it (`null` for a nullable
 * type, a number, a free string, or one of the listed values).
 */
const NEGATED_TAKES = new Map(Object.entries({
  _auth: 'null str', access: 'null =restricted =public', also: 'null =dev =development',
  'audit-level': 'null =info =low =moderate =high =critical =none', 'auth-type': '=legacy =web', before: 'null',
  ca: 'null str', cert: 'null str', cidr: 'null str', cpu: 'null str', depth: 'null num', diff: 'str',
  'expect-result-count': 'null num', 'https-proxy': 'null', include: '=prod =dev =optional =peer',
  'install-strategy': '=hoisted =nested =shallow =linked', key: 'null str', libc: 'null str', 'local-address': 'null',
  location: '=global =user =project', 'lockfile-version': 'null =1 =2 =3',
  loglevel: '=silent =error =warn =notice =http =info =verbose =silly', 'logs-dir': 'null', 'node-options': 'null str',
  noproxy: 'str', omit: '=dev =optional =peer', only: 'null =prod =production', os: 'null str', otp: 'null str',
  package: 'str', proxy: 'null', 'replace-registry-host': 'str =npmjs =never =always', 'sbom-format': '=cyclonedx =spdx',
  'sbom-type': '=library =application =framework', 'script-shell': 'null str', which: 'null num', workspace: 'str',
}).map(([k, v]) => [k, new Set(v.split(' '))]));

function negatedTakes(key: string, la: string): boolean {
  const t = NEGATED_TAKES.get(key);
  if (!t) return false;
  if (t.has(`=${la}`)) return true;
  if (la === 'null' && t.has('null')) return true;
  if (t.has('num') && !/^-{2,}[^-]/.test(la) && !Number.isNaN(Number(la))) return true;
  return t.has('str') && !/^-[^-]/.test(la);
}

const SHORTHANDS = new Map<string, readonly string[]>(Object.entries({
  'enjoy-by': '--before', d: '--loglevel info', dd: '--loglevel verbose', ddd: '--loglevel silly',
  quiet: '--loglevel warn', q: '--loglevel warn', s: '--loglevel silent', silent: '--loglevel silent',
  verbose: '--loglevel verbose', desc: '--description', help: '--usage', local: '--no-global', n: '--no-yes',
  no: '--no-yes', porcelain: '--parseable', readonly: '--read-only', reg: '--registry',
  iwr: '--include-workspace-root', a: '--all', c: '--call', f: '--force', g: '--global', L: '--location',
  l: '--long', m: '--message', p: '--parseable', C: '--prefix', S: '--save', B: '--save-bundle',
  D: '--save-dev', E: '--save-exact', O: '--save-optional', P: '--save-prod', '?': '--usage', H: '--usage',
  h: '--usage', v: '--version', w: '--workspace', ws: '--workspaces', y: '--yes',
}).map(([k, v]) => [k, v.split(' ')]));
const SINGLES = new Set([...SHORTHANDS.keys()].filter((k) => k.length === 1));

/** `abbrev`: every unique prefix of a word maps to it; a word maps to itself even when it prefixes another. */
function uniquePrefixes(list: readonly string[]): Map<string, string> {
  const out = new Map<string, string>();
  const sorted = [...new Set(list)].sort();
  for (let i = 0; i < sorted.length; i++) {
    const cur = sorted[i];
    const prev = sorted[i - 1] ?? '';
    const next = sorted[i + 1] ?? '';
    let j = 0;
    let withPrev = true;
    let withNext = true;
    for (; j < cur.length; j++) {
      withPrev &&= cur[j] === prev[j];
      withNext &&= cur[j] === next[j];
      if (!withPrev && !withNext) break;
    }
    if (j === cur.length) { out.set(cur, cur); continue; }
    for (let n = j + 1; n <= cur.length; n++) out.set(cur.slice(0, n), cur);
  }
  return out;
}
const OPTION_ABBREV = uniquePrefixes([...KINDS.keys()]);
const SHORTHAND_ABBREV = uniquePrefixes([...SHORTHANDS.keys()]);

/** nopt's `resolveShort`: the words an option word expands to, or null when it is not a shorthand. */
function resolveShort(word: string): readonly string[] | null {
  const arg = word.replace(/^-+/, '');
  if (OPTION_ABBREV.get(arg) === arg) return null;
  const exact = SHORTHANDS.get(arg);
  if (exact) return exact;
  // Single-character shorthands run together (`-gD`).
  if ([...arg].every((c) => SINGLES.has(c))) return [...arg].flatMap((c) => SHORTHANDS.get(c) ?? []);
  if (OPTION_ABBREV.has(arg)) return null;
  const viaAbbrev = SHORTHAND_ABBREV.get(arg);
  return viaAbbrev ? SHORTHANDS.get(viaAbbrev) ?? null : null;
}

export interface NpmOption {
  /** Canonical npm config key (`before` for `--bef` / `--enjoy-by` / `-e`), or the bare word when unknown. */
  key: string;
  /** False when npm 10.9 defines no such option. */
  known: boolean;
  /** `--no-<key>`. */
  negated: boolean;
  /** The value taken, inline (`=`) or from the next word. */
  value?: string;
}

export interface NpmArgv {
  /** Positionals in order: the command word, then its arguments. */
  remain: string[];
  options: NpmOption[];
  /**
   * Indexes into `remain` of words that directly followed an unknown option
   * written without `=`. npm 10.9 reads such an option as a boolean, so the word
   * is a positional; an npm that knows the option might read it as its value.
   */
  afterUnknown: Set<number>;
}

/** Expansion steps allowed per word (a shorthand expands to defined options, so a handful at most). */
const MAX_STEPS_PER_WORD = 16;

/** nopt's parse over npm's definitions, reduced to what the package check needs. */
export function parseNpmArgv(argv: readonly string[]): NpmArgv {
  const args = [...argv];
  const out: NpmArgv = { remain: [], options: [], afterUnknown: new Set() };
  let steps = 0;
  let followsUnknown = false;
  for (let i = 0; i < args.length; i++) {
    if (++steps > MAX_STEPS_PER_WORD * (argv.length + 1)) break;
    let arg = args[i];
    const prevUnknown = followsUnknown;
    followsUnknown = false;
    if (/^-{2,}$/.test(arg)) { out.remain.push(...args.slice(i + 1)); break; }
    if (!(arg.startsWith('-') && arg.length > 1)) {
      if (prevUnknown) out.afterUnknown.add(out.remain.length);
      out.remain.push(arg);
      continue;
    }
    let hadEq = false;
    const at = arg.indexOf('=');
    if (at > -1) {
      hadEq = true;
      const v = arg.slice(at + 1);
      arg = arg.slice(0, at);
      args.splice(i, 1, arg, v);
    }
    const expanded = resolveShort(arg);
    if (expanded) {
      args.splice(i, 1, ...expanded);
      if (arg !== expanded[0]) { i--; continue; }
    }
    let key = arg.replace(/^-+/, '');
    let negated: boolean | null = null;
    while (key.toLowerCase().startsWith('no-')) { negated = !negated; key = key.slice(3); }
    const full = OPTION_ABBREV.get(key);
    if (full) key = full;
    const kind = KINDS.get(key);
    const opt: NpmOption = { key, known: kind !== undefined, negated: negated === true };
    out.options.push(opt);
    let la: string | undefined = args[i + 1];
    const isBool = negated !== null || kind === 'bool' || kind === 'bool-or-null' || kind === 'browser' || kind === 'color'
      || (kind === undefined && !hadEq);
    if (isBool) {
      if (la === 'true' || la === 'false') { opt.value = la; i++; la = undefined; }
      if (la) {
        if (kind === 'color' && la === 'always') { opt.value = la; i++; }
        else if ((kind === 'bool-or-null' || kind === 'browser') && la === 'null') { opt.value = la; i++; }
        else if (kind === 'browser' && !/^-[^-]/.test(la)) { opt.value = la; i++; }
        else if (negated !== null && negatedTakes(key, la)) { opt.value = la; i++; }
      }
      if (kind === undefined && !hadEq) followsUnknown = true;
      continue;
    }
    if (kind === 'string') {
      if (la === undefined) la = '';
      else if (/^-{1,2}[^-]+/.test(la)) { la = ''; i--; }
    }
    if (la && /^-{2,}$/.test(la)) { la = undefined; i--; }
    opt.value = la;
    i++;
  }
  return out;
}

// ── npx ─────────────────────────────────────────────────────────────────────

const NPX_REMOVED_SWITCHES = ['always-spawn', 'ignore-existing', 'shell-auto-fallback'];
const NPX_REMOVED_OPTS = ['npm', 'node-arg', 'n'];
const NPX_REMOVED = new Set([...NPX_REMOVED_SWITCHES, ...NPX_REMOVED_OPTS]);
const NPX_SWITCHES = new Set([
  ...NPX_REMOVED_SWITCHES,
  ...[...KINDS].filter(([, k]) => k !== 'string' && k !== 'value').map(([key]) => key),
  'no-install', 'quiet', 'q', 'version', 'v', 'help', 'h',
]);
const NPX_OPTS = new Set([...NPX_REMOVED_OPTS, 'package', 'p', 'cache', 'userconfig', 'call', 'c', 'shell']);

/**
 * `npx-cli.js`: rewrites `-p`, expands exact shorthands, and puts `--` before
 * the first positional, so npm reads options only up to the command it runs.
 * Returns the argv `npm exec` then parses (without the leading `exec`).
 */
export function npxArgv(argv: readonly string[]): string[] {
  const a = [...argv];
  let steps = 0;
  for (let i = 0; i < a.length; i++) {
    if (++steps > MAX_STEPS_PER_WORD * (argv.length + 1)) break;
    const arg = a[i];
    if (arg === '--') break;
    if (!arg.startsWith('-')) { a.splice(i, 0, '--'); break; }
    const [key, ...v] = arg.replace(/^-+/, '').split('=');
    if (key === 'p') a[i] = ['--package', ...v].join('=');
    else if (key === 'shell') a[i] = ['--script-shell', ...v].join('=');
    else if (key === 'no-install') a[i] = '--yes=false';
    else {
      const sh = SHORTHANDS.get(key);
      if (sh && !NPX_REMOVED.has(key)) {
        a.splice(i, 1, ...sh, ...(v.length ? [v.join('=')] : []));
        i--;
        continue;
      }
    }
    if (NPX_REMOVED.has(key)) { a.splice(i, 1); i--; }
    if (v.length === 0 && !NPX_SWITCHES.has(key) && (NPX_OPTS.has(key) || !/^-/.test(a[i + 1] ?? ''))) {
      if (NPX_REMOVED.has(key)) a.splice(i + 1, 1);
      else i++;
    }
  }
  return a;
}

// ── Commands ────────────────────────────────────────────────────────────────

const COMMANDS = words(
  'access adduser audit bugs cache ci completion config dedupe deprecate diff dist-tag docs doctor edit',
  'exec explain explore find-dupes fund get help help-search hook init install install-ci-test',
  'install-test link ll login logout ls org outdated owner pack ping pkg prefix profile prune publish',
  'query rebuild repo restart root run-script sbom search set shrinkwrap star stars start stop team',
  'test token uninstall unpublish unstar update version view whoami',
);
const ALIASES = new Map(words(
  'author:owner home:docs issues:bugs info:view show:view find:search add:install unlink:uninstall',
  'remove:uninstall rm:uninstall r:uninstall un:uninstall rb:rebuild list:ls ln:link create:init i:install',
  'it:install-test cit:install-ci-test up:update c:config s:search se:search tst:test t:test ddp:dedupe',
  'v:view run:run-script clean-install:ci clean-install-test:install-ci-test x:exec why:explain la:ll',
  'verison:version ic:ci innit:init in:install ins:install inst:install insta:install instal:install',
  'isnt:install isnta:install isntal:install isntall:install install-clean:ci isntall-clean:ci hlep:help',
  'dist-tags:dist-tag upgrade:update udpate:update rum:run-script sit:install-ci-test urn:run-script',
  'ogr:org add-user:adduser',
).map((p) => p.split(':') as [string, string]));
const COMMAND_ABBREV = uniquePrefixes([...COMMANDS, ...ALIASES.keys()]);

/** npm's `deref`: the command a typed command word names (aliases, typos and unique prefixes), or undefined. */
export function npmCommand(word: string | undefined): string | undefined {
  if (!word) return undefined;
  const c = /[A-Z]/.test(word) ? word.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`) : word;
  if (COMMANDS.includes(c)) return c;
  const direct = ALIASES.get(c);
  if (direct) return direct;
  let a = COMMAND_ABBREV.get(c);
  for (let n = 0; a !== undefined && ALIASES.has(a) && n < 4; n++) a = ALIASES.get(a);
  return a;
}
