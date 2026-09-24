/**
 * Hermes plugin discovery — asked of Hermes itself (#569).
 *
 * Hermes discovers plugins by walking every child directory of
 * `$HERMES_HOME/plugins/` (default `~/.hermes/plugins/`) and keying each one
 * on the `name:` in its manifest — NOT on the folder name. It walks in sorted
 * order and, when two manifests from the same source claim the same key, the
 * LATER one silently wins (NousResearch/hermes-agent#121078).
 *
 * That makes a backup left beside a live plugin an invisible downgrade: our
 * installer writes `plugins/shieldcortex/`, an operator copies it aside as
 * `plugins/shieldcortex.bak-pre510-<ts>/`, and because `shieldcortex.bak…`
 * sorts after `shieldcortex`, the backup is what Hermes loads. The upgrade
 * completes, doctor sees the new bytes on disk, and the gateway keeps running
 * the old code. Observed in the field on the Ekho plugin through exactly this
 * mechanism.
 *
 * ## There is exactly one source of truth, and it is Hermes
 *
 * Rounds 1 to 3 shipped a second implementation: first a line reader that
 * mirrored the discovery rules, then a deliberately narrow reader that was
 * supposed to answer only about manifests it fully understood. Four rounds of
 * independent review on the sibling Ekho change found a confident wrong answer
 * in EVERY version of that grammar, each one narrower than the last:
 *
 *   - `name: >-` with an indented name under it (read as absent, so a shadowed
 *     host was certified clean);
 *   - `description: backup: before upgrade` (accepted, where Hermes rejects the
 *     whole manifest);
 *   - `name: "ekho"` (the escape left undecoded, so the copy was missed);
 *   - `description: 2026-99-99` — YAML types the plain scalar as a timestamp,
 *     the month is invalid, construction fails and Hermes drops the manifest;
 *   - `manifest_version: .inf` — YAML constructs infinity and Hermes' `int()`
 *     conversion raises `OverflowError`, so the manifest is dropped.
 *
 * The last two need no exotic syntax at all: they are ordinary-looking lines
 * whose meaning lives in YAML's implicit typing and in Hermes' own conversion
 * code. Chasing that is endless, and a health check whose entire job is to be
 * right about what the gateway loads cannot ship "probably".
 *
 * So round 4 removed the grammar entirely. Hermes' own discovery answers, or
 * NOTHING answers: `scanHermesPluginCopies` returns `fromHermes: false` with
 * the real reason, every caller reports "could not determine", and the repair
 * moves nothing. The only thing offered without Hermes is a HINT list — the
 * directories whose folder name starts with `shieldcortex`, or whose manifest
 * text contains that substring — which is explicitly unverified and is never
 * turned into a copy, a winner or a shadow.
 *
 * Profiles get their own plugin root at `<root>/profiles/<name>/plugins/`,
 * scanned independently — a collision is per-root.
 *
 * ## The ROOTS come from Hermes too (#569 r5)
 *
 * Asking Hermes' own discovery about the wrong directory is not parity. Two
 * ways of computing the roots ourselves were both wrong, and both produced a
 * confident answer about a tree the gateway does not load from:
 *
 *   - `HERMES_HOME=$HOME/.hermes` (the literal string, as a service unit or a
 *     shell profile can easily leave it). Hermes expands it —
 *     `hermes_constants._expand_hermes_home` is
 *     `expanduser(expandvars(path))` — and loads the backup under the real
 *     directory. We took it literally, scanned a path that does not exist,
 *     found no copies and reported PASS.
 *   - `HERMES_HOME=<root>/profiles/work`. Hermes' `get_default_hermes_root()`
 *     hands back `<root>` for profile-level work, so `<root>/plugins` and the
 *     SIBLING profiles are all live plugin roots. We looked for profiles under
 *     the ACTIVE home instead, so a repair run from `work` never saw
 *     `<root>/plugins/shieldcortex -> profiles/work/plugins/shieldcortex.bak-x`
 *     and happily moved the directory that link depends on.
 *
 * So the probe now asks `hermes_constants` for the active home AND the
 * containing root, builds the protective root set there, and scans all of it.
 * Nothing in TypeScript re-implements that resolution: if `hermes_constants`
 * is missing or either function raises, the answer is UNDETERMINED, exactly as
 * an unavailable discovery is. `resolveHermesHome` below still exists, but it
 * decides nothing — see its own comment.
 */

import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

/** The manifest key our plugin declares — the thing that can collide. */
export const HERMES_PLUGIN_NAME = 'shieldcortex';

/** How long the Hermes probe may take before we give up on an answer. */
const PROBE_TIMEOUT_MS = 8_000;

/**
 * How much of a manifest the HINT list reads. Nothing parses these bytes; the
 * only question asked of them is whether the literal string `shieldcortex`
 * appears, so an unbounded read would buy nothing and cost a health check its
 * memory ceiling.
 */
const HINT_BYTE_CAP = 64 * 1024;

/**
 * `plugins_discovery._FOREIGN_HARNESS_MANIFEST_DIRS` — per-harness manifest
 * directories Hermes skips before it looks for a manifest at all. The hint list
 * skips them for the same reason: they are never plugin directories.
 */
const FOREIGN_HARNESS_MANIFEST_DIRS: ReadonlySet<string> = new Set([
  '.claude-plugin',
  '.codex-plugin',
  '.cursor-plugin',
  '.devin-plugin',
  '.kimi-plugin',
]);

/** One directory under a `plugins/` root whose manifest declares our name. */
export interface HermesPluginCopy {
  /** Absolute path of the plugin directory, exactly as discovery names it. */
  dir: string;
  /** Its basename — the string Hermes sorts on. */
  dirName: string;
  /** The `plugins/` root it was found under. */
  root: string;
  /** True only for `<root>/shieldcortex`, the directory our installer writes. */
  canonical: boolean;
}

/** Hermes' answer for one `plugins/` root. */
export interface HermesPluginRootScan {
  root: string;
  /** Every copy keyed `shieldcortex`, in Hermes' discovery order. */
  copies: HermesPluginCopy[];
  /** The one Hermes actually loads: the winner of the key. */
  loaded: HermesPluginCopy | null;
  /** Whether `<root>/shieldcortex` is among the copies. */
  hasCanonical: boolean;
  /** More than one copy, or a single copy that is not the canonical one. */
  shadowed: boolean;
  /**
   * True for the ACTIVE home's own `plugins/` — the root the process Hermes is
   * running now loads from. The others are just as real (a sibling profile is
   * a live plugin root the moment something starts under it), which is why
   * they are scanned and repaired; this only says which one is in use today.
   */
  active: boolean;
}

/**
 * The unverified hint for one root, offered ONLY when Hermes could not answer.
 * These are directories that merely look like they might be ours; no manifest
 * was parsed, and nothing here is a copy, a winner or a shadow.
 */
export interface HermesPluginHintRoot {
  root: string;
  dirs: string[];
}

export interface HermesPluginScan {
  /**
   * The ACTIVE Hermes home. Hermes' own `get_hermes_home()` when `fromHermes`;
   * otherwise the best-effort guess from `resolveHermesHome`, which is good
   * enough to say "there is no Hermes here" and nothing more.
   */
  hermesHome: string;
  /**
   * The CONTAINING root — `get_default_hermes_root()`, which is `<root>` when
   * `HERMES_HOME=<root>/profiles/<name>`. Null when Hermes did not answer:
   * this one is never guessed, because it is what decides which OTHER profiles
   * a repair has to protect.
   */
  hermesRoot: string | null;
  /** Whether the Hermes home directory exists at all. */
  present: boolean;
  /**
   * True when Hermes' own discovery answered. When it is FALSE nothing below
   * is a verdict: `roots` and `copies` are empty, `shadowed` is false because
   * it is unknown rather than because it is absent, and only `hintRoots` and
   * `undeterminedReason` carry anything.
   */
  fromHermes: boolean;
  /** Why Hermes could not be asked, verbatim. Null when `fromHermes`. */
  undeterminedReason: string | null;
  roots: HermesPluginRootScan[];
  /** Every copy across every root, roots in order. */
  copies: HermesPluginCopy[];
  shadowed: boolean;
  /** Unverified hints per root. Empty when `fromHermes`. */
  hintRoots: HermesPluginHintRoot[];
}

export interface HermesScanOptions {
  /**
   * Override interpreter resolution. `null` is "this box has no Hermes to
   * ask", which is the seam the undetermined-path tests use: a box with a
   * working Hermes would otherwise never exercise it.
   */
  interpreter?: string | null;
}

/**
 * The environment a scan runs under: the two variables Hermes resolves its own
 * home from. They travel together, and they travel UNEXPANDED — expanding
 * `HERMES_HOME` before handing it over is precisely the mistake #569 r5 fixes.
 */
export interface HermesEnvironment {
  /** `HOME`. Hermes' platform default home is derived from it. */
  home: string;
  /** `HERMES_HOME` exactly as the operator set it, or null when unset. */
  hermesHome: string | null;
}

/**
 * This process's environment, with `home` overridable so a test (and the
 * installer) can name the tree to scan. `HERMES_HOME` is trimmed and empty is
 * unset, matching Hermes' own `os.environ.get("HERMES_HOME", "").strip()`.
 */
export function hermesEnvironment(home: string = os.homedir()): HermesEnvironment {
  const raw = process.env.HERMES_HOME;
  const trimmed = typeof raw === 'string' ? raw.trim() : '';
  return { home, hermesHome: trimmed === '' ? null : trimmed };
}

/** The environment the probe child runs under: this one's, with HOME replaced. */
function childEnvironment(env: HermesEnvironment): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: env.home,
    // Windows' `Path.home()`; harmless everywhere else.
    USERPROFILE: env.home,
    // Nothing here should leave artefacts in the tree it is inspecting.
    PYTHONDONTWRITEBYTECODE: '1',
    PYTHONWARNINGS: 'ignore',
  };
  if (env.hermesHome === null) delete out.HERMES_HOME;
  else out.HERMES_HOME = env.hermesHome;
  return out;
}

/**
 * `os.path.expandvars` for the same strings Hermes sees: `$NAME` and
 * `${NAME}`, left verbatim when the variable is unset — which is what Python
 * does, and the reason an unset variable does not collapse a path to a
 * relative one.
 */
function expandVars(value: string, env: NodeJS.ProcessEnv): string {
  return value.replace(/\$(\w+|\{[^}]*\})/g, (whole, token: string) => {
    const name = token.startsWith('{') ? token.slice(1, -1) : token;
    const found = env[name];
    return typeof found === 'string' ? found : whole;
  });
}

/**
 * A best-effort Hermes home, used for THREE things and none of them a verdict:
 * finding an interpreter to ask, deciding whether there is a Hermes here at
 * all, and listing unverified hint directories when there is nothing to ask.
 *
 * It mirrors `hermes_constants._expand_hermes_home` (`expanduser` after
 * `expandvars`) because a literal `HERMES_HOME=$HOME/.hermes` otherwise makes
 * this report "Hermes not detected" on a host that has one — but a mirror is
 * exactly what rounds 1 to 4 proved cannot be trusted to decide anything. The
 * roots that verdicts and repairs are built on come from `hermes_constants`
 * itself, through the probe; see `probeHermesDiscovery`.
 */
export function resolveHermesHome(env: HermesEnvironment): string {
  const childEnv = childEnvironment(env);
  if (env.hermesHome !== null) {
    const expanded = expandUser(expandVars(env.hermesHome, childEnv), env.home);
    if (expanded !== '') return path.resolve(expanded);
  }
  return path.join(env.home, '.hermes');
}

/** `os.path.expanduser` for the only form Hermes homes take: a leading `~`. */
function expandUser(value: string, home: string): string {
  if (value === '~') return home;
  if (value.startsWith(`~${path.sep}`) || value.startsWith('~/')) {
    return path.join(home, value.slice(2));
  }
  return value;
}

function isDirectory(target: string): boolean {
  try {
    return fs.statSync(target).isDirectory();
  } catch {
    return false;
  }
}

function isFile(target: string): boolean {
  try {
    return fs.statSync(target).isFile();
  } catch {
    return false;
  }
}

/**
 * Child directories of `dir`, sorted by code unit — Hermes' own order
 * (`sorted(path.iterdir())`, and within one parent that is a plain name
 * compare). A symlink to a directory counts: Hermes' `child.is_dir()` follows
 * it. An unreadable or absent `dir` yields nothing rather than throwing.
 */
function childDirectories(dir: string): string[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const names: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory()) names.push(entry.name);
    else if (entry.isSymbolicLink() && isDirectory(path.join(dir, entry.name))) names.push(entry.name);
  }
  // Plain code-unit compare, deliberately not localeCompare: it has to match
  // Python's `sorted()`, which is what decides the winner on the Hermes side.
  return names.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * The `plugins/` roots UNDER one home: the main one, then its profiles.
 *
 * Hint-list scaffolding only (#569 r5). This is not where Hermes discovers
 * from when `HERMES_HOME` names a profile — the containing root and its
 * SIBLING profiles are live roots too, and working that out is
 * `hermes_constants.get_default_hermes_root()`'s job, asked through the probe.
 * Nothing that produces a verdict or a move may call this.
 */
export function hermesPluginRoots(hermesHome: string): string[] {
  const roots = [path.join(hermesHome, 'plugins')];
  const profiles = path.join(hermesHome, 'profiles');
  for (const name of childDirectories(profiles)) {
    roots.push(path.join(profiles, name, 'plugins'));
  }
  return roots;
}

// ── Primary path: ask Hermes ──────────────────────────────────────────────

/**
 * The interpreter that can import `hermes_cli`: the agent's own virtualenv
 * first, then whatever the `hermes` launcher on PATH is shebanged to. Returns
 * null when neither is there, which is the signal to fall back.
 */
export function resolveHermesInterpreter(hermesHome: string): string | null {
  const venv = path.join(hermesHome, 'hermes-agent', '.venv');
  const candidates = [
    path.join(venv, 'bin', 'python3'),
    path.join(venv, 'bin', 'python'),
    path.join(venv, 'Scripts', 'python.exe'),
  ];
  for (const candidate of candidates) {
    if (isFile(candidate)) return candidate;
  }
  return shebangInterpreter(hermesOnPath());
}

/** The `hermes` launcher on PATH, or null. */
function hermesOnPath(): string | null {
  const raw = process.env.PATH;
  if (typeof raw !== 'string' || raw === '') return null;
  for (const entry of raw.split(path.delimiter)) {
    if (entry === '') continue;
    const candidate = path.join(entry, 'hermes');
    if (isFile(candidate)) return candidate;
  }
  return null;
}

/**
 * The Python a console script is shebanged to. Only an absolute path whose
 * basename looks like a Python counts — a `#!/usr/bin/env python3` launcher
 * tells us nothing we can spawn with confidence, so it falls back instead.
 */
function shebangInterpreter(executable: string | null): string | null {
  if (executable === null) return null;
  let head: string;
  try {
    const fd = fs.openSync(executable, 'r');
    try {
      const buf = Buffer.alloc(512);
      const read = fs.readSync(fd, buf, 0, buf.length, 0);
      head = buf.subarray(0, read).toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
  if (!head.startsWith('#!')) return null;
  const line = head.split(/\r?\n/, 1)[0].slice(2).trim();
  const token = line.split(/\s+/)[0];
  if (token === undefined || !path.isAbsolute(token)) return null;
  if (!path.basename(token).startsWith('python')) return null;
  return isFile(token) ? token : null;
}

/**
 * Directories that might hold `hermes_cli`, for the child's `sys.path`. The
 * agent's virtualenv normally has the repo installed already; this covers the
 * editable/source layouts where it does not.
 */
function hermesImportRoots(hermesHome: string, interpreter: string): string[] {
  const roots = new Set<string>();
  const home = path.join(hermesHome, 'hermes-agent');
  if (isDirectory(home)) roots.add(home);
  // `<root>/.venv/bin/python3` → walk up looking for the checkout that owns it.
  let cursor = path.dirname(interpreter);
  for (let i = 0; i < 6; i += 1) {
    if (isDirectory(path.join(cursor, 'hermes_cli'))) roots.add(cursor);
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return [...roots];
}

/**
 * The embedded probe. It imports Hermes' own discovery AND Hermes' own home
 * resolution, works out which `plugins/` roots this host actually loads from,
 * scans each of them with source `"user"` (the source our plugins root really
 * is), and prints the copies keyed `shieldcortex` plus the winner per root.
 *
 * `resolve_manifest_winners` is what decides the winner inside Hermes, so the
 * winner here is not "the last entry" by our reckoning — it is Hermes' answer.
 *
 * ## Where the roots come from (#569 r5)
 *
 *   - `hermes_constants.get_hermes_home()` — the ACTIVE home, after Hermes'
 *     own `expanduser(expandvars(...))`, so a literal `$HOME/.hermes` names
 *     the directory the gateway really loads from and not a path that does not
 *     exist.
 *   - `hermes_constants.get_default_hermes_root()` — the CONTAINING root,
 *     which is `<root>` when `HERMES_HOME=<root>/profiles/<name>` and handles
 *     the Docker/custom-root layout as well. `<root>/plugins` and every
 *     `<root>/profiles/<name>/plugins` are live plugin roots whatever profile this
 *     process happens to be running as, and a repair that cannot see them will
 *     move a directory another profile's install points at.
 *   - The active home's own `plugins/`, appended when the two above did not
 *     already cover it.
 *
 * Either function missing or raising is a HARD failure of the whole probe: the
 * caller then has no roots, so it has no verdict either. Re-deriving the rules
 * here is the thing this round exists to stop doing.
 *
 * stdout and stderr are captured across the import and the scan so a chatty
 * module or a discovery warning cannot land in the middle of the JSON; the
 * result is written to the real stdout afterwards. (`get_hermes_home()` writes
 * a profile-fallback notice straight to stderr in one case, which is exactly
 * the sort of thing that redirect is there for.)
 *
 * Logging is quietened on HERMES' DISCOVERY LOGGERS ONLY and never on the root
 * logger (#569 r3) — the names Hermes uses today plus whatever `logger` the
 * imported discovery modules actually carry, so a rename upstream cannot
 * silently widen or narrow the suppression. This runs in a child process that
 * exists solely for the scan, so "for the duration of the scan" and "for the
 * life of the process" are the same window; the in-process Python detector has
 * to be more careful, and is (see `shadow.py`).
 */
const PROBE_SCRIPT = [
  'import contextlib, io, json, logging, os, sys',
  '_payload = json.loads(sys.argv[1])',
  '_real = sys.stdout',
  'try:',
  '    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):',
  '        for _cand in _payload.get("importRoots") or []:',
  '            if os.path.isdir(os.path.join(_cand, "hermes_cli")) and _cand not in sys.path:',
  '                sys.path.insert(0, _cand)',
  '        from pathlib import Path',
  '        import hermes_cli.plugins_discovery as _pd',
  '        import hermes_cli.plugins_manifest as _pm',
  '        from hermes_cli.plugins_discovery import resolve_manifest_winners, scan_directory',
  '        from hermes_cli.plugins_manifest import manifest_key',
  '        _quiet = set(["hermes_cli.plugins", "hermes_cli.plugins_discovery",',
  '                      "hermes_cli.plugins_manifest", "hermes_cli.agent_plugins"])',
  '        for _mod in (_pd, _pm):',
  '            _lg = getattr(_mod, "logger", None)',
  '            if isinstance(_lg, logging.Logger):',
  '                _quiet.add(_lg.name)',
  '        for _lname in _quiet:',
  '            logging.getLogger(_lname).disabled = True',
  '        _name = _payload["name"]',
  // Hermes' own home resolution, from Hermes. Anything at all going wrong here
  // is reported as itself and never worked around: a root set we made up is
  // what this round is removing.
  '        try:',
  '            import hermes_constants as _hc',
  '            _active = os.path.normpath(os.path.abspath(str(_hc.get_hermes_home())))',
  '            _root = os.path.normpath(os.path.abspath(str(_hc.get_default_hermes_root())))',
  '        except BaseException as _hexc:',
  '            raise RuntimeError("hermes_constants could not resolve the Hermes home and root '
    + '(%s: %s)" % (type(_hexc).__name__, _hexc))',
  '        _roots = []',
  '        def _add(_p):',
  '            _p = os.path.normpath(os.path.abspath(_p))',
  '            if _p not in _roots:',
  '                _roots.append(_p)',
  '        _add(os.path.join(_root, "plugins"))',
  '        _profiles = os.path.join(_root, "profiles")',
  '        try:',
  '            _names = sorted(os.listdir(_profiles))',
  '        except OSError:',
  '            _names = []',
  '        for _n in _names:',
  '            if os.path.isdir(os.path.join(_profiles, _n)):',
  '                _add(os.path.join(_profiles, _n, "plugins"))',
  '        _add(os.path.join(_active, "plugins"))',
  '        _out = []',
  '        for _r in _roots:',
  '            _ms = scan_directory(Path(_r), "user")',
  '            _copies = [str(_m.path) for _m in _ms if manifest_key(_m) == _name]',
  '            _win = resolve_manifest_winners(_ms).get(_name)',
  '            _out.append({"root": _r, "copies": _copies,',
  '                         "loaded": (str(_win.path) if _win is not None else None)})',
  '    _real.write(json.dumps({"ok": True, "activeHome": _active, "root": _root, "roots": _out}))',
  'except BaseException as _exc:',
  '    _real.write(json.dumps({"ok": False, "error": "%s: %s" % (type(_exc).__name__, _exc)}))',
].join('\n');

interface ProbeRoot {
  root: string;
  copies: string[];
  loaded: string | null;
}

/** Everything the probe answers: where Hermes lives, and what is in each root. */
export interface HermesProbeResult {
  /** `hermes_constants.get_hermes_home()`. */
  activeHome: string;
  /** `hermes_constants.get_default_hermes_root()`. */
  root: string;
  /** Every protective root, in the order the probe built them. */
  roots: ProbeRoot[];
}

/**
 * Ask Hermes where it loads plugins from and what is there. Returns
 * `{ error }` when there is no interpreter, the spawn failed, it timed out,
 * `hermes_constants` could not answer, or the output was not the JSON we asked
 * for — every one of which means "no answer", never "there are no copies".
 *
 * `env` is passed to the child UNEXPANDED (see `childEnvironment`): Hermes
 * expands `HERMES_HOME` itself, and the whole point is that its expansion is
 * the one that counts.
 */
export function probeHermesDiscovery(
  env: HermesEnvironment,
  opts: HermesScanOptions = {},
): HermesProbeResult | { error: string } {
  // The interpreter is LOOKED FOR under the best-effort home. That is a search
  // for something to ask, not an answer: a wrong guess here costs a venv
  // lookup and falls through to the `hermes` launcher on PATH.
  const searchHome = resolveHermesHome(env);
  const interpreter =
    opts.interpreter !== undefined ? opts.interpreter : resolveHermesInterpreter(searchHome);
  if (interpreter === null) return { error: 'no Hermes interpreter found' };

  const payload = JSON.stringify({
    name: HERMES_PLUGIN_NAME,
    importRoots: hermesImportRoots(searchHome, interpreter),
  });

  // spawnSync, no shell: the only untrusted strings here are paths, and they
  // travel as one argv element that nothing re-parses.
  const run = spawnSync(interpreter, ['-c', PROBE_SCRIPT, payload], {
    encoding: 'utf8',
    timeout: PROBE_TIMEOUT_MS,
    maxBuffer: 4 * 1024 * 1024,
    windowsHide: true,
    env: childEnvironment(env),
  });

  if (run.error) return { error: `Hermes probe failed to run — ${run.error.message}` };
  if (run.signal !== null && run.signal !== undefined) {
    return { error: `Hermes probe was killed (${run.signal}) — possibly the ${PROBE_TIMEOUT_MS}ms timeout` };
  }
  if (run.status !== 0) {
    const detail = (run.stderr || '').trim().split(/\r?\n/).slice(-1)[0] || `exit ${run.status}`;
    return { error: `Hermes probe exited non-zero — ${detail}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse((run.stdout || '').trim());
  } catch {
    return { error: 'Hermes probe produced no parseable result' };
  }
  const record = parsed as {
    ok?: unknown;
    error?: unknown;
    activeHome?: unknown;
    root?: unknown;
    roots?: unknown;
  };
  if (record.ok !== true || !Array.isArray(record.roots)) {
    const why = typeof record.error === 'string' ? record.error : 'unknown reason';
    return { error: `Hermes could not be asked — ${why}` };
  }
  if (typeof record.activeHome !== 'string' || typeof record.root !== 'string') {
    return { error: 'Hermes probe named no home or no containing root' };
  }
  const out: ProbeRoot[] = [];
  for (const entry of record.roots as Array<Record<string, unknown>>) {
    const root = typeof entry.root === 'string' ? entry.root : null;
    if (root === null || !Array.isArray(entry.copies)) {
      return { error: 'Hermes probe returned a malformed root entry' };
    }
    out.push({
      root,
      copies: (entry.copies as unknown[]).filter((c): c is string => typeof c === 'string'),
      loaded: typeof entry.loaded === 'string' ? entry.loaded : null,
    });
  }
  return { activeHome: record.activeHome, root: record.root, roots: out };
}

function toCopy(dir: string, root: string): HermesPluginCopy {
  const dirName = path.basename(dir);
  return {
    dir,
    dirName,
    root,
    // Canonical is a position, not just a name: `<root>/shieldcortex` is the
    // directory the installer writes. A `shieldcortex` nested under a category
    // is a different key entirely and never reaches here.
    canonical: dirName === HERMES_PLUGIN_NAME && path.resolve(path.dirname(dir)) === path.resolve(root),
  };
}


/**
 * Hermes' answer for one root, turned into the shape doctor reports on.
 */
function rootScanFrom(probe: ProbeRoot, activeHome: string): HermesPluginRootScan {
  const copies = probe.copies.map((dir) => toCopy(dir, probe.root));
  const loaded =
    probe.loaded === null
      ? null
      : copies.find((c) => c.dir === probe.loaded) ?? toCopy(probe.loaded, probe.root);
  return {
    root: probe.root,
    copies,
    loaded,
    hasCanonical: copies.some((c) => c.canonical),
    shadowed: copies.length > 1 || (loaded !== null && !loaded.canonical),
    active: path.resolve(probe.root) === path.resolve(path.join(activeHome, 'plugins')),
  };
}

// ── Without Hermes: hints, and nothing that decides ───────────────────────

/**
 * The manifest file Hermes would read from `dir`, or null.
 *
 * Selection, not parsing: `plugin.yaml` then `plugin.yml` on EXISTENCE (which
 * is what Hermes uses — a `plugin.yaml` DIRECTORY is selected and then fails),
 * then a portable `plugin.json` when neither YAML spelling is there. The hint
 * list only wants somewhere to look for a literal substring.
 */
function hintManifestFile(dir: string): string | null {
  for (const base of ['plugin.yaml', 'plugin.yml', 'plugin.json']) {
    const candidate = path.join(dir, base);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

/** Whether a manifest's first `HINT_BYTE_CAP` bytes mention our key at all. */
function manifestMentionsUs(file: string): boolean {
  let fd: number;
  try {
    fd = fs.openSync(file, 'r');
  } catch {
    return false;
  }
  try {
    const buf = Buffer.alloc(HINT_BYTE_CAP);
    const read = fs.readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, read).toString('utf8').includes(HERMES_PLUGIN_NAME);
  } catch {
    return false;
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      /* the answer is already decided */
    }
  }
}

/**
 * Directories under `root` that MIGHT be a copy of our plugin — the folder name
 * starts with `shieldcortex`, or the manifest text contains that substring.
 *
 * This is a hint and nothing more. It is offered only when Hermes' own
 * discovery could not be reached, it is labelled unverified everywhere it is
 * printed, and no caller may turn it into a copy, a winner or a shadow: both
 * halves of the test are wrong in both directions (a manifest can spell our key
 * in escapes and never contain the bytes; a third-party manifest can mention us
 * in prose), which is precisely why rounds 1 to 3 kept shipping wrong answers.
 * A substring test cannot be mistaken for a parse.
 */
export function hintDirsInRoot(root: string): string[] {
  const hints: string[] = [];
  for (const dirName of childDirectories(root)) {
    if (dirName.startsWith('__') && dirName.endsWith('__')) continue;
    if (FOREIGN_HARNESS_MANIFEST_DIRS.has(dirName)) continue;
    const dir = path.join(root, dirName);
    if (dirName.startsWith(HERMES_PLUGIN_NAME)) {
      hints.push(dir);
      continue;
    }
    const manifest = hintManifestFile(dir);
    if (manifest !== null && manifestMentionsUs(manifest)) hints.push(dir);
  }
  return hints;
}

// ── Public entry point ───────────────────────────────────────────────────

/**
 * Scan this host for copies of our plugin. `env` is the environment to scan
 * UNDER — the installer hands it the home it just wrote to, the doctor hands
 * it the operator's — and it is never pre-resolved, because Hermes' own
 * expansion of `HERMES_HOME` is the one that decides where the plugins are.
 *
 * Hermes' own discovery answers, or nothing does. `fromHermes === false` is not
 * a lesser answer to be labelled "approximate" and acted on anyway — it is the
 * absence of an answer, and every caller has to say so and stop (#569 r4).
 * Since r5 that covers the ROOTS as well: if `hermes_constants` cannot say
 * where this host's plugin roots are, there is no verdict to give about them.
 */
export function scanHermesPluginCopies(
  env: HermesEnvironment,
  opts: HermesScanOptions = {},
): HermesPluginScan {
  // Best-effort, and used only to answer "is there a Hermes here at all" and
  // to list hint directories when there is nothing to ask. See
  // `resolveHermesHome`.
  const guessedHome = resolveHermesHome(env);
  const present = isDirectory(guessedHome);
  const base = {
    hermesHome: guessedHome,
    hermesRoot: null as string | null,
    present,
    fromHermes: false,
    undeterminedReason: null as string | null,
    roots: [] as HermesPluginRootScan[],
    copies: [] as HermesPluginCopy[],
    shadowed: false,
    hintRoots: [] as HermesPluginHintRoot[],
  };
  if (!present) return base;

  const probe = probeHermesDiscovery(env, opts);

  if ('error' in probe) {
    return {
      ...base,
      undeterminedReason: probe.error,
      hintRoots: hermesPluginRoots(guessedHome).map((root) => ({
        root,
        dirs: hintDirsInRoot(root),
      })),
    };
  }

  const rootScans = probe.roots.map((entry) => rootScanFrom(entry, probe.activeHome));
  return {
    ...base,
    hermesHome: probe.activeHome,
    hermesRoot: probe.root,
    fromHermes: true,
    roots: rootScans,
    copies: rootScans.flatMap((r) => r.copies),
    shadowed: rootScans.some((r) => r.shadowed),
  };
}
