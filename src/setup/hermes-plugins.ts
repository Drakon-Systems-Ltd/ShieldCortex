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
 *
 * ## A directory that cannot be read is not an empty directory (#569 r6)
 *
 * The root set was built with `except OSError: names = []` around
 * `os.listdir(<root>/profiles)`. A `profiles/` that can be traversed but not
 * listed — a mode change, an ACL — raises PermissionError, so the profile list
 * became empty, the sibling profiles left the protective scan, and the repair
 * moved the backup that `profiles/work/plugins/shieldcortex` pointed at.
 *
 * That is a class, not a line. Every enumeration and stat that feeds the root
 * set, the per-copy symlink walk, the plan preflight or the destination checks
 * now answers one of three things:
 *
 *   - what is there;
 *   - GENUINELY ABSENT — ENOENT on the path itself (and ENOTDIR for a name
 *     under a non-directory). It contributes nothing, which is TRUE;
 *   - UNDETERMINED — anything else at all. It is recorded with its path and
 *     error in `HermesPluginScan.undetermined`, `fromHermes` goes false, the
 *     doctor row WARNs naming the path, and `--fix-hermes-plugin-copies`
 *     refuses the WHOLE plan and exits non-zero.
 *
 * `fs.existsSync` and Python's `Path.exists()` both return false on a
 * permission error, so neither is allowed anywhere an absence would permit a
 * move; the checked helpers below use stat/lstat and test the errno.
 *
 * ## The collision set is not the protection set (#569 r7)
 *
 * Only an exact `shieldcortex` key can collide with the installed plugin, so
 * the copy list stays exactly that. But `scan_directory` keys a manifest one
 * level down as `<category>/<name>`, and
 * `profiles/work/plugins/security/shieldcortex -> plugins/shieldcortex.bak-x`
 * is a real, enabled installation that resolves THROUGH a directory the repair
 * would move. Filtering it out of the scan took it out of the symlink walk and
 * the dependent-path preflight as well, and the repair stranded it.
 *
 * So the probe now also returns `discovered` — every manifest directory in
 * every protective root, all keys, categories included. It decides nothing:
 * no collision, no winner, no move. The repair walks it and protects it.
 *
 * ## The user roots are not the whole of discovery either (#569 r7)
 *
 * `collect_directory_manifests` scans `Path.cwd()/.hermes/plugins` as source
 * `"project"` AFTER the user source when `HERMES_ENABLE_PROJECT_PLUGINS` is
 * enabled, and `resolve_manifest_winners` lets the later source win. A
 * canonical home install with an older copy in a project directory is
 * therefore a host running the old code, and the per-root winner alone called
 * it clean. The probe asks Hermes' own `_env_enabled` whether the switch is
 * on, scans the project directory when it is, and reports the EFFECTIVE winner
 * per root. Nothing is ever moved from or into that directory: which copy is
 * authoritative there is a human's call, and the gateway's working directory
 * is not something this process can see.
 *
 * ## A manifest that was not READ is not a manifest that says nothing (#569 r8)
 *
 * The reported layout is ordinary: `plugins/shieldcortex` beside a valid
 * portable package in `plugins/shieldcortex.bak-portable`, whose `plugin.json`
 * is owned by the gateway's service account at mode 0600. Readable, the row
 * warns — the backup sorts later and is what loads. Unreadable, it PASSED
 * "clean", by two separate routes:
 *
 *   - the pre-verdict check STATTED each manifest candidate and stopped there.
 *     Stat and open are two different permissions: a 0600 file stats for
 *     everybody and opens for nobody but its owner, so the bytes that decide
 *     the key were never consulted. Every candidate that is there is now
 *     opened and one byte taken out of it;
 *   - Hermes WRAPS what it hits. `agent_plugins._read_json_object` turns the
 *     PermissionError into an `AgentPluginError` — a ValueError — with
 *     `raise ... from exc`, and `plugins_discovery` logs the wrapper. On its
 *     own type that is indistinguishable from a schema rejection, which is an
 *     ANSWER. The probe used to DISABLE those loggers; it now collects the
 *     records and follows every exception they carry down its
 *     `__cause__`/`__context__` chain.
 *
 * Either one makes the path undetermined, with the same consequence as every
 * other hole since r6: no verdict on this host, and the whole repair refused.
 * An ordinary rejection — bad JSON, a wrong `$schema`, YAML that will not
 * construct — has no OSError under it and is untouched: Hermes' answer there
 * is "this is not a plugin", which is a verdict and not a gap.
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

/**
 * Which of Hermes' discovery sources a manifest came from.
 *
 * `user` is a `plugins/` root under the Hermes home or a profile — the tree the
 * installer writes to and the only one this command ever moves anything in.
 * `project` is `<cwd>/.hermes/plugins`, scanned after user when
 * `HERMES_ENABLE_PROJECT_PLUGINS` is enabled, which means it WINS (#569 r7).
 */
export type HermesPluginSource = 'user' | 'project';

/** One directory under a `plugins/` root whose manifest declares our name. */
export interface HermesPluginCopy {
  /** Absolute path of the plugin directory, exactly as discovery names it. */
  dir: string;
  /** Its basename — the string Hermes sorts on. */
  dirName: string;
  /** The `plugins/` root it was found under. */
  root: string;
  /**
   * True only for `<root>/shieldcortex` under a USER root, the directory our
   * installer writes. A copy in the project directory is never canonical
   * however it is named: the installer never writes there, and a repair never
   * touches it (#569 r7).
   */
  canonical: boolean;
  /** Which discovery source found it. */
  source: HermesPluginSource;
}

/** Hermes' answer for one `plugins/` root. */
export interface HermesPluginRootScan {
  root: string;
  /** Every copy keyed `shieldcortex`, in Hermes' discovery order. */
  copies: HermesPluginCopy[];
  /**
   * The winner of the key among THIS ROOT's own copies. `effective` is what
   * the gateway really loads; the two differ only when a project plugin
   * overrides this root (#569 r7).
   */
  loaded: HermesPluginCopy | null;
  /**
   * What a gateway running on this root actually loads for the key, once the
   * project source is taken into account — `resolve_manifest_winners` over
   * this root plus the project directory, which is Hermes' own precedence.
   * Equal to `loaded` whenever project plugins are off or hold no copy.
   */
  effective: HermesPluginCopy | null;
  /**
   * Every plugin directory Hermes discovered a manifest in under this root —
   * ALL keys, categories included, ours and everyone else's (#569 r7).
   *
   * This is a PROTECTION list and nothing else. It never decides a collision,
   * a winner or a move: only an exact `shieldcortex` key can collide with the
   * installed plugin. But `profiles/work/plugins/security/shieldcortex` is
   * keyed `security/shieldcortex`, and it can be a symlink to the very backup
   * this repair would move — so the repair walks and protects every one of
   * these paths even though none of them is a copy.
   */
  discovered: string[];
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

/**
 * One place the filesystem could not be read, and what it said (#569 r6).
 *
 * This is the third answer every enumeration and stat on this path has to be
 * able to give. "There is nothing there" and "I could not look" are different
 * facts about a directory, and only the first one makes it safe to move
 * something: a `profiles/` that can be traversed but not listed raises
 * PermissionError, and a caller that catches that and carries on with an empty
 * list has just dropped every sibling profile out of the safety scan.
 */
export interface HermesUndetermined {
  /** The exact path that could not be read. */
  path: string;
  /** The error, as `ErrorName: message` (Python) or `CODE: message` (Node). */
  error: string;
}

/**
 * Hermes' OPT-IN PROJECT PLUGIN SOURCE, as this host has it configured (#569
 * r7).
 *
 * `collect_directory_manifests` scans `Path.cwd()/.hermes/plugins` as source
 * `"project"` AFTER the user plugins when `HERMES_ENABLE_PROJECT_PLUGINS` is
 * enabled, and later sources win. So an old copy in a project directory beats
 * the canonical install silently, and a check that looked only at the user
 * roots would certify that host clean.
 *
 * Two honest limits, both said out loud in the row rather than papered over:
 * the working directory here is the DOCTOR's, not the gateway's, and the
 * variable read here is the DOCTOR's environment. Nothing in this process can
 * see either of the gateway's.
 */
export interface HermesProjectState {
  /** Whether `HERMES_ENABLE_PROJECT_PLUGINS` is present at all in this environment. */
  envSet: boolean;
  /** Hermes' own `_env_enabled` verdict for it — set is not the same as enabled. */
  enabled: boolean;
  /** `<cwd>/.hermes/plugins`, as Hermes would compute it here. Null unless enabled. */
  dir: string | null;
  /** Copies keyed `shieldcortex` in that directory, in discovery order. */
  copies: HermesPluginCopy[];
  /** Every manifest directory there, all keys — the protection list again. */
  discovered: string[];
  /**
   * That directory, resolved through symlinks, IS the ACTIVE plugins root
   * (#569 r9) — `cwd=$HOME` with `HERMES_HOME=$HOME/.hermes` is the ordinary
   * way to arrive here. Hermes scans one directory twice under two labels:
   * same manifests, same winner, and a root the repair may fix like any other.
   * So `copies` and `discovered` are EMPTY when this is true, not because the
   * directory is empty but because everything in it is already reported as
   * that root's own.
   *
   * It is deliberately NOT set for any other root. With
   * `HERMES_HOME=<root>/profiles/work` the user source is the profile and
   * `<root>/plugins` is read as `project` alone, so it wins the key over the
   * profile's install — the exact host the sibling Ekho change reported as
   * clean (ekho#85 r9 blocker C).
   */
  sameAsActiveRoot: boolean;
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
   * a repair has to protect. It IS set when Hermes named the root and the
   * enumeration under it then failed (#569 r6) — that is Hermes' own answer to
   * the only question it was asked, and it is what the row needs to say where
   * the unreadable path is; `fromHermes` is still false and nothing is a
   * verdict.
   */
  hermesRoot: string | null;
  /** Whether the Hermes home directory exists at all. */
  present: boolean;
  /**
   * True when Hermes' own discovery answered COMPLETELY. When it is FALSE
   * nothing below is a verdict: `roots` and `copies` are empty, `shadowed` is
   * false because it is unknown rather than because it is absent, and only
   * `hintRoots`, `undetermined` and `undeterminedReason` carry anything.
   *
   * A scan with a hole in it is false here too (#569 r6). Hermes may have
   * answered about every root it could read, but a root it could not read is
   * not an empty root, and a caller that cannot tell the difference is exactly
   * the caller that moves the directory another profile loads from.
   */
  fromHermes: boolean;
  /** Why Hermes could not be asked, verbatim. Null when `fromHermes`. */
  undeterminedReason: string | null;
  /**
   * The paths that could not be read, with their errors (#569 r6). Non-empty
   * implies `fromHermes === false`; it is the reason-with-detail behind
   * `undeterminedReason`, kept structured so a row can name every one of them.
   */
  undetermined: HermesUndetermined[];
  roots: HermesPluginRootScan[];
  /** Every copy across every root, roots in order. Never project copies. */
  copies: HermesPluginCopy[];
  /**
   * Every plugin directory Hermes discovered a manifest in, across every
   * protective root AND the project directory — all keys, deduplicated, roots
   * in order (#569 r7). Protection only; see `HermesPluginRootScan.discovered`.
   */
  discovered: string[];
  shadowed: boolean;
  /** The project source, and what is in it. */
  project: HermesProjectState;
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

/**
 * One filesystem error in the words an operator can act on: the errno code
 * first, because `EACCES` is the whole diagnosis, then whatever the platform
 * said. Shared with the doctor's repair so both halves of #569 r6 name a
 * failure the same way.
 */
export function describeFsError(err: unknown): string {
  const code = (err as NodeJS.ErrnoException)?.code;
  const message = err instanceof Error ? err.message : String(err);
  return typeof code === 'string' && code !== '' ? `${code}: ${message}` : message;
}

/**
 * Is this a directory, is it absent, or could we not tell (#569 r6)?
 *
 * `statSync` in a `try/catch` that returns false conflates the last two, and
 * "there is no Hermes here" is a conclusion this module draws from exactly
 * that answer. ENOENT and ENOTDIR are genuine absence — nothing is there, and
 * nothing under a non-directory can be either; anything else is undetermined.
 */
function directoryState(target: string): 'dir' | 'notdir' | 'absent' | { error: string } {
  try {
    return fs.statSync(target).isDirectory() ? 'dir' : 'notdir';
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return 'absent';
    return { error: describeFsError(err) };
  }
}

function isDirectory(target: string): boolean {
  return directoryState(target) === 'dir';
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
 * ## What it could not read (#569 r6)
 *
 * Alongside the roots it returns an `undetermined` list of `{path, error}`.
 * Every enumeration and stat in the script feeds it, and so does an audit walk
 * over each root that follows `scan_directory`'s own traversal looking for the
 * places Hermes would have skipped silently — an unlistable root, a child it
 * cannot stat, a manifest name it cannot ask about. Hermes' discovery is
 * forgiving by design, because one unreadable plugin must not break the
 * loader; a safety scan cannot afford the same forgiveness, because the copy
 * that was skipped is the one the repair would move something out from under.
 * One entry is enough to withdraw every verdict on this host.
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
  'import contextlib, io, json, logging, os, stat, sys',
  '_payload = json.loads(sys.argv[1])',
  '_real = sys.stdout',
  // ── Absent, or undetermined — never "empty" (#569 r6) ─────────────────
  //
  // A directory that can be traversed but not listed raises PermissionError,
  // and `except OSError: names = []` reads that as an empty directory. That is
  // how a whole profile root fell out of the protective scan while the repair
  // ran on and moved the backup the profile's install pointed at.
  //
  // So every enumeration and stat below answers one of three things: what is
  // there, GENUINELY ABSENT (ENOENT on the path itself — it contributes
  // nothing, which is true), or UNDETERMINED. Undetermined is recorded here
  // with the path and the error and travels out in the JSON; the TypeScript
  // side turns a single entry into "no verdict, no repair" for every root.
  '_undet = []',
  'def _note(_p, _exc):',
  // Deduplicated because the same failure is now found twice on purpose: our
  // own pre-read opens the manifest, and Hermes logs its own attempt at it
  // (#569 r8). Two identical rows would only crowd the bounded summary.
  '    _entry = {"path": str(_p), "error": "%s: %s" % (type(_exc).__name__, _exc)}',
  '    if _entry not in _undet:',
  '        _undet.append(_entry)',
  'def _listdir(_p):',
  '    """Sorted names under _p. [] when _p is genuinely absent, None when undetermined."""',
  '    try:',
  '        return sorted(os.listdir(_p))',
  '    except FileNotFoundError:',
  '        return []',
  '    except BaseException as _exc:',
  '        _note(_p, _exc)',
  '        return None',
  'def _state(_p):',
  '    """(exists, is_dir), following links as Hermes\' own `Path.is_dir()` does.',
  '',
  '    None is undetermined. ENOENT and ENOTDIR mean the path is not there: a',
  '    dangling link and a name under a non-directory are both genuinely absent,',
  '    and Hermes reads them the same way."""',
  '    try:',
  '        _st = os.stat(_p)',
  '    except (FileNotFoundError, NotADirectoryError):',
  '        return (False, False)',
  '    except BaseException as _exc:',
  '        _note(_p, _exc)',
  '        return None',
  '    return (True, stat.S_ISDIR(_st.st_mode))',
  // ── Is this project dir the ACTIVE plugins root? (#569 r9) ────────────
  //
  // `<cwd>/.hermes/plugins` and `get_hermes_home()/plugins` can be one
  // directory, and which of the two situations it is decides the verdict. See
  // `_same_directory`. Both are resolved through symlinks, and a path that
  // will not resolve is a NON-ANSWER: `_state` records it, which withdraws the
  // verdict for this whole host rather than guessing either way.
  'def _resolved_dir(_p):',
  '    """_p with its symlinks resolved, or None when the filesystem could not say.',
  '',
  '    Absence is an ANSWER here, not a problem: `<home>/plugins` is in the root',
  '    set whether or not it exists, and project plugins enabled in a directory',
  '    with no `.hermes` at all is an ordinary clean run. Every component that IS',
  '    there still resolves, which is what makes `<cwd>/.hermes -> <home>/.hermes`',
  '    compare equal with the `plugins/` inside it absent.',
  '',
  '    `_state` is what tells the two apart: it answers ENOENT/ENOTDIR as absence',
  '    and records anything else — a symlink loop, a component that cannot be',
  '    traversed — as undetermined. A stat that succeeded also means every',
  '    component was traversable, which is exactly what `realpath` needs to be',
  '    right about the links it reads."""',
  '    _abs = os.path.normpath(os.path.abspath(_p))',
  '    if _state(_abs) is None:',
  '        return None',
  '    return os.path.normpath(os.path.realpath(_abs))',
  'def _same_directory(_left, _right):',
  '    """(do these name the same directory?, was that answerable at all?)',
  '',
  '    One caller: noticing that the enabled project dir IS the ACTIVE plugins',
  '    root. `cwd=$HOME` with `HERMES_HOME=$HOME/.hermes` makes',
  '    `<cwd>/.hermes/plugins` and `<home>/plugins` one directory, which Hermes',
  '    then scans twice under two source labels — harmless to the loader, and',
  '    taken literally here it turns the operator\'s own plugins root into an',
  '    untouchable project dir and refuses its repair.',
  '',
  '    Only the ACTIVE root, and only ever the active root. Matching some OTHER',
  '    root is not the same situation: Hermes\' user source is',
  '    `get_hermes_home()/plugins` ALONE, so with',
  '    `HERMES_HOME=<root>/profiles/work` the profile is the user source and',
  '    `<root>/plugins` is read as `project` alone — which means it WINS the key',
  '    over the profile\'s install. Reading that as "a root we already cover"',
  '    discards the source that decides which tree loads, and reports the root',
  '    that lost as clean (ekho#85 r9 blocker C).',
  '',
  '    Neither answer is safe to guess, so a path that will not resolve comes',
  '    back unanswerable: "no" scans a root a second time and refuses the repair',
  '    of a tree that may be the operator\'s own, and "yes" drops the one source',
  '    that beats every root."""',
  '    if os.path.normpath(_left) == os.path.normpath(_right):',
  '        return (True, True)',
  '    _l = _resolved_dir(_left)',
  '    _r = _resolved_dir(_right)',
  '    if _l is None or _r is None:',
  '        return (False, False)',
  '    return (_l == _r, True)',
  // Hermes' own skip rules, mirrored so the audit walks where discovery walks
  // and does not report an undetermined entry for a directory Hermes never
  // looks inside.
  '_FOREIGN = set([".claude-plugin", ".codex-plugin", ".cursor-plugin", ".devin-plugin",',
  '                ".kimi-plugin"])',
  '_MANIFESTS = ("plugin.yaml", "plugin.yml", "plugin.json")',
  // ── Statting a manifest is not reading it (#569 r8) ───────────────────
  //
  // The pre-verdict check stopped at `os.stat`, and stat and open are two
  // different permissions. `plugins/shieldcortex.bak-portable/plugin.json`
  // written 0600 by the service account lists and stats for anybody and opens
  // for nobody else: Hermes reads it, keys the directory `shieldcortex` and
  // loads it, while this check saw a manifest that was "there", found no
  // problem, and reported ONE canonical copy — a clean PASS on a host running
  // the backup. So every candidate that is there is OPENED and one byte is
  // taken out of it.
  'def _manifest_state(_child):',
  '    """(has_manifest, blind) for one plugin directory.',
  '',
  '    Absent is the ordinary case and no problem at all — most directories',
  '    hold one of the three names and not the other two. A candidate that is',
  '    not a REGULAR file is an answer as well and is left alone: nobody reads',
  '    a directory as a manifest, here or in the loader, and opening a FIFO',
  '    named `plugin.json` would hang this scan rather than answer it.',
  '',
  '    Every other error is UNDETERMINED and is recorded with its path, which',
  '    withdraws the verdict for this whole host: a manifest this process',
  '    cannot read may say `name: shieldcortex` to the account that can."""',
  '    _has = False',
  '    _blind = False',
  '    for _base in _MANIFESTS:',
  '        _p = os.path.join(_child, _base)',
  '        try:',
  '            _st = os.stat(_p)',
  '        except (FileNotFoundError, NotADirectoryError):',
  '            continue',
  '        except BaseException as _exc:',
  '            _note(_p, _exc)',
  '            _blind = True',
  '            continue',
  '        _has = True',
  '        if not stat.S_ISREG(_st.st_mode):',
  '            continue',
  '        try:',
  '            with open(_p, "rb") as _fh:',
  '                _fh.read(1)',
  '        except FileNotFoundError:',
  '            continue',
  '        except BaseException as _exc:',
  '            _note(_p, _exc)',
  '            _blind = True',
  '    return (_has, _blind)',
  'def _audit(_d, _depth):',
  '    """Walk one `plugins/` root exactly where `scan_directory` walks it and',
  '    record every place the filesystem could not answer.',
  '',
  '    Hermes\' discovery is deliberately forgiving: an unlistable root logs a',
  '    warning and returns the manifests it managed to read, and an unreadable',
  '    child is skipped so that one bad plugin cannot break every other one.',
  '    That is right for a loader and fatal for a safety scan, because the copy',
  '    it skipped is exactly the one a repair would then move something out from',
  '    under. Nothing here reads or parses a manifest — the only question asked',
  '    is whether the filesystem could answer at all."""',
  '    _names = _listdir(_d)',
  '    if _names is None:',
  '        return',
  '    for _n in _names:',
  '        if _n.startswith("__") and _n.endswith("__"):',
  '            continue',
  '        if _n in _FOREIGN:',
  '            continue',
  '        _child = os.path.join(_d, _n)',
  '        _cs = _state(_child)',
  '        if _cs is None or not _cs[1]:',
  '            continue',
  '        _has, _blind = _manifest_state(_child)',
  // A manifest-less directory is a category directory to Hermes and it
  // recurses one level into it; the audit follows to the same depth cap.
  '        if not _blind and not _has and _depth == 0:',
  '            _audit(_child, 1)',
  // ── What Hermes met, followed down its cause chain (#569 r8) ──────────
  //
  // Hermes does not always log the error it hit. `agent_plugins
  // ._read_json_object` turns a PermissionError on `plugin.json` into an
  // `AgentPluginError` — a ValueError — with `raise ... from exc`, and
  // `plugins_discovery` logs that wrapper. Judged on the logged object alone
  // it is indistinguishable from a manifest that failed schema validation,
  // which is an ANSWER ("this is not a plugin"), so a directory neither
  // Hermes nor this process could read was recorded as no plugin at all and
  // the root came out clean.
  '_MAX_CHAIN = 12',
  '_records = []',
  'class _Collect(logging.Filter):',
  '    """Keep what Hermes logs while it scans, and keep it off the console.',
  '',
  '    This probe used to set `disabled = True` on the discovery loggers,',
  '    which is quieter still and throws the record away before anything can',
  '    look at it. A WARNING is how `scan_directory` reports the manifest it',
  '    could not read, so the record IS the evidence and discarding it is how',
  '    an unreadable copy became a clean verdict. Returning False stops the',
  '    record before `callHandlers`, so it reaches no handler and no ancestor',
  '    logger either."""',
  '',
  '    def filter(self, _record):',
  '        _records.append(_record)',
  '        return False',
  'def _os_error_in_chain(_e):',
  '    """The filesystem failure underneath _e, or None if there is not one.',
  '',
  '    `__cause__` first (the explicit `raise ... from`), then `__context__`',
  '    (what was being handled), bounded by _MAX_CHAIN with a seen-set for the',
  '    cycles `__context__` can form. FileNotFoundError is not one of these at',
  '    any depth — a manifest that went away mid-scan was discovered by nobody',
  '    — and a JSON or schema error with no OSError under it comes back None',
  '    and stays the verdict it is."""',
  '    _seen = set()',
  '    while isinstance(_e, BaseException) and len(_seen) < _MAX_CHAIN:',
  '        if id(_e) in _seen:',
  '            return None',
  '        _seen.add(id(_e))',
  '        if isinstance(_e, OSError) and not isinstance(_e, FileNotFoundError):',
  '            return _e',
  '        _e = _e.__cause__ if _e.__cause__ is not None else _e.__context__',
  '    return None',
  'def _record_excs(_r, _args):',
  '    """Every exception one record carries: in its args, and in `exc_info`.',
  '',
  '    Hermes logs the exception as a formatting argument ("Failed to parse',
  '    %s: %s", path, exc) and sometimes attaches it as well —',
  '    `parse_manifest_file` passes `exc_info=` under the plugins debug flag.',
  '    Both are read, because which one is populated is a Hermes-side setting',
  '    and not something a verdict here may depend on."""',
  '    _found = [_a for _a in _args if isinstance(_a, BaseException)]',
  '    _info = getattr(_r, "exc_info", None)',
  '    if isinstance(_info, tuple) and len(_info) > 1 and isinstance(_info[1], BaseException):',
  '        _found.append(_info[1])',
  '    return _found',
  'def _note_logged():',
  '    """Record every filesystem failure Hermes met, as one of ours.',
  '',
  '    The test is on the record\'s arguments rather than on its wording, so a',
  '    rephrased log line still counts. The path is the first path-like',
  '    argument — Hermes puts it there in every one of these lines — and falls',
  '    back to the errno\'s own `filename`."""',
  '    for _r in _records:',
  '        _args = _r.args if isinstance(_r.args, tuple) else (_r.args,)',
  '        _under = None',
  '        for _cand in _record_excs(_r, _args):',
  '            _under = _os_error_in_chain(_cand)',
  '            if _under is not None:',
  '                break',
  '        if _under is None:',
  '            continue',
  '        _named = None',
  '        for _a in _args:',
  '            if isinstance(_a, str) or hasattr(_a, "__fspath__"):',
  '                _named = _a',
  '                break',
  '        if _named is None:',
  '            _named = getattr(_under, "filename", None)',
  '        _note(_named if _named is not None else "(path not reported)", _under)',
  'try:',
  '    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):',
  '        for _cand in _payload.get("importRoots") or []:',
  // Not a protective path: this only decides whether a candidate joins
  // `sys.path`. A wrong answer cannot invent a verdict — it can only cost us
  // the import, which is already a hard probe failure — but an unreadable
  // candidate is still recorded, because "which `hermes_cli` answered" is the
  // premise the whole parity claim rests on.
  '            _cs = _state(os.path.join(_cand, "hermes_cli"))',
  '            if _cs is not None and _cs[1] and _cand not in sys.path:',
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
  // A record that is never created cannot be classified, so the suppression
  // that used to live here is replaced by a collector (#569 r8). A level or a
  // global `logging.disable` high enough to swallow a WARNING is lifted on
  // these loggers only, which costs nothing: this child process exists solely
  // for the scan, and everything the lift lets through `_Collect` drops.
  '        logging.disable(logging.NOTSET)',
  '        _collector = _Collect()',
  '        for _lname in _quiet:',
  '            _lg = logging.getLogger(_lname)',
  '            _lg.disabled = False',
  '            if _lg.getEffectiveLevel() > logging.WARNING:',
  '                _lg.setLevel(logging.WARNING)',
  '            _lg.addFilter(_collector)',
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
  // The line this round exists for. A `profiles/` that can be traversed but
  // not listed used to become `[]` here, and every sibling profile silently
  // left the protective set.
  '        _names = _listdir(_profiles)',
  '        for _n in (_names or []):',
  '            _ps = _state(os.path.join(_profiles, _n))',
  '            if _ps is not None and _ps[1]:',
  '                _add(os.path.join(_profiles, _n, "plugins"))',
  '        _add(os.path.join(_active, "plugins"))',
  // ── Project plugins, from Hermes' own switch (#569 r7) ────────────────
  //
  // `collect_directory_manifests` scans `Path.cwd()/.hermes/plugins` as source
  // `"project"` AFTER the user source when `HERMES_ENABLE_PROJECT_PLUGINS` is
  // enabled, and `resolve_manifest_winners` lets the later source win. So an
  // older copy sitting in a project directory beats the canonical install, and
  // a scan of the user roots alone reports a host that is clean and is not.
  //
  // Whether the switch is on is Hermes' own question, asked of Hermes' own
  // helper through the same origin module `plugins_discovery` uses. If that
  // helper cannot be reached and the variable is set to anything at all, the
  // whole probe fails: "the switch might be on and I could not ask" is not a
  // clean bill of health.
  '        _proj = {"envSet": ("HERMES_ENABLE_PROJECT_PLUGINS" in os.environ), "enabled": False,',
  '                 "dir": None, "copies": [], "discovered": [], "sameAsActiveRoot": False}',
  '        try:',
  '            from hermes_cli import plugins as _origin',
  '            _proj["enabled"] = bool(_origin._env_enabled("HERMES_ENABLE_PROJECT_PLUGINS"))',
  '        except BaseException as _pexc:',
  '            if _proj["envSet"]:',
  '                raise RuntimeError("HERMES_ENABLE_PROJECT_PLUGINS is set but the Hermes helper '
    + '_env_enabled could not be reached (%s: %s)" % (type(_pexc).__name__, _pexc))',
  '        _proj_ms = []',
  '        if _proj["enabled"]:',
  // Hermes' own expression, evaluated in this child: the doctor's working
  // directory. It is NOT the gateway's, which nothing here can see — the
  // caller says so in the row rather than pretending otherwise.
  '            _pdir = os.path.normpath(os.path.abspath(os.path.join(os.getcwd(), ".hermes", "plugins")))',
  '            _proj["dir"] = _pdir',
  // The ACTIVE plugins root and nothing else (#569 r9). When the project dir
  // IS that root, Hermes reads one directory twice under two labels: same
  // manifests, same winner, and an ordinary root the repair is allowed to fix.
  // When it is any OTHER root — `<root>/plugins` under
  // `HERMES_HOME=<root>/profiles/work` — it is not a source this scan already
  // covers, because Hermes' user source is the active home alone; it is read
  // as `project` only, and it therefore wins the key over every root. See
  // `_same_directory`.
  '            _same, _known = _same_directory(_pdir, os.path.join(_active, "plugins"))',
  '            _proj["sameAsActiveRoot"] = _same',
  // Unanswerable is neither branch: `_state` has already recorded the failure,
  // which makes the whole host undetermined on the TypeScript side, and there
  // is nothing to gain by scanning a directory whose role could not be
  // established.
  '            if _known and not _same:',
  '                _audit(_pdir, 0)',
  '                _proj_ms = scan_directory(Path(_pdir), "project")',
  '                _proj["copies"] = [str(_m.path) for _m in _proj_ms if manifest_key(_m) == _name]',
  '                _proj["discovered"] = [str(_m.path) for _m in _proj_ms]',
  '        _out = []',
  '        for _r in _roots:',
  '            _audit(_r, 0)',
  '            _ms = scan_directory(Path(_r), "user")',
  '            _copies = [str(_m.path) for _m in _ms if manifest_key(_m) == _name]',
  // EVERY manifest in the root, under every key — categories included (#569
  // r7). The collision set stays exactly what it was, because only an exact
  // `shieldcortex` key can collide; but `security/shieldcortex` in a profile
  // is a real installation that can be a symlink to the very backup this
  // repair would move, and a plan that cannot see it strands it.
  '            _disc = [str(_m.path) for _m in _ms]',
  '            _win = resolve_manifest_winners(_ms).get(_name)',
  '            _eff = resolve_manifest_winners(_ms + _proj_ms).get(_name)',
  '            _out.append({"root": _r, "copies": _copies, "discovered": _disc,',
  '                         "loaded": (str(_win.path) if _win is not None else None),',
  '                         "effective": (str(_eff.path) if _eff is not None else None),',
  '                         "effectiveSource": (str(_eff.source) if _eff is not None else None)})',
  // Last, because it reads what EVERY scan above logged. A wrapped
  // PermissionError on a portable manifest arrives here and nowhere else
  // (#569 r8).
  '        _note_logged()',
  '    _real.write(json.dumps({"ok": True, "activeHome": _active, "root": _root, "roots": _out,',
  '                            "project": _proj, "undetermined": _undet}))',
  'except BaseException as _exc:',
  '    _real.write(json.dumps({"ok": False, "error": "%s: %s" % (type(_exc).__name__, _exc)}))',
].join('\n');

interface ProbeRoot {
  root: string;
  copies: string[];
  /** Every manifest directory in the root, all keys (#569 r7). */
  discovered: string[];
  /** The winner among this root's own copies. */
  loaded: string | null;
  /** The winner once the project source is included. */
  effective: string | null;
  /** Which source `effective` came from. Null exactly when `effective` is. */
  effectiveSource: HermesPluginSource | null;
}

interface ProbeProject {
  envSet: boolean;
  enabled: boolean;
  dir: string | null;
  copies: string[];
  discovered: string[];
  /** Whether that directory resolves to the ACTIVE plugins root (#569 r9). */
  sameAsActiveRoot: boolean;
}

/** Everything the probe answers: where Hermes lives, and what is in each root. */
export interface HermesProbeResult {
  /** `hermes_constants.get_hermes_home()`. */
  activeHome: string;
  /** `hermes_constants.get_default_hermes_root()`. */
  root: string;
  /** Every protective root, in the order the probe built them. */
  roots: ProbeRoot[];
  /** Hermes' project source, as this environment has it configured (#569 r7). */
  project: ProbeProject;
  /**
   * Every place the filesystem could not answer (#569 r6). Empty is the normal
   * case and the only one in which `roots` is a complete picture; a single
   * entry means the scan has a hole in it, and a hole is not an absence.
   */
  undetermined: HermesUndetermined[];
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
  // Shape first, dereference second (#569 r7). `JSON.parse('null')` is a
  // perfectly successful parse, and reading `.ok` off it throws a TypeError out
  // of a function whose whole contract is to RETURN "no answer" — the caller
  // then reports a crash rather than an undetermined scan. Nothing below is
  // filtered, either: a response with one malformed element is a response from
  // something that is not the probe, and taking the rest of it on trust is how
  // a copy goes missing from the collision set.
  if (!isRecord(parsed)) return { error: 'Hermes probe produced no result object' };
  const record = parsed;
  if (record.ok !== true || !Array.isArray(record.roots)) {
    const why = typeof record.error === 'string' ? record.error : 'unknown reason';
    return { error: `Hermes could not be asked — ${why}` };
  }
  if (typeof record.activeHome !== 'string' || typeof record.root !== 'string') {
    return { error: 'Hermes probe named no home or no containing root' };
  }
  // An older probe that does not carry the field at all is not "nothing went
  // wrong" — it is a probe whose answer cannot be trusted on this question, and
  // the whole point of the field is that silence is not a clean bill of health.
  if (!Array.isArray(record.undetermined)) {
    return { error: 'Hermes probe did not say which paths it could not read' };
  }
  const undetermined: HermesUndetermined[] = [];
  for (const entry of record.undetermined) {
    if (!isRecord(entry) || typeof entry.path !== 'string' || typeof entry.error !== 'string') {
      return { error: 'Hermes probe returned a malformed undetermined entry' };
    }
    undetermined.push({ path: entry.path, error: entry.error });
  }
  const out: ProbeRoot[] = [];
  for (const entry of record.roots) {
    if (!isRecord(entry) || typeof entry.root !== 'string') {
      return { error: 'Hermes probe returned a malformed root entry' };
    }
    const copies = stringArray(entry.copies);
    const discovered = stringArray(entry.discovered);
    if (copies === null || discovered === null) {
      return { error: 'Hermes probe returned a malformed root entry' };
    }
    const loaded = optionalString(entry.loaded);
    const effective = optionalString(entry.effective);
    if (loaded === undefined || effective === undefined) {
      return { error: 'Hermes probe returned a malformed root entry' };
    }
    const effectiveSource = pluginSource(entry.effectiveSource);
    if (effectiveSource === undefined || (effective === null) !== (effectiveSource === null)) {
      return { error: 'Hermes probe returned a malformed root entry' };
    }
    out.push({ root: entry.root, copies, discovered, loaded, effective, effectiveSource });
  }
  const project = projectFrom(record.project);
  if (project === null) return { error: 'Hermes probe returned a malformed project entry' };
  return { activeHome: record.activeHome, root: record.root, roots: out, project, undetermined };
}

/** A JSON object — not null, not an array, which `typeof` alone cannot say. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** `value` as an array of strings, or null when ANY element is not one. */
function stringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string') return null;
    out.push(item);
  }
  return out;
}

/** A string or an explicit null; `undefined` means "neither, so malformed". */
function optionalString(value: unknown): string | null | undefined {
  if (typeof value === 'string') return value;
  if (value === null) return null;
  return undefined;
}

/** One of Hermes' two directory sources, or null; `undefined` is malformed. */
function pluginSource(value: unknown): HermesPluginSource | null | undefined {
  if (value === 'user' || value === 'project') return value;
  if (value === null) return null;
  return undefined;
}

/** The project block, validated whole; null rejects the entire response. */
function projectFrom(value: unknown): ProbeProject | null {
  if (!isRecord(value)) return null;
  if (typeof value.envSet !== 'boolean' || typeof value.enabled !== 'boolean') return null;
  const dir = optionalString(value.dir);
  if (dir === undefined) return null;
  const copies = stringArray(value.copies);
  const discovered = stringArray(value.discovered);
  if (copies === null || discovered === null) return null;
  // A probe that does not carry the field is not one that found no equality —
  // it is one that never asked, and "the project dir might BE this root" is
  // the difference between an untouchable source and the operator's own
  // plugins tree (#569 r9).
  if (typeof value.sameAsActiveRoot !== 'boolean') return null;
  // Enabled means the directory was computed and scanned; a payload that says
  // it scanned a directory it cannot name is not one to act on.
  if (value.enabled && dir === null) return null;
  return {
    envSet: value.envSet,
    enabled: value.enabled,
    dir,
    copies,
    discovered,
    sameAsActiveRoot: value.sameAsActiveRoot,
  };
}

function toCopy(dir: string, root: string, source: HermesPluginSource): HermesPluginCopy {
  const dirName = path.basename(dir);
  return {
    dir,
    dirName,
    root,
    // Canonical is a position AND a source, not just a name: it is the
    // directory the installer writes, which is always `<root>/shieldcortex`
    // under a user root. A `shieldcortex` nested under a category is a
    // different key entirely and never reaches here; a `shieldcortex` in the
    // project directory is a copy the installer never wrote and this command
    // never moves, so it is not the canonical one either (#569 r7).
    canonical:
      source === 'user' &&
      dirName === HERMES_PLUGIN_NAME &&
      path.resolve(path.dirname(dir)) === path.resolve(root),
    source,
  };
}


/**
 * Hermes' answer for one root, turned into the shape doctor reports on.
 *
 * `projectCopies` are the project source's own copies, already built: the
 * effective winner for this root can be one of them, and it has to come back
 * carrying its real root and source rather than being re-attributed to the
 * user root that it beat (#569 r7).
 */
function rootScanFrom(
  probe: ProbeRoot,
  activeHome: string,
  projectCopies: HermesPluginCopy[],
): HermesPluginRootScan {
  const copies = probe.copies.map((dir) => toCopy(dir, probe.root, 'user'));
  const known = [...copies, ...projectCopies];
  // The SOURCE is Hermes' own answer and is matched on first (#569 r9). One
  // directory can be both this root's own copy and the project source's — a
  // project dir that is some other plugins root — and taking whichever entry
  // happened to be built first re-labels the source that actually won the key.
  const resolve = (dir: string | null, source: HermesPluginSource): HermesPluginCopy | null =>
    dir === null
      ? null
      : known.find((c) => c.dir === dir && c.source === source) ??
        known.find((c) => c.dir === dir) ??
        toCopy(dir, probe.root, source);
  const loaded = resolve(probe.loaded, 'user');
  const effective = resolve(probe.effective, probe.effectiveSource ?? 'user');
  return {
    root: probe.root,
    copies,
    loaded,
    effective,
    discovered: probe.discovered,
    hasCanonical: copies.some((c) => c.canonical),
    // Root-local, deliberately: "is the copy this root installed the one this
    // root loads". A project plugin overriding the root is a different fact
    // with a different remedy, carried by `effective` and reported on its own.
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
 * Since r6 it covers a PARTIAL answer too: if any directory in the tree could
 * not be read, `undetermined` names it and `fromHermes` is false, because a
 * scan that missed a root is indistinguishable from one where that root was
 * empty — and those two hosts want opposite things from the repair.
 */
export function scanHermesPluginCopies(
  env: HermesEnvironment,
  opts: HermesScanOptions = {},
): HermesPluginScan {
  // Best-effort, and used only to answer "is there a Hermes here at all" and
  // to list hint directories when there is nothing to ask. See
  // `resolveHermesHome`.
  const guessedHome = resolveHermesHome(env);
  const homeState = directoryState(guessedHome);
  const base = {
    hermesHome: guessedHome,
    hermesRoot: null as string | null,
    present: homeState === 'dir',
    fromHermes: false,
    undeterminedReason: null as string | null,
    undetermined: [] as HermesUndetermined[],
    roots: [] as HermesPluginRootScan[],
    copies: [] as HermesPluginCopy[],
    discovered: [] as string[],
    shadowed: false,
    // Nothing was asked of Hermes on these paths, so `enabled` stays false and
    // says only that: whether the switch is ON is Hermes' answer to give, and
    // where there is no answer there is no verdict. `envSet` is a fact about
    // this process's own environment and is true regardless.
    project: {
      envSet: process.env.HERMES_ENABLE_PROJECT_PLUGINS !== undefined,
      enabled: false,
      dir: null,
      copies: [] as HermesPluginCopy[],
      discovered: [] as string[],
      sameAsActiveRoot: false,
    } as HermesProjectState,
    hintRoots: [] as HermesPluginHintRoot[],
  };
  // "Not detected" is a conclusion, and it may only be drawn from an answer.
  // A home that cannot be statted is undetermined, not absent (#569 r6):
  // reporting "no Hermes here" for an EACCES would tell an operator the one
  // thing that makes it safe to stop looking.
  if (typeof homeState === 'object') {
    return {
      ...base,
      undetermined: [{ path: guessedHome, error: homeState.error }],
      undeterminedReason: undeterminedSummary([{ path: guessedHome, error: homeState.error }]),
    };
  }
  if (homeState !== 'dir') return base;

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

  // Hermes answered, but part of the tree could not be read (#569 r6). What
  // came back is a scan with a hole in it, and a hole is not an absence: the
  // roots it did see are dropped rather than reported, because a caller given
  // three roots out of four has no way to know the fourth was ever there.
  // No hint list either — the hints come off the same filesystem that just
  // said it could not answer.
  if (probe.undetermined.length > 0) {
    return {
      ...base,
      hermesHome: probe.activeHome,
      hermesRoot: probe.root,
      undetermined: probe.undetermined,
      undeterminedReason: undeterminedSummary(probe.undetermined),
    };
  }

  const projectDir = probe.project.dir;
  const projectCopies = probe.project.copies.map((dir) =>
    toCopy(dir, projectDir ?? path.dirname(dir), 'project'),
  );
  const rootScans = probe.roots.map((entry) =>
    rootScanFrom(entry, probe.activeHome, projectCopies),
  );
  const discovered = [
    ...new Set([...rootScans.flatMap((r) => r.discovered), ...probe.project.discovered]),
  ];
  return {
    ...base,
    hermesHome: probe.activeHome,
    hermesRoot: probe.root,
    fromHermes: true,
    roots: rootScans,
    copies: rootScans.flatMap((r) => r.copies),
    discovered,
    shadowed: rootScans.some((r) => r.shadowed),
    project: {
      envSet: probe.project.envSet,
      enabled: probe.project.enabled,
      dir: projectDir,
      copies: projectCopies,
      discovered: probe.project.discovered,
      sameAsActiveRoot: probe.project.sameAsActiveRoot,
    },
  };
}

/** How many undetermined paths a message spells out before it counts the rest. */
const UNDETERMINED_NAMED_LIMIT = 3;

/**
 * The undetermined paths as one sentence, every path with its own error.
 *
 * Bounded on purpose: a host with a mode-000 `plugins/` can produce one entry
 * per child, and a doctor row is read by a human. The first few are named in
 * full — a path and an errno is the whole remedy — and the remainder is
 * counted, so nothing is hidden and the row stays a row.
 */
export function undeterminedSummary(entries: HermesUndetermined[]): string {
  const named = entries
    .slice(0, UNDETERMINED_NAMED_LIMIT)
    .map((e) => `${e.path} (${e.error})`)
    .join('; ');
  const rest = entries.length - Math.min(entries.length, UNDETERMINED_NAMED_LIMIT);
  const more = rest > 0 ? `; and ${rest} more path${rest === 1 ? '' : 's'}` : '';
  return `could not read ${named}${more}`;
}
