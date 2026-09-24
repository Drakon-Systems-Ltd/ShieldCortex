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
 * ## Why this does not re-implement the rules
 *
 * Round 1 of this fix mirrored the discovery rules in a line reader, and an
 * independent review of the sibling Ekho change found six shapes where a line
 * reader and Hermes disagree — each one a silent wrong answer in a health
 * check whose entire job is to be right about what Hermes loads:
 * `name: shieldcortex # backup` (Hermes strips the comment), a manifest with no
 * `name:` at all (Hermes falls back to the directory name), quoted names, a
 * portable `plugin.json` (Hermes accepts it), a `plugin.yaml` DIRECTORY beside
 * a valid `plugin.yml` (Hermes selects on `exists()`, fails to parse, and takes
 * nothing from that directory), and a valid `name:` line above broken YAML
 * (Hermes rejects the manifest).
 *
 * So the primary path asks Hermes: resolve the Hermes interpreter, spawn it
 * with a small embedded script, and let `hermes_cli.plugins_discovery` answer.
 * There is no parity to maintain because there is no second implementation.
 *
 * `setup/hermes-manifest-parse.ts` is the fallback for a host where no Hermes
 * interpreter can be found or the spawn fails. Its answers are marked
 * `approximate`, every caller says so out loud, and a manifest whose shape it
 * does not model comes back `unknown` rather than guessed.
 *
 * Profiles get their own plugin root at `<hermesHome>/profiles/<name>/plugins/`,
 * scanned independently — a collision is per-root.
 */

import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  classifyPluginDir,
  FOREIGN_HARNESS_MANIFEST_DIRS,
  HERMES_PLUGIN_NAME,
} from './hermes-manifest-parse.js';

export { HERMES_PLUGIN_NAME };

/** How long the Hermes probe may take before we fall back. */
const PROBE_TIMEOUT_MS = 8_000;

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

/** The outcome for one `plugins/` root. */
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
   * Directories the FALLBACK reader could not classify and that could still be
   * ours. Always empty on the primary path — Hermes always has an answer.
   */
  unknownDirs: string[];
  /**
   * True when this root holds at least one unknown directory. The root then
   * has NO winner and NO shadow verdict: the copy Hermes loads may well be one
   * of the directories the reader would not read, so naming a winner or
   * calling the root clean would both be guesses (#569 r3).
   */
  undetermined: boolean;
}

export interface HermesPluginScan {
  hermesHome: string;
  /** Whether the Hermes home directory exists at all. */
  present: boolean;
  roots: HermesPluginRootScan[];
  /** Every copy across every root, roots in order. */
  copies: HermesPluginCopy[];
  shadowed: boolean;
  /** True when Hermes' own discovery answered; false when the fallback did. */
  fromHermes: boolean;
  /** Why the fallback was used, for the message. Null when `fromHermes`. */
  fallbackReason: string | null;
  /** Any directory the fallback could not classify, across every root. */
  unknownDirs: string[];
  /** True when at least one root came back undetermined. */
  undetermined: boolean;
}

export interface HermesScanOptions {
  /**
   * Override interpreter resolution. `null` is "this box has no Hermes to
   * ask", which is the seam the fallback tests use: a box with a working
   * Hermes would otherwise never exercise the approximate path.
   */
  interpreter?: string | null;
}

/**
 * `HERMES_HOME` when the operator has set it, else `<home>/.hermes`. Hermes
 * reads the same variable, so a host that has moved its agent home is scanned
 * where its plugins actually are.
 */
export function resolveHermesHome(home: string = os.homedir()): string {
  const override = process.env.HERMES_HOME;
  if (typeof override === 'string' && override.trim() !== '') {
    return path.resolve(override.trim());
  }
  return path.join(home, '.hermes');
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

/** Every `plugins/` root Hermes discovers from: the main one, then profiles. */
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
 * The embedded probe. It imports Hermes' own discovery, scans each root with
 * source `"user"` (the source our plugins root actually is), and prints the
 * copies keyed `shieldcortex` plus the winner.
 *
 * `resolve_manifest_winners` is what decides the winner inside Hermes, so the
 * winner here is not "the last entry" by our reckoning — it is Hermes' answer.
 *
 * stdout and stderr are captured across the import and the scan so a chatty
 * module or a discovery warning cannot land in the middle of the JSON; the
 * result is written to the real stdout afterwards.
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
  '        _out = []',
  '        for _root in _payload["roots"]:',
  '            _ms = scan_directory(Path(_root), "user")',
  '            _copies = [str(_m.path) for _m in _ms if manifest_key(_m) == _name]',
  '            _win = resolve_manifest_winners(_ms).get(_name)',
  '            _out.append({"root": _root, "copies": _copies,',
  '                         "loaded": (str(_win.path) if _win is not None else None)})',
  '    _real.write(json.dumps({"ok": True, "roots": _out}))',
  'except BaseException as _exc:',
  '    _real.write(json.dumps({"ok": False, "error": "%s: %s" % (type(_exc).__name__, _exc)}))',
].join('\n');

interface ProbeRoot {
  root: string;
  copies: string[];
  loaded: string | null;
}

/**
 * Run the Hermes probe over `roots`. Returns null when there is no interpreter,
 * the spawn failed, it timed out, or the output was not the JSON we asked for —
 * every one of which means "fall back", never "there are no copies".
 */
export function probeHermesDiscovery(
  hermesHome: string,
  roots: string[],
  opts: HermesScanOptions = {},
): { roots: ProbeRoot[] } | { error: string } {
  const interpreter =
    opts.interpreter !== undefined ? opts.interpreter : resolveHermesInterpreter(hermesHome);
  if (interpreter === null) return { error: 'no Hermes interpreter found' };

  const payload = JSON.stringify({
    name: HERMES_PLUGIN_NAME,
    roots,
    importRoots: hermesImportRoots(hermesHome, interpreter),
  });

  // spawnSync, no shell: the only untrusted strings here are paths, and they
  // travel as one argv element that nothing re-parses.
  const run = spawnSync(interpreter, ['-c', PROBE_SCRIPT, payload], {
    encoding: 'utf8',
    timeout: PROBE_TIMEOUT_MS,
    maxBuffer: 4 * 1024 * 1024,
    windowsHide: true,
    env: {
      ...process.env,
      HERMES_HOME: hermesHome,
      // Nothing here should leave artefacts in the tree it is inspecting.
      PYTHONDONTWRITEBYTECODE: '1',
      PYTHONWARNINGS: 'ignore',
    },
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
  const record = parsed as { ok?: unknown; error?: unknown; roots?: unknown };
  if (record.ok !== true || !Array.isArray(record.roots)) {
    const why = typeof record.error === 'string' ? record.error : 'unknown reason';
    return { error: `Hermes discovery could not be imported — ${why}` };
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
  return { roots: out };
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

function rootScanFrom(probe: ProbeRoot, unknownDirs: string[] = []): HermesPluginRootScan {
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
    unknownDirs,
    undetermined: unknownDirs.length > 0,
  };
}

// ── Fallback path: the conservative reader ────────────────────────────────

/**
 * Apply Hermes' discovery rules to one `plugins/` root with the conservative
 * reader. Used only when Hermes itself could not be asked; the result is
 * `approximate` and its `unknownDirs` are the directories it refused to guess
 * about.
 */
export function scanHermesPluginRootFallback(root: string): HermesPluginRootScan {
  const copies: HermesPluginCopy[] = [];
  const unknownDirs: string[] = [];
  for (const dirName of childDirectories(root)) {
    // Hermes skips dunder children and the per-harness manifest dirs outright.
    if (dirName.startsWith('__') && dirName.endsWith('__')) continue;
    if (FOREIGN_HARNESS_MANIFEST_DIRS.has(dirName)) continue;
    const dir = path.join(root, dirName);
    const verdict = classifyPluginDir(dir, dirName);
    // A manifest-less child is a CATEGORY dir: its plugins are keyed
    // `<category>/<name>`, which can never collide with a flat name.
    if (verdict === 'category' || verdict === 'other') continue;
    if (verdict === 'unknown') {
      unknownDirs.push(dir);
      continue;
    }
    copies.push(toCopy(dir, root));
  }
  // One unknown costs the whole root its verdict (#569 r3). The directory this
  // reader would not read may be a copy, and it may sort after every copy it
  // did read — so "the last one wins" cannot be applied, and "no shadow here"
  // cannot be claimed either. `copies` stays: those are facts, and the message
  // is better for naming them.
  const undetermined = unknownDirs.length > 0;
  // `copies` is in Hermes' sorted order, and the last writer of the key wins.
  const loaded = !undetermined && copies.length > 0 ? copies[copies.length - 1] : null;
  return {
    root,
    copies,
    loaded,
    hasCanonical: copies.some((c) => c.canonical),
    shadowed: !undetermined && (copies.length > 1 || (loaded !== null && !loaded.canonical)),
    unknownDirs,
    undetermined,
  };
}

// ── Public entry point ───────────────────────────────────────────────────

/**
 * Scan a Hermes home for copies of our plugin. `hermesHome` is passed in rather
 * than resolved here so the installer can scan the tree it just wrote to, and
 * the doctor can scan the one `HERMES_HOME` points at.
 *
 * Hermes' own discovery answers when it can. Callers must surface
 * `fromHermes === false` to the operator: an approximate answer about which
 * copy runs is still worth printing, but not worth mistaking for a fact.
 */
export function scanHermesPluginCopies(
  hermesHome: string,
  opts: HermesScanOptions = {},
): HermesPluginScan {
  const present = isDirectory(hermesHome);
  if (!present) {
    return {
      hermesHome,
      present,
      roots: [],
      copies: [],
      shadowed: false,
      fromHermes: false,
      fallbackReason: null,
      unknownDirs: [],
      undetermined: false,
    };
  }

  const roots = hermesPluginRoots(hermesHome);

  const probe = probeHermesDiscovery(hermesHome, roots, opts);
  if ('roots' in probe) {
    const rootScans = probe.roots.map((r) => rootScanFrom(r));
    return {
      hermesHome,
      present,
      roots: rootScans,
      copies: rootScans.flatMap((r) => r.copies),
      shadowed: rootScans.some((r) => r.shadowed),
      fromHermes: true,
      fallbackReason: null,
      unknownDirs: [],
      undetermined: false,
    };
  }

  const fallbackReason = probe.error;
  const rootScans = roots.map(scanHermesPluginRootFallback);
  return {
    hermesHome,
    present,
    roots: rootScans,
    copies: rootScans.flatMap((r) => r.copies),
    shadowed: rootScans.some((r) => r.shadowed),
    fromHermes: false,
    fallbackReason,
    unknownDirs: rootScans.flatMap((r) => r.unknownDirs),
    undetermined: rootScans.some((r) => r.undetermined),
  };
}
