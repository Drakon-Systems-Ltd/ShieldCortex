/**
 * Hermes plugin discovery, mirrored (#569).
 *
 * Hermes discovers plugins by walking every child directory of
 * `$HERMES_HOME/plugins/` (default `~/.hermes/plugins/`) and keying each one
 * on the `name:` in its `plugin.yaml` / `plugin.yml` — NOT on the folder name.
 * It walks in sorted order and, when two manifests from the same source claim
 * the same key, the LATER one silently wins (NousResearch/hermes-agent#121078).
 *
 * That makes a backup left beside a live plugin an invisible downgrade: our
 * installer writes `plugins/shieldcortex/`, an operator copies it aside as
 * `plugins/shieldcortex.bak-pre510-<ts>/`, and because `shieldcortex.bak…`
 * sorts after `shieldcortex`, the backup is what Hermes loads. The upgrade
 * completes, doctor sees the new bytes on disk, and the gateway keeps running
 * the old code. Observed in the field on the Ekho plugin through exactly this
 * mechanism.
 *
 * This module is the read-only half: it reproduces the four discovery rules
 * that decide the outcome, and nothing else.
 *
 *   1. A child whose name starts AND ends with `__` is skipped outright.
 *   2. A child holding `plugin.yaml` or `plugin.yml` is a flat plugin, keyed
 *      on the manifest `name:`.
 *   3. A child with no manifest is a CATEGORY directory — its plugins are
 *      keyed `<category>/<name>`, which can never collide with a flat name,
 *      so it cannot shadow us and is ignored here.
 *   4. Sort order is a plain code-unit compare on the directory name (what
 *      Python's `sorted()` does for ASCII), and the last entry wins.
 *
 * Profiles get their own plugin root at `<hermesHome>/profiles/<name>/plugins/`,
 * scanned independently — a collision is per-root.
 *
 * Everything here tolerates an unreadable directory or a malformed manifest by
 * skipping it. A health check that throws on a bad file tells an operator
 * nothing about the copies it did manage to read.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';

/** The manifest key our plugin declares — the thing that can collide. */
export const HERMES_PLUGIN_NAME = 'shieldcortex';

/**
 * Manifests are a few hundred bytes. The cap is there so a hostile or corrupt
 * `plugin.yaml` cannot make a health check read an arbitrarily large file.
 */
const MANIFEST_BYTE_CAP = 256 * 1024;

/** One directory under a `plugins/` root whose manifest declares our name. */
export interface HermesPluginCopy {
  /** Absolute path of the plugin directory. */
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
  /** Every copy declaring `name: shieldcortex`, in Hermes' discovery order. */
  copies: HermesPluginCopy[];
  /** The one Hermes actually loads: last in sorted order. */
  loaded: HermesPluginCopy | null;
  /** Whether `<root>/shieldcortex` is among the copies. */
  hasCanonical: boolean;
  /** More than one copy, or a single copy that is not the canonical one. */
  shadowed: boolean;
}

export interface HermesPluginScan {
  hermesHome: string;
  /** Whether the Hermes home directory exists at all. */
  present: boolean;
  roots: HermesPluginRootScan[];
  /** Every copy across every root, roots in order. */
  copies: HermesPluginCopy[];
  shadowed: boolean;
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

/**
 * Child directories of `dir`, sorted by code unit — Hermes' own order. A
 * symlink to a directory counts: Hermes resolves it like any other child.
 * An unreadable or absent `dir` yields nothing rather than throwing.
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

/** The manifest path for a plugin directory, or null when it has none. */
function manifestPath(dir: string): string | null {
  for (const base of ['plugin.yaml', 'plugin.yml']) {
    const candidate = path.join(dir, base);
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // absent or unreadable — try the other spelling, then give up
    }
  }
  return null;
}

/**
 * A scalar value off a top-level YAML key, without a YAML dependency: quotes
 * off, a trailing `# comment` off, whitespace trimmed. Anything it cannot read
 * as a plain scalar (a block scalar, an empty value) comes back null, which
 * callers treat as "not our plugin" — the conservative direction, since a
 * manifest we cannot read is one we must not claim to have identified.
 */
function plainScalar(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed === '' || trimmed.startsWith('#')) return null;
  // Quoted first, and up to the CLOSING quote: a trailing `# comment` after
  // the closing quote must not stop the value being recognised as quoted, and
  // a `#` inside the quotes is part of the value.
  const quote = trimmed[0];
  if (quote === "'" || quote === '"') {
    const close = trimmed.indexOf(quote, 1);
    if (close === -1) return null;
    const inner = trimmed.slice(1, close).trim();
    return inner === '' ? null : inner;
  }
  const uncommented = trimmed.replace(/\s+#.*$/, '').trim();
  return uncommented === '' ? null : uncommented;
}

/**
 * The `name:` a plugin manifest declares, read line by line. Only a top-level
 * key counts — an indented `name:` belongs to a nested block and is not the
 * plugin key. Returns null for an unreadable, oversized or malformed file.
 */
export function readManifestPluginName(manifest: string): string | null {
  let raw: string;
  try {
    const stat = fs.statSync(manifest);
    if (!stat.isFile() || stat.size > MANIFEST_BYTE_CAP) return null;
    raw = fs.readFileSync(manifest, 'utf8');
  } catch {
    return null;
  }
  for (const line of raw.split(/\r?\n/)) {
    if (/^\s/.test(line)) continue;
    const match = /^name\s*:\s*([\s\S]*)$/.exec(line);
    if (!match) continue;
    return plainScalar(match[1]);
  }
  return null;
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

/** Apply the four discovery rules to one `plugins/` root. */
export function scanHermesPluginRoot(root: string): HermesPluginRootScan {
  const copies: HermesPluginCopy[] = [];
  for (const dirName of childDirectories(root)) {
    // Rule 1: dunder children are skipped by Hermes outright.
    if (dirName.startsWith('__') && dirName.endsWith('__')) continue;
    const dir = path.join(root, dirName);
    const manifest = manifestPath(dir);
    // Rule 3: no manifest → a category dir, keyed `<cat>/<name>`. It cannot
    // collide with a flat name, so it cannot shadow us.
    if (manifest === null) continue;
    // Rule 2: the key is the manifest name, not the folder name.
    if (readManifestPluginName(manifest) !== HERMES_PLUGIN_NAME) continue;
    copies.push({ dir, dirName, root, canonical: dirName === HERMES_PLUGIN_NAME });
  }
  // Rule 4: `copies` is already in sorted order, and the last one wins.
  const loaded = copies.length > 0 ? copies[copies.length - 1] : null;
  const hasCanonical = copies.some((c) => c.canonical);
  return {
    root,
    copies,
    loaded,
    hasCanonical,
    shadowed: copies.length > 1 || (loaded !== null && !loaded.canonical),
  };
}

/**
 * Scan a Hermes home for copies of our plugin. `hermesHome` is passed in
 * rather than resolved here so the installer can scan the tree it just wrote
 * to, and the doctor can scan the one `HERMES_HOME` points at.
 */
export function scanHermesPluginCopies(hermesHome: string): HermesPluginScan {
  const present = isDirectory(hermesHome);
  const roots = present ? hermesPluginRoots(hermesHome).map(scanHermesPluginRoot) : [];
  return {
    hermesHome,
    present,
    roots,
    copies: roots.flatMap((r) => r.copies),
    shadowed: roots.some((r) => r.shadowed),
  };
}
