/**
 * Conservative Hermes manifest reader — the FALLBACK half of #569.
 *
 * The source of truth for "which directory does Hermes key as `shieldcortex`"
 * is Hermes itself: `setup/hermes-plugins.ts` spawns the Hermes interpreter and
 * asks `hermes_cli.plugins_discovery`. This module is what runs when there is
 * no interpreter to ask, and everything it returns is labelled approximate.
 *
 * It mirrors `plugins_discovery.scan_directory` and
 * `plugins_manifest.parse_manifest_file` as closely as a non-YAML reader can:
 *
 *   - `plugin.yaml` then `plugin.yml`, chosen on EXISTENCE, not on "is a file".
 *     Hermes uses `Path.exists()`; a `plugin.yaml` DIRECTORY beside a valid
 *     `plugin.yml` therefore wins the selection and then fails to parse, and
 *     Hermes takes no manifest from that directory at all. Falling through to
 *     the `.yml` would claim a copy Hermes never loads.
 *   - a portable `plugin.json` only when neither YAML spelling exists, keyed on
 *     its `name` after the same v1 gate Hermes applies (`$schema`, name shape).
 *   - a manifest with no top-level `name:` keys on the DIRECTORY name
 *     (`data.get("name", plugin_dir.name)`), so `shieldcortex/plugin.yaml`
 *     holding only `version: 1` is still our plugin.
 *   - an unparseable manifest is rejected by Hermes outright, so a `name:` line
 *     followed by broken YAML is NOT a copy.
 *
 * The last rule is the one a line reader cannot decide, so it does not pretend
 * to. When the text carries a shape this reader does not model — a tab in the
 * indentation, an unterminated flow collection or quote, a top-level line that
 * is not a `key:`, a `name:` whose value is not a plain scalar — the verdict is
 * `unknown`, and the caller says so instead of guessing.
 *
 * `unknown` is reserved for manifests that could still be ours: the text
 * mentions `shieldcortex`, or the directory is named `shieldcortex` (which is
 * what the missing-name fallback would key it as). A neighbour's broken
 * manifest that never mentions us cannot take our key however it parses, so it
 * is simply not a copy — otherwise every host with one messy third-party
 * plugin would get a warning about ours.
 */

import fs from 'fs';
import path from 'path';

/** The manifest key our plugin declares — the thing that can collide. */
export const HERMES_PLUGIN_NAME = 'shieldcortex';

/**
 * Manifests are a few hundred bytes. Hermes reads them whole; we stop at 64 KiB
 * because an unbounded read in a health check (and in the plugin's own start-up
 * path) is a hazard the last scrap of parity is not worth. A manifest over the
 * cap is reported `unknown`, never "not ours" — Hermes would have read it.
 */
export const MANIFEST_BYTE_CAP = 64 * 1024;

/** Agent Plugins v1 schema id — `agent_plugins._validate_manifest` rejects anything else. */
const PLUGIN_SCHEMA_V1 = 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json';

/** `agent_plugins._PLUGIN_NAME_RE`, verbatim. */
const PORTABLE_NAME_RE = /^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;

/**
 * `plugins_discovery._FOREIGN_HARNESS_MANIFEST_DIRS` — per-harness manifest
 * directories that Hermes skips before it ever looks for a manifest.
 */
export const FOREIGN_HARNESS_MANIFEST_DIRS: ReadonlySet<string> = new Set([
  '.claude-plugin',
  '.codex-plugin',
  '.cursor-plugin',
  '.devin-plugin',
  '.kimi-plugin',
]);

/**
 * What one child directory resolves to.
 *
 *   `copy`     — Hermes keys it `shieldcortex`.
 *   `other`    — Hermes keys it something else (or takes no manifest from it).
 *   `category` — no manifest at all: a category dir, keyed `<cat>/<name>`,
 *                which can never collide with a flat name.
 *   `unknown`  — could be ours; this reader will not say.
 */
export type ManifestVerdict = 'copy' | 'other' | 'category' | 'unknown';

/** A plain YAML scalar read off a `key: value` line, or why it could not be. */
interface ScalarRead {
  value: string | null;
  /** False when the shape is one this reader does not model. */
  modelled: boolean;
}

/** The result of reading a manifest body. */
interface YamlRead {
  /** The declared top-level `name:`, or null when there is no such key. */
  name: string | null;
  /** False when the document carries a shape this reader does not model. */
  modelled: boolean;
}

function readBounded(target: string): { text: string; truncated: boolean } | null {
  let fd: number;
  try {
    fd = fs.openSync(target, 'r');
  } catch {
    return null;
  }
  try {
    // cap + 1 so "exactly at the cap" and "over the cap" are distinguishable.
    const buf = Buffer.alloc(MANIFEST_BYTE_CAP + 1);
    const read = fs.readSync(fd, buf, 0, buf.length, 0);
    if (read > MANIFEST_BYTE_CAP) {
      return { text: buf.subarray(0, MANIFEST_BYTE_CAP).toString('utf8'), truncated: true };
    }
    return { text: buf.subarray(0, read).toString('utf8'), truncated: false };
  } catch {
    // EISDIR (a `plugin.yaml` directory), EACCES, EIO — Hermes' own read raises
    // here too and `parse_manifest_file` returns None.
    return null;
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      /* the read verdict is already decided */
    }
  }
}

/**
 * The first `:` that ends a block-mapping key: followed by a space, a tab or
 * the end of the line, and not inside quotes. -1 when the line has none.
 */
function keyColon(line: string): number {
  let quote = '';
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quote !== '') {
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === ':') {
      const next = line[i + 1];
      if (next === undefined || next === ' ' || next === '\t') return i;
    }
  }
  return -1;
}

/** Index of the ` #` that starts a trailing comment, or -1. */
function commentStart(text: string): number {
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] !== '#') continue;
    if (i === 0) return 0;
    const prev = text[i - 1];
    if (prev === ' ' || prev === '\t') return i;
  }
  return -1;
}

/**
 * A plain YAML scalar value, the way `yaml.safe_load` would read it off a
 * single line: quotes honoured, a ` #` comment stripped, whitespace trimmed.
 * Shapes with the value somewhere other than this line — an empty value, a
 * block scalar, an anchor/alias/tag — come back unmodelled.
 */
function plainScalar(raw: string): ScalarRead {
  const text = raw.trim();
  // `name:` with nothing after it can still be a multi-line plain scalar on the
  // following indented lines, so the value is genuinely unknown from here.
  if (text === '') return { value: null, modelled: false };
  if (text.startsWith('#')) return { value: null, modelled: false };
  const lead = text[0];
  // A collection is not a string, so it can never equal our key. That is a
  // decision, not a gap.
  if (lead === '[' || lead === '{') return { value: null, modelled: true };
  // Block scalars, anchors, aliases and tags all put the value out of reach.
  if (lead === '|' || lead === '>' || lead === '&' || lead === '*' || lead === '!') {
    return { value: null, modelled: false };
  }
  if (lead === "'" || lead === '"') {
    const close = text.indexOf(lead, 1);
    if (close === -1) return { value: null, modelled: false };
    // Escapes (`''` in single quotes, `\"` in double) are a shape this reader
    // does not unescape; say so rather than return the raw bytes.
    const inner = text.slice(1, close);
    if (lead === '"' && inner.includes('\\')) return { value: null, modelled: false };
    if (lead === "'" && text[close + 1] === "'") return { value: null, modelled: false };
    const after = text.slice(close + 1).trim();
    if (after !== '' && !after.startsWith('#')) return { value: null, modelled: false };
    return { value: inner, modelled: true };
  }
  // Plain scalar: `#` only starts a comment when whitespace precedes it, which
  // is exactly what `name: shieldcortex # backup` needs and what
  // `name: a#b` must not trigger.
  const cut = commentStart(text);
  const head = (cut === -1 ? text : text.slice(0, cut)).trim();
  return head === '' ? { value: null, modelled: false } : { value: head, modelled: true };
}

/** Net `[`/`{` minus `]`/`}` on one line, ignoring quoted text and comments. */
function flowDelta(line: string): number {
  let depth = 0;
  let quote = '';
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quote !== '') {
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === '#' && (i === 0 || line[i - 1] === ' ' || line[i - 1] === '\t')) break;
    if (ch === '[' || ch === '{') depth += 1;
    else if (ch === ']' || ch === '}') depth -= 1;
  }
  return depth;
}

/**
 * Read a manifest body for its top-level `name:`, refusing to guess.
 *
 * Deliberately narrow: this models a flat block mapping of `key: value` lines,
 * which is every real `plugin.yaml`. Anything else — a sequence document, a
 * second document, tab indentation, an unterminated flow collection, a
 * top-level line that is not a key — is reported unmodelled so the caller can
 * say "unknown" instead of accepting a manifest Hermes rejects.
 */
export function readYamlManifestName(text: string): YamlRead {
  const unmodelled: YamlRead = { name: null, modelled: false };
  const lines = text.split(/\r?\n/);
  let name: string | null = null;
  let sawKey = false;
  let sawContent = false;
  let docStarted = false;
  let ended = false;
  // Depth of an open `[`/`{` collection that began on an earlier line.
  let flow = 0;

  for (const line of lines) {
    if (flow > 0) {
      flow += flowDelta(line);
      if (flow < 0) return unmodelled;
      continue;
    }
    if (line.trim() === '') continue;
    // A tab anywhere in the indentation is invalid YAML; libyaml rejects the
    // whole document, so Hermes takes no manifest from it.
    if (/^ *\t/.test(line)) return unmodelled;
    if (ended) return unmodelled;
    if (/^\s/.test(line)) {
      // Nested content. It cannot hold a top-level key, but it can open a flow
      // collection that swallows the lines after it.
      flow += flowDelta(line);
      if (flow < 0) return unmodelled;
      continue;
    }
    if (line.startsWith('#')) continue;
    if (line.startsWith('%')) continue;
    if (line === '---' || line.startsWith('--- ')) {
      // A second document start means `safe_load` raises on multiple documents.
      if (docStarted || sawContent) return unmodelled;
      docStarted = true;
      continue;
    }
    if (line === '...' || line.startsWith('... ')) {
      ended = true;
      continue;
    }
    if (line === '-' || line.startsWith('- ')) {
      // A sequence item before any key means the document is a list, and
      // `parse_manifest_file` rejects a non-mapping top level outright.
      if (!sawKey) return unmodelled;
      sawContent = true;
      flow += flowDelta(line);
      if (flow < 0) return unmodelled;
      continue;
    }
    const colon = keyColon(line);
    if (colon === -1) return unmodelled;
    const rawKey = line.slice(0, colon).trim();
    if (rawKey === '') return unmodelled;
    const quoted =
      rawKey.length > 1 &&
      ((rawKey.startsWith("'") && rawKey.endsWith("'")) ||
        (rawKey.startsWith('"') && rawKey.endsWith('"')));
    const key = quoted ? rawKey.slice(1, -1) : rawKey;
    sawKey = true;
    sawContent = true;
    const rest = line.slice(colon + 1);
    if (key === 'name' && name === null) {
      const scalar = plainScalar(rest);
      if (!scalar.modelled) return unmodelled;
      name = scalar.value;
    }
    const trimmedRest = rest.trim();
    if (trimmedRest.startsWith('[') || trimmedRest.startsWith('{')) {
      flow += flowDelta(rest);
      if (flow < 0) return unmodelled;
    }
  }
  // A collection still open at EOF is the classic "valid `name:` line, broken
  // YAML underneath" — Hermes rejects the file; we refuse to claim it.
  if (flow !== 0) return unmodelled;
  return { name, modelled: true };
}

/** The `name` a portable `plugin.json` declares, after Hermes' v1 gate. */
export function readPortableManifestName(manifest: string): string | null {
  const read = readBounded(manifest);
  if (read === null || read.truncated) return null;
  let data: unknown;
  try {
    data = JSON.parse(read.text);
  } catch {
    return null;
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return null;
  const record = data as Record<string, unknown>;
  if (record.$schema !== PLUGIN_SCHEMA_V1) return null;
  const name = record.name;
  if (typeof name !== 'string' || name.length < 1 || name.length > 64) return null;
  if (!PORTABLE_NAME_RE.test(name)) return null;
  return name;
}

/**
 * Hermes' manifest selection for one child directory: `plugin.yaml`, then
 * `plugin.yml`, on existence; a portable `plugin.json` only when neither YAML
 * spelling is there. `null` means the directory has no manifest at all, which
 * makes it a category directory.
 */
export function selectManifest(
  dir: string,
): { kind: 'yaml' | 'portable'; file: string } | null {
  for (const base of ['plugin.yaml', 'plugin.yml']) {
    const candidate = path.join(dir, base);
    // `Path.exists()`, not `is_file()`: a `plugin.yaml` DIRECTORY is selected
    // by Hermes and then fails to parse.
    if (fs.existsSync(candidate)) return { kind: 'yaml', file: candidate };
  }
  const portable = path.join(dir, 'plugin.json');
  // `portable_file.exists() or portable_file.is_symlink()` — a dangling symlink
  // counts as present, and then raises inside the portable reader.
  let isLink = false;
  try {
    isLink = fs.lstatSync(portable).isSymbolicLink();
  } catch {
    isLink = false;
  }
  if (fs.existsSync(portable) || isLink) return { kind: 'portable', file: portable };
  return null;
}

/**
 * Classify one child directory of a `plugins/` root the way Hermes would,
 * conservatively. `dirName` is the basename Hermes sorts on and the name a
 * manifest with no `name:` inherits.
 */
export function classifyPluginDir(dir: string, dirName: string): ManifestVerdict {
  const selected = selectManifest(dir);
  if (selected === null) return 'category';

  if (selected.kind === 'portable') {
    return readPortableManifestName(selected.file) === HERMES_PLUGIN_NAME ? 'copy' : 'other';
  }

  const read = readBounded(selected.file);
  // Unreadable is decided, not unknown: Hermes' `read_text` raises the same way
  // and `parse_manifest_file` returns None.
  if (read === null) return 'other';

  const plausible = dirName === HERMES_PLUGIN_NAME || read.text.includes(HERMES_PLUGIN_NAME);
  if (read.truncated) return plausible ? 'unknown' : 'other';

  const parsed = readYamlManifestName(read.text);
  if (!parsed.modelled) return plausible ? 'unknown' : 'other';
  // `data.get("name", plugin_dir.name)` — a manifest with no name is keyed on
  // the directory it lives in.
  const name = parsed.name ?? dirName;
  return name === HERMES_PLUGIN_NAME ? 'copy' : 'other';
}
