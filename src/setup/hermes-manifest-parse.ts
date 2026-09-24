/**
 * Conservative Hermes manifest reader — the FALLBACK half of #569.
 *
 * The source of truth for "which directory does Hermes key as `shieldcortex`"
 * is Hermes itself: `setup/hermes-plugins.ts` spawns the Hermes interpreter and
 * asks `hermes_cli.plugins_discovery`. This module is what runs when there is
 * no interpreter to ask, and everything it returns is labelled approximate.
 *
 * ## It is not a YAML parser, and round 3 stopped it pretending to be one
 *
 * Round 2 modelled as much of YAML as a line reader can and guessed at the
 * rest. Independent review of the sibling Ekho change found that the guesses
 * are wrong in both directions, and both directions are a health check lying:
 *
 *   - `name: >-` with an indented `shieldcortex` under it. Hermes reads the
 *     block scalar, gets `shieldcortex`, and loads that backup. Round 2 saw a
 *     shape it did not model, called the name ABSENT, substituted the directory
 *     name, and reported a clean canonical install.
 *   - `name: shieldcortex` followed by `description: backup: before upgrade`.
 *     That is not valid YAML and Hermes drops the manifest. Round 2 only ever
 *     inspected the value of the `name:` line, so it accepted the rest of the
 *     document sight unseen and labelled the backup LOADED.
 *
 * So the rule is now the narrow one, and everything outside it is `unknown`:
 *
 *   **A manifest is UNDERSTOOD only when every non-blank, non-comment line is
 *   either a column-0 `key: value` whose value is a plain or quoted
 *   single-line scalar with no unquoted `: ` in it, or an indented
 *   continuation of a key other than `name`.**
 *
 * Block scalars (`|`, `>`, `>-`), flow collections, anchors, aliases, tags, a
 * `name:` with no value, document markers, tabs and an unquoted value carrying
 * `: ` all make the directory unknown. So does ANY directory whose effective
 * manifest is a portable `plugin.json` — `agent_plugins._validate_manifest`
 * rejects a manifest that does not resolve inside the plugin root, unknown
 * author fields and non-object extension namespaces, and mirroring that is
 * another second implementation to get wrong.
 *
 * Selection still follows Hermes exactly, because selection is not a parse:
 * `plugin.yaml` then `plugin.yml` on EXISTENCE (a `plugin.yaml` DIRECTORY is
 * selected and then fails, and Hermes takes nothing from that child), then
 * `plugin.json` only when neither YAML spelling is there. A manifest with no
 * `name:` is keyed on the DIRECTORY (`data.get("name", plugin_dir.name)`).
 *
 * ## Why `unknown` is gated on "could this be ours"
 *
 * `unknown` costs its whole root a verdict, so it is reserved for manifests
 * that could still take OUR key: the directory is named `shieldcortex` (what
 * the missing-name fallback would key it as), or the text mentions
 * `shieldcortex`, or the text carries a backslash. Those three are exhaustive.
 * For Hermes to key a directory `shieldcortex` the manifest must produce that
 * exact string, and the only way to write it without the literal bytes is a
 * double-quoted escape — a folded block scalar joins its lines with whitespace
 * and cannot spell one word, and an alias resolves to an anchor whose text is
 * in the same file. Without the gate one neighbouring third-party manifest
 * with a `description: >` in it would put a permanent "cannot determine" on a
 * host where nothing is wrong.
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
 *   `other`    — Hermes keys it something else, or takes no manifest from it.
 *   `category` — no manifest at all: a category dir, keyed `<cat>/<name>`,
 *                which can never collide with a flat name.
 *   `unknown`  — could be ours; this reader will not say.
 */
export type ManifestVerdict = 'copy' | 'other' | 'category' | 'unknown';

/**
 * A column-0 mapping key. YAML needs the space (or the end of the line) after
 * the colon — `name:shieldcortex` is the plain scalar `name:shieldcortex`, and
 * a scalar document is not a mapping, so Hermes rejects it outright.
 */
const KEY_LINE = /^([A-Za-z_][A-Za-z0-9_.-]*):(?:[ \t](.*))?$/;

/**
 * A value opening with any of these is not a plain or quoted scalar: a block
 * scalar (`|`/`>`), a flow collection, an anchor, an alias, a tag, or one of
 * YAML's reserved indicators. We do not read those, so the directory is
 * unknown rather than guessed at.
 */
const NOT_A_SCALAR = '|>[]{},&*!%@`?';

/** C0 controls other than tab/LF/CR, plus DEL — outside YAML's printable set. */
const NON_PRINTABLE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

/** The value read off one `key:` line, and whether the shape was understood. */
interface ScalarRead {
  /** Null when the line carries no value at all, which opens a nested block. */
  payload: string | null;
  understood: boolean;
}

/** What a manifest body declares, and whether the reader understood all of it. */
export interface ManifestRead {
  /** The declared top-level `name:`, or null when there is no such key. */
  name: string | null;
  understood: boolean;
}

/** A bounded read of a manifest file. */
interface BoundedRead {
  text: string;
  /** True when the file is larger than the cap and `text` is a prefix. */
  truncated: boolean;
  /**
   * False when the bytes are not valid UTF-8. Hermes' `read_text(encoding=
   * "utf-8")` RAISES on those, so the manifest is dropped — a decided answer,
   * not an unknown one. Node would silently hand back U+FFFD instead.
   */
  decodable: boolean;
}

function readBounded(target: string): BoundedRead | null {
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
      const text = buf.subarray(0, MANIFEST_BYTE_CAP).toString('utf8');
      // A cap that lands mid-character would fail the round trip below for a
      // reason that says nothing about the file, so truncation is not judged.
      return { text, truncated: true, decodable: true };
    }
    const bytes = buf.subarray(0, read);
    const text = bytes.toString('utf8');
    return { text, truncated: false, decodable: Buffer.from(text, 'utf8').equals(bytes) };
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
 * The index of the quote closing the one at `start`, or -1 when the string
 * runs off the end of the line. A backslash escape inside double quotes and
 * `''` inside single quotes, exactly as YAML has it.
 */
function closingQuote(value: string, start: number): number {
  const quote = value[start];
  let index = start + 1;
  while (index < value.length) {
    const ch = value[index];
    if (quote === '"' && ch === '\\') {
      index += 2;
      continue;
    }
    if (ch === quote) {
      if (quote === "'" && value[index + 1] === "'") {
        index += 2;
        continue;
      }
      return index;
    }
    index += 1;
  }
  return -1;
}

/**
 * One line's value with its trailing comment removed. A `#` only starts a
 * comment at the start of the value or after whitespace, and never inside
 * quotes — which is why `name: shieldcortex # backup` is `shieldcortex` and
 * `name: a#b` is `a#b`. An unterminated quote is not YAML this reader can read.
 */
function stripComment(value: string): { payload: string; readable: boolean } {
  let out = '';
  let index = 0;
  while (index < value.length) {
    const ch = value[index];
    if (ch === '#' && (index === 0 || value[index - 1] === ' ' || value[index - 1] === '\t')) break;
    if (ch === '"' || ch === "'") {
      const close = closingQuote(value, index);
      if (close === -1) return { payload: '', readable: false };
      out += value.slice(index, close + 1);
      index = close + 1;
      continue;
    }
    out += ch;
    index += 1;
  }
  return { payload: out.trim(), readable: true };
}

/** The string a quoted YAML scalar stands for; a plain one passes through. */
function unquote(payload: string): string {
  if (payload.length >= 2 && payload[0] === '"' && payload[payload.length - 1] === '"') {
    return payload.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  if (payload.length >= 2 && payload[0] === "'" && payload[payload.length - 1] === "'") {
    return payload.slice(1, -1).replace(/''/g, "'");
  }
  return payload;
}

/**
 * The value on one `key:` line. `payload === null` with `understood` means the
 * line carries no value and opens a nested block — fine for every key except
 * `name`, whose value would then be somewhere this reader cannot see.
 */
function scalarValue(value: string): ScalarRead {
  const { payload, readable } = stripComment(value);
  if (!readable) return { payload: null, understood: false };
  if (payload === '') return { payload: null, understood: true };
  if (payload[0] === '"' || payload[0] === "'") {
    const close = closingQuote(payload, 0);
    // Anything after the closing quote is a shape we are not modelling.
    if (close !== payload.length - 1) return { payload: null, understood: false };
    return { payload, understood: true };
  }
  if (NOT_A_SCALAR.includes(payload[0])) return { payload: null, understood: false };
  // A flow collection, or a quote starting mid-scalar.
  if (/[[\]{}"']/.test(payload)) return { payload: null, understood: false };
  // `description: backup: before upgrade` — not YAML, and Hermes drops it.
  if (payload.includes(': ') || payload.endsWith(':')) return { payload: null, understood: false };
  return { payload, understood: true };
}

/**
 * Read a manifest body under the narrow rule at the top of this file.
 *
 * `understood: false` is the whole point: it means this reader does not know
 * what `yaml.safe_load` would make of the document, so the caller must say
 * "unknown" rather than name a winner or call a root clean.
 */
export function readYamlManifestName(text: string): ManifestRead {
  const unknown: ManifestRead = { name: null, understood: false };
  // YAML's printable set excludes the C0 controls other than tab/LF/CR, and
  // DEL. A manifest carrying one does not load at all.
  if (NON_PRINTABLE.test(text)) return unknown;

  let name: string | null = null;
  let sawName = false;
  let key: string | null = null;

  for (const raw of text.split(/\r?\n/)) {
    if (raw.trim() === '' || raw.trimStart().startsWith('#')) continue;
    // A tab may never indent YAML, and this reader reads none inside values
    // either — either way the answer is "ask Hermes".
    if (raw.includes('\t')) return unknown;
    const body = raw.replace(/^ +/, '');
    const indent = raw.length - body.length;

    if (indent === 0) {
      const head = body.trimEnd();
      // `---`/`...`: a second document makes `safe_load` raise, and this reader
      // is not going to work out whether there is one.
      if (head === '---' || head === '...' || /^(---|\.\.\.) /.test(body)) return unknown;
      const match = body.match(KEY_LINE);
      // The top level is not a plain mapping — a sequence item, a bare scalar,
      // a quoted key, a directive.
      if (match === null) return unknown;
      key = match[1];
      const scalar = scalarValue(match[2] ?? '');
      if (!scalar.understood) return unknown;
      if (key === 'name') {
        // `name:` with the value on following lines (a block scalar, a folded
        // scalar, a nested mapping) is the shape that made round 2 report a
        // clean install while Hermes was loading the backup.
        if (scalar.payload === null) return unknown;
        // Duplicate keys are legal to PyYAML and the LAST one wins, so this
        // deliberately overwrites rather than keeping the first.
        name = unquote(scalar.payload);
        sawName = true;
      }
      continue;
    }

    // An indented line continues the last column-0 key. A continuation of
    // `name` means its value is not the single-line scalar we just read.
    if (key === null || key === 'name') return unknown;
    let item = body;
    while (item.startsWith('- ')) item = item.slice(2).replace(/^ +/, '');
    if (item === '' || item === '-') continue;
    const nested = item.match(KEY_LINE);
    const value = nested === null ? item : nested[2] ?? '';
    if (!scalarValue(value).understood) return unknown;
  }

  return { name: sawName ? name : null, understood: true };
}

/**
 * Hermes' manifest selection for one child directory: `plugin.yaml`, then
 * `plugin.yml`, on existence; a portable `plugin.json` only when neither YAML
 * spelling is there. `null` means the directory has no manifest at all, which
 * makes it a category directory.
 */
export function selectManifest(dir: string): { kind: 'yaml' | 'portable'; file: string } | null {
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
 * Whether a directory could possibly be keyed `shieldcortex` — see the header.
 * Exported because both the verdict and the tests hang off the same rule.
 */
export function couldBeOurs(dirName: string, text: string): boolean {
  if (dirName === HERMES_PLUGIN_NAME) return true;
  if (text.includes(HERMES_PLUGIN_NAME)) return true;
  // A double-quoted scalar can spell the name in escapes, and a backslash is
  // the only way to write it without the literal bytes appearing.
  return text.includes('\\');
}

/**
 * Classify one child directory of a `plugins/` root the way Hermes would,
 * conservatively. `dirName` is the basename Hermes sorts on and the name a
 * manifest with no `name:` inherits.
 */
export function classifyPluginDir(dir: string, dirName: string): ManifestVerdict {
  const selected = selectManifest(dir);
  if (selected === null) return 'category';

  const read = readBounded(selected.file);
  // Unreadable is DECIDED, not unknown: Hermes' own read raises the same way
  // and it takes no manifest from the child.
  if (read === null) return 'other';
  const plausible = couldBeOurs(dirName, read.text);

  if (selected.kind === 'portable') {
    // `agent_plugins._validate_manifest` demands a regular file resolving
    // INSIDE the plugin root, known author fields and object extension
    // namespaces. Mirroring that is how round 2 called a backup with a
    // symlinked `plugin.json` the winner when Hermes had rejected it.
    return plausible ? 'unknown' : 'other';
  }

  if (read.truncated) return plausible ? 'unknown' : 'other';
  // Undecodable bytes: `read_text` raises for Hermes too, so this is a fact.
  if (!read.decodable) return 'other';

  const parsed = readYamlManifestName(read.text);
  if (!parsed.understood) return plausible ? 'unknown' : 'other';
  // `data.get("name", plugin_dir.name)` — a manifest with no name is keyed on
  // the directory it lives in.
  return (parsed.name ?? dirName) === HERMES_PLUGIN_NAME ? 'copy' : 'other';
}
