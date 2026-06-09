/**
 * Shared, dependency-free helpers for reading and writing user-owned JSON
 * config files during install.
 *
 * The whole point: an installer must NEVER replace a user's config because a
 * file was momentarily unparseable (trailing comma, JSONC `// comments` — VS
 * Code / Cursor config files are JSONC — or a partial concurrent write by
 * Claude Code itself). The historical bug: read with `catch { return {} }`,
 * then unconditionally write the mutated object back, wiping everything the
 * file held.
 *
 * This mirrors the discipline the uninstall path already follows
 * (uninstall.ts: "aborting to avoid corruption"): if a file EXISTS but won't
 * parse, abort — don't pretend it was empty.
 */

import fs from 'fs';
import path from 'path';

/** Suffix for the safety copy written before any mutating write. */
export const BACKUP_SUFFIX = '.bak-shieldcortex';

/**
 * Read a JSON config file.
 *
 * - Missing file → `{}` (a fresh install legitimately starts from nothing).
 * - Exists and parses → the parsed object.
 * - Exists but does NOT parse → THROW (never silently return `{}`, which would
 *   let the caller overwrite the file with only its own entries).
 *
 * VS Code / Cursor `mcp.json` files are JSONC and may contain `//` comments;
 * `JSON.parse` rejects those. That rejection is the CORRECT safe outcome here
 * (better to abort than wipe), so the thrown message says so explicitly rather
 * than silently stripping comments and rewriting (which would still lose the
 * user's formatting and comments).
 */
export function readJsonConfigOrAbort(filePath: string): Record<string, any> {
  if (!fs.existsSync(filePath)) {
    return {};
  }

  const raw = fs.readFileSync(filePath, 'utf-8');
  // An existing but empty/whitespace file is treated as empty config — there
  // is no content to lose, so this is not the corruption case.
  if (raw.trim() === '') {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch (err: any) {
    throw new Error(
      `ShieldCortex: refusing to overwrite ${filePath} — it exists but is not valid JSON ` +
        `(${err.message}). Aborting to avoid corruption. ` +
        `Note: JSON-with-comments (JSONC, // comments) and trailing commas are not supported here. ` +
        `Fix or remove the file, then re-run the installer.`,
    );
  }
}

/**
 * Write a JSON config file, backing up any existing file first.
 *
 * Before writing, if the target already exists it is copied to
 * `<path>${BACKUP_SUFFIX}` (overwriting any prior backup). Then the new JSON is
 * written with the project's conventional 2-space indentation and a trailing
 * newline. Parent directories are created as needed.
 */
export function writeJsonConfigWithBackup(filePath: string, data: unknown): void {
  if (fs.existsSync(filePath)) {
    fs.copyFileSync(filePath, `${filePath}${BACKUP_SUFFIX}`);
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n', 'utf-8');
}
