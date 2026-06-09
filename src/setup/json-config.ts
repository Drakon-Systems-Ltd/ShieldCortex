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
 * Write a JSON config file atomically, backing up any existing file first.
 *
 * The torn-write hazard this guards against: an in-place `fs.writeFileSync`
 * can leave a TRUNCATED file if the process dies mid-write — and the targets
 * here include `~/.claude.json`, Claude Code's primary state file. So instead
 * the new content is written to a sibling temp file and then `renameSync`d
 * into place (atomic on the same filesystem); a reader never sees a partial
 * file, and a crash between temp-write and rename leaves the ORIGINAL intact.
 *
 * Sequence:
 *  1. Ensure the parent directory exists.
 *  2. If the target already exists, copy it to `<path>${BACKUP_SUFFIX}` first.
 *  3. Write the new JSON (2-space indent + trailing newline) to a temp file.
 *  4. `renameSync` the temp file over the target.
 *
 * The original file is never deleted or overwritten before step 4 succeeds, so
 * a failure during the temp-write leaves the live config untouched; the temp
 * file is cleaned up on failure. Mirrors the tmp+rename precedent in
 * `openclaw.ts`.
 *
 * Note: the backup is SINGLE-GENERATION — it captures the pre-write state and
 * is overwritten on every run, so it only ever reflects the file as it was
 * immediately before the most recent write.
 */
export function writeJsonConfigWithBackup(filePath: string, data: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  if (fs.existsSync(filePath)) {
    fs.copyFileSync(filePath, `${filePath}${BACKUP_SUFFIX}`);
  }
  const tmp = `${filePath}.tmp-shieldcortex`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', 'utf-8');
    fs.renameSync(tmp, filePath);
  } catch (err) {
    // Leave the original file untouched; just clean up the temp file.
    try {
      if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
    } catch {
      /* best-effort cleanup */
    }
    throw err;
  }
}

/**
 * Ownership check: an `mcpServers` entry "looks like ShieldCortex" if its
 * command path or any args string contains a `shieldcortex` / `shield-cortex`
 * token.
 *
 * `mcpServers.memory` is a generic key — the official upstream
 * `@modelcontextprotocol/server-memory` registers under the same name — so
 * BOTH the install path (before overwriting an entry) and the uninstall path
 * (before deleting one) MUST verify ownership or risk clobbering an unrelated
 * MCP server the user installed. This is the single canonical definition;
 * `claude-md.ts` and `uninstall.ts` import it rather than each holding a copy.
 */
export function looksLikeShieldcortex(entry: unknown): boolean {
  if (!entry || typeof entry !== 'object') return false;
  const e = entry as { command?: unknown; args?: unknown };
  const tokens: string[] = [];
  if (typeof e.command === 'string') tokens.push(e.command);
  if (Array.isArray(e.args)) for (const a of e.args) if (typeof a === 'string') tokens.push(a);
  return tokens.some((t) => /shield[-]?cortex/i.test(t));
}
