/**
 * Script-path extraction shared by every cron discovery source (#309, #375).
 *
 * Lifted verbatim out of `allowlist-scan.ts` when the SQLite cron source
 * (#375) arrived: `openclaw-cron-store.ts` needs the same extraction, and
 * importing it from `allowlist-scan.ts` would have dragged the whole pin
 * write path — and with it `defence/iron-dome/*` — into a module that the
 * correlation surface must be able to import without touching guard runtime
 * code (see the security invariants in DESIGN-375.md).
 *
 * Deliberately conservative and unchanged: no shell parsing, no relative
 * names. A path is extracted only when it is absolute or `~/`-rooted AND
 * ends in a known script extension, so `python3 /a/b.py && rm -rf /` yields
 * exactly one path.
 */

import { join } from 'node:path';

/** Path-shaped tokens ending in a script extension — absolute or `~/`.
 *  Deliberately narrow: no spaces, no shell metacharacters, so a prompt like
 *  `python3 /a/b.py && rm x` yields exactly the script path. */
export const SCRIPT_PATH_RE = /(?:~\/|\/)[\w.\/@+-]*\.(?:py|sh|bash|mjs|cjs|js|ts|rb|pl)\b/g;
export const SCRIPT_EXT_RE = /\.(?:py|sh|bash|mjs|cjs|js|ts|rb|pl)$/;

export function expandHome(p: string, home: string): string {
  return p.startsWith('~/') ? join(home, p.slice(2)) : p;
}

export function extractScriptPaths(text: string, home: string): string[] {
  const out: string[] = [];
  for (const match of text.matchAll(SCRIPT_PATH_RE)) {
    out.push(expandHome(match[0], home));
  }
  return out;
}
