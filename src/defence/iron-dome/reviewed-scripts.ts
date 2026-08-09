/**
 * ShieldCortex — the reviewed-script allowlist (#189).
 *
 * The mechanism Friday actually asked for: a human reviews a script — a
 * security sentry that must name `id_rsa` to audit its permissions, a
 * hardening checker whose whole job is talking about dangerous things — and
 * pins it by ABSOLUTE PATH + CONTENT HASH. The guard then stops folding that
 * file's source into the scan surface. Any edit to the file changes the hash
 * and silently re-gates it; there is no "trust this path forever" shape on
 * offer, because a path is a name and names get reused.
 *
 * What review does NOT relieve, by construction:
 *   - the invoking COMMAND LINE — scanned in full, catastrophic tier included;
 *   - inline code riding the same call (`python x.py; rm -rf /`, `-c '…'`,
 *     heredoc bodies) — separate scan regions, untouched;
 *   - a MOVED or COPIED file — the entry pins one canonical path, and a
 *     rename breaks the match (`realpath` on both sides);
 *   - an EDITED file — hash mismatch, folds normally, no error, no warning
 *     needed: the re-gate IS the feature.
 *
 * Trust surface discipline: entries are added only by `shieldcortex allowlist
 * add`, which is TTY-gated like `approve`/`deny` — a human at a keyboard,
 * never an agent mid-session. This module only READS the config; the entries
 * it is handed were already shape-validated by `normaliseReviewedScripts`,
 * and it re-checks every field anyway because "already validated" is an
 * assumption, not a property of the bytes.
 */
import { createHash } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve as resolvePath } from 'node:path';

export interface ReviewedScriptEntry {
  /** Absolute, canonical path as pinned at review time. */
  path: string;
  /** Lowercase hex sha256 of the file's utf-8 content at review time. */
  sha256: string;
  /** Operator's own note — why this file is trusted. Display only. */
  note?: string;
  /** Epoch ms when the entry was added. Display only. */
  addedAt?: number;
}

/** A runaway config must not turn the guard into a hash mill. */
const MAX_ENTRIES = 200;
const MAX_PATH_LENGTH = 1_024;
const MAX_NOTE_LENGTH = 200;
const SHA256_RE = /^[0-9a-f]{64}$/;

/** sha256 hex of the EXACT string the resolver returned (utf-8) — the same
 *  bytes the guard would have folded. `shieldcortex allowlist add` computes
 *  its hash the same way (utf-8 read), so the two sides can only agree on
 *  identical content. */
export function hashScriptSource(source: string): string {
  return createHash('sha256').update(source, 'utf8').digest('hex');
}

/**
 * Shape-validate the raw `actionGuard.reviewedScripts` config value. Total
 * and tighten-only in the only sense that matters for an allowlist: an entry
 * that is malformed in ANY field is dropped whole — a half-understood entry
 * must never half-match. Absolute paths only; a relative path in config
 * would silently mean different files from different cwds.
 */
export function normaliseReviewedScripts(raw: unknown): ReviewedScriptEntry[] {
  if (!Array.isArray(raw)) return [];
  const entries: ReviewedScriptEntry[] = [];
  for (const item of raw.slice(0, MAX_ENTRIES)) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) continue;
    const rec = item as Record<string, unknown>;
    if (typeof rec.path !== 'string' || typeof rec.sha256 !== 'string') continue;
    const path = rec.path.trim();
    const sha256 = rec.sha256.trim().toLowerCase();
    if (!path || path.length > MAX_PATH_LENGTH || !isAbsolute(path)) continue;
    if (!SHA256_RE.test(sha256)) continue;
    const entry: ReviewedScriptEntry = { path, sha256 };
    if (typeof rec.note === 'string' && rec.note.trim()) entry.note = rec.note.trim().slice(0, MAX_NOTE_LENGTH);
    if (typeof rec.addedAt === 'number' && Number.isFinite(rec.addedAt)) entry.addedAt = rec.addedAt;
    entries.push(entry);
  }
  return entries;
}

/**
 * Build the `isReviewedScript` predicate for `ToolGuardOptions`. The fs work
 * (canonicalising the invoked path) lives HERE, beside the resolver's own fs
 * work, so the guard core stays pure. The content comparison is against the
 * source text the guard just resolved — hash-then-skip on the same read, no
 * second read, no TOCTOU window.
 *
 * Never throws; every failure — bad path, dead symlink, realpath error —
 * answers `false`, which downstream means "fold it like any other file".
 */
export function createReviewedScriptCheck(
  entries: ReviewedScriptEntry[],
  cwd?: string,
): (scriptPath: string, source: string) => boolean {
  const valid = normaliseReviewedScripts(entries);
  if (valid.length === 0) return () => false;

  // Canonicalise the PINNED paths once. An entry whose pinned path no longer
  // resolves is dead weight, not a wildcard — drop it for this call.
  const byCanonical = new Map<string, ReviewedScriptEntry>();
  for (const e of valid) {
    try {
      byCanonical.set(realpathSync(e.path), e);
    } catch {
      /* pinned file missing — entry cannot match anything */
    }
  }
  if (byCanonical.size === 0) return () => false;

  const base = cwd && typeof cwd === 'string' ? cwd : process.cwd();
  return (scriptPath: string, source: string): boolean => {
    try {
      if (!scriptPath || typeof scriptPath !== 'string' || typeof source !== 'string') return false;
      const expanded = scriptPath.startsWith('~/') ? join(homedir(), scriptPath.slice(2)) : scriptPath;
      const full = isAbsolute(expanded) ? expanded : resolvePath(base, expanded);
      const canonical = realpathSync(full);
      const entry = byCanonical.get(canonical);
      if (!entry) return false;
      return hashScriptSource(source) === entry.sha256;
    } catch {
      return false;
    }
  };
}
