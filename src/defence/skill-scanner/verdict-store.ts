/**
 * Scan Verdict Store (issue #121).
 *
 * When an operator has reviewed a flagged skill/hook file and decided it is
 * acceptable, that decision is persisted so the scanner stops re-flagging it on
 * every run. Verdicts are keyed by a SHA-256 of the file's *content* — so the
 * moment the file changes, its hash changes and the acceptance no longer
 * applies, forcing a fresh review. This is deliberately content-addressed
 * rather than path-addressed: swapping malicious content into a path that was
 * previously accepted must NOT inherit the old acceptance.
 *
 * Stored at ${SHIELDCORTEX_CONFIG_DIR:-~/.shieldcortex}/scan-verdicts.json,
 * mirroring the cortex mistakes store (mode 0o600, atomic-ish overwrite).
 */

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ScanVerdict {
  /** Last known path the accepted content lived at (informational only). */
  path: string;
  /** Skill/hook name at the time of acceptance. */
  skillName: string;
  /** Risk level the scanner reported when the operator accepted it. */
  riskLevel: string;
  /** ISO-8601 timestamp of when the verdict was recorded. */
  acceptedAt: string;
}

interface VerdictFile {
  version: number;
  /** Keyed by content hash (sha256 hex). */
  verdicts: Record<string, ScanVerdict>;
}

const STORE_VERSION = 1;

// ── Paths ────────────────────────────────────────────────────────────────────

function getDataDir(): string {
  const dir = process.env.SHIELDCORTEX_CONFIG_DIR || join(homedir(), '.shieldcortex');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function getVerdictsFile(): string {
  return join(getDataDir(), 'scan-verdicts.json');
}

// ── Hashing ──────────────────────────────────────────────────────────────────

/** SHA-256 (hex) of file content — the verdict key. */
export function contentHash(content: string): string {
  return createHash('sha256').update(content, 'utf-8').digest('hex');
}

// ── Load / Save ──────────────────────────────────────────────────────────────

function emptyStore(): VerdictFile {
  return { version: STORE_VERSION, verdicts: {} };
}

/** Load the verdict store. Never throws — returns an empty store on any error. */
export function loadVerdicts(): VerdictFile {
  const file = getVerdictsFile();
  if (!existsSync(file)) return emptyStore();
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf-8')) as Partial<VerdictFile>;
    if (!parsed || typeof parsed !== 'object' || !parsed.verdicts) return emptyStore();
    return { version: parsed.version ?? STORE_VERSION, verdicts: parsed.verdicts };
  } catch {
    return emptyStore();
  }
}

function saveVerdicts(store: VerdictFile): void {
  const file = getVerdictsFile();
  writeFileSync(file, JSON.stringify(store, null, 2) + '\n', { mode: 0o600 });
}

// ── Query / Mutate ───────────────────────────────────────────────────────────

/** Return the stored verdict for a content hash, if the operator accepted it. */
export function getVerdict(hash: string): ScanVerdict | undefined {
  return loadVerdicts().verdicts[hash];
}

/** Record (or overwrite) an acceptance for a content hash. */
export function recordVerdict(hash: string, verdict: ScanVerdict): void {
  const store = loadVerdicts();
  store.verdicts[hash] = verdict;
  saveVerdicts(store);
}

/** Remove the verdict for a content hash. Returns true if one was removed. */
export function removeVerdict(hash: string): boolean {
  const store = loadVerdicts();
  if (!(hash in store.verdicts)) return false;
  delete store.verdicts[hash];
  saveVerdicts(store);
  return true;
}

/**
 * Resolve the acceptance for a file by reading and hashing its *current*
 * content. Returns null when the file is unreadable or has no accepted verdict
 * for its present content (i.e. it changed since acceptance). Never throws.
 */
export function getFileVerdict(
  filePath: string,
): { hash: string; verdict: ScanVerdict } | null {
  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
  const hash = contentHash(content);
  const verdict = getVerdict(hash);
  return verdict ? { hash, verdict } : null;
}
