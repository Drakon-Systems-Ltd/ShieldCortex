/**
 * ShieldCortex — the one lock and commit discipline for the small JSON stores
 * that decide single-use approvals: the #310 retry-control store and the
 * #815 B one-tap nonce store. One module, so the two cannot drift.
 *
 * ## The lock
 *
 * An exclusive `mkdir` with a random owner token inside, a bounded spin, and
 * stale takeover by RENAMING the old lock directory to a unique tombstone
 * (only one contender's rename can succeed). The lock only keeps contenders
 * from wasting work. It is NOT what makes a commit safe: a holder that pauses
 * past the stale threshold has its lock taken over while it still believes it
 * holds it, and no check it makes before writing can close that window.
 *
 * ## The fence: every commit claims a generation number exactly once
 *
 * Each committed state is generation N, a file `<store>.gen/<N>`. A commit
 * reads the newest generation N, builds its new state from it, and claims
 * N+1 with `link(2)` from a fully written temp file. `link` fails if the name
 * already exists, so of all the writers that built on generation N exactly
 * one can commit; a holder that lost its lock to a takeover finds N+1 already
 * taken and its commit refused. After the claim it confirms nothing newer
 * exists (a name pruned long ago can be claimed again by a very stale writer;
 * such a claim is not the newest and is withdrawn).
 *
 * `<store>` itself stays the readable copy the rest of the system and the
 * operator see, carrying `"fence": N`. A stale writer can still rename an
 * old copy over it, so readers never trust it alone: when its fence is older
 * than the newest generation they read the generation. A copy with NO fence
 * was written by something else (an older binary, a hand edit, a test) and is
 * taken as written, exactly as before this module existed. A missing copy is
 * an empty store.
 */

import { randomBytes } from 'node:crypto';
import {
  linkSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';

import { mkdirSecure } from '../../setup/state-permissions.js';

// ── Lock ──────────────────────────────────────────────────────────────────

export interface StoreLock {
  path: string;
  token: string;
}

export interface StoreLockOptions {
  attempts: number;
  sleepMs: number;
  staleMs: number;
}

function sleepSync(ms: number): void {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    return;
  } catch {
    /* SharedArrayBuffer / Atomics.wait unavailable — wall-clock wait */
  }
  const until = Date.now() + ms;
  while (Date.now() < until) {
    /* bounded spin so lock retries actually back off */
  }
}

/** Failing to lock is failing CLOSED: null, and the caller writes nothing. */
export function acquireStoreLock(lockPath: string, opts: StoreLockOptions): StoreLock | null {
  try {
    mkdirSecure(dirname(lockPath));
  } catch {
    return null;
  }
  const token = randomBytes(16).toString('hex');
  for (let attempt = 0; attempt < opts.attempts; attempt += 1) {
    try {
      // Not `recursive` — that would succeed on an existing directory and
      // hand two processes the same "exclusive" lock.
      mkdirSync(lockPath, { mode: 0o700 });
      try {
        writeFileSync(join(lockPath, 'owner'), token, { mode: 0o600, flag: 'wx' });
      } catch {
        try { rmdirSync(lockPath); } catch { /* leave it to go stale */ }
        return null;
      }
      return { path: lockPath, token };
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') return null;
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > opts.staleMs) {
          const tomb = `${lockPath}.stale-${process.pid}-${randomBytes(4).toString('hex')}`;
          try {
            renameSync(lockPath, tomb);
            rmSync(tomb, { recursive: true, force: true });
          } catch { /* another contender won the takeover */ }
          continue;
        }
      } catch {
        continue; // vanished between EEXIST and stat — retry immediately
      }
      sleepSync(opts.sleepMs);
    }
  }
  return null;
}

/** Never removes a lock someone else now holds. */
export function releaseStoreLock(lock: StoreLock | null): void {
  if (!lock) return;
  try {
    if (readFileSync(join(lock.path, 'owner'), 'utf8') !== lock.token) return;
  } catch {
    return;
  }
  try { rmSync(join(lock.path, 'owner'), { force: true }); } catch { /* ignore */ }
  try { rmdirSync(lock.path); } catch { /* ignore */ }
}

// ── Fenced read / commit ──────────────────────────────────────────────────

/** Read result: the parsed JSON (undefined = no store, CORRUPT = unreadable)
 *  and the generation a commit built on it must claim the successor of. */
export interface FencedSnapshot {
  value: unknown;
  /** -1 when the generations cannot be listed: every commit is refused. */
  base: number;
  /** True when `value` came from a commit made through this module. */
  fenced: boolean;
}

export const CORRUPT_STORE: unique symbol = Symbol('corrupt-store');

const GEN_NAME_RE = /^[1-9][0-9]{0,14}$/;
/** Generations kept behind the newest (the newest is never removed). */
const GENERATIONS_KEPT = 4;
const STRAY_TMP_MAX_AGE_MS = 60_000;

export function fencedGenerationDir(storePath: string): string {
  return `${storePath}.gen`;
}

/** Newest committed generation, 0 when there is none. Throws when the
 *  directory exists but cannot be listed. */
function newestGeneration(dir: string): number {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return 0;
    throw err;
  }
  let max = 0;
  for (const n of names) {
    if (!GEN_NAME_RE.test(n)) continue;
    const g = Number(n);
    if (Number.isSafeInteger(g) && g > max) max = g;
  }
  return max;
}

function fenceOf(value: unknown): number | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const f = (value as { fence?: unknown }).fence;
  return Number.isSafeInteger(f) && (f as number) >= 1 ? (f as number) : undefined;
}

function parseOrCorrupt(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return CORRUPT_STORE;
  }
}

export function readFencedJson(storePath: string): FencedSnapshot {
  const dir = fencedGenerationDir(storePath);
  let newest: number;
  try {
    newest = newestGeneration(dir);
  } catch {
    return { value: CORRUPT_STORE, base: -1, fenced: false };
  }
  let text: string | null;
  try {
    text = readFileSync(storePath, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') return { value: CORRUPT_STORE, base: newest, fenced: false };
    text = null;
  }
  // No readable copy: an empty store (deleted, or never published).
  if (text === null) return { value: undefined, base: newest, fenced: false };
  const value = parseOrCorrupt(text);
  const fence = value === CORRUPT_STORE ? undefined : fenceOf(value);
  // No fence: written by something other than this module — taken as written.
  if (fence === undefined) return { value, base: newest, fenced: false };
  if (fence >= newest) return { value, base: fence, fenced: true };
  // The copy is behind the newest commit (a late rename by a stale writer, or
  // a publish that failed): the generation is the truth.
  try {
    const gen = parseOrCorrupt(readFileSync(join(dir, String(newest)), 'utf8'));
    if (gen !== CORRUPT_STORE && fenceOf(gen) === newest) return { value: gen, base: newest, fenced: true };
  } catch {
    /* fall through */
  }
  return { value: CORRUPT_STORE, base: newest, fenced: false };
}

function removeQuietly(p: string): void {
  try { unlinkSync(p); } catch { /* ignore */ }
}

function pruneGenerations(dir: string, newest: number, now: number): void {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const n of names) {
    if (GEN_NAME_RE.test(n)) {
      if (Number(n) <= newest - GENERATIONS_KEPT) removeQuietly(join(dir, n));
      continue;
    }
    if (n.endsWith('.tmp')) {
      try {
        if (now - statSync(join(dir, n)).mtimeMs > STRAY_TMP_MAX_AGE_MS) removeQuietly(join(dir, n));
      } catch { /* ignore */ }
    }
  }
}

/**
 * Commit `value` as the successor of `base`. True only when this write IS
 * the newest committed state. False means it is not, and nothing a reader
 * sees came from it — with one exception a caller must respect: a writer
 * that was paused past the stale threshold AFTER claiming its generation can
 * be told false even though a later writer already built on its state. So
 * false is "not known to have committed", never "safe to undo".
 */
export function commitFencedJson(storePath: string, base: number, value: Record<string, unknown>): boolean {
  if (!Number.isSafeInteger(base) || base < 0) return false;
  const next = base + 1;
  const dir = fencedGenerationDir(storePath);
  const slot = join(dir, String(next));
  const tmp = join(dir, `.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  try {
    mkdirSecure(dirname(storePath));
    mkdirSecure(dir);
    writeFileSync(tmp, `${JSON.stringify({ ...value, fence: next }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  } catch {
    removeQuietly(tmp);
    return false;
  }
  try {
    linkSync(tmp, slot); // THE commit point: fails if generation `next` is taken
  } catch {
    removeQuietly(tmp);
    return false;
  }
  let newest: number;
  try {
    newest = newestGeneration(dir);
  } catch {
    newest = Number.POSITIVE_INFINITY;
  }
  if (newest !== next) {
    // Something newer than our claim already exists: our name was one pruned
    // long ago. Withdraw it; the newer state stands.
    removeQuietly(slot);
    removeQuietly(tmp);
    return false;
  }
  try {
    renameSync(tmp, storePath); // the readable copy; readers fall back to the generation
  } catch {
    removeQuietly(tmp);
  }
  pruneGenerations(dir, next, Date.now());
  return true;
}
