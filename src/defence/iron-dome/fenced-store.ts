/**
 * ShieldCortex — the one lock and commit discipline for the small JSON stores
 * that decide single-use approvals: the #310 retry-control store and the
 * #815 B one-tap nonce store. One module, so the two cannot drift.
 *
 * ## The lock
 *
 * An exclusive `mkdir` with a random owner token inside, a wait bounded by
 * time as well as tries (always well inside the stale threshold), and stale
 * takeover by RENAMING the old lock directory to a unique tombstone (only one
 * contender's rename can succeed). Only a lock that was already past the
 * stale threshold the first time a call looked is taken over: one the call
 * saw fresh is never, however slowly the host runs. The lock only keeps
 * contenders from wasting work. It is NOT what makes a commit safe: a holder
 * that pauses past the stale threshold has its lock taken over while it still
 * believes it holds it, and no check it makes before writing can close that
 * window.
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
 * ## One authority: the newest generation
 *
 * Once any generation exists, the newest one IS the store, and readers read
 * nothing else. `<store>` itself is only a pointer published for the operator
 * — `{ "fence": N, "state": "<store>.gen/N" }` — and holds no state at all.
 * The releases before this module (readers of the #310 retry store; the tap
 * nonce store is new) read `<store>` and nothing else, and read a file
 * without `rows` as an empty store, so an older hook can never be shown a
 * grant that this store will also honour; whatever such a release writes
 * there later is a file no reader here consults. The claim alone is the
 * commit, and a pointer that is stale, missing or rewritten by anything
 * changes nothing a reader can obtain.
 *
 * ## Migration: the first claim imports the pre-fence store, once
 *
 * Before the first generation, the copy is all there is: a store an older
 * release wrote (it had no generations) is read as written, and a missing
 * copy is an empty store. The first commit builds on that state and, BEFORE
 * it claims generation 1, takes that copy out of every reader's sight (a
 * rename aside, so an older reader that looks during the claim finds no
 * store) and confirms it is exactly the copy it read; a copy some other
 * writer replaced in between refuses the commit. The withdrawn copy is then
 * dropped whatever happens next, so a first claim that fails leaves an empty
 * store — the refusal side — and never puts a grant back where an older
 * reader could spend it. `link` lets exactly one writer claim generation 1,
 * and from that instant the copy is never read again, so the import cannot
 * repeat and cannot hand back anything that first commit consumed. A copy
 * that carries a fence while no generation exists was published by this
 * module and has lost the generations that gave it authority: it reads as
 * corrupt — which every store here treats as empty, the refusal side — never
 * as the state it shows.
 *
 * ## Deleting files is not revocation
 *
 * Removing `<store>` alone changes nothing: the generations are the store.
 * Removing `<store>.gen` alone leaves a pointer with no generations, which
 * reads as empty. The supported reset is: no writer running, then remove
 * `<store>` and `<store>.gen` together.
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
import { basename, dirname, join } from 'node:path';

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
  /** Test seam: the clock and the wait. Defaults: `Date.now` and a blocking
   *  sleep. */
  clock?: { now(): number; sleep(ms: number): void };
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
  const now = opts.clock ? () => opts.clock!.now() : Date.now;
  const sleep = opts.clock ? (ms: number) => opts.clock!.sleep(ms) : sleepSync;
  const token = randomBytes(16).toString('hex');
  // The wait is bounded by time, not only by tries, and always ends well
  // inside the stale threshold, so a host whose every sleep overruns still
  // gives up long before a lock that was fresh when it started could count
  // as abandoned.
  const deadline = now() + Math.min(opts.attempts * opts.sleepMs, Math.floor(opts.staleMs / 2));
  // A lock this call has seen fresh is never taken over by this call.
  let sawFresh = false;
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
        if (!sawFresh && now() - statSync(lockPath).mtimeMs > opts.staleMs) {
          const tomb = `${lockPath}.stale-${process.pid}-${randomBytes(4).toString('hex')}`;
          try {
            renameSync(lockPath, tomb);
            rmSync(tomb, { recursive: true, force: true });
          } catch { /* another contender won the takeover */ }
          continue;
        }
        sawFresh = true;
      } catch {
        continue; // vanished between EEXIST and stat — retry immediately
      }
      const left = deadline - now();
      if (left <= 0) return null;
      sleep(Math.min(opts.sleepMs, left));
    }
  }
  return null;
}

/**
 * Best-effort release of an ADVISORY lock. The owner-token check and the
 * removal are separate steps, so a holder paused between them can remove a
 * successor's lock after a stale takeover, and a third contender can then
 * take it while the successor still believes it holds it. Nothing may rely on
 * the lock being exclusive; the fenced commit is what refuses the loser.
 */
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
  /** -1 when the generations cannot be listed, or kept vanishing while
   *  being read: every commit is refused. */
  base: number;
  /** True when `value` came from a commit made through this module. */
  fenced: boolean;
  /** Only when `base` is 0: the exact text of the pre-fence copy read (null:
   *  there was none). The first commit must be given it back; it claims
   *  nothing unless this very copy is what it withdraws. */
  preFence?: string | null;
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

/** Listing and reading are separate steps; a generation pruned (or a first
 *  claim made) in between is retried this many times. */
const READ_ATTEMPTS = 4;

export function readFencedJson(storePath: string): FencedSnapshot {
  const dir = fencedGenerationDir(storePath);
  for (let attempt = 1; attempt <= READ_ATTEMPTS; attempt += 1) {
    let newest: number;
    try {
      newest = newestGeneration(dir);
    } catch {
      return { value: CORRUPT_STORE, base: -1, fenced: false };
    }
    if (newest > 0) {
      // The generation is the committed state; the copy is never consulted.
      let text: string;
      try {
        text = readFileSync(join(dir, String(newest)), 'utf8');
      } catch (err) {
        if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') continue; // pruned since the listing
        return { value: CORRUPT_STORE, base: newest, fenced: false };
      }
      const value = parseOrCorrupt(text);
      return { value, base: newest, fenced: value !== CORRUPT_STORE && fenceOf(value) === newest };
    }
    // No generation yet: the pre-fence store (the migration source), or none.
    let text: string;
    try {
      text = readFileSync(storePath, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return { value: undefined, base: 0, fenced: false, preFence: null };
      // Unreadable: no text to confirm, so a first commit is refused.
      return { value: CORRUPT_STORE, base: 0, fenced: false };
    }
    const value = parseOrCorrupt(text);
    if (value === CORRUPT_STORE || fenceOf(value) === undefined) return { value, base: 0, fenced: false, preFence: text };
    // A published pointer with no generation: a first claim landing right
    // now (list again), or generations that are gone — then it has no
    // authority.
    if (attempt === READ_ATTEMPTS) return { value: CORRUPT_STORE, base: 0, fenced: false, preFence: text };
  }
  return { value: CORRUPT_STORE, base: -1, fenced: false };
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
 * Before the first claim: take the pre-fence copy out of every reader's sight
 * and confirm it is exactly the copy the caller built on (`expected`; null:
 * there was none). The rename aside captures whatever is at `<store>` at one
 * instant, so a copy replaced since the caller read it is caught here. The
 * withdrawn copy is dropped either way, never put back.
 */
function withdrawPreFenceCopy(storePath: string, dir: string, expected: string | null): boolean {
  const aside = join(dir, `.${process.pid}.${randomBytes(6).toString('hex')}.pre-fence.tmp`);
  try {
    renameSync(storePath, aside);
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'ENOENT' && expected === null;
  }
  let withdrawn: string | null = null;
  try {
    withdrawn = readFileSync(aside, 'utf8');
  } catch { /* unreadable: not the copy that was read */ }
  removeQuietly(aside);
  return withdrawn !== null && withdrawn === expected;
}

/** The pointer at `<store>`: names the newest generation, holds no state. */
function publishPointer(storePath: string, dir: string, generation: number): void {
  const tmp = join(dir, `.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  try {
    const pointer = { fence: generation, state: `${basename(dir)}/${generation}` };
    writeFileSync(tmp, `${JSON.stringify(pointer, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(tmp, storePath);
  } catch {
    removeQuietly(tmp);
  }
}

/**
 * Commit `value` as the successor of `base`. True only when this write IS
 * the newest committed state — every reader now obtains it, whether or not
 * the pointer could be published. False means it is not, and nothing a
 * reader sees came from it — with one exception a caller must respect: a
 * writer that was paused past the stale threshold AFTER claiming its
 * generation can be told false even though a later writer already built on
 * its state. So false is "not known to have committed", never "safe to undo".
 *
 * A first commit (`base` 0) must pass `preFence`, the snapshot's own: it
 * withdraws the pre-fence copy before claiming, and refuses unless that copy
 * is the one the snapshot read.
 */
export function commitFencedJson(
  storePath: string,
  base: number,
  value: Record<string, unknown>,
  preFence: string | null = null,
): boolean {
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
  if (base === 0 && !withdrawPreFenceCopy(storePath, dir, preFence)) {
    removeQuietly(tmp);
    return false;
  }
  try {
    linkSync(tmp, slot); // THE commit point: fails if generation `next` is taken
  } catch {
    removeQuietly(tmp);
    return false;
  }
  removeQuietly(tmp);
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
    return false;
  }
  publishPointer(storePath, dir, next); // for the operator only; no reader consults it
  pruneGenerations(dir, next, Date.now());
  return true;
}
