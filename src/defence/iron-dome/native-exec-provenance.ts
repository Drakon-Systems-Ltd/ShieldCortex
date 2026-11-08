/**
 * Iron Dome — native-exec provenance store (#1025, audit-only).
 *
 * Remembers, per session, which paths the agent WROTE or COMPILED, so a later
 * call that runs or loads one of those paths can be named on the audit row
 * (`nativeExec` on the verdict). It is observation only: nothing here, and
 * nothing that reads what this module returns, can deny, hold, escalate or
 * change a verdict. A path this store does not know about is simply not
 * observed — current behaviour, no signal.
 *
 * Reused from the frozen #907 PR 1 store (93810414, agent-artifact-store.ts /
 * agent-artifact-provenance.ts) after static review: the one canonicaliser
 * (`canonicalTarget`), the content identity stat (`statContentId`), the
 * non-blocking header read (`readArtifactHeader`), the native-magic test
 * (`isNativeImageHeader`), create-once per-record publication with an
 * HMAC'd, content-free file name, Rule P (`rulePProducer`) and the TTL sweep.
 * NOT reused: the complete-history machinery, the observation-boundary
 * re-list, the hold-on-unrecorded-capture path and every deny/hold row. An
 * audit signal does not need to be exact — a missed record is a missed log
 * line, not a bypass — so a write that cannot be recorded is simply not
 * recorded.
 *
 * Storage is flat create-once files under
 * `<configDir>/native-provenance/<sessionKey>/`, never SQLite, for the same
 * reason the frozen store gave: the Claude Code hook has no DB on its hot path.
 * File names carry an HMAC of the canonical path keyed by the session key, so
 * the store never holds path text.
 */

import { createHmac, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

// -- Types --------------------------------------------------------------------

/** How a recorded path came to be: written by a write-family tool / a shell
 *  write, or produced as a compiler output. */
export type NativeArtifactKind = 'agent-written' | 'compiled-output';

/** What the probe reports for one path. `ambiguous`: two records with the same
 *  pre-state but different kinds, so which one produced the bytes is unknown. */
export type NativeArtifactProvenance = NativeArtifactKind | 'ambiguous';

/** stat fields that decide content identity. ctime is deliberately excluded
 *  so a metadata-only chmod does not read as a content change. */
export interface ContentId {
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
}

/** A record's identity before the recorded call ran. `'absent'`: the target
 *  did not exist; `'unknown'`: the capture-side stat failed. */
export type PreId = ContentId | 'absent' | 'unknown';

export interface NativeArtifactRecord {
  kind: NativeArtifactKind;
  preId: PreId;
  /** ms, ordering only. */
  at: number;
}

/** One write/compile target a call names, as `nativeArtifactCaptures` returns it. */
export interface NativeArtifactCapture {
  token: string;
  kind: NativeArtifactKind;
}

/** A realpath that THROWS a NodeJS.ErrnoException-like error with `.code`. */
export type Realpath = (p: string) => string;

// -- Bounds -------------------------------------------------------------------

/** Records kept per session; at the cap further captures are not recorded. */
export const NATIVE_PROVENANCE_RECORD_CAP = 4096;
/** Captures recorded from one call. */
export const MAX_CAPTURES_PER_CALL = 16;
/** TTL measured from a session directory's last activity. */
export const NATIVE_PROVENANCE_TTL_MS = 24 * 60 * 60 * 1000;
/** Live (unexpired) sessions kept. At the cap a NEW session is not recorded;
 *  no live session is ever evicted to make room. */
export const MAX_NATIVE_PROVENANCE_SESSIONS = 512;
/** Bytes read for the native-header test — enough for every magic checked. */
export const NATIVE_HEADER_BYTES = 64;
/** A record body is ~130 bytes of JSON; anything larger is not one of ours
 *  and is not read past this many bytes. */
export const MAX_RECORD_BYTES = 512;
/** Entries the probe lists from a session directory, of ANY name (records,
 *  in-flight `.tmp` names, junk). The hook never publishes past
 *  `NATIVE_PROVENANCE_RECORD_CAP`; the slack covers in-flight temp names. A
 *  directory with more entries was stuffed by something else and is no
 *  evidence at all, so a planted volume costs a bounded listing, not a
 *  read per planted file. */
export const MAX_PROBE_DIR_ENTRIES = NATIVE_PROVENANCE_RECORD_CAP + 256;
/** Record entries read for one path hash. A hash with more is "not observed"
 *  as a whole — never classified on a partial read. The cost: a path written
 *  or compiled more than this many times in one session is not logged. */
export const MAX_RECORDS_PER_PATH = 128;
/** Entries the sweep lists from the store root. At most
 *  `MAX_NATIVE_PROVENANCE_SESSIONS` live sessions are ever created and
 *  expired ones are swept when a session starts, so a root with more entries
 *  was stuffed by something else: nothing in it is swept and no NEW session
 *  is created (a new session's first record needs a sweep that succeeds).
 *  A session that already has its directory keeps recording, bounded by
 *  `NATIVE_PROVENANCE_RECORD_CAP`, since that path never lists the root. */
export const MAX_STORE_ROOT_ENTRIES = 4 * MAX_NATIVE_PROVENANCE_SESSIONS;
/** Wall-clock budget, in ms, for one probe — every candidate of one
 *  evaluated call shares it, from the probe's first use. Past it every
 *  remaining lookup is "not observed". */
export const NATIVE_PROBE_BUDGET_MS = 250;

/** Both planes key sessions as `sc-` + 16 hex (session-guard.ts sessionKeyFor,
 *  scripts/pre-tool-hook.mjs). Anything else is refused, so a key can never be
 *  a path component that walks out of the store. */
const SESSION_KEY_RE = /^sc-[a-f0-9]{16}$/;

// -- Paths --------------------------------------------------------------------

/** Honours SHIELDCORTEX_CONFIG_DIR exactly like the hook's hookConfigDir(). */
export function resolveNativeProvenanceDir(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.SHIELDCORTEX_CONFIG_DIR?.trim();
  return path.join(override || path.join(os.homedir(), '.shieldcortex'), 'native-provenance');
}

// -- canonicalTarget (reused from the frozen #907 core) -----------------------

function longestExistingRealpath(start: string, realpath: Realpath): string | null {
  const stripped: string[] = [];
  let cur = start;
  for (let i = 0; i < 4096; i++) {
    try {
      const real = realpath(cur);
      return stripped.length ? [real, ...stripped].join(path.sep) : real;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code === 'ENOENT' || code === 'ENOTDIR') {
        const parent = path.dirname(cur);
        if (parent === cur) return null;
        stripped.unshift(path.basename(cur));
        cur = parent;
        continue;
      }
      return null;
    }
  }
  return null;
}

/**
 * Turn a path token into the absolute string records are keyed by. Capture
 * and query both call it, so `./helper`, `helper` and `/work/helper` written
 * from `/work` agree. The final component is NOT resolved (a symlink at the
 * target is keyed by its own name); parents are. `null` when unresolvable —
 * deliberately no `process.cwd()` fallback: a guessed base would key capture
 * and query differently.
 */
export function canonicalTarget(
  token: string,
  cwd: string | undefined,
  home: string | undefined,
  realpath: Realpath,
): string | null {
  if (typeof token !== 'string') return null;
  if (!token || token.includes('\0') || token.length > 4096) return null;

  let abs: string;
  if (token === '~' || token.startsWith('~/')) {
    if (typeof home !== 'string' || !home || !path.isAbsolute(home)) return null;
    abs = token === '~' ? home : `${home}/${token.slice(2)}`;
  } else if (path.isAbsolute(token)) {
    abs = token;
  } else {
    if (typeof cwd !== 'string' || !cwd || cwd.includes('\0') || cwd.length > 4096 || !path.isAbsolute(cwd)) {
      return null;
    }
    abs = `${cwd}/${token}`;
  }

  abs = path.normalize(abs);
  if (abs.length > 1 && abs.endsWith(path.sep)) abs = abs.slice(0, -1);

  const base = path.basename(abs);
  const parent = path.dirname(abs);
  if (!base || parent === abs) {
    try {
      return realpath(abs);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code === 'ENOENT' || code === 'ENOTDIR') return abs;
      return null;
    }
  }
  const resolvedParent = longestExistingRealpath(parent, realpath);
  if (resolvedParent === null) return null;
  return resolvedParent === path.sep ? `${path.sep}${base}` : `${resolvedParent}${path.sep}${base}`;
}

// -- Native header (reused) ---------------------------------------------------

/** True when the first bytes are an ELF, Mach-O (incl. fat) or PE/DOS magic.
 *  Known false positives, accepted because the answer only labels a log row:
 *  any file starting `MZ` (0x4d5a) reads as PE, and `0xcafebabe` is both the
 *  Mach-O fat magic and the Java class-file magic. */
export function isNativeImageHeader(bytes: Uint8Array | null | undefined): boolean {
  if (!bytes || bytes.length < 4) return false;
  if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return true; // ELF
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) return true; // MZ
  const be = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  switch (be) {
    case 0xfeedface: case 0xfeedfacf: case 0xcefaedfe: case 0xcffaedfe: // Mach-O
    case 0xcafebabe: case 0xbebafeca: // fat / universal
      return true;
    default:
      return false;
  }
}

// -- stat / header (reused) ---------------------------------------------------

/**
 * The target's content identity (following a final symlink, as exec does),
 * `'absent'` only when the final component does not exist, `null` for every
 * other failure. Never throws.
 */
export function statContentId(absPath: string): ContentId | 'absent' | null {
  try {
    const st = fs.statSync(absPath);
    return { dev: st.dev, ino: st.ino, size: st.size, mtimeMs: st.mtimeMs };
  } catch {
    try {
      fs.lstatSync(absPath);
      return null;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      return code === 'ENOENT' || code === 'ENOTDIR' ? 'absent' : null;
    }
  }
}

/** `O_NONBLOCK` where the platform has it: opening a FIFO must never park the
 *  guard waiting for a writer. */
const OPEN_HEADER_FLAGS = fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0);

/** The first bytes of a regular file, or `null` (unreadable, or not a regular
 *  file — a FIFO, socket or device is never read). A final symlink IS
 *  followed, as exec follows it. A static stat refuses a non-regular target
 *  before any open (so a device is not even opened); the open is still
 *  non-blocking and re-checked with fstat, because the path can be swapped
 *  between the two. Never throws. */
export function readArtifactHeader(absPath: string): Uint8Array | null {
  let fd: number | null = null;
  try {
    if (!fs.statSync(absPath).isFile()) return null;
    fd = fs.openSync(absPath, OPEN_HEADER_FLAGS);
    if (!fs.fstatSync(fd).isFile()) return null;
    const buf = Buffer.alloc(NATIVE_HEADER_BYTES);
    const n = fs.readSync(fd, buf, 0, NATIVE_HEADER_BYTES, 0);
    return new Uint8Array(buf.subarray(0, n));
  } catch {
    return null;
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch { /* best effort */ }
    }
  }
}

// -- Rule P (reused, pure) ----------------------------------------------------

function sameContentId(a: ContentId, b: ContentId): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs;
}

function preIdEquals(a: PreId, b: PreId): boolean {
  if (typeof a === 'string' || typeof b === 'string') return a === b;
  return sameContentId(a, b);
}

/**
 * Rule P: which recorded call produced the CURRENT bytes? The candidate is the
 * newest record whose pre-state differs from the current identity (a record
 * whose pre-state still equals the file did not change it — a failed write, or
 * a compile that wrote nothing). `null` when no record changed the file;
 * `'ambiguous'` when another record shares the candidate's pre-state with a
 * different kind.
 *
 * An `'unknown'` pre-state (the capture-side stat failed) is not evidence of a
 * change: such a record is never the candidate, and if one at or after the
 * candidate has a different kind it may have been the producer, so attribution
 * is impossible and the answer is `null` (not observed).
 */
export function rulePProducer(
  records: ReadonlyArray<NativeArtifactRecord>,
  current: ContentId,
): NativeArtifactProvenance | null {
  const differing = records.filter((r) => r.preId === 'absent' || (typeof r.preId === 'object' && !sameContentId(r.preId, current)));
  if (differing.length === 0) return null;
  let candidate = differing[0];
  for (const r of differing) if (r.at > candidate.at) candidate = r;
  if (records.some((r) => r.preId === 'unknown' && r.at >= candidate.at && r.kind !== candidate.kind)) return null;
  const conflicting = records.some(
    (r) => r !== candidate && preIdEquals(r.preId, candidate.preId) && r.kind !== candidate.kind,
  );
  return conflicting ? 'ambiguous' : candidate.kind;
}

/**
 * The pure classification behind the probe: given the records for a path, its
 * current identity and its header, which provenance (if any) the audit row
 * names. Only a native image with a Rule P producer is observed; a script, a
 * data file, an absent or unreadable file, or a file no record changed is
 * not.
 */
export function classifyNativeProvenance(
  records: ReadonlyArray<NativeArtifactRecord>,
  current: ContentId | 'absent' | null,
  header: Uint8Array | null,
): NativeArtifactProvenance | null {
  if (records.length === 0) return null;
  if (current === null || current === 'absent') return null;
  if (!isNativeImageHeader(header)) return null;
  return rulePProducer(records, current);
}

// -- Store --------------------------------------------------------------------

const realpathThrowing: Realpath = (p: string) => fs.realpathSync(p);

function pathHashFor(sessionKey: string, canonical: string): string {
  return createHmac('sha256', sessionKey).update(canonical).digest('hex');
}

const FINAL_RE = /^([0-9a-f]{64})\.\d+\.[0-9a-f]+$/;

// The store lives in a directory the monitored agent can write (it runs as the
// same user), so every entry in it is untrusted: a FIFO named like a record
// would park a blocking open (and a hook that never answers is an allow), and
// a symlinked root or session directory would aim the writes and the sweep at
// another tree.
//
// What is defended — entries already in place when the hook looks (static):
// the root (normalised lexically, see `storeRoot`) and the session directory
// are lstat'd and must be REAL directories before anything lists, creates,
// writes or sweeps under them; the sweep removes only entries that lstat as
// real directories named like a session key and older than the TTL; a record
// is read only if it is a small regular file. Independently of any race, a
// record open is O_NONBLOCK (it does not wait for a FIFO writer), its fd is
// re-checked with fstat, and its read is bounded by a fixed buffer; a record
// is created with O_EXCL, so publication never opens an existing entry.
//
// What is NOT defended — a concurrent swap (TOCTOU): Node has no
// openat()/dirfd API, so each check and the operation after it are separate
// path lookups. An agent racing the hook can replace a checked root or
// session directory with a link or another directory in between, so a record
// may be written, listed or read through it, and the directory the sweep
// renames and deletes need not be the one it lstat'd (rmSync of the renamed
// path unlinks a link rather than following it, but a swapped-in real
// directory is deleted). None of this is race-proof containment, and other
// filesystem calls (mkdir, readdir, rename, rm) are ordinary synchronous I/O
// with no timeout. The parents of the root (`~/.shieldcortex` or
// SHIELDCORTEX_CONFIG_DIR) are trusted as for every other state file there.
// The probe's output, raced or not, only labels a log row and never changes a
// decision.
//
// Volume: the agent can also fill the store with ordinary files. Every
// listing is an `opendir` iterated against a hard entry cap (an over-full
// session directory is no evidence and nothing more is recorded into it; an
// over-full root is not swept and no new session is created in it, while a
// session already there keeps recording up to its own cap), the probe reads
// at most `MAX_RECORDS_PER_PATH` entries per path hash and classifies each
// hash once per call (each spelling is still resolved), and the whole probe
// of one call shares one `NATIVE_PROBE_BUDGET_MS` budget. The budget is checked between filesystem
// operations: a single synchronous call that itself blocks (a hung network
// filesystem, say) cannot be interrupted, so it bounds the work, not the
// latency of any one syscall.
//
// Ownership: where the platform has `process.getuid` (not Windows), the root
// and the session directory must be owned by this uid, and the sweep only
// removes session directories this uid owns — a store under a shared
// SHIELDCORTEX_CONFIG_DIR cannot feed another uid's records into a label.

/** The store root as a lexical absolute path with no trailing separator, or
 *  `null` for an empty path. `lstat('link/')` resolves the link (a trailing
 *  separator makes the final component a directory lookup), so a caller's
 *  `stateDir` of `link/` would pass the real-directory check below while
 *  pointing elsewhere. `path.resolve` is purely lexical — deliberately NOT
 *  realpath, which would erase the evidence of a link — and every later
 *  check and operation uses this one string. */
function storeRoot(stateDir: string | undefined): string | null {
  const raw = stateDir ?? resolveNativeProvenanceDir();
  return typeof raw === 'string' && raw !== '' ? path.resolve(raw) : null;
}

/** True when `st` is owned by this process's uid, or the platform has no
 *  `process.getuid` (Windows), where ownership is not checked. */
function ownedByThisUid(st: fs.Stats): boolean {
  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  return uid === undefined || st.uid === uid;
}

/** True only for a real directory owned by this uid: not a symlink, not a
 *  special file, not another user's directory. */
function isRealDirectory(p: string): boolean {
  try {
    const st = fs.lstatSync(p);
    return st.isDirectory() && ownedByThisUid(st);
  } catch {
    return false;
  }
}

/** The entry names of `dir`, read with `opendir` and never more than `max` of
 *  them, or `null`: more than `max` entries (the overflow sentinel — every
 *  name counts, record-shaped or not), `expired()` became true, or the
 *  directory could not be opened or read. The handle is always closed. The
 *  whole directory is never materialised. Never throws. */
function listDirBounded(dir: string, max: number, expired?: () => boolean): string[] | null {
  let d: fs.Dir | null = null;
  try {
    d = fs.opendirSync(dir);
    const names: string[] = [];
    for (;;) {
      if (expired && (names.length & 63) === 0 && expired()) return null;
      const e = d.readSync();
      if (e === null) return names;
      if (names.length >= max) return null;
      names.push(e.name);
    }
  } catch {
    return null;
  } finally {
    if (d !== null) {
      try { d.closeSync(); } catch { /* best effort */ }
    }
  }
}

/** `O_NOFOLLOW` where the platform has it, plus the static lstat below where
 *  it does not (Windows), so a record-named link is never followed. */
const OPEN_RECORD_FLAGS = fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0) | (fs.constants.O_NOFOLLOW ?? 0);

/** A record file's text, or `null`: not a regular file (link, FIFO, socket,
 *  device, directory), larger than `MAX_RECORD_BYTES`, or unreadable. The
 *  open does not wait for a FIFO writer (O_NONBLOCK) and the fd is fstat'd
 *  before any read; a fixed buffer bounds the read even if the file grows
 *  after the size checks. Never throws. */
function readRecordFile(p: string): string | null {
  let fd: number | null = null;
  try {
    const st = fs.lstatSync(p);
    if (!st.isFile() || st.size > MAX_RECORD_BYTES) return null;
    fd = fs.openSync(p, OPEN_RECORD_FLAGS);
    const fst = fs.fstatSync(fd);
    if (!fst.isFile() || fst.size > MAX_RECORD_BYTES) return null;
    const buf = Buffer.alloc(MAX_RECORD_BYTES + 1);
    let n = 0;
    while (n < buf.length) {
      const got = fs.readSync(fd, buf, n, buf.length - n, n);
      if (got <= 0) break;
      n += got;
    }
    return n > MAX_RECORD_BYTES ? null : buf.toString('utf8', 0, n);
  } catch {
    return null;
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch { /* best effort */ }
    }
  }
}

function parseRecordBody(raw: string): NativeArtifactRecord | null {
  try {
    const o = JSON.parse(raw) as Record<string, unknown> | null;
    if (!o || typeof o !== 'object') return null;
    if (o.kind !== 'agent-written' && o.kind !== 'compiled-output') return null;
    if (typeof o.at !== 'number') return null;
    let preId: PreId;
    if (o.preId === 'absent' || o.preId === 'unknown') {
      preId = o.preId;
    } else if (o.preId && typeof o.preId === 'object') {
      const p = o.preId as Record<string, unknown>;
      if (typeof p.dev !== 'number' || typeof p.ino !== 'number'
        || typeof p.size !== 'number' || typeof p.mtimeMs !== 'number') return null;
      preId = { dev: p.dev, ino: p.ino, size: p.size, mtimeMs: p.mtimeMs };
    } else {
      return null;
    }
    return { kind: o.kind, preId, at: o.at };
  } catch {
    return null;
  }
}

function publishRecord(dir: string, finalName: string, body: string): boolean {
  const tmp = path.join(dir, `${finalName}.tmp`);
  // `wx` is O_CREAT|O_EXCL: it never follows or opens an entry already at
  // that name (a planted link or FIFO fails EEXIST), and only a file this
  // call created is ever unlinked.
  let created = false;
  try {
    fs.writeFileSync(tmp, body, { flag: 'wx', mode: 0o600 });
    created = true;
    fs.renameSync(tmp, path.join(dir, finalName));
    return true;
  } catch {
    if (created) {
      try { fs.unlinkSync(tmp); } catch { /* best effort */ }
    }
    return false;
  }
}

/**
 * Record this call's write/compile targets for its session. Best effort and
 * never throws: an unresolvable path, an unwritable store or a full session
 * simply goes unrecorded, and the only consequence is a later exec of that
 * path is not observed. Called by the hook / interceptor AFTER the call's own
 * evaluation, so a same-call write is not visible to that call's own probe.
 * Returns how many records were published (for tests).
 */
export function recordNativeArtifactCaptures(opts: {
  sessionKey: string;
  captures: ReadonlyArray<NativeArtifactCapture>;
  cwd: string | undefined;
  stateDir?: string;
  home?: string;
  now?: number;
  maxSessions?: number;
}): number {
  try {
    if (!SESSION_KEY_RE.test(String(opts.sessionKey ?? ''))) return 0;
    if (!Array.isArray(opts.captures) || opts.captures.length === 0) return 0;
    const root = storeRoot(opts.stateDir);
    if (root === null) return 0;
    const home = opts.home ?? os.homedir();
    const dir = path.join(root, opts.sessionKey);
    const at = opts.now ?? Date.now();

    // The root: a real directory, or absent (then created). Anything else —
    // a symlink, a file, a FIFO — and nothing is recorded.
    if (!isRealDirectory(root)) {
      try {
        fs.lstatSync(root);
        return 0; // exists, and is not a real directory
      } catch { /* absent: create it */ }
      try {
        fs.mkdirSync(root, { recursive: true, mode: 0o700 });
      } catch { /* re-checked below */ }
      if (!isRealDirectory(root)) return 0;
    }

    let existing: string[] | null;
    let sessionPresent = true;
    try {
      fs.lstatSync(dir);
    } catch {
      sessionPresent = false;
    }
    if (sessionPresent) {
      if (!isRealDirectory(dir)) return 0; // a planted link, special file or another uid's
      // Bounded: past the record cap there is no room anyway, so the listing
      // reads at most the cap's worth of entries plus one overflow sentinel
      // (any entry past the cap → nothing recorded) instead of reading a
      // stuffed directory whole.
      existing = listDirBounded(dir, NATIVE_PROVENANCE_RECORD_CAP);
      if (existing === null) return 0;
    } else {
      // First record of this session: the one moment a sweep is paid for, so
      // the hot path never lists the whole store.
      const live = pruneNativeProvenance({ stateDir: root, now: at });
      if (live === null || live >= (opts.maxSessions ?? MAX_NATIVE_PROVENANCE_SESSIONS)) return 0;
      try {
        fs.mkdirSync(dir, { mode: 0o700 });
      } catch { /* EEXIST from a concurrent call: re-checked below */ }
      if (!isRealDirectory(dir)) return 0;
      existing = [];
    }
    let room = NATIVE_PROVENANCE_RECORD_CAP - existing.length;
    let published = 0;
    for (const c of opts.captures.slice(0, MAX_CAPTURES_PER_CALL)) {
      if (room <= 0) break;
      if (!c || typeof c.token !== 'string') continue;
      if (c.kind !== 'agent-written' && c.kind !== 'compiled-output') continue;
      const canon = canonicalTarget(c.token, opts.cwd, home, realpathThrowing);
      if (canon === null) continue;
      const id = statContentId(canon);
      const record: NativeArtifactRecord = { kind: c.kind, preId: id === null ? 'unknown' : id, at };
      const name = `${pathHashFor(opts.sessionKey, canon)}.${at}.${randomBytes(6).toString('hex')}`;
      if (publishRecord(dir, name, JSON.stringify(record))) {
        published++;
        room--;
      }
    }
    return published;
  } catch {
    return 0;
  }
}

/**
 * The per-call probe the evaluator receives as
 * `ToolGuardOptions.nativeArtifactProvenance`: given a path token the command
 * runs, loads or names, the provenance to put on the audit row, or `null`.
 * The session's record directory is listed at most once per call, lazily,
 * and only a path with a record is stat'd and header-read.
 *
 * Bounded whatever the store holds: the listing stops at
 * `MAX_PROBE_DIR_ENTRIES` (over-full → no evidence for any path), a path
 * hash with more than `MAX_RECORDS_PER_PATH` entries is not observed, each
 * hash is classified at most once per probe (each spelling is still
 * resolved, but `./x`, `././x`, … cost one read set; a `null` is remembered
 * too), and every lookup of this probe
 * shares one `NATIVE_PROBE_BUDGET_MS` budget that starts at its first use and
 * is checked during the listing, the indexing, path resolution, between
 * record reads, after resolution (before a remembered answer is returned) and
 * after the final header read. Past the budget the answer is `null`, even for
 * a hash already classified. Never throws.
 *
 * `clock` is a monotonic millisecond clock, `performance.now` by default.
 */
export function createNativeArtifactProbe(opts: {
  sessionKey: string;
  cwd: string | undefined;
  stateDir?: string;
  home?: string;
  clock?: () => number;
}): (token: string) => NativeArtifactProvenance | null {
  const root = storeRoot(opts.stateDir);
  const valid = root !== null && SESSION_KEY_RE.test(String(opts.sessionKey ?? ''));
  const dir = path.join(root ?? '_', valid ? opts.sessionKey : '_');
  const home = opts.home ?? os.homedir();
  const clock = typeof opts.clock === 'function' ? opts.clock : () => performance.now();
  let deadline: number | null = null;
  /** True once the shared budget is spent (or the clock misbehaves). */
  const expired = (): boolean => {
    try {
      return deadline === null || !(clock() <= deadline);
    } catch {
      return true;
    }
  };
  /** realpath that refuses once the budget is spent; `canonicalTarget` then
   *  answers `null` (a non-ENOENT failure). */
  const realpathInBudget: Realpath = (p: string) => {
    if (expired()) throw Object.assign(new Error('native provenance probe budget spent'), { code: 'ETIMEDOUT' });
    return fs.realpathSync(p);
  };
  // Path hash → its record names, or `null` for a hash over the per-path cap.
  let byHash: Map<string, string[] | null> | null = null;
  const memo = new Map<string, NativeArtifactProvenance | null>();
  const listing = (): Map<string, string[] | null> => {
    if (byHash) return byHash;
    const empty = new Map<string, string[] | null>();
    byHash = empty;
    // Nothing is listed or read through a planted link, special file or
    // another uid's directory; an over-full, unreadable or out-of-time
    // listing is no evidence.
    const names = root !== null && isRealDirectory(root) && isRealDirectory(dir)
      ? listDirBounded(dir, MAX_PROBE_DIR_ENTRIES, expired)
      : null;
    if (names === null) return empty;
    const map = new Map<string, string[] | null>();
    for (let i = 0; i < names.length; i++) {
      if ((i & 255) === 0 && expired()) return empty;
      const m = FINAL_RE.exec(names[i]);
      if (!m) continue;
      const list = map.get(m[1]);
      if (list === null) continue; // already over the per-path cap
      if (list === undefined) map.set(m[1], [names[i]]);
      else if (list.length >= MAX_RECORDS_PER_PATH) map.set(m[1], null);
      else list.push(names[i]);
    }
    byHash = map;
    return map;
  };
  const classify = (names: string[] | null | undefined, canon: string): NativeArtifactProvenance | null => {
    if (!names) return null; // no record, or over the per-path cap
    const records: NativeArtifactRecord[] = [];
    for (const n of names) {
      if (expired()) return null;
      // Not a small regular file (a planted FIFO, link, directory, an
      // oversized file) or unreadable: not evidence.
      const raw = readRecordFile(path.join(dir, n));
      const r = raw === null ? null : parseRecordBody(raw);
      if (r) records.push(r);
    }
    if (records.length === 0 || expired()) return null;
    const current = statContentId(canon);
    if (expired()) return null;
    const header = readArtifactHeader(canon);
    // The header read is the last syscall: if it spent the budget, the
    // answer is still "not observed".
    if (expired()) return null;
    return classifyNativeProvenance(records, current, header);
  };
  return (token: string) => {
    try {
      if (!valid) return null;
      if (deadline === null) deadline = clock() + NATIVE_PROBE_BUDGET_MS;
      if (expired()) return null;
      const map = listing();
      if (map.size === 0) return null;
      const canon = canonicalTarget(token, opts.cwd, home, realpathInBudget);
      // Rechecked after a resolution that SUCCEEDED too: its last lookup may
      // have spent the budget, and then even a remembered answer is null.
      if (canon === null || expired()) return null;
      const hash = pathHashFor(opts.sessionKey, canon);
      if (memo.has(hash)) return memo.get(hash) ?? null;
      const result = classify(map.get(hash), canon);
      memo.set(hash, result);
      return result;
    } catch {
      return null;
    }
  };
}

/**
 * Sweep expired session directories. Best effort, never throws. Returns how
 * many live (unexpired) session directories remain, or `null` when the root is
 * not a real directory or cannot be listed (then nothing is touched).
 *
 * Selection: only entries that lstat as real directories (not a link) owned
 * by this uid (where the platform has `getuid`), named like a session key,
 * whose last activity is older than the TTL are chosen for removal. A root
 * with more than `MAX_STORE_ROOT_ENTRIES` entries is listed no further and
 * nothing in it is touched (`null`). Every other name, link, file or special file present at the lstat
 * is left as it is, and a live session is never evicted for room — the
 * session cap is enforced by not recording a new session instead. A doomed
 * directory is renamed away before deletion so a reader sees all of a
 * session's records or none. The lstat and the rename are separate lookups:
 * an entry swapped in between is what gets renamed and deleted (a link is
 * unlinked, not followed; a real directory is removed) — see the store note
 * above on what a concurrent swap can still reach.
 */
export function pruneNativeProvenance(opts: {
  stateDir?: string;
  now?: number;
  ttlMs?: number;
} = {}): number | null {
  try {
    const root = storeRoot(opts.stateDir);
    const now = opts.now ?? Date.now();
    const ttlMs = opts.ttlMs ?? NATIVE_PROVENANCE_TTL_MS;
    if (root === null || !isRealDirectory(root)) return null;
    // Listed whole (bounded) before anything is removed: an over-full or
    // unreadable root is left exactly as it is.
    const names = listDirBounded(root, MAX_STORE_ROOT_ENTRIES);
    if (names === null) return null;
    let live = 0;
    for (const name of names) {
      if (!SESSION_KEY_RE.test(name)) continue;
      const src = path.join(root, name);
      let st: fs.Stats;
      try {
        st = fs.lstatSync(src);
      } catch {
        continue;
      }
      if (!st.isDirectory() || !ownedByThisUid(st)) continue;
      if (now - st.mtimeMs <= ttlMs) {
        live++;
        continue;
      }
      const grave = `${src}.expired.${now}.${randomBytes(6).toString('hex')}`;
      try {
        fs.renameSync(src, grave);
      } catch {
        continue;
      }
      try { fs.rmSync(grave, { recursive: true, force: true }); } catch { /* best effort */ }
    }
    return live;
  } catch {
    return null;
  }
}
