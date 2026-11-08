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
/** Distinct sessions kept before the oldest are swept. */
export const MAX_NATIVE_PROVENANCE_SESSIONS = 512;
/** Bytes read for the native-header test — enough for every magic checked. */
export const NATIVE_HEADER_BYTES = 64;

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

/** True when the first bytes are an ELF, Mach-O (incl. fat) or PE/DOS magic. */
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
 *  file — a FIFO, socket or device is never read). Never throws. */
export function readArtifactHeader(absPath: string): Uint8Array | null {
  let fd: number | null = null;
  try {
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
  try {
    fs.writeFileSync(tmp, body, { flag: 'wx', mode: 0o600 });
    fs.renameSync(tmp, path.join(dir, finalName));
    return true;
  } catch {
    try { fs.unlinkSync(tmp); } catch { /* best effort */ }
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
}): number {
  try {
    if (!SESSION_KEY_RE.test(String(opts.sessionKey ?? ''))) return 0;
    if (!Array.isArray(opts.captures) || opts.captures.length === 0) return 0;
    const root = opts.stateDir ?? resolveNativeProvenanceDir();
    const home = opts.home ?? os.homedir();
    const dir = path.join(root, opts.sessionKey);
    const at = opts.now ?? Date.now();

    let existing: string[] | null = null;
    try {
      existing = fs.readdirSync(dir);
    } catch {
      existing = null;
    }
    if (existing === null) {
      // First record of this session: the one moment a sweep is paid for, so
      // the hot path never lists the whole store.
      pruneNativeProvenance({ stateDir: root, now: at });
      try {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      } catch {
        return 0;
      }
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
 * The session's record directory is listed at most once per call, lazily, and
 * only a path with a record is stat'd and header-read. Never throws.
 */
export function createNativeArtifactProbe(opts: {
  sessionKey: string;
  cwd: string | undefined;
  stateDir?: string;
  home?: string;
}): (token: string) => NativeArtifactProvenance | null {
  const valid = SESSION_KEY_RE.test(String(opts.sessionKey ?? ''));
  const dir = path.join(opts.stateDir ?? resolveNativeProvenanceDir(), valid ? opts.sessionKey : '_');
  const home = opts.home ?? os.homedir();
  let byHash: Map<string, string[]> | null = null;
  const listing = (): Map<string, string[]> => {
    if (byHash) return byHash;
    const map = new Map<string, string[]>();
    byHash = map;
    let names: string[] = [];
    try {
      names = fs.readdirSync(dir);
    } catch {
      names = [];
    }
    for (const n of names) {
      const m = n.match(FINAL_RE);
      if (!m) continue;
      const list = map.get(m[1]);
      if (list) list.push(n);
      else map.set(m[1], [n]);
    }
    return map;
  };
  return (token: string) => {
    try {
      if (!valid) return null;
      const map = listing();
      if (map.size === 0) return null;
      const canon = canonicalTarget(token, opts.cwd, home, realpathThrowing);
      if (canon === null) return null;
      const names = map.get(pathHashFor(opts.sessionKey, canon));
      if (!names) return null;
      const records: NativeArtifactRecord[] = [];
      for (const n of names) {
        try {
          const r = parseRecordBody(fs.readFileSync(path.join(dir, n), 'utf8'));
          if (r) records.push(r);
        } catch { /* unreadable record: not evidence */ }
      }
      return classifyNativeProvenance(records, statContentId(canon), readArtifactHeader(canon));
    } catch {
      return null;
    }
  };
}

/**
 * Sweep expired or over-count session directories. Best effort, never throws.
 * A directory is renamed away before deletion so a reader sees all of a
 * session's records or none.
 */
export function pruneNativeProvenance(opts: {
  stateDir?: string;
  now?: number;
  ttlMs?: number;
  maxSessions?: number;
} = {}): void {
  const root = opts.stateDir ?? resolveNativeProvenanceDir();
  const now = opts.now ?? Date.now();
  const ttlMs = opts.ttlMs ?? NATIVE_PROVENANCE_TTL_MS;
  const maxSessions = opts.maxSessions ?? MAX_NATIVE_PROVENANCE_SESSIONS;
  let dirs: fs.Dirent[];
  try {
    dirs = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  const sessions: Array<{ name: string; mtimeMs: number }> = [];
  for (const d of dirs) {
    if (!d.isDirectory()) continue;
    try {
      sessions.push({ name: d.name, mtimeMs: fs.statSync(path.join(root, d.name)).mtimeMs });
    } catch { /* skip */ }
  }
  const doomed = new Set<string>();
  for (const s of sessions) if (now - s.mtimeMs > ttlMs || !SESSION_KEY_RE.test(s.name)) doomed.add(s.name);
  const live = sessions.filter((s) => !doomed.has(s.name)).sort((a, b) => a.mtimeMs - b.mtimeMs);
  for (let i = 0; i < live.length - maxSessions; i++) doomed.add(live[i].name);
  for (const name of doomed) {
    const src = path.join(root, name);
    const grave = `${src}.expired.${now}.${randomBytes(6).toString('hex')}`;
    try {
      fs.renameSync(src, grave);
      fs.rmSync(grave, { recursive: true, force: true });
    } catch { /* best effort */ }
  }
}
