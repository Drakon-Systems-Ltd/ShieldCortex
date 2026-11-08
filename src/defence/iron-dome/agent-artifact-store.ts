/**
 * Iron Dome — agent-artifact provenance, fs LAYER (#907 PR 1).
 *
 * The ONE entry point both enforcement planes call to RECORD a write/compile
 * (`recordArtifactCapture`) and to BUILD the per-call ledger view
 * (`buildArtifactView`) the pure classifier reads. Storage is flat create-once
 * files — never SQLite — for the same reason the lease store is
 * (session-lease-store.ts): the Claude Code hook has no DB on its hot path, and
 * a store one plane cannot read is a plane that silently does not bind.
 *
 * Every record is a create-once file with a unique name; nothing is ever
 * evicted or rewritten. A record that cannot be published HOLDS its call
 * (row J) rather than letting the write through unrecorded. A damaged record
 * is reported to the core as damaged, never dropped — there is no
 * corrupt-as-empty read here (3.3).
 *
 * Design: docs/design/907-native-exec-of-agent-artifact.md section 3.
 */

import { createHmac, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  canonicalTarget,
  parseRecordName,
  RECORD_CAP,
  type AgentArtifactRecord,
  type AgentArtifactView,
  type ContentId,
  type LedgerEntry,
  type PreId,
  type RecordKind,
  type Realpath,
} from './agent-artifact-provenance.js';

// -- Paths --------------------------------------------------------------------

/** Honours SHIELDCORTEX_CONFIG_DIR like session-lease-store.ts / cloud/config.ts. */
export function resolveArtifactStateDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.SHIELDCORTEX_CONFIG_DIR || path.join(os.homedir(), '.shieldcortex');
}

function artifactsRoot(dir: string): string {
  return path.join(dir, 'artifacts');
}

function sessionRecDir(dir: string, sessionKey: string): string {
  return path.join(artifactsRoot(dir), sessionKey, 'rec');
}

/** TTL measured from a session directory's last activity. */
export const ARTIFACT_TTL_MS = 24 * 60 * 60 * 1000;
/** Bound on distinct sessions retained before the oldest are swept. */
export const MAX_ARTIFACT_SESSIONS = 512;

// -- realpath wrapper (throws with .code, as the pure core expects) -----------

const realpathThrowing: Realpath = (p: string) => fs.realpathSync(p);

// -- Path hashing (content-free; per-session keyed) ---------------------------

/** HMAC the canonical path with the session key — stores a hash, never the
 *  path text (invariant 4). Capture and query both go through this. */
function pathHashFor(sessionKey: string, canonical: string): string {
  return createHmac('sha256', sessionKey).update(canonical).digest('hex');
}

// -- Capture (3.4) ------------------------------------------------------------

export interface CaptureResult {
  /** true when a recognised write/compile call could NOT be recorded — the
   *  caller must HOLD the call (row J), never let it through unrecorded. */
  held: boolean;
}

/**
 * The ONE stat both sides use (section 5 `statPath` contract): the target's
 * `ContentId` (following a final symlink, as exec does), `'absent'` ONLY when
 * `lstat` of the final component fails with not-found, `null` for every other
 * failure. An I/O error is never reported as absent; a dangling symlink is
 * `null`, not absent. Never throws.
 */
export function statContentId(absPath: string): ContentId | 'absent' | null {
  try {
    const st = fs.statSync(absPath);
    return { dev: st.dev, ino: st.ino, size: st.size, mtimeMs: st.mtimeMs };
  } catch {
    try {
      fs.lstatSync(absPath);
      return null; // the entry exists but cannot be followed/stat'd
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      return code === 'ENOENT' || code === 'ENOTDIR' ? 'absent' : null;
    }
  }
}

/** Bytes read for the native-header test — enough for every magic it checks. */
export const ARTIFACT_HEADER_BYTES = 64;

/** The first bytes of a resolved target, or `null` when it cannot be read.
 *  Never throws. */
export function readArtifactHeader(absPath: string): Uint8Array | null {
  let fd: number | null = null;
  try {
    fd = fs.openSync(absPath, 'r');
    const buf = Buffer.alloc(ARTIFACT_HEADER_BYTES);
    const n = fs.readSync(fd, buf, 0, ARTIFACT_HEADER_BYTES, 0);
    return new Uint8Array(buf.subarray(0, n));
  } catch {
    return null;
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        /* best effort */
      }
    }
  }
}

/** Capture-side stat: a `null` stat is recorded as `'unknown'` (history
 *  incomplete for that path, 3.1 item 4); the record is still published. */
function statPreId(absPath: string): PreId {
  const id = statContentId(absPath);
  return id === null ? 'unknown' : id;
}

function randSuffix(): string {
  // 6 random bytes, hex — matches the lease/approval store convention.
  return randomBytes(6).toString('hex');
}

function publishRecord(recDir: string, finalName: string, body: string): boolean {
  try {
    fs.mkdirSync(recDir, { recursive: true, mode: 0o700 });
  } catch {
    return false;
  }
  const tmp = path.join(recDir, `${finalName}.tmp`);
  const final = path.join(recDir, finalName);
  try {
    // O_CREAT|O_EXCL|O_WRONLY — a unique create-once temp entry.
    fs.writeFileSync(tmp, body, { flag: 'wx', mode: 0o600 });
    fs.renameSync(tmp, final);
    return true;
  } catch {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* best effort */
    }
    return false;
  }
}

/**
 * Publish ONE capture record for a recognised write/compile target. Returns
 * `{ held: true }` iff publication failed (the recorded call must be held,
 * row J). An unresolvable path publishes an `unresolved.*` record (history
 * incomplete for the session, 3.4) and is NOT held unless that publish fails.
 */
export function recordArtifactCapture(opts: {
  stateDir?: string;
  sessionKey: string;
  token: string;
  cwd: string | undefined;
  home?: string;
  kind: RecordKind;
  now?: number;
}): CaptureResult {
  const stateDir = opts.stateDir ?? resolveArtifactStateDir();
  const home = opts.home ?? os.homedir();
  const at = opts.now ?? Date.now();
  const recDir = sessionRecDir(stateDir, opts.sessionKey);

  const canon = canonicalTarget(opts.token, opts.cwd, home, realpathThrowing);
  if (canon === null) {
    // Unresolvable: record the fact so later execs read incomplete history.
    const name = `unresolved.${at}.${randSuffix()}`;
    const ok = publishRecord(recDir, name, JSON.stringify({ kind: opts.kind, at }));
    return { held: !ok };
  }
  const preId = statPreId(canon);
  const hash = pathHashFor(opts.sessionKey, canon);
  const record: AgentArtifactRecord = { kind: opts.kind, preId, at };
  const name = `${hash}.${at}.${randSuffix()}`;
  const ok = publishRecord(recDir, name, JSON.stringify(record));
  return { held: !ok };
}

// -- View (3.1, 3.2) ----------------------------------------------------------

function parseRecordBody(raw: string): AgentArtifactRecord | null {
  try {
    const v = JSON.parse(raw) as unknown;
    if (!v || typeof v !== 'object') return null;
    const o = v as Record<string, unknown>;
    if (o.kind !== 'agent-written' && o.kind !== 'compiled-output') return null;
    if (typeof o.at !== 'number') return null;
    let preId: PreId;
    if (o.preId === 'absent' || o.preId === 'unknown') {
      preId = o.preId;
    } else if (o.preId && typeof o.preId === 'object') {
      const p = o.preId as Record<string, unknown>;
      if (
        typeof p.dev !== 'number' ||
        typeof p.ino !== 'number' ||
        typeof p.size !== 'number' ||
        typeof p.mtimeMs !== 'number'
      ) {
        return null;
      }
      preId = { dev: p.dev, ino: p.ino, size: p.size, mtimeMs: p.mtimeMs } as ContentId;
    } else {
      return null;
    }
    return { kind: o.kind, preId, at: o.at };
  } catch {
    return null;
  }
}

function listNames(recDir: string): { names: string[]; listable: boolean } {
  try {
    return { names: fs.readdirSync(recDir), listable: true };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return { names: [], listable: true };
    return { names: [], listable: false };
  }
}

/** Build the per-call ledger view for a KEYED session. */
export function buildArtifactView(opts: {
  stateDir?: string;
  sessionKey: string;
  home?: string;
  cap?: number;
}): AgentArtifactView {
  const stateDir = opts.stateDir ?? resolveArtifactStateDir();
  const home = opts.home ?? os.homedir();
  const recDir = sessionRecDir(stateDir, opts.sessionKey);

  const { names, listable } = listNames(recDir);
  const entries: LedgerEntry[] = [];
  for (const name of names) {
    const parsed = parseRecordName(name);
    // A name that parses as a FINAL record carries a body we read; everything
    // else (tmp, unresolved, garbage) is carried by name alone so the core can
    // mark history incomplete. A FINAL record that cannot be read/parsed is
    // reported as damaged (body null), never dropped.
    if (parsed && parsed.kind === 'final') {
      let body: AgentArtifactRecord | null = null;
      try {
        body = parseRecordBody(fs.readFileSync(path.join(recDir, name), 'utf8'));
      } catch {
        body = null; // unreadable → damaged
      }
      entries.push({ name, body });
    } else {
      entries.push({ name, body: null });
    }
  }

  return {
    listable,
    entries,
    relist: () => {
      try {
        return fs.readdirSync(recDir);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === 'ENOENT' || code === 'ENOTDIR') return [];
        return null;
      }
    },
    canonical: (token, cwd) => canonicalTarget(token, cwd, home, realpathThrowing),
    pathHash: (canonical) => pathHashFor(opts.sessionKey, canonical),
    cap: opts.cap ?? RECORD_CAP,
    keyed: true,
  };
}

/**
 * The view for an UNKEYED session (no session key). History is never complete,
 * so every native image is state 3 (row J). Resolution still works — the exec
 * target is canonicalised and classified — but no records exist and nothing is
 * recorded (3.1 "Keyed by host-owned session identity").
 */
export function unkeyedArtifactView(home: string = os.homedir()): AgentArtifactView {
  return {
    listable: false,
    entries: [],
    relist: () => null,
    canonical: (token, cwd) => canonicalTarget(token, cwd, home, realpathThrowing),
    pathHash: () => '',
    cap: RECORD_CAP,
    keyed: false,
  };
}

// -- TTL / bound (best effort) ------------------------------------------------

/**
 * Sweep expired or over-count session directories. Best-effort and never
 * throws. A session directory is renamed away before deletion so a reader sees
 * all of a session's records or none (3.1 "Bounded").
 */
export function pruneArtifactStore(opts: {
  stateDir?: string;
  now?: number;
  ttlMs?: number;
  maxSessions?: number;
} = {}): void {
  const root = artifactsRoot(opts.stateDir ?? resolveArtifactStateDir());
  const now = opts.now ?? Date.now();
  const ttlMs = opts.ttlMs ?? ARTIFACT_TTL_MS;
  const maxSessions = opts.maxSessions ?? MAX_ARTIFACT_SESSIONS;
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
      const st = fs.statSync(path.join(root, d.name));
      sessions.push({ name: d.name, mtimeMs: st.mtimeMs });
    } catch {
      /* skip */
    }
  }
  const doomed = new Set<string>();
  for (const s of sessions) if (now - s.mtimeMs > ttlMs) doomed.add(s.name);
  if (sessions.length - doomed.size > maxSessions) {
    const live = sessions.filter((s) => !doomed.has(s.name)).sort((a, b) => a.mtimeMs - b.mtimeMs);
    const excess = live.length - maxSessions;
    for (let i = 0; i < excess; i++) doomed.add(live[i].name);
  }
  for (const name of doomed) {
    const src = path.join(root, name);
    const grave = `${src}.expired.${now}.${randSuffix()}`;
    try {
      fs.renameSync(src, grave);
      fs.rmSync(grave, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}
