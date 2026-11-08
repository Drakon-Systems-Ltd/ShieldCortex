/**
 * Iron Dome — agent-artifact provenance, PURE CORE (#907 PR 1).
 *
 * The content-free, bounded, cross-call provenance model behind the
 * `native-exec-of-agent-artifact` floor. This file is PURE: no `fs`, no clock,
 * no crypto side effects. It holds the canonicaliser, the native-image header
 * test, the complete-history test, Rule P (production evidence) and the total
 * classifier state machine — everything that decides, from an injected ledger
 * view plus an injected stat/header reader, whether an exec/load target is an
 * agent-produced native image (state 1, floor), a compiled-output subtype
 * (state 1c, row B), an install-root image with no session write (state 2,
 * current behaviour) or unknown (state 3, the row-J door).
 *
 * The fs layer — create-once record publication, directory listing, TTL — is
 * `agent-artifact-store.ts`. The command parsing that finds the exec/load
 * target and the write/compile capture targets lives in `tool-action-guard.ts`
 * (it reuses that module's tokeniser). This file knows nothing about either.
 *
 * Design: docs/design/907-native-exec-of-agent-artifact.md section 3.
 */

import { basename, dirname, isAbsolute, normalize, sep } from 'node:path';

// -- Types --------------------------------------------------------------------

/** stat fields that decide content identity. ctime is DELIBERATELY excluded so
 *  a metadata-only chmod/chown does not read as a content change (3.1). */
export interface ContentId {
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
}

/** A record's identity at the pre-gate (5). `'absent'` = the target did not
 *  exist; `'unknown'` = the capture-side stat failed (makes history incomplete). */
export type PreId = ContentId | 'absent' | 'unknown';

export type RecordKind = 'agent-written' | 'compiled-output';

/** The body of one create-once ledger record. */
export interface AgentArtifactRecord {
  kind: RecordKind;
  /** identity at the pre-gate of the recorded write/compile call. */
  preId: PreId;
  /** ms, ordering only. */
  at: number;
}

/** One entry in a session's `rec/` directory as the store read it. `body` is
 *  `null` when the record file could not be read or parsed (damaged) — never
 *  dropped, so the core can withdraw relief for it (3.1 item 4). */
export interface LedgerEntry {
  name: string;
  body: AgentArtifactRecord | null;
}

/**
 * The listing of this call's session record directory, already bound by the
 * caller (hook / interceptor). The pure evaluator never derives a session key
 * and never receives one — only this bound view (5).
 *
 * `canonical` / `pathHash` are the caller's wiring of the ONE canonicaliser
 * (`canonicalTarget`) plus the per-session path hash; the query side calls
 * them so capture and query compute the same `pathHash` (3.4). An unkeyed
 * session (no session key) is represented by a view with `keyed: false` and
 * `listable: false`: history is then never complete, so every native image is
 * state 3 (3.1 "Keyed by host-owned session identity").
 */
export interface AgentArtifactView {
  /** false when the record directory could not be listed (any error other than
   *  not-found). A not-found directory is `listable: true` with no entries. */
  listable: boolean;
  /** every entry in `rec/` (install root or not), unfiltered. */
  entries: ReadonlyArray<LedgerEntry>;
  /** list `rec/` again; entry names, `[]` for not-found, `null` for any other
   *  error. Never throws. The core calls it once per evaluated call, AFTER the
   *  target's stat and header read (the 3.1 item-5 observation boundary). */
  relist: () => string[] | null;
  /** canonicalise a path token to its absolute realpath'd form, or `null` when
   *  unresolvable. The caller wires this to {@link canonicalTarget}. */
  canonical: (token: string, cwd: string | undefined) => string | null;
  /** per-session path hash of a canonical absolute path. */
  pathHash: (canonical: string) => string;
  /** record cap; default {@link RECORD_CAP}. */
  cap?: number;
  /** false when this session has no key (store disabled) — history never complete. */
  keyed: boolean;
}

/** Proposed per-session record cap (3.1 item 3). At the cap, further calls
 *  proceed unrecorded, so a full directory is incomplete by definition. */
export const RECORD_CAP = 4096;

/** The three authorship states plus the 1c compile-lineage subtype (3.1). */
export type ArtifactState =
  | 'state-1-agent-produced' // floor (A / C)
  | 'state-1c-compile-lineage' // row B
  | 'state-2-install-root' // current behaviour
  | 'state-3-unknown' // row J (door)
  | 'outside'; // step 0 — not a native image / nothing to execute

// -- canonicalTarget — the ONE resolver for record and query (3.4) ------------

/** A realpath that THROWS a NodeJS.ErrnoException-like error with `.code`. */
export type Realpath = (p: string) => string;

function longestExistingRealpath(start: string, realpath: Realpath): string | null {
  const stripped: string[] = [];
  let cur = start;
  // Bounded: a path has at most 4096 chars, so at most that many components.
  for (let i = 0; i < 4096; i++) {
    try {
      const real = realpath(cur);
      return stripped.length ? [real, ...stripped].join(sep) : real;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code === 'ENOENT' || code === 'ENOTDIR') {
        const parent = dirname(cur);
        if (parent === cur) {
          // reached the root and even it did not resolve: fail closed.
          return null;
        }
        stripped.unshift(basename(cur));
        cur = parent;
        continue;
      }
      // EACCES / EIO / ELOOP / ... — unresolvable (3.4).
      return null;
    }
  }
  return null;
}

/**
 * Turn a path token into the absolute string `pathHash` is computed over. The
 * ONLY resolver; capture (write targets, compile `-o` operands) and query
 * (exec and loader targets) both call it, so the two agree (3.4). Returns
 * `null` for an unresolvable token — there is deliberately NO `process.cwd()`
 * fallback: a guessed base would give record and query different hashes.
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
    if (typeof home !== 'string' || !home || !isAbsolute(home)) return null;
    abs = token === '~' ? home : `${home}/${token.slice(2)}`;
  } else if (isAbsolute(token)) {
    abs = token;
  } else {
    // Relative: resolved against cwd ONLY if cwd is a usable absolute string.
    if (
      typeof cwd !== 'string' ||
      !cwd ||
      cwd.includes('\0') ||
      cwd.length > 4096 ||
      !isAbsolute(cwd)
    ) {
      return null;
    }
    abs = `${cwd}/${token}`;
  }

  abs = normalize(abs);
  if (abs.length > 1 && abs.endsWith(sep)) abs = abs.slice(0, -1);

  const base = basename(abs);
  const parent = dirname(abs);
  // A root / near-root target with no basename: resolve the whole thing.
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
  return resolvedParent === sep ? `${sep}${base}` : `${resolvedParent}${sep}${base}`;
}

// -- Native-image header classification (2, Q5) -------------------------------

/** True when the first bytes are an ELF, Mach-O (incl. fat), or PE magic. */
export function isNativeImageHeader(bytes: Uint8Array | null | undefined): boolean {
  if (!bytes || bytes.length < 4) return false;
  // ELF: 0x7f 'E' 'L' 'F'
  if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return true;
  // PE / DOS: 'M' 'Z'
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) return true;
  const be = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  switch (be) {
    case 0xfeedface: // Mach-O 32 BE
    case 0xfeedfacf: // Mach-O 64 BE
    case 0xcefaedfe: // Mach-O 32 LE
    case 0xcffaedfe: // Mach-O 64 LE
    case 0xcafebabe: // fat/universal BE
    case 0xbebafeca: // fat/universal LE
      return true;
    default:
      return false;
  }
}

/** A NUL byte in the inspected header — the Q5 "binary without a known magic"
 *  signal, honoured only when Rule P already names an agent-written producer. */
export function headerHasNul(bytes: Uint8Array | null | undefined): boolean {
  if (!bytes) return false;
  for (let i = 0; i < bytes.length; i++) if (bytes[i] === 0) return true;
  return false;
}

// -- Record-name parsing (3.1) ------------------------------------------------

export type ParsedName =
  | { kind: 'final'; hash: string }
  | { kind: 'tmp'; hash: string }
  | { kind: 'unresolved-final' }
  | { kind: 'unresolved-tmp' };

const FINAL_RE = /^([0-9a-f]{64})\.\d+\.[0-9a-f]+$/;
const TMP_RE = /^([0-9a-f]{64})\.\d+\.[0-9a-f]+\.tmp$/;
const UNRESOLVED_FINAL_RE = /^unresolved\.\d+\.[0-9a-f]+$/;
const UNRESOLVED_TMP_RE = /^unresolved\.\d+\.[0-9a-f]+\.tmp$/;

/** Parse a record file name, or `null` when it does not match the scheme at
 *  all (which makes history incomplete, 3.1 item 2). */
export function parseRecordName(name: string): ParsedName | null {
  const f = FINAL_RE.exec(name);
  if (f) return { kind: 'final', hash: f[1] };
  const t = TMP_RE.exec(name);
  if (t) return { kind: 'tmp', hash: t[1] };
  if (UNRESOLVED_TMP_RE.test(name)) return { kind: 'unresolved-tmp' };
  if (UNRESOLVED_FINAL_RE.test(name)) return { kind: 'unresolved-final' };
  return null;
}

// -- Complete history (3.1) ---------------------------------------------------

function sortedNames(names: ReadonlyArray<string>): string[] {
  return [...names].sort();
}

/**
 * Is the session's history complete FOR a path hash, inspected by one exec
 * check (3.1)? `relistNames` is the result of `view.relist()` taken AFTER the
 * target's stat and header read (the observation boundary, item 5). Any
 * failure makes history incomplete.
 */
export function completeHistoryForPath(
  view: AgentArtifactView,
  pathHash: string,
  relistNames: string[] | null,
): boolean {
  if (!view.keyed) return false; // no session key → never complete
  if (!view.listable) return false; // item 1: listing error
  const cap = view.cap ?? RECORD_CAP;
  if (view.entries.length >= cap) return false; // item 3: at/over the cap

  // item 2 (session-wide): every name parses, none is unresolved.*
  for (const e of view.entries) {
    const p = parseRecordName(e.name);
    if (!p) return false;
    if (p.kind === 'unresolved-final' || p.kind === 'unresolved-tmp') return false;
  }

  // item 4 (path-local): every entry for this hash is final, reads, parses,
  // and has a preId other than 'unknown'.
  for (const e of view.entries) {
    const p = parseRecordName(e.name);
    if (!p || !('hash' in p) || p.hash !== pathHash) continue;
    if (p.kind === 'tmp') return false; // still publishing
    if (e.body === null) return false; // damaged
    if (e.body.preId === 'unknown') return false;
  }

  // item 5 (per check): the observation boundary. The re-list must equal the
  // first listing's names exactly. A re-list that failed or differs is incomplete.
  if (relistNames === null) return false;
  const before = sortedNames(view.entries.map((e) => e.name));
  const after = sortedNames(relistNames);
  if (before.length !== after.length) return false;
  for (let i = 0; i < before.length; i++) if (before[i] !== after[i]) return false;
  return true;
}

/** Every FINAL (non-tmp) readable record for a path hash; Rule P orders by `at`. */
export function recordsForPath(
  view: AgentArtifactView,
  pathHash: string,
): AgentArtifactRecord[] {
  const out: AgentArtifactRecord[] = [];
  for (const e of view.entries) {
    const p = parseRecordName(e.name);
    if (!p || p.kind !== 'final' || p.hash !== pathHash) continue;
    if (e.body) out.push(e.body);
  }
  return out;
}

// -- Rule P — production evidence (3.1) ---------------------------------------

function sameContentId(a: ContentId, b: ContentId): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs;
}

function preIdEqualsCurrent(preId: PreId, current: ContentId): boolean {
  if (preId === 'absent' || preId === 'unknown') return false;
  return sameContentId(preId, current);
}

function preIdEquals(a: PreId, b: PreId): boolean {
  if (a === 'absent' || a === 'unknown' || b === 'absent' || b === 'unknown') return a === b;
  return sameContentId(a, b);
}

export type RulePProducer = { kind: RecordKind } | 'no-producer' | 'ambiguous';

/**
 * Rule P: did one of these records produce the current bytes, and of what
 * kind? The candidate is the newest record (by `at`) whose `preId` DIFFERS
 * from the current identity; it is the producer only if it is unique — no
 * other record has the same `preId` and a different kind (3.1).
 */
export function rulePProducer(records: AgentArtifactRecord[], current: ContentId): RulePProducer {
  const differing = records.filter((r) => !preIdEqualsCurrent(r.preId, current));
  if (differing.length === 0) return 'no-producer';
  let candidate = differing[0];
  for (const r of differing) if (r.at > candidate.at) candidate = r;
  const conflicting = records.some(
    (r) => r !== candidate && preIdEquals(r.preId, candidate.preId) && r.kind !== candidate.kind,
  );
  if (conflicting) return 'ambiguous';
  return { kind: candidate.kind };
}

// -- The total classifier (3.1) -----------------------------------------------

export interface ClassifyInput {
  /** current identity of the resolved target, from the injected stat. */
  currentId: ContentId | 'absent' | null;
  /** inspected header bytes, or null when unreadable. */
  header: Uint8Array | null;
  /** records for this path hash (final, readable). */
  records: AgentArtifactRecord[];
  /** whether history is complete for this path (incl. the observation boundary). */
  complete: boolean;
  /** does the resolved path pass `isInstalledBinaryPath` (Rule H location). */
  installRoot: boolean;
}

/**
 * The total classifier (3.1 table). Pure: given a resolved target's identity,
 * header, records and completeness, return its authorship state.
 */
export function classifyArtifactState(input: ClassifyInput): ArtifactState {
  const { currentId, header, records, complete, installRoot } = input;

  // Step 0: 'absent' at exec — nothing to execute.
  if (currentId === 'absent') return 'outside';

  const producer =
    complete && currentId && typeof currentId === 'object'
      ? rulePProducer(records, currentId)
      : null;

  const magic = isNativeImageHeader(header);
  const native =
    magic ||
    (producer !== null &&
      producer !== 'no-producer' &&
      producer !== 'ambiguous' &&
      producer.kind === 'agent-written' &&
      headerHasNul(header));

  if (!native) {
    // Header is not a native image, or could not be read.
    if (header === null) {
      // Unreadable header: step 0 only when history is complete and holds no
      // record for the path; otherwise unknown (row J).
      if (complete && records.length === 0) return 'outside';
      return 'state-3-unknown';
    }
    // A script / text header is outside this design (current behaviour).
    return 'outside';
  }

  // Native image from here on.
  if (currentId === null) return 'state-3-unknown'; // current identity unknown
  if (!complete) return 'state-3-unknown';
  if (producer === 'ambiguous' || producer === null) return 'state-3-unknown';
  if (producer === 'no-producer') {
    return installRoot ? 'state-2-install-root' : 'state-3-unknown';
  }
  return producer.kind === 'agent-written'
    ? 'state-1-agent-produced'
    : 'state-1c-compile-lineage';
}
