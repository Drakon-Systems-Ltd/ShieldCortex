/**
 * Iron Dome — Session taint and lineage contract (ADR-002 §2.1 / §2.2, #598)
 *
 * WHAT THIS IS
 * ------------
 * The pure core of the taint and lineage contract the ADR says every adapter
 * must satisfy: a span's trust BAND is derived from its provenance label with
 * a fail-closed rule; a session becomes TAINTED when an `untrusted-external`
 * span — or a span whose content lineage is external, whatever the transport —
 * enters its context; taint is keyed by the identity the HOST supplies, lasts
 * for the session, is inherited by children, summaries and recalled memory,
 * and has no clear.
 *
 * WHAT THIS IS NOT
 * ----------------
 * Not wired. Nothing in the effect plane reads this store yet, no verdict
 * changes, and the existing detection-triggered taint in the OpenClaw plugin
 * (`plugins/openclaw/session-taint.ts`, #233: a scan hit, fifteen-minute TTL,
 * cleared at session end) is untouched — the ADR names that lifetime as the
 * wrong one for a PROVENANCE-triggered taint (§2.2 "Lifetime"), so this is a
 * separate contract rather than a change to that one. §8 records that the
 * operator has not accepted the taint trade; this module gives the contract
 * an exact, testable shape so the §5B taint controls have a store to read and
 * the later wiring PR is a wiring PR, not a design PR.
 *
 * DESIGN (same discipline as `session-lease.ts`)
 * ----------------------------------------------
 * Pure decisions, injected state and clock. No I/O, no config, no host.
 *
 *   - "Unknown or missing provenance is fail-closed" (§2.1): a label that is
 *     absent, not a string, `unknown`, or NOT A RECOGNISED MEMBER of the
 *     `ProvenanceLabel` vocabulary is `untrusted-external` for taint. That
 *     last clause is what makes a span unable to name its own band: `operator`
 *     is not a label, so a span spelled `operator` fails closed.
 *   - "Declaration is input, attestation is authority" (§2.1): `operator` is
 *     reachable only from a HOST-attested `user`/`cli` (the same rungs
 *     `env-detector.ts` treats as host-only); a merely declared one is `agent`.
 *     `signed-peer` is reachable only from a host-verified signature, never
 *     from the label and never from a declared flag.
 *   - "Taint is transitive by content, regardless of transport trust" (§2.2):
 *     lineage taints even when the band would not — a signed peer relaying
 *     hostile material, a tool result proxying a fetch, a return from a
 *     tainted session.
 *   - "Bound to host-owned session identity" (§2.2): every entry point takes a
 *     `SessionIdentity` that says who asserted the id. A content-asserted
 *     identity is REFUSED — it is never keyed, read or ended — so prose can
 *     neither set nor clear anything.
 *   - "Lifetime … for the session" / "Reset … there is no operator clear"
 *     (§2.2): there is no `clear`, no `reset`, no TTL. The host reporting the
 *     session's end RETIRES the record — it stops being a live session that
 *     spans can enter — but a tainted session's snapshot is kept, because its
 *     products are still in flight: a late peer return, a late memory write
 *     or a late spawn from an ended tainted producer still carries the taint
 *     (#599 review, finding 1). Ending is lifecycle, never laundering.
 *   - "Memory written from a tainted session and later imported" (§2.2): the
 *     marker travels IN THE MEMORY FRAME (#531), not in this process. A write
 *     returns a portable, frozen `TaintMarker`; a recall consumes the frame's
 *     marker (or its explicit known-clean attestation) so two independent
 *     instances agree. A recall with NO evidence — unseen here and no frame —
 *     is missing provenance and fails closed (§2.1), never silently clean
 *     (#599 review, finding 2).
 *   - Owned snapshots: every origin, lineage entry, state and marker handed
 *     out is a frozen copy. A caller that mutates what it was given changes
 *     nothing here — attribution cannot be rewritten from outside (#599
 *     review, finding 3).
 *
 * Injected state: the clock, and optionally memory markers hydrated from
 * frames on construction. Nothing else is read from the environment.
 */

import type { ProvenanceLabel } from '../types.js';

// ── §2.1 bands ───────────────────────────────────────────────────────────────

/** The six bands of ADR-002 §2.1, an ordering over the existing label vocabulary. */
export type TrustBand =
  | 'operator'
  | 'signed-peer'
  | 'agent'
  | 'stored-memory'
  | 'tool-result'
  | 'untrusted-external';

export const TRUST_BANDS: readonly TrustBand[] = [
  'operator', 'signed-peer', 'agent', 'stored-memory', 'tool-result', 'untrusted-external',
];

/**
 * Who vouches for a span's label. `host` means the adapter read it off a
 * host-owned field (the gateway's message role, the hook's event kind);
 * `declared` means a caller said so. Default is `declared` — the safe one.
 */
export type SpanAttestation = 'host' | 'declared';

export interface SpanLineage {
  /** The producing peer or sub-agent session was itself tainted. */
  fromTaintedSession?: boolean;
  /**
   * The span relays or quotes externally fetched or externally authored
   * material — a proxy fetch through an MCP server, a peer quoting a hostile
   * page, a cloned repository's README read through a trusted `file` source.
   */
  carriesExternalContent?: boolean;
}

export interface SpanProvenance {
  /** The provenance label. Anything outside the vocabulary fails closed. */
  label: unknown;
  attestation?: SpanAttestation;
  /**
   * The HOST verified a signature on this envelope. Only honoured together
   * with `attestation: 'host'`; a declared flag is a claim inside content.
   */
  signatureVerified?: boolean;
  lineage?: SpanLineage;
  /** A stable id for the span, kept on the lineage record. */
  spanId?: string;
}

export interface BandDecision {
  band: TrustBand;
  /** True when the fail-closed rule assigned the band (unknown, missing, unrecognised). */
  failClosed: boolean;
  reason: string;
}

/**
 * The fixed mapping from the label vocabulary to bands. `Record<ProvenanceLabel, …>`
 * is the completeness check: a new label member fails to compile here until
 * it is classified, so no label can arrive unclassified and fall to a default.
 *
 * `user` / `cli` are listed at their DECLARED band; the host-attested lift to
 * `operator` is applied in `bandForSpan`. `agent_message` is listed at its
 * UNSIGNED band; the host-verified lift to `signed-peer` is applied there too.
 * No label maps to `stored-memory`: that band is reached only through the
 * memory-recall route of the store, because "stored memory" is a fact about
 * where the span came from that only the recall path can attest.
 */
const DECLARED_LABEL_BAND: Readonly<Record<ProvenanceLabel, TrustBand>> = {
  // Host-only rungs (env-detector.ts): declared, they are the agent's own words.
  user: 'agent',
  cli: 'agent',
  // The agent's own harness, hooks and API surface.
  hook: 'agent',
  api: 'agent',
  agent: 'agent',
  system: 'agent',
  // Tool output not otherwise classified.
  tool_response: 'tool-result',
  tool_result: 'tool-result',
  // An unsigned message from another agent is an unsigned message (§2.1 table).
  agent_message: 'untrusted-external',
  // Network, documents, mail, and locally read files of unknown authorship
  // (§2.2: "a local file authored externally … even though it is read through
  // a `file` source on a trusted host").
  web: 'untrusted-external',
  document: 'untrusted-external',
  email: 'untrusted-external',
  file: 'untrusted-external',
  // A capture candidate has no stored provenance yet.
  memory_candidate: 'untrusted-external',
  unknown: 'untrusted-external',
};

const KNOWN_LABELS: ReadonlySet<string> = new Set(Object.keys(DECLARED_LABEL_BAND));

/** The §2.1 band of a span, with the fail-closed rule applied. Pure. */
export function bandForSpan(span: SpanProvenance): BandDecision {
  const label = span.label;
  if (typeof label !== 'string' || label.length === 0) {
    return { band: 'untrusted-external', failClosed: true, reason: 'provenance label missing — fail-closed to untrusted-external (§2.1)' };
  }
  if (!KNOWN_LABELS.has(label)) {
    // Includes every attempt by a span to name its own band ("operator",
    // "signed-peer", …): not a label, so not recognised, so fail-closed.
    return { band: 'untrusted-external', failClosed: true, reason: `provenance label not recognised — fail-closed to untrusted-external (§2.1)` };
  }
  const known = label as ProvenanceLabel;
  if (known === 'unknown') {
    return { band: 'untrusted-external', failClosed: true, reason: 'provenance label unknown — fail-closed to untrusted-external (§2.1)' };
  }
  const attested = span.attestation === 'host';
  if ((known === 'user' || known === 'cli') && attested) {
    return { band: 'operator', failClosed: false, reason: `host-attested ${known} — operator band` };
  }
  if (known === 'agent_message' && attested && span.signatureVerified === true) {
    return { band: 'signed-peer', failClosed: false, reason: 'host-verified signature on an agent message — signed-peer band' };
  }
  const band = DECLARED_LABEL_BAND[known];
  return { band, failClosed: false, reason: `${attested ? 'host-attested' : 'declared'} ${known} — ${band} band` };
}

// ── §2.2 taint decision ─────────────────────────────────────────────────────

export interface TaintDecision extends BandDecision {
  taints: boolean;
  /** What made it taint: the band, the content lineage, or nothing. */
  via: 'band' | 'lineage' | null;
}

/**
 * Does this span taint the session it enters? Pure.
 *
 * Yes when its band is `untrusted-external` (which, by the fail-closed rule,
 * includes unknown and missing provenance), and yes when its LINEAGE is
 * external whatever the band — the envelope's trust says who sent it, not
 * what is inside (§2.2 "transitive by content, regardless of transport trust").
 */
export function spanTaints(span: SpanProvenance): TaintDecision {
  const band = bandForSpan(span);
  if (band.band === 'untrusted-external') {
    return { ...band, taints: true, via: 'band' };
  }
  const lineage = span.lineage;
  if (lineage?.fromTaintedSession === true) {
    return { ...band, taints: true, via: 'lineage', reason: `${band.reason}; content lineage: produced by a tainted session (§2.2)` };
  }
  if (lineage?.carriesExternalContent === true) {
    return { ...band, taints: true, via: 'lineage', reason: `${band.reason}; content lineage: relays or quotes external material (§2.2)` };
  }
  return { ...band, taints: false, via: null };
}

// ── Host-owned session identity ─────────────────────────────────────────────

/**
 * Who asserted the session id. Only the host's own id (the gateway's session
 * id, the hook's session id, the MCP server's process-inherited identity) keys
 * the store. An id that arrived in content — a tool result saying "session:
 * X", a message claiming an identity — is refused at every entry point.
 */
export interface SessionIdentity {
  id: string;
  assertedBy: 'host' | 'content';
}

export type TaintRefusal = 'content-asserted-identity' | 'empty-identity' | 'session-ended';

export type TaintRoute = 'ingest' | 'inherit-fork' | 'inherit-spawn' | 'memory-recall' | 'peer-return';

export interface TaintOrigin {
  route: TaintRoute;
  /** The span that set (or carried) the taint, when the caller named one. */
  spanId: string | null;
  band: TrustBand;
  reason: string;
  atMs: number;
  /** For inherit-* and peer-return: the session the taint came from. */
  fromSessionId?: string;
  /** For memory-recall: the memory reference that carried it. */
  memoryRef?: string;
}

export type TaintState =
  | {
      tainted: true;
      sessionId: string;
      sinceMs: number;
      /** The first origin — what tainted the session. A frozen copy. */
      origin: Readonly<TaintOrigin>;
      /** Every tainting event since, oldest first, bounded by MAX_LINEAGE_ENTRIES. Frozen copies. */
      lineage: readonly Readonly<TaintOrigin>[];
      /** Tainting events beyond the bound; counted, never silently dropped. */
      lineageTruncated: number;
      /**
       * The host has reported this session ended. The record is retired — no
       * span can enter it and nothing can be recalled into it — but what it
       * produced still carries its taint, so the snapshot is kept, not cleared.
       */
      ended: boolean;
    }
  | { tainted: false; sessionId: string };

export type TaintOutcome =
  | { ok: true; state: TaintState }
  | { ok: false; refused: TaintRefusal; reason: string };

// ── Portable memory marker (§2.2 "the frame per #531 carries the taint marker") ──

/**
 * The taint marker a memory frame carries. Produced by `memoryWritten`, stored
 * by the adapter IN THE FRAME next to the memory, handed back to
 * `memoryRecalled` by whichever process recalls it — possibly a different
 * instance, host or machine. Plain data, frozen, versioned; validated on the
 * way in with `isTaintMarker` because storage is not this module.
 *
 * It describes the WRITER's origin (what tainted the session that wrote the
 * memory), so a later HOLD is attributable to the span that started it.
 */
export interface TaintMarker {
  readonly v: 1;
  readonly memoryRef: string;
  /** The session that wrote the memory while tainted. */
  readonly fromSessionId: string;
  readonly writtenAtMs: number;
  /** The writer's origin. */
  readonly route: TaintRoute;
  readonly spanId: string | null;
  readonly band: TrustBand;
  readonly reason: string;
  readonly atMs: number;
}

const TAINT_ROUTES: ReadonlySet<string> = new Set<TaintRoute>(['ingest', 'inherit-fork', 'inherit-spawn', 'memory-recall', 'peer-return']);
const BAND_SET: ReadonlySet<string> = new Set(TRUST_BANDS);

/** Structural validation of a marker read back from storage. Anything else is missing evidence. */
export function isTaintMarker(x: unknown): x is TaintMarker {
  if (typeof x !== 'object' || x === null) return false;
  const m = x as Record<string, unknown>;
  return m.v === 1
    && typeof m.memoryRef === 'string' && m.memoryRef.length > 0
    && typeof m.fromSessionId === 'string' && m.fromSessionId.length > 0
    && typeof m.writtenAtMs === 'number' && Number.isFinite(m.writtenAtMs)
    && typeof m.route === 'string' && TAINT_ROUTES.has(m.route)
    && (m.spanId === null || typeof m.spanId === 'string')
    && typeof m.band === 'string' && BAND_SET.has(m.band)
    && typeof m.reason === 'string'
    && typeof m.atMs === 'number' && Number.isFinite(m.atMs);
}

/**
 * What the recalling adapter read off the memory frame. `taint: null` is the
 * frame's explicit statement that the memory was written clean (set from a
 * `memoryWritten` result of `tainted: false`); a marker is the taint; an
 * absent frame, or anything that is not a valid marker, is missing evidence.
 */
export interface MemoryFrameTaint {
  taint: unknown;
}

/** How a recall decided. `missing` is the fail-closed branch. */
export type MemoryEvidence = 'marker' | 'local-marker' | 'known-clean' | 'missing';

/** Lineage entries kept per session; beyond this the count is kept, not the rows. */
export const MAX_LINEAGE_ENTRIES = 64;

export type MemoryWriteOutcome =
  | { ok: true; tainted: true; marker: TaintMarker }
  | { ok: true; tainted: false; marker: null }
  | { ok: false; refused: TaintRefusal; reason: string };

/**
 * Lifecycle contract (#599 finding 1). A session is LIVE from its first
 * mention until the host reports its end, then ENDED. The SUBJECT of an
 * operation — the session a span enters, a child that inherits, a receiver of
 * a return, a recaller of a memory — must be live: an ended subject is refused
 * (`session-ended`), because a span arriving for an ended id is either a late
 * delivery or an id reuse, and both are ambiguous. The PRODUCER of an
 * operation — the parent a child inherits from, the peer a return came from,
 * the writer of a memory — may be ended: its snapshot still answers, so an
 * end-before-delivery ordering cannot launder what the producer made.
 */
export interface SessionTaintLineage {
  /** A span entered this session's context. Records taint if the span taints. Subject must be live. */
  ingest(session: SessionIdentity, span: SpanProvenance): TaintOutcome & { decision?: TaintDecision };
  /** A child was forked or spawned from `parent`: it inherits the parent's taint, live or ended. */
  inherit(child: SessionIdentity, parent: SessionIdentity, route: 'inherit-fork' | 'inherit-spawn'): TaintOutcome;
  /**
   * A return from `peer` entered `receiver`. Taints when the peer's session is
   * tainted IN THIS STORE (authoritative; live or ended), or when the span
   * itself taints — signature or not.
   */
  peerReturn(receiver: SessionIdentity, peer: SessionIdentity, span: SpanProvenance): TaintOutcome;
  /**
   * A memory was written from `session` (live or ended). Returns the portable
   * marker for the adapter to store IN THE FRAME, or `null` for a clean write.
   */
  memoryWritten(memoryRef: string, session: SessionIdentity): MemoryWriteOutcome;
  /**
   * A memory was recalled into `session`. `frame` is what the adapter read off
   * the memory frame; omit it only when the adapter has no frame, which fails
   * closed unless this store marked the reference itself.
   */
  memoryRecalled(memoryRef: string, session: SessionIdentity, frame?: MemoryFrameTaint): TaintOutcome & { evidence?: MemoryEvidence };
  /** Read the taint state. A refused identity cannot be read either. An ended tainted session reads as tainted and ended. */
  state(session: SessionIdentity): TaintOutcome;
  /**
   * The host reports the session ended. Retires the record — host lifecycle,
   * not a clear: a tainted session's snapshot is kept for its in-flight
   * products, and anything inherited or written from it keeps its own taint.
   * Idempotent.
   */
  endSession(session: SessionIdentity): { ok: true } | { ok: false; refused: TaintRefusal; reason: string };
  /** Live tainted sessions. */
  size(): number;
  /** Ended tainted sessions whose snapshot is retained. Unbounded by design: eviction would be laundering. */
  endedSize(): number;
}

interface TaintRecord {
  sessionId: string;
  sinceMs: number;
  origin: Readonly<TaintOrigin>;
  lineage: Readonly<TaintOrigin>[];
  lineageTruncated: number;
}

function refuse(session: SessionIdentity): { ok: false; refused: TaintRefusal; reason: string } | null {
  if (typeof session.id !== 'string' || session.id.length === 0) {
    return { ok: false, refused: 'empty-identity', reason: 'session identity is empty — nothing to key (§2.2)' };
  }
  if (session.assertedBy !== 'host') {
    return { ok: false, refused: 'content-asserted-identity', reason: 'session identity asserted in content carries no authority — refused, not keyed (§2.2)' };
  }
  return null;
}

function refuseEmptyRef(memoryRef: string): { ok: false; refused: TaintRefusal; reason: string } | null {
  if (typeof memoryRef !== 'string' || memoryRef.length === 0) {
    return { ok: false, refused: 'empty-identity', reason: 'memory reference is empty — nothing to mark or recall' };
  }
  return null;
}

/** A detached, frozen copy of an origin. The store never hands out its own objects. */
function freezeOrigin(o: TaintOrigin): Readonly<TaintOrigin> {
  const copy: TaintOrigin = { route: o.route, spanId: o.spanId, band: o.band, reason: o.reason, atMs: o.atMs };
  if (o.fromSessionId !== undefined) copy.fromSessionId = o.fromSessionId;
  if (o.memoryRef !== undefined) copy.memoryRef = o.memoryRef;
  return Object.freeze(copy);
}

function freezeMarker(m: TaintMarker): TaintMarker {
  return Object.freeze({
    v: 1, memoryRef: m.memoryRef, fromSessionId: m.fromSessionId, writtenAtMs: m.writtenAtMs,
    route: m.route, spanId: m.spanId, band: m.band, reason: m.reason, atMs: m.atMs,
  });
}

export interface SessionTaintLineageOptions {
  /** Injected clock. */
  now?: () => number;
  /**
   * Markers hydrated from frames on construction, so a fresh instance can
   * answer recalls for memories another instance marked. Invalid entries are
   * ignored — they are missing evidence, and a recall will fail closed.
   */
  memoryMarkers?: Iterable<unknown>;
}

/** Create an in-memory store. */
export function createSessionTaintLineage(options: SessionTaintLineageOptions = {}): SessionTaintLineage {
  const now = options.now ?? (() => Date.now());
  const live = new Map<string, TaintRecord>();
  const ended = new Map<string, TaintRecord>();
  /** `null` = written clean by a session this store knows; a marker = tainted. */
  const memories = new Map<string, TaintMarker | null>();
  for (const m of options.memoryMarkers ?? []) {
    if (isTaintMarker(m) && !memories.get(m.memoryRef)) memories.set(m.memoryRef, freezeMarker(m));
  }

  function find(sessionId: string): { rec: TaintRecord; ended: boolean } | null {
    const l = live.get(sessionId);
    if (l) return { rec: l, ended: false };
    const e = ended.get(sessionId);
    if (e) return { rec: e, ended: true };
    return null;
  }

  function refuseEnded(session: SessionIdentity, what: string): { ok: false; refused: TaintRefusal; reason: string } | null {
    if (!ended.has(session.id)) return null;
    return { ok: false, refused: 'session-ended', reason: `${what} an ended session is ambiguous (late delivery or id reuse) — refused; its snapshot is kept, not cleared (§2.2 lifetime)` };
  }

  function view(sessionId: string): TaintState {
    const f = find(sessionId);
    if (!f) return { tainted: false, sessionId };
    const { rec } = f;
    return Object.freeze({
      tainted: true as const,
      sessionId,
      sinceMs: rec.sinceMs,
      origin: rec.origin,
      lineage: Object.freeze(rec.lineage.slice()),
      lineageTruncated: rec.lineageTruncated,
      ended: f.ended,
    });
  }

  /** Only a LIVE session is written to; callers check `refuseEnded` first. */
  function taint(sessionId: string, originIn: TaintOrigin): TaintState {
    const origin = freezeOrigin(originIn);
    const existing = live.get(sessionId);
    if (!existing) {
      live.set(sessionId, { sessionId, sinceMs: origin.atMs, origin, lineage: [origin], lineageTruncated: 0 });
    } else if (existing.lineage.length < MAX_LINEAGE_ENTRIES) {
      existing.lineage.push(origin);
    } else {
      existing.lineageTruncated += 1;
    }
    return view(sessionId);
  }

  function markerFor(memoryRef: string, rec: TaintRecord): TaintMarker {
    return freezeMarker({
      v: 1, memoryRef, fromSessionId: rec.sessionId, writtenAtMs: now(),
      route: rec.origin.route, spanId: rec.origin.spanId, band: rec.origin.band, reason: rec.origin.reason, atMs: rec.origin.atMs,
    });
  }

  return {
    ingest(session, span) {
      const r = refuse(session) ?? refuseEnded(session, 'a span entering');
      if (r) return r;
      const decision = spanTaints(span);
      if (!decision.taints) return { ok: true, state: view(session.id), decision };
      const state = taint(session.id, {
        route: 'ingest', spanId: span.spanId ?? null, band: decision.band, reason: decision.reason, atMs: now(),
      });
      return { ok: true, state, decision };
    },

    inherit(child, parent, route) {
      const rc = refuse(child) ?? refuseEnded(child, 'a child inheriting into');
      if (rc) return rc;
      const rp = refuse(parent);
      if (rp) return rp;
      const p = find(parent.id);
      if (!p) return { ok: true, state: view(child.id) };
      // The reason names the ROOT cause once; it does not nest per generation.
      const root = p.rec.origin.route === 'inherit-fork' || p.rec.origin.route === 'inherit-spawn'
        ? p.rec.origin.reason
        : `inherited from tainted session: ${p.rec.origin.reason}`;
      const state = taint(child.id, {
        route, spanId: p.rec.origin.spanId, band: p.rec.origin.band,
        reason: p.ended ? `${root} (parent ended before the spawn was recorded; snapshot)` : root,
        atMs: now(), fromSessionId: parent.id,
      });
      return { ok: true, state };
    },

    peerReturn(receiver, peer, span) {
      const rr = refuse(receiver) ?? refuseEnded(receiver, 'a return delivered to');
      if (rr) return rr;
      const rp = refuse(peer);
      if (rp) return rp;
      const p = find(peer.id);
      const decision = spanTaints(p ? { ...span, lineage: { ...span.lineage, fromTaintedSession: true } } : span);
      if (!decision.taints) return { ok: true, state: view(receiver.id) };
      const state = taint(receiver.id, {
        route: 'peer-return', spanId: span.spanId ?? null, band: decision.band,
        reason: p
          ? `return from tainted peer session${p.ended ? ' (peer ended before delivery; snapshot)' : ''}: ${decision.reason}`
          : decision.reason,
        atMs: now(), fromSessionId: peer.id,
      });
      return { ok: true, state };
    },

    memoryWritten(memoryRef, session) {
      const r = refuse(session) ?? refuseEmptyRef(memoryRef);
      if (r) return r;
      const already = memories.get(memoryRef);
      // A marker, once set, is never unset by a later clean write: the stored
      // text may still be the tainted one.
      if (already) return { ok: true, tainted: true, marker: already };
      const f = find(session.id);
      if (!f) {
        // Written clean by a session this store has seen nothing bad from:
        // record the clean fact so a later recall here is known-clean, not unseen.
        if (already === undefined) memories.set(memoryRef, null);
        return { ok: true, tainted: false, marker: null };
      }
      const marker = markerFor(memoryRef, f.rec);
      memories.set(memoryRef, marker);
      return { ok: true, tainted: true, marker };
    },

    memoryRecalled(memoryRef, session, frame) {
      const r = refuse(session) ?? refuseEmptyRef(memoryRef) ?? refuseEnded(session, 'a memory recalled into');
      if (r) return r;
      const local = memories.get(memoryRef);
      // Evidence, in order of authority: a marker anywhere taints; then the
      // frame's or this store's explicit clean attestation; then nothing.
      let marker: TaintMarker | null = local ?? null;
      let evidence: MemoryEvidence;
      if (marker) {
        evidence = 'local-marker';
      } else if (frame !== undefined && isTaintMarker(frame.taint) && frame.taint.memoryRef === memoryRef) {
        marker = freezeMarker(frame.taint);
        if (local === undefined) memories.set(memoryRef, marker);
        evidence = 'marker';
      } else if (local === null || (frame !== undefined && frame.taint === null)) {
        evidence = 'known-clean';
      } else {
        evidence = 'missing';
      }
      if (evidence === 'known-clean') return { ok: true, state: view(session.id), evidence };
      const state = marker
        ? taint(session.id, {
            route: 'memory-recall', spanId: marker.spanId, band: 'stored-memory',
            reason: `recalled a memory written from a tainted session: ${marker.reason}`,
            atMs: now(), fromSessionId: marker.fromSessionId, memoryRef,
          })
        : taint(session.id, {
            route: 'memory-recall', spanId: null, band: 'stored-memory',
            reason: 'recalled a memory with no provenance evidence (no frame marker, not written through this store) — fail-closed (§2.1)',
            atMs: now(), memoryRef,
          });
      return { ok: true, state, evidence };
    },

    state(session) {
      const r = refuse(session);
      if (r) return r;
      return { ok: true, state: view(session.id) };
    },

    endSession(session) {
      const r = refuse(session);
      if (r) return r;
      const rec = live.get(session.id);
      if (rec) {
        live.delete(session.id);
        ended.set(session.id, rec);
      }
      return { ok: true };
    },

    size() {
      return live.size;
    },

    endedSize() {
      return ended.size;
    },
  };
}
