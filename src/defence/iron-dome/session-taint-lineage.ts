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
 *     (§2.2): there is no `clear`, no `reset`, no TTL. The only release is the
 *     host reporting the session's end, which is lifecycle, not laundering.
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

export type TaintRefusal = 'content-asserted-identity' | 'empty-identity';

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
      /** The first origin — what tainted the session. */
      origin: TaintOrigin;
      /** Every tainting event since, oldest first, bounded by MAX_LINEAGE_ENTRIES. */
      lineage: readonly TaintOrigin[];
      /** Tainting events beyond the bound; counted, never silently dropped. */
      lineageTruncated: number;
    }
  | { tainted: false; sessionId: string };

export type TaintOutcome =
  | { ok: true; state: TaintState }
  | { ok: false; refused: TaintRefusal; reason: string };

/** Lineage entries kept per session; beyond this the count is kept, not the rows. */
export const MAX_LINEAGE_ENTRIES = 64;

export interface SessionTaintLineage {
  /** A span entered this session's context. Records taint if the span taints. */
  ingest(session: SessionIdentity, span: SpanProvenance): TaintOutcome & { decision?: TaintDecision };
  /** A child was forked or spawned from `parent`: it inherits the parent's taint. */
  inherit(child: SessionIdentity, parent: SessionIdentity, route: 'inherit-fork' | 'inherit-spawn'): TaintOutcome;
  /**
   * A return from `peer` entered `receiver`. Taints when the peer's session is
   * tainted IN THIS STORE (authoritative), or when the span itself taints —
   * signature or not.
   */
  peerReturn(receiver: SessionIdentity, peer: SessionIdentity, span: SpanProvenance): TaintOutcome;
  /** A memory was written from `session`: it carries the session's taint marker. */
  memoryWritten(memoryRef: string, session: SessionIdentity): { ok: true; tainted: boolean } | { ok: false; refused: TaintRefusal; reason: string };
  /** A memory was recalled into `session`: a tainted memory taints the recalling session. */
  memoryRecalled(memoryRef: string, session: SessionIdentity): TaintOutcome;
  /** Read the taint state. A refused identity cannot be read either. */
  state(session: SessionIdentity): TaintOutcome;
  /**
   * The host reports the session ended. Releases the record — host lifecycle,
   * not a clear: a new session is a new identity, and anything inherited or
   * written from this one keeps its own taint.
   */
  endSession(session: SessionIdentity): { ok: true } | { ok: false; refused: TaintRefusal; reason: string };
  size(): number;
}

interface TaintRecord {
  sessionId: string;
  sinceMs: number;
  origin: TaintOrigin;
  lineage: TaintOrigin[];
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

/** Create an in-memory store. `now` is the injected clock. */
export function createSessionTaintLineage(options: { now?: () => number } = {}): SessionTaintLineage {
  const now = options.now ?? (() => Date.now());
  const records = new Map<string, TaintRecord>();
  const taintedMemories = new Map<string, TaintOrigin>();

  function view(sessionId: string): TaintState {
    const rec = records.get(sessionId);
    if (!rec) return { tainted: false, sessionId };
    return {
      tainted: true,
      sessionId,
      sinceMs: rec.sinceMs,
      origin: rec.origin,
      lineage: [...rec.lineage],
      lineageTruncated: rec.lineageTruncated,
    };
  }

  function taint(sessionId: string, origin: TaintOrigin): TaintState {
    const existing = records.get(sessionId);
    if (!existing) {
      records.set(sessionId, { sessionId, sinceMs: origin.atMs, origin, lineage: [origin], lineageTruncated: 0 });
    } else if (existing.lineage.length < MAX_LINEAGE_ENTRIES) {
      existing.lineage.push(origin);
    } else {
      existing.lineageTruncated += 1;
    }
    return view(sessionId);
  }

  return {
    ingest(session, span) {
      const r = refuse(session);
      if (r) return r;
      const decision = spanTaints(span);
      if (!decision.taints) return { ok: true, state: view(session.id), decision };
      const state = taint(session.id, {
        route: 'ingest', spanId: span.spanId ?? null, band: decision.band, reason: decision.reason, atMs: now(),
      });
      return { ok: true, state, decision };
    },

    inherit(child, parent, route) {
      const rc = refuse(child);
      if (rc) return rc;
      const rp = refuse(parent);
      if (rp) return rp;
      const parentRec = records.get(parent.id);
      if (!parentRec) return { ok: true, state: view(child.id) };
      const state = taint(child.id, {
        route, spanId: parentRec.origin.spanId, band: parentRec.origin.band,
        reason: `inherited from tainted session (${route}): ${parentRec.origin.reason}`,
        atMs: now(), fromSessionId: parent.id,
      });
      return { ok: true, state };
    },

    peerReturn(receiver, peer, span) {
      const rr = refuse(receiver);
      if (rr) return rr;
      const rp = refuse(peer);
      if (rp) return rp;
      const peerRec = records.get(peer.id);
      const decision = spanTaints(peerRec ? { ...span, lineage: { ...span.lineage, fromTaintedSession: true } } : span);
      if (!decision.taints) return { ok: true, state: view(receiver.id) };
      const state = taint(receiver.id, {
        route: 'peer-return', spanId: span.spanId ?? null, band: decision.band,
        reason: peerRec ? `return from tainted peer session: ${decision.reason}` : decision.reason,
        atMs: now(), fromSessionId: peer.id,
      });
      return { ok: true, state };
    },

    memoryWritten(memoryRef, session) {
      const r = refuse(session);
      if (r) return r;
      if (typeof memoryRef !== 'string' || memoryRef.length === 0) {
        return { ok: false, refused: 'empty-identity', reason: 'memory reference is empty — nothing to mark' };
      }
      const rec = records.get(session.id);
      if (!rec) return { ok: true, tainted: taintedMemories.has(memoryRef) };
      // A marker, once set, is never unset by a later clean write: the stored
      // text may still be the tainted one.
      if (!taintedMemories.has(memoryRef)) {
        taintedMemories.set(memoryRef, { ...rec.origin, fromSessionId: session.id });
      }
      return { ok: true, tainted: true };
    },

    memoryRecalled(memoryRef, session) {
      const r = refuse(session);
      if (r) return r;
      const marker = taintedMemories.get(memoryRef);
      if (!marker) return { ok: true, state: view(session.id) };
      const state = taint(session.id, {
        route: 'memory-recall', spanId: marker.spanId, band: 'stored-memory',
        reason: `recalled a memory written from a tainted session: ${marker.reason}`,
        atMs: now(), fromSessionId: marker.fromSessionId, memoryRef,
      });
      return { ok: true, state };
    },

    state(session) {
      const r = refuse(session);
      if (r) return r;
      return { ok: true, state: view(session.id) };
    },

    endSession(session) {
      const r = refuse(session);
      if (r) return r;
      records.delete(session.id);
      return { ok: true };
    },

    size() {
      return records.size;
    },
  };
}
