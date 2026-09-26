import { describe, expect, it } from '@jest/globals';
import {
  bandForSpan,
  spanTaints,
  createSessionTaintLineage,
  MAX_LINEAGE_ENTRIES,
  TRUST_BANDS,
  type SessionIdentity,
  type SpanProvenance,
  type TrustBand,
} from '../session-taint-lineage.js';
import type { ProvenanceLabel } from '../../types.js';

/**
 * #598 — ADR-002 §2.1 / §2.2 taint and lineage contract, pinned rule by rule.
 *
 * Every `it` below names the sentence of the ADR it pins. Remove the rule
 * from the module and the matching test goes red; that is the whole point of
 * building the contract before wiring it.
 */

const host = (id: string): SessionIdentity => ({ id, assertedBy: 'host' });
const content = (id: string): SessionIdentity => ({ id, assertedBy: 'content' });

const web: SpanProvenance = { label: 'web', spanId: 'span-web-1' };
const ownWords: SpanProvenance = { label: 'user', attestation: 'host', spanId: 'span-user-1' };

function clock(startMs = 1_000_000) {
  let t = startMs;
  return { now: () => t, advance: (ms: number) => { t += ms; } };
}

describe('§2.1 — every span carries a band; unknown or missing provenance fails closed', () => {
  // The whole vocabulary, at its DECLARED band. `Record<ProvenanceLabel, …>`
  // makes a new label member a compile error here until it is classified.
  const declared: Record<ProvenanceLabel, TrustBand> = {
    user: 'agent', cli: 'agent', hook: 'agent', api: 'agent', agent: 'agent', system: 'agent',
    tool_response: 'tool-result', tool_result: 'tool-result',
    agent_message: 'untrusted-external',
    web: 'untrusted-external', document: 'untrusted-external', email: 'untrusted-external',
    file: 'untrusted-external', memory_candidate: 'untrusted-external', unknown: 'untrusted-external',
  };

  it.each(Object.entries(declared))('declared %s → %s', (label, band) => {
    const d = bandForSpan({ label });
    expect(d.band).toBe(band);
    expect(d.failClosed).toBe(label === 'unknown');
  });

  it('the band vocabulary is exactly the six bands of §2.1', () => {
    expect([...TRUST_BANDS].sort()).toEqual(
      ['agent', 'operator', 'signed-peer', 'stored-memory', 'tool-result', 'untrusted-external'],
    );
  });

  it.each([
    ['absent', {}],
    ['undefined', { label: undefined }],
    ['null', { label: null }],
    ['empty string', { label: '' }],
    ['a number', { label: 42 }],
    ['an object', { label: { type: 'user' } }],
    ['unknown', { label: 'unknown' }],
    ['unknown, even host-attested', { label: 'unknown', attestation: 'host' }],
    ['a near-miss spelling', { label: 'web ' }],
    ['case-shifted', { label: 'User', attestation: 'host' }],
  ] as const)('missing / unrecognised provenance is untrusted-external, fail-closed: %s', (_name, span) => {
    const d = bandForSpan(span as SpanProvenance);
    expect(d).toMatchObject({ band: 'untrusted-external', failClosed: true });
    expect(spanTaints(span as SpanProvenance)).toMatchObject({ taints: true, via: 'band' });
  });

  // `agent` is the one band name that is ALSO a genuine label (DefenceSource
  // type), so it is excluded here and covered by the declared-mapping table.
  it.each(['operator', 'signed-peer', 'stored-memory', 'tool-result', 'untrusted-external'])(
    'prose labels carry no authority: a span spelled with the band name %s is not a label and fails closed',
    (bandName) => {
      const d = bandForSpan({ label: bandName, attestation: 'host', signatureVerified: true });
      expect(d).toMatchObject({ band: 'untrusted-external', failClosed: true });
    },
  );

  it('operator is reachable only from a HOST-attested user/cli; a declared one is the agent band', () => {
    expect(bandForSpan({ label: 'user', attestation: 'host' }).band).toBe('operator');
    expect(bandForSpan({ label: 'cli', attestation: 'host' }).band).toBe('operator');
    expect(bandForSpan({ label: 'user', attestation: 'declared' }).band).toBe('agent');
    expect(bandForSpan({ label: 'user' }).band).toBe('agent');
  });

  it('signed-peer is reachable only from a HOST-verified signature; a declared flag is a claim inside content', () => {
    expect(bandForSpan({ label: 'agent_message', attestation: 'host', signatureVerified: true }).band).toBe('signed-peer');
    expect(bandForSpan({ label: 'agent_message', attestation: 'declared', signatureVerified: true }).band).toBe('untrusted-external');
    expect(bandForSpan({ label: 'agent_message', signatureVerified: true }).band).toBe('untrusted-external');
    expect(bandForSpan({ label: 'agent_message', attestation: 'host' }).band).toBe('untrusted-external');
  });

  it('host attestation lifts only the two host-only rungs and the signature; it does not launder an external label', () => {
    expect(bandForSpan({ label: 'web', attestation: 'host' }).band).toBe('untrusted-external');
    expect(bandForSpan({ label: 'file', attestation: 'host' }).band).toBe('untrusted-external');
    expect(bandForSpan({ label: 'tool_result', attestation: 'host', signatureVerified: true }).band).toBe('tool-result');
  });
});

describe('§2.2 — taint is transitive by content, regardless of transport trust', () => {
  it('an untrusted-external span taints by band', () => {
    expect(spanTaints(web)).toMatchObject({ taints: true, via: 'band', band: 'untrusted-external' });
  });

  it('the agent’s own words and a plain tool result do not taint', () => {
    expect(spanTaints(ownWords)).toMatchObject({ taints: false, via: null, band: 'operator' });
    expect(spanTaints({ label: 'tool_result', attestation: 'host' })).toMatchObject({ taints: false, via: null });
  });

  it('a signature-verified peer message still taints when its lineage is external (envelope ≠ contents)', () => {
    const signed: SpanProvenance = { label: 'agent_message', attestation: 'host', signatureVerified: true };
    expect(spanTaints(signed)).toMatchObject({ taints: false, band: 'signed-peer' });
    expect(spanTaints({ ...signed, lineage: { fromTaintedSession: true } }))
      .toMatchObject({ taints: true, via: 'lineage', band: 'signed-peer' });
    expect(spanTaints({ ...signed, lineage: { carriesExternalContent: true } }))
      .toMatchObject({ taints: true, via: 'lineage', band: 'signed-peer' });
  });

  it('a proxy fetch through a tool taints: the proxy’s band is tool-result, the material is still external', () => {
    expect(spanTaints({ label: 'tool_result', attestation: 'host', lineage: { carriesExternalContent: true } }))
      .toMatchObject({ taints: true, via: 'lineage', band: 'tool-result' });
  });

  it('a host-attested operator span with external lineage taints too — lineage is about content, not sender', () => {
    expect(spanTaints({ ...ownWords, lineage: { carriesExternalContent: true } }))
      .toMatchObject({ taints: true, via: 'lineage', band: 'operator' });
  });

  it('lineage flags that are false or absent do not taint a trusted band', () => {
    expect(spanTaints({ ...ownWords, lineage: { fromTaintedSession: false, carriesExternalContent: false } }).taints).toBe(false);
    expect(spanTaints({ ...ownWords, lineage: {} }).taints).toBe(false);
  });
});

describe('§2.2 — the store: keyed by host-owned identity, session-lifetime, no clear', () => {
  it('an untrusted-external span taints the session and the state names the span that set it', () => {
    const c = clock();
    const store = createSessionTaintLineage({ now: c.now });
    const s = host('sess-A');
    expect(store.state(s)).toEqual({ ok: true, state: { tainted: false, sessionId: 'sess-A' } });

    const r = store.ingest(s, web);
    expect(r.ok).toBe(true);
    expect(r).toMatchObject({
      decision: { taints: true, via: 'band' },
      state: {
        tainted: true, sessionId: 'sess-A', sinceMs: c.now(),
        origin: { route: 'ingest', spanId: 'span-web-1', band: 'untrusted-external' },
        lineageTruncated: 0,
      },
    });
    expect(store.size()).toBe(1);
  });

  it('a non-tainting span leaves a clean session clean and is not recorded', () => {
    const store = createSessionTaintLineage();
    const r = store.ingest(host('sess-B'), ownWords);
    expect(r).toMatchObject({ ok: true, state: { tainted: false }, decision: { taints: false } });
    expect(store.size()).toBe(0);
  });

  it('no TTL: the taint is still there thirty days later', () => {
    const c = clock();
    const store = createSessionTaintLineage({ now: c.now });
    const s = host('sess-C');
    store.ingest(s, web);
    c.advance(30 * 24 * 60 * 60 * 1000);
    expect(store.state(s)).toMatchObject({ ok: true, state: { tainted: true } });
  });

  it('no clear: the store exposes no clear/reset, and later trusted spans do not launder the taint', () => {
    const store = createSessionTaintLineage();
    const s = host('sess-D');
    store.ingest(s, web);
    expect(Object.keys(store).sort()).toEqual(
      ['endSession', 'ingest', 'inherit', 'memoryRecalled', 'memoryWritten', 'peerReturn', 'size', 'state'],
    );
    for (let i = 0; i < 5; i++) store.ingest(s, ownWords);
    expect(store.state(s)).toMatchObject({ ok: true, state: { tainted: true, origin: { spanId: 'span-web-1' } } });
  });

  it('a content-asserted identity is refused at every entry point and is never keyed', () => {
    const store = createSessionTaintLineage();
    const fake = content('sess-claimed-in-a-tool-result');
    const refused = { ok: false, refused: 'content-asserted-identity' };
    expect(store.ingest(fake, web)).toMatchObject(refused);
    expect(store.state(fake)).toMatchObject(refused);
    expect(store.inherit(host('child'), fake, 'inherit-fork')).toMatchObject(refused);
    expect(store.inherit(fake, host('parent'), 'inherit-fork')).toMatchObject(refused);
    expect(store.peerReturn(host('rx'), fake, web)).toMatchObject(refused);
    expect(store.peerReturn(fake, host('peer'), web)).toMatchObject(refused);
    expect(store.memoryWritten('mem-1', fake)).toMatchObject(refused);
    expect(store.memoryRecalled('mem-1', fake)).toMatchObject(refused);
    expect(store.endSession(fake)).toMatchObject(refused);
    expect(store.size()).toBe(0);
    // And the same id, once the HOST asserts it, is an ordinary clean session:
    // the refusal never created a shadow record either way.
    expect(store.state(host(fake.id))).toMatchObject({ ok: true, state: { tainted: false } });
  });

  it('a content-asserted identity cannot END a tainted host session (no laundering through the lifecycle door)', () => {
    const store = createSessionTaintLineage();
    const s = host('sess-E');
    store.ingest(s, web);
    expect(store.endSession(content('sess-E'))).toMatchObject({ ok: false, refused: 'content-asserted-identity' });
    expect(store.state(s)).toMatchObject({ ok: true, state: { tainted: true } });
  });

  it('an empty identity is refused', () => {
    const store = createSessionTaintLineage();
    expect(store.ingest(host(''), web)).toMatchObject({ ok: false, refused: 'empty-identity' });
    expect(store.state({ id: '', assertedBy: 'host' })).toMatchObject({ ok: false, refused: 'empty-identity' });
    expect(store.size()).toBe(0);
  });

  it('the host ending the session releases the record; a new session is a new identity', () => {
    const store = createSessionTaintLineage();
    const s = host('sess-F');
    store.ingest(s, web);
    expect(store.endSession(s)).toEqual({ ok: true });
    expect(store.size()).toBe(0);
    expect(store.state(s)).toMatchObject({ ok: true, state: { tainted: false } });
  });

  it('lineage is bounded: rows beyond the cap are counted, never silently dropped', () => {
    const store = createSessionTaintLineage();
    const s = host('sess-G');
    for (let i = 0; i < MAX_LINEAGE_ENTRIES + 6; i++) store.ingest(s, { label: 'web', spanId: `w${i}` });
    const r = store.state(s);
    expect(r.ok && r.state.tainted && r.state.lineage.length).toBe(MAX_LINEAGE_ENTRIES);
    expect(r.ok && r.state.tainted && r.state.lineageTruncated).toBe(6);
    expect(r.ok && r.state.tainted && r.state.origin.spanId).toBe('w0');
  });
});

describe('§2.2 — lifetime: taint is inherited by children, memory and peer returns', () => {
  it('a fork or spawn from a tainted parent is tainted, naming the parent and the route; from a clean parent it is clean', () => {
    const store = createSessionTaintLineage();
    const parent = host('parent');
    store.ingest(parent, web);
    expect(store.inherit(host('fork-1'), parent, 'inherit-fork')).toMatchObject({
      ok: true, state: { tainted: true, origin: { route: 'inherit-fork', fromSessionId: 'parent', spanId: 'span-web-1' } },
    });
    expect(store.inherit(host('spawn-1'), parent, 'inherit-spawn')).toMatchObject({
      ok: true, state: { tainted: true, origin: { route: 'inherit-spawn', fromSessionId: 'parent' } },
    });
    expect(store.inherit(host('child-of-clean'), host('clean-parent'), 'inherit-fork')).toMatchObject({
      ok: true, state: { tainted: false },
    });
  });

  it('inheritance is transitive: a grandchild of a tainted session is tainted', () => {
    const store = createSessionTaintLineage();
    store.ingest(host('g0'), web);
    store.inherit(host('g1'), host('g0'), 'inherit-spawn');
    expect(store.inherit(host('g2'), host('g1'), 'inherit-fork'))
      .toMatchObject({ ok: true, state: { tainted: true, origin: { fromSessionId: 'g1' } } });
  });

  it('ending the parent does not un-taint a child that already inherited', () => {
    const store = createSessionTaintLineage();
    store.ingest(host('p'), web);
    store.inherit(host('c'), host('p'), 'inherit-spawn');
    store.endSession(host('p'));
    expect(store.state(host('c'))).toMatchObject({ ok: true, state: { tainted: true } });
  });

  it('a memory written from a tainted session carries the marker; recalling it taints a fresh session via stored-memory', () => {
    const store = createSessionTaintLineage();
    const writer = host('writer');
    store.ingest(writer, web);
    expect(store.memoryWritten('mem-tainted', writer)).toEqual({ ok: true, tainted: true });

    const fresh = host('fresh');
    expect(store.state(fresh)).toMatchObject({ ok: true, state: { tainted: false } });
    expect(store.memoryRecalled('mem-tainted', fresh)).toMatchObject({
      ok: true,
      state: {
        tainted: true,
        origin: { route: 'memory-recall', band: 'stored-memory', memoryRef: 'mem-tainted', fromSessionId: 'writer', spanId: 'span-web-1' },
      },
    });
  });

  it('a memory written from a clean session carries no marker, and recalling it does not taint', () => {
    const store = createSessionTaintLineage();
    expect(store.memoryWritten('mem-clean', host('clean-writer'))).toEqual({ ok: true, tainted: false });
    expect(store.memoryRecalled('mem-clean', host('reader'))).toMatchObject({ ok: true, state: { tainted: false } });
  });

  it('a memory marker is never unset by a later clean write of the same reference', () => {
    const store = createSessionTaintLineage();
    store.ingest(host('w1'), web);
    store.memoryWritten('mem-x', host('w1'));
    expect(store.memoryWritten('mem-x', host('w2-clean'))).toEqual({ ok: true, tainted: true });
  });

  it('an empty memory reference is refused', () => {
    const store = createSessionTaintLineage();
    expect(store.memoryWritten('', host('w'))).toMatchObject({ ok: false, refused: 'empty-identity' });
  });

  it('a return from a peer whose session is tainted IN THE STORE taints the receiver, even signature-verified', () => {
    const store = createSessionTaintLineage();
    const peer = host('peer');
    store.ingest(peer, web);
    const signed: SpanProvenance = { label: 'agent_message', attestation: 'host', signatureVerified: true, spanId: 'reply-1' };
    expect(spanTaints(signed).taints).toBe(false); // the envelope alone would not
    expect(store.peerReturn(host('rx'), peer, signed)).toMatchObject({
      ok: true,
      state: { tainted: true, origin: { route: 'peer-return', fromSessionId: 'peer', band: 'signed-peer', spanId: 'reply-1' } },
    });
  });

  it('a return from a clean peer taints only when the span itself does (external lineage or band)', () => {
    const store = createSessionTaintLineage();
    const signed: SpanProvenance = { label: 'agent_message', attestation: 'host', signatureVerified: true };
    expect(store.peerReturn(host('rx1'), host('clean-peer'), signed)).toMatchObject({ ok: true, state: { tainted: false } });
    expect(store.peerReturn(host('rx2'), host('clean-peer'), { ...signed, lineage: { carriesExternalContent: true } }))
      .toMatchObject({ ok: true, state: { tainted: true, origin: { route: 'peer-return' } } });
    expect(store.peerReturn(host('rx3'), host('clean-peer'), { label: 'agent_message' }))
      .toMatchObject({ ok: true, state: { tainted: true, origin: { band: 'untrusted-external' } } });
  });

  it('taint records are per session: one tainted session does not taint an unrelated one', () => {
    const store = createSessionTaintLineage();
    store.ingest(host('x'), web);
    expect(store.state(host('y'))).toMatchObject({ ok: true, state: { tainted: false } });
  });
});
