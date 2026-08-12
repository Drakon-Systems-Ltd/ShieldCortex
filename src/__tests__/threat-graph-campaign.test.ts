/**
 * Phase D — campaign detection (design doc Loop 4).
 *
 * Clusters CAUGHT events (attribution: "these blocks across three sessions are
 * one actor"), NOT quiet successful campaigns. JS union-find over shared
 * pivots (source / session / non-hub pattern). Pivot-quality rules:
 *  - a pattern tripped by > hubThreshold distinct sources is a HUB, excluded
 *    as a connector (co-tripping credential_exfil is not a campaign);
 *  - entity_ref links corroborate confidence but never form membership on
 *    their own (invariant 5);
 *  - a component qualifies only when it spans ≥2 sources OR ≥2 sessions.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { clusterEvents, runCampaignDetection, type CampaignEvent } from '../threat-graph/campaign.js';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { canonicalDump, projectToCompletion, rebuildThreatGraph } from '../threat-graph/projector.js';

function ev(id: number, source: string | null, session: string | null, patterns: string[] = [], entities: string[] = []): CampaignEvent {
  return { id, source, session, patterns, entities };
}

const OPTS = { hubThreshold: 10 };

describe('clusterEvents', () => {
  it('clusters one source across ≥2 sessions (attribution)', () => {
    const groups = clusterEvents([
      ev(1, 'agent:jarvis', 'sess-a', ['instruction_injection']),
      ev(2, 'agent:jarvis', 'sess-b', ['instruction_injection']),
    ], OPTS);
    expect(groups).toHaveLength(1);
    expect(groups[0].members.sort()).toEqual([1, 2]);
    expect(groups[0].sessions.sort()).toEqual(['sess-a', 'sess-b']);
  });

  it('clusters ≥2 sources sharing a session (coordination)', () => {
    const groups = clusterEvents([
      ev(1, 'agent:a', 'sess-x', ['p1']),
      ev(2, 'agent:b', 'sess-x', ['p2']),
    ], OPTS);
    expect(groups).toHaveLength(1);
    expect(groups[0].sources.sort()).toEqual(['agent:a', 'agent:b']);
  });

  it('clusters ≥2 sources sharing a rare (non-hub) pattern', () => {
    const groups = clusterEvents([
      ev(1, 'agent:a', 'sess-1', ['rare_pattern']),
      ev(2, 'agent:b', 'sess-2', ['rare_pattern']),
    ], OPTS);
    expect(groups).toHaveLength(1);
    expect(groups[0].sources.sort()).toEqual(['agent:a', 'agent:b']);
    expect(groups[0].patterns).toContain('rare_pattern');
  });

  it('does NOT cluster two sources whose only shared pattern is a HUB', () => {
    // credential_exfil tripped by 12 distinct sources → hub, not a connector.
    const events: CampaignEvent[] = [];
    for (let i = 0; i < 12; i++) events.push(ev(i + 1, `agent:s${i}`, `sess-${i}`, ['credential_exfil']));
    const groups = clusterEvents(events, { hubThreshold: 10 });
    // No qualifying campaign — the only link is the hub pattern.
    expect(groups).toHaveLength(0);
  });

  it('does NOT qualify a single source in a single session', () => {
    const groups = clusterEvents([
      ev(1, 'agent:solo', 'sess-1', ['p1']),
      ev(2, 'agent:solo', 'sess-1', ['p1']),
    ], OPTS);
    expect(groups).toHaveLength(0);
  });

  it('does NOT form a campaign from entity_ref links alone (invariant 5)', () => {
    // Two unrelated sources/sessions that only share a mentioned entity.
    const groups = clusterEvents([
      ev(1, 'agent:a', 'sess-1', [], ['entity:server.ts']),
      ev(2, 'agent:b', 'sess-2', [], ['entity:server.ts']),
    ], OPTS);
    expect(groups).toHaveLength(0);
  });

  it('records entity overlap as confidence when a real link also exists', () => {
    const groups = clusterEvents([
      ev(1, 'agent:a', 'sess-x', ['rare'], ['entity:key']),
      ev(2, 'agent:b', 'sess-x', ['rare'], ['entity:key']),
    ], OPTS);
    expect(groups).toHaveLength(1);
    expect(groups[0].entityOverlap).toBe(true);
  });

  it('does NOT merge pooled conversation:<hook> sources into a mega-campaign', () => {
    // The blocker: every conversation detection shares source conversation:llm_input.
    // Pooled sources are categories, not actors — they must never connect.
    const events: CampaignEvent[] = [];
    for (let i = 0; i < 8; i++) events.push(ev(i + 1, 'conversation:llm_input', `sess-${i}`, []));
    expect(clusterEvents(events, OPTS)).toHaveLength(0);
  });

  it('does NOT merge the overflow-bucket source (no shared pattern to bridge)', () => {
    // Distinct patterns per event, so the ONLY potential connector is the
    // pooled overflow source — which must not connect. (A shared rare pattern
    // would legitimately bridge them, so each event gets its own pattern here.)
    const events: CampaignEvent[] = [];
    for (let i = 0; i < 8; i++) events.push(ev(i + 1, 'overflow', `sess-${i}`, [`p${i}`]));
    expect(clusterEvents(events, OPTS)).toHaveLength(0);
  });

  it('hub-excludes a session shared by ≥hubThreshold distinct sources', () => {
    // 10 distinct sources all in one session → that session is a shared bus.
    const events: CampaignEvent[] = [];
    for (let i = 0; i < 10; i++) events.push(ev(i + 1, `agent:s${i}`, 'sess-bus', []));
    expect(clusterEvents(events, { hubThreshold: 10 })).toHaveLength(0);
  });

  it('hub boundary is inclusive: exactly hubThreshold sources on a pattern do NOT cluster; one fewer does', () => {
    const exactly = Array.from({ length: 10 }, (_, i) => ev(i + 1, `agent:s${i}`, `sess-${i}`, ['shared_p']));
    expect(clusterEvents(exactly, { hubThreshold: 10 })).toHaveLength(0);
    const oneFewer = Array.from({ length: 9 }, (_, i) => ev(i + 1, `agent:s${i}`, `sess-${i}`, ['shared_p']));
    const groups = clusterEvents(oneFewer, { hubThreshold: 10 });
    expect(groups).toHaveLength(1);
    expect(groups[0].sources).toHaveLength(9);
  });

  it('ranks the most significant campaign first (breadth over recency)', () => {
    const groups = clusterEvents([
      ev(1, 'agent:a', 'sess-1', ['pa']), ev(2, 'agent:b', 'sess-1', ['pa']), // small: 2 sources
      ev(3, 'agent:c', 'sess-9', ['pz']), ev(4, 'agent:d', 'sess-9', ['pz']),
      ev(5, 'agent:e', 'sess-9', ['pz']),                                     // bigger: 3 sources
    ], OPTS);
    expect(groups[0].sources.length).toBeGreaterThanOrEqual(groups[1].sources.length);
  });

  it('keeps distinct campaigns separate', () => {
    const groups = clusterEvents([
      ev(1, 'agent:a', 'sess-1', ['pa']),
      ev(2, 'agent:b', 'sess-1', ['pa']),   // campaign 1 via sess-1
      ev(3, 'agent:c', 'sess-9', ['pz']),
      ev(4, 'agent:d', 'sess-9', ['pz']),   // campaign 2 via sess-9
    ], OPTS);
    expect(groups).toHaveLength(2);
  });
});

describe('runCampaignDetection (DB)', () => {
  beforeEach(() => initDatabase(':memory:'));
  afterEach(() => closeDatabase());

  function insertBlock(identifier: string, ts: string, pattern: string): void {
    getDatabase().prepare(`
      INSERT INTO defence_audit (project, timestamp, source_type, source_identifier,
        trust_score, sensitivity_level, firewall_result, anomaly_score,
        threat_indicators, blocked_patterns, source_attested)
      VALUES ('test', ?, 'agent', ?, 0.8, 'INTERNAL', 'BLOCK', 0, '[]', ?, 1)
    `).run(ts, identifier, JSON.stringify([pattern]));
  }

  const NOW = Date.parse('2026-08-12T12:00:00.000Z');

  it('mints a campaign node + part_of edges for two sources sharing a rare pattern', () => {
    insertBlock('actor-a', '2026-08-11T10:00:00.000Z', 'rare_injection');
    insertBlock('actor-b', '2026-08-11T11:00:00.000Z', 'rare_injection');
    projectToCompletion();
    const result = runCampaignDetection({ nowMs: NOW });
    expect(result.campaigns).toBe(1);

    const db = getDatabase();
    const camp = db.prepare("SELECT * FROM threat_nodes WHERE kind = 'campaign'").get() as any;
    expect(camp).toBeDefined();
    const attrs = JSON.parse(camp.attrs);
    expect(attrs.sources.sort()).toEqual(['agent:actor-a', 'agent:actor-b']);
    expect(attrs.size).toBe(2);

    const partOf = db.prepare("SELECT COUNT(*) AS c FROM threat_edges WHERE predicate = 'part_of'").get() as { c: number };
    expect(partOf.c).toBe(2);
  });

  it('excludes events outside the window', () => {
    insertBlock('actor-a', '2026-07-01T00:00:00.000Z', 'rare_injection'); // >7d old
    insertBlock('actor-b', '2026-08-11T11:00:00.000Z', 'rare_injection');
    projectToCompletion();
    const result = runCampaignDetection({ nowMs: NOW, windowMs: 7 * 24 * 60 * 60 * 1000 });
    expect(result.campaigns).toBe(0); // only one in-window event
  });

  it('is idempotent — a second run yields the same single campaign', () => {
    insertBlock('actor-a', '2026-08-11T10:00:00.000Z', 'rare_injection');
    insertBlock('actor-b', '2026-08-11T11:00:00.000Z', 'rare_injection');
    projectToCompletion();
    runCampaignDetection({ nowMs: NOW });
    const key1 = (getDatabase().prepare("SELECT key FROM threat_nodes WHERE kind = 'campaign'").get() as { key: string }).key;
    runCampaignDetection({ nowMs: NOW });
    const rows = getDatabase().prepare("SELECT key FROM threat_nodes WHERE kind = 'campaign'").all() as Array<{ key: string }>;
    expect(rows).toHaveLength(1);
    expect(rows[0].key).toBe(key1);
  });

  it('records a truncation note when more campaigns qualify than the cap', () => {
    // 3 distinct 2-source campaigns, cap of 2 → one truncated.
    for (const [a, b, p] of [['a1', 'a2', 'p1'], ['b1', 'b2', 'p2'], ['c1', 'c2', 'p3']]) {
      insertBlock(a, '2026-08-11T10:00:00.000Z', p);
      insertBlock(b, '2026-08-11T11:00:00.000Z', p);
    }
    projectToCompletion();
    const result = runCampaignDetection({ nowMs: NOW, maxCampaigns: 2 });
    expect(result.campaigns).toBe(2);
    expect(result.truncated).toMatch(/cap/i);
  });

  it('campaign nodes/part_of edges are excluded from the determinism dump', () => {
    insertBlock('actor-a', '2026-08-11T10:00:00.000Z', 'rare_injection');
    insertBlock('actor-b', '2026-08-11T11:00:00.000Z', 'rare_injection');
    projectToCompletion();
    const before = canonicalDump();
    runCampaignDetection({ nowMs: NOW });
    // The dump is unchanged by campaign minting; a rebuild still matches it.
    expect(canonicalDump()).toBe(before);
    rebuildThreatGraph();
    expect(canonicalDump()).toBe(before);
  });
});
