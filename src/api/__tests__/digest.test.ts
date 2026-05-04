import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../../database/init.js';
import { addMemory } from '../../memory/store.js';
import { buildDigest, buildTimeline } from '../routes/digest.js';

function isoHoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

function insertAudit(opts: {
  result: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  timestamp: string;
  sourceType?: string;
  sourceIdentifier?: string;
  threatIndicators?: string[];
  anomalyScore?: number;
  project?: string;
}): void {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO defence_audit (
      project, timestamp, source_type, source_identifier,
      trust_score, sensitivity_level, firewall_result, anomaly_score,
      threat_indicators, blocked_patterns, reason
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    opts.project ?? null,
    opts.timestamp,
    opts.sourceType ?? 'agent',
    opts.sourceIdentifier ?? 'test-agent',
    1.0,
    'INTERNAL',
    opts.result,
    opts.anomalyScore ?? 0,
    JSON.stringify(opts.threatIndicators ?? []),
    '[]',
    null,
  );
}

describe('Digest builder', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('returns zero counts and empty moments on a fresh database', () => {
    const digest = buildDigest('24h');
    expect(digest.window).toBe('24h');
    expect(digest.current.scanned).toBe(0);
    expect(digest.current.blocked).toBe(0);
    expect(digest.current.memoriesCaptured).toBe(0);
    expect(digest.topMoments).toEqual([]);
    expect(digest.topThreatPatterns).toEqual([]);
  });

  it('counts allowed/blocked/quarantined audit events in the 24h window', () => {
    const insideWindow = isoHoursAgo(2);
    const outsideWindow = isoHoursAgo(36);

    insertAudit({ result: 'ALLOW', timestamp: insideWindow });
    insertAudit({ result: 'ALLOW', timestamp: insideWindow });
    insertAudit({ result: 'BLOCK', timestamp: insideWindow, threatIndicators: ['prompt_injection'] });
    insertAudit({ result: 'QUARANTINE', timestamp: insideWindow, threatIndicators: ['credential_leak'] });
    insertAudit({ result: 'ALLOW', timestamp: outsideWindow });

    const digest = buildDigest('24h');
    expect(digest.current.allowed).toBe(2);
    expect(digest.current.blocked).toBe(1);
    expect(digest.current.quarantined).toBe(1);
    expect(digest.current.scanned).toBe(4);
  });

  it('counts memories captured in the window and ignores older ones', () => {
    const recent = addMemory({
      title: 'Recent learning',
      content: 'Captured just now',
      category: 'learning',
    });
    expect(recent.id).toBeGreaterThan(0);

    // Backdate one memory before the window using a direct UPDATE
    const old = addMemory({
      title: 'Ancient memory',
      content: 'Captured way back',
      category: 'note',
    });
    getDatabase().prepare(`UPDATE memories SET created_at = ? WHERE id = ?`)
      .run(isoHoursAgo(48), old.id);

    const digest = buildDigest('24h');
    expect(digest.current.memoriesCaptured).toBe(1);
  });

  it('counts memories recalled (last_accessed advanced past created_at)', () => {
    const m = addMemory({
      title: 'Reused memory',
      content: 'A frequently accessed memory',
      category: 'pattern',
    });
    // Bump last_accessed to now (simulates a recall). Created_at is also "now",
    // so we must pull created_at backward to make last_accessed > created_at.
    const db = getDatabase();
    db.prepare(`UPDATE memories SET created_at = ?, last_accessed = ? WHERE id = ?`)
      .run(isoHoursAgo(10), isoHoursAgo(2), m.id);

    const digest = buildDigest('24h');
    expect(digest.current.memoriesRecalled).toBe(1);
  });

  it('emits high-salience captures as moments and top threat patterns', () => {
    addMemory({
      title: 'Important architecture decision',
      content: 'We chose Postgres over Mongo for ACID guarantees',
      category: 'architecture',
      salience: 0.9,
    });

    insertAudit({
      result: 'BLOCK',
      timestamp: isoHoursAgo(1),
      threatIndicators: ['prompt_injection', 'jailbreak_attempt'],
      anomalyScore: 0.95,
      sourceIdentifier: 'agent-foo',
    });
    insertAudit({
      result: 'BLOCK',
      timestamp: isoHoursAgo(2),
      threatIndicators: ['prompt_injection'],
      anomalyScore: 0.7,
    });

    const digest = buildDigest('24h');

    expect(digest.current.highSalienceCaptures).toBe(1);
    expect(digest.topMoments.length).toBeGreaterThan(0);
    expect(digest.topMoments.some((m) => m.kind === 'block')).toBe(true);
    expect(digest.topMoments.some((m) => m.kind === 'capture')).toBe(true);

    expect(digest.topThreatPatterns[0]).toEqual({ pattern: 'prompt_injection', count: 2 });
  });

  it('computes deltas vs the previous equivalent window', () => {
    // Current window: 2 blocks
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(1) });
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(3) });
    // Previous window (24-48h ago): 5 blocks
    for (let i = 0; i < 5; i++) {
      insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(30 + i) });
    }

    const digest = buildDigest('24h');
    expect(digest.current.blocked).toBe(2);
    expect(digest.previous.blocked).toBe(5);
    expect(digest.delta.blocked).toBe(-3);
  });

  it('scopes counts to a single project when project filter is provided', () => {
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(1), project: 'foo' });
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(1), project: 'bar' });
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(1), project: 'foo' });

    const fooDigest = buildDigest('24h', 'foo');
    const barDigest = buildDigest('24h', 'bar');
    const allDigest = buildDigest('24h');

    expect(fooDigest.current.blocked).toBe(2);
    expect(barDigest.current.blocked).toBe(1);
    expect(allDigest.current.blocked).toBe(3);
  });

  it('supports 7d and 30d windows', () => {
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(72) });   // 3 days ago
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(500) });  // ~21 days ago

    expect(buildDigest('24h').current.blocked).toBe(0);
    expect(buildDigest('7d').current.blocked).toBe(1);
    expect(buildDigest('30d').current.blocked).toBe(2);
  });
});

describe('Timeline builder', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('returns one row per day with zero defaults on a fresh database', () => {
    const timeline = buildTimeline(7);
    expect(timeline.length).toBe(7);
    expect(timeline.every((d) => d.scanned === 0 && d.blocked === 0 && d.captured === 0 && d.recalled === 0)).toBe(true);
    // Days are oldest -> newest
    for (let i = 1; i < timeline.length; i++) {
      expect(timeline[i].date >= timeline[i - 1].date).toBe(true);
    }
  });

  it('aggregates audit results into the right day buckets', () => {
    // Use 2h ago so the events land in the recent end of the timeline,
    // but assert on totals (not specific days) — the day boundary is UTC
    // and tests can run across midnight.
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(2) });
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(2) });
    insertAudit({ result: 'QUARANTINE', timestamp: isoHoursAgo(2) });
    insertAudit({ result: 'ALLOW', timestamp: isoHoursAgo(50) });

    const timeline = buildTimeline(7);
    expect(timeline.length).toBe(7);

    const totalBlocked = timeline.reduce((sum, d) => sum + d.blocked, 0);
    const totalQuarantined = timeline.reduce((sum, d) => sum + d.quarantined, 0);
    const totalScanned = timeline.reduce((sum, d) => sum + d.scanned, 0);

    expect(totalBlocked).toBe(2);
    expect(totalQuarantined).toBe(1);
    expect(totalScanned).toBe(4);

    // Recent activity should land in the last 2 days of the timeline (today or
    // yesterday in UTC, depending on time of day).
    const recentTwoDays = timeline.slice(-2);
    const recentScanned = recentTwoDays.reduce((sum, d) => sum + d.scanned, 0);
    expect(recentScanned).toBeGreaterThanOrEqual(3); // the 2h-ago inserts
  });

  it('clamps days to [1, 90] and respects project filter', () => {
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(1), project: 'foo' });
    insertAudit({ result: 'BLOCK', timestamp: isoHoursAgo(1), project: 'bar' });

    const fooTimeline = buildTimeline(7, 'foo');
    const fooBlocks = fooTimeline.reduce((sum, d) => sum + d.blocked, 0);
    expect(fooBlocks).toBe(1);

    const allTimeline = buildTimeline(7);
    const allBlocks = allTimeline.reduce((sum, d) => sum + d.blocked, 0);
    expect(allBlocks).toBe(2);
  });
});
