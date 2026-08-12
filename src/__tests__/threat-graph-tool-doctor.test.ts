/**
 * Threat Graph — Phase A.3: MCP query tool, doctor check, config gate.
 *
 *  - The tool is bounded from day one (hard row cap + byte cap with an
 *    explicit truncation marker) — the unbounded-output bug fixed in
 *    graph_query in Phase 0 does not get reintroduced by its successor.
 *  - The doctor check makes a dead projector a finding instead of a silent
 *    regression: invariant 4's "stale means no modifier" is fail-safe but
 *    invisible by construction.
 *  - threatGraph.enabled defaults to ON; an explicit false disables.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { projectToCompletion } from '../threat-graph/projector.js';
import { handleThreatGraphQuery } from '../tools/threat-graph.js';
import { checkThreatGraph } from '../cli/doctor.js';
import { isThreatGraphEnabled } from '../cloud/config.js';

function insertAuditRow(seed: {
  verdict?: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  identifier?: string;
  patterns?: string[];
  project?: string;
  timestamp?: string;
} = {}): void {
  getDatabase().prepare(`
    INSERT INTO defence_audit (
      project, timestamp, source_type, source_identifier, trust_score,
      sensitivity_level, firewall_result, anomaly_score, threat_indicators, blocked_patterns
    ) VALUES (@project, @timestamp, 'agent', @identifier, 0.8,
      'INTERNAL', @verdict, 0, '[]', @patterns)
  `).run({
    project: seed.project ?? 'test',
    timestamp: seed.timestamp ?? '2026-08-01T10:00:00.000Z',
    identifier: seed.identifier ?? 'jarvis',
    verdict: seed.verdict ?? 'ALLOW',
    patterns: JSON.stringify(seed.patterns ?? []),
  });
}

function payload(result: { content: Array<{ text: string }> }): any {
  return JSON.parse(result.content[0].text);
}

beforeEach(() => {
  initDatabase(':memory:');
});

afterEach(() => {
  closeDatabase();
});

describe('threat_graph MCP tool', () => {
  it('lists sources with parsed attrs', () => {
    insertAuditRow({ identifier: 'jarvis', verdict: 'BLOCK' });
    insertAuditRow({ identifier: 'researcher' });
    projectToCompletion();

    const out = payload(handleThreatGraphQuery({ view: 'sources' }));
    const keys = out.sources.map((s: any) => s.key).sort();
    expect(keys).toEqual(['agent:jarvis', 'agent:researcher']);
    const jarvis = out.sources.find((s: any) => s.key === 'agent:jarvis');
    expect(jarvis.attrs.block_count).toBe(1);
  });

  it('shows a single source with its triggered patterns and recent events', () => {
    insertAuditRow({ verdict: 'BLOCK', patterns: ['credential_exfil'] });
    insertAuditRow({ patterns: ['credential_exfil'], timestamp: '2026-08-02T10:00:00.000Z' });
    projectToCompletion();

    const out = payload(handleThreatGraphQuery({ view: 'source', key: 'agent:jarvis' }));
    expect(out.source.key).toBe('agent:jarvis');
    expect(out.patterns).toContainEqual(expect.objectContaining({ key: 'credential_exfil', count: 2 }));
    expect(out.events.length).toBe(1);
    expect(out.events[0].attrs.verdict).toBe('BLOCK');
  });

  it('filters events by project', () => {
    insertAuditRow({ verdict: 'BLOCK', project: 'alpha' });
    insertAuditRow({ verdict: 'BLOCK', project: 'beta', identifier: 'other' });
    projectToCompletion();

    const out = payload(handleThreatGraphQuery({ view: 'events', project: 'alpha' }));
    expect(out.events.length).toBe(1);
    expect(out.events[0].attrs.project).toBe('alpha');
  });

  it('clamps limit to the hard row cap', () => {
    insertAuditRow();
    projectToCompletion();
    const out = payload(handleThreatGraphQuery({ view: 'sources', limit: 99_999 }));
    expect(out.limit).toBeLessThanOrEqual(200);
  });

  it('truncates oversized responses with an explicit marker', () => {
    for (let i = 0; i < 30; i++) {
      insertAuditRow({ verdict: 'BLOCK', identifier: `agent-${i}` });
    }
    projectToCompletion();
    const out = payload(handleThreatGraphQuery({ view: 'events' }, { byteCap: 2_000 }));
    expect(out.truncated).toBe(true);
    expect(out.events.length).toBeLessThan(30);
  });

  it('returns an error payload for an unknown source key', () => {
    const out = payload(handleThreatGraphQuery({ view: 'source', key: 'agent:nobody' }));
    expect(out.error).toContain('agent:nobody');
  });
});

describe('doctor checkThreatGraph', () => {
  it('passes on a healthy, caught-up projector', async () => {
    insertAuditRow();
    projectToCompletion();
    const result = await checkThreatGraph();
    expect(result.status).toBe('pass');
  });

  it('passes with nothing to project (fresh install)', async () => {
    const result = await checkThreatGraph();
    expect(result.status).toBe('pass');
  });

  it('warns when the projector lags the ledger', async () => {
    for (let i = 0; i < 5; i++) insertAuditRow();
    // Projector never ran: state row absent or cursor 0 while rows exist.
    const result = await checkThreatGraph({ lagWarnThreshold: 3 });
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/lag|behind/i);
  });

  it('reports info, not warn, when the feature is disabled by config', async () => {
    for (let i = 0; i < 50; i++) insertAuditRow(); // lag that would otherwise WARN
    const result = await checkThreatGraph({ lagWarnThreshold: 3, enabled: false });
    expect(result.status).toBe('info');
    expect(result.message).toContain('disabled');
  });

  it('warns when the last run recorded an error', async () => {
    insertAuditRow();
    projectToCompletion();
    getDatabase().prepare("UPDATE threat_graph_state SET last_error = 'event cap reached' WHERE id = 1").run();
    const result = await checkThreatGraph();
    expect(result.status).toBe('warn');
    expect(result.message).toContain('event cap reached');
  });
});

describe('threatGraph config gate', () => {
  it('defaults to enabled', () => {
    expect(isThreatGraphEnabled({})).toBe(true);
    expect(isThreatGraphEnabled({ threatGraph: {} })).toBe(true);
  });

  it('disables only on explicit false', () => {
    expect(isThreatGraphEnabled({ threatGraph: { enabled: false } })).toBe(false);
    expect(isThreatGraphEnabled({ threatGraph: { enabled: true } })).toBe(true);
  });
});
