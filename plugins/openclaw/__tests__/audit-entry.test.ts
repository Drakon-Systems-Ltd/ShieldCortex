import { toAuditEntry } from '../audit-entry.js';

describe('toAuditEntry — interceptor', () => {
  it('builds a full canonical entry from a rich interceptor record', () => {
    const e = toAuditEntry({
      kind: 'intercept', tool: 'mcp__memory__remember', firewallResult: 'BLOCK',
      threats: ['credential_leak'], anomalyScore: 0.9, trustScore: 0.1,
      sensitivityLevel: 'RESTRICTED', fragmentationScore: 0.2, outcome: 'auto_denied',
      pipelineDurationMs: 12, ts: '2026-06-11T06:00:00.000Z',
    })!;
    expect(e.source_type).toBe('openclaw-interceptor');
    expect(e.source_identifier).toBe('mcp__memory__remember');
    expect(e.firewall_result).toBe('BLOCK');
    expect(e.trust_score).toBe(0.1);
    expect(e.sensitivity_level).toBe('RESTRICTED');
    expect(e.anomaly_score).toBe(0.9);
    expect(e.fragmentation_score).toBe(0.2);
    expect(e.threat_indicators).toEqual(['credential_leak']);
    expect(e.pipeline_duration_ms).toBe(12);
    expect(e.timestamp).toBe('2026-06-11T06:00:00.000Z');
  });
  it('defaults missing fields (no anomaly → QUARANTINE fallback, trust 1, fragmentation null)', () => {
    const e = toAuditEntry({ kind: 'intercept', tool: 'remember' })!;
    expect(e.firewall_result).toBe('QUARANTINE');
    expect(e.anomaly_score).toBe(0);
    expect(e.trust_score).toBe(1);
    expect(e.threat_indicators).toEqual([]);
    expect(e.fragmentation_score).toBeNull();
  });
  it('clamps fragmentation_score into [0,1]', () => {
    expect(toAuditEntry({ kind: 'intercept', tool: 't', fragmentationScore: 1.5 })!.fragmentation_score).toBe(1);
    expect(toAuditEntry({ kind: 'intercept', tool: 't', fragmentationScore: -0.3 })!.fragmentation_score).toBe(0);
    expect(toAuditEntry({ kind: 'intercept', tool: 't' })!.fragmentation_score).toBeNull();
  });
  it('normalizes an offset-form timestamp to UTC Z-form', () => {
    const e = toAuditEntry({ kind: 'intercept', tool: 't', ts: '2026-06-11T06:00:00+01:00' })!;
    expect(e.timestamp).toMatch(/Z$/);
    expect(e.timestamp).toBe(new Date('2026-06-11T06:00:00+01:00').toISOString());
  });
});

describe('toAuditEntry — realtime', () => {
  it('builds a QUARANTINE entry with conservative defaults', () => {
    const e = toAuditEntry({ kind: 'realtime', hook: 'llm_input', model: 'claude', reason: 'prompt injection', ts: '2026-06-11T06:01:00.000Z' })!;
    expect(e.source_type).toBe('llm_input');
    expect(e.source_identifier).toBe('claude');
    expect(e.firewall_result).toBe('QUARANTINE');
    expect(e.trust_score).toBe(0.5);
    expect(e.reason).toBe('prompt injection');
  });
  it('never includes content/preview', () => {
    const e = toAuditEntry({ kind: 'realtime', hook: 'llm_input', reason: 'x', preview: 'SECRET', content: 'SECRET' } as never)!;
    expect(JSON.stringify(e)).not.toContain('SECRET');
  });
  it('falls back source_identifier to sessionId then "openclaw"', () => {
    expect(toAuditEntry({ kind: 'realtime', hook: 'h', sessionId: 's', reason: 'r' })!.source_identifier).toBe('s');
    expect(toAuditEntry({ kind: 'realtime', reason: 'r' })!.source_identifier).toBe('openclaw');
  });
  it('supplies a valid UTC Z-form ISO timestamp when missing/invalid', () => {
    const e = toAuditEntry({ kind: 'realtime', reason: 'r', ts: 'not-a-date' })!;
    expect(Number.isNaN(new Date(e.timestamp).getTime())).toBe(false);
    expect(e.timestamp).toMatch(/Z$/);
  });
});
