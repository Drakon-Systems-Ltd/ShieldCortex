import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { PROJECTOR_VERSION, runProjectorWithLease } from '../threat-graph/projector.js';

describe('#320 lease version-mismatch snapshot', () => {
  beforeEach(() => initDatabase(':memory:'));
  afterEach(() => closeDatabase());

  it('reseeds a higher snapshot after the mismatch drain completes', async () => {
    const db = getDatabase();
    const now = '2026-08-16T00:00:00.000Z';
    db.prepare(`
      INSERT INTO defence_audit (
        memory_id, project, timestamp, source_type, source_identifier,
        trust_score, sensitivity_level, firewall_result,
        anomaly_score, threat_indicators, blocked_patterns,
        reason, fragmentation_score, pipeline_duration_ms, source_attested
      ) VALUES (NULL, 'test', ?, 'agent', 'bump-src', 0.2, 'PUBLIC', 'BLOCK', 0, '[]', '[]', NULL, NULL, 0, 1)
    `).run(now);

    await runProjectorWithLease({ now: Date.parse(now) });

    const before = db.prepare("SELECT attrs FROM threat_nodes WHERE kind='source' AND key='agent:bump-src'")
      .get() as { attrs: string };
    const attrs = JSON.parse(before.attrs) as { risk_sum: number; risk_ref_ts: string };
    expect(attrs.risk_sum).toBeGreaterThan(0);

    // Inflate the incremental sum, then force a version-mismatch rebuild.
    attrs.risk_sum = attrs.risk_sum + 5;
    db.prepare("UPDATE threat_nodes SET attrs = ? WHERE kind='source' AND key='agent:bump-src'")
      .run(JSON.stringify(attrs));
    db.prepare('UPDATE threat_graph_state SET projector_version = ? WHERE id = 1')
      .run(PROJECTOR_VERSION - 1);

    await runProjectorWithLease({ now: Date.parse(now) });

    const pending = db.prepare('SELECT rebuild_pending FROM threat_graph_state WHERE id = 1')
      .get() as { rebuild_pending: string | null };
    expect(pending.rebuild_pending).toBeNull();

    const after = db.prepare("SELECT attrs FROM threat_nodes WHERE kind='source' AND key='agent:bump-src'")
      .get() as { attrs: string };
    const afterAttrs = JSON.parse(after.attrs) as { risk_sum: number };
    expect(afterAttrs.risk_sum).toBeGreaterThanOrEqual(5);
  });
});
