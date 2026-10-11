import { describe, expect, it } from '@jest/globals';
import { checkRecallLanePin } from '../cli/doctor.js';

/**
 * #722 review (non-blocking a): lane detection only sees markers written by
 * OpenClaw's prompt builders. Doctor names the SHIELDCORTEX_RECALL_LANE pin for
 * jobs launched by other schedulers, and flags a pin the hook would ignore.
 */
describe('doctor — recall lane pin (#722)', () => {
  it('unset: names the env pin for schedulers outside OpenClaw', () => {
    const r = checkRecallLanePin({});
    expect(r.status).toBe('info');
    expect(r.message).toContain('SHIELDCORTEX_RECALL_LANE=cron');
    expect(r.message).toMatch(/systemd|crontab/);
  });

  it('valid pin: reports it, case-insensitively', () => {
    const r = checkRecallLanePin({ SHIELDCORTEX_RECALL_LANE: ' Cron ' });
    expect(r).toMatchObject({ status: 'info' });
    expect(r.message).toContain('"cron"');
  });

  it('invalid pin: WARN, naming the fail-safe the hook applies (#722 R4)', () => {
    const r = checkRecallLanePin({ SHIELDCORTEX_RECALL_LANE: 'nightly' });
    expect(r.status).toBe('warn');
    expect(r.message).toContain('"nightly"');
    expect(r.message).toContain('automation');
    expect(r.message).not.toContain('ignored');
    expect(r.fix).toContain('interactive, cron, automation, subagent');
  });
});
