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

  /**
   * #729: "automation (no recall)" was absolute, but the hook still recalls
   * PUBLIC rows on the automation lane when recallLanes.automation.recall is
   * true. The WARN now names the default and the opt-in exception; severity,
   * fix and the absent/valid rows are unchanged, and nothing advises opting in.
   */
  it('invalid pin: WARN states the automation default and its PUBLIC-only opt-in exception (#729)', () => {
    const r = checkRecallLanePin({ SHIELDCORTEX_RECALL_LANE: ' nightly ' });
    expect(r).toEqual({
      label: 'Recall lane',
      status: 'warn',
      message: 'SHIELDCORTEX_RECALL_LANE="nightly" is not a lane — prompt recall treats every turn in this environment '
        + 'as automation until it is fixed (no recall by default; PUBLIC rows only if recallLanes.automation.recall is true)',
      fix: 'Set SHIELDCORTEX_RECALL_LANE to one of: interactive, cron, automation, subagent',
    });
    expect(r.message).not.toContain('automation (no recall)');
    expect(r.fix).not.toContain('recallLanes');
  });

  it('absent / blank pin: output unchanged, no opt-in advice (#729)', () => {
    const expected = {
      label: 'Recall lane',
      status: 'info',
      message: 'detected from OpenClaw prompt markers. Jobs launched by another scheduler (systemd, crontab, CI) '
        + 'carry no marker and recall as interactive — set SHIELDCORTEX_RECALL_LANE=cron (or automation) in that job\'s environment.',
    };
    expect(checkRecallLanePin({})).toEqual(expected);
    expect(checkRecallLanePin({ SHIELDCORTEX_RECALL_LANE: '   ' })).toEqual(expected);
    expect(checkRecallLanePin({}).message).not.toContain('recallLanes');
  });

  it.each(['interactive', 'cron', 'automation', 'subagent'])('valid pin %s: output unchanged (#729)', (lane) => {
    expect(checkRecallLanePin({ SHIELDCORTEX_RECALL_LANE: lane.toUpperCase() })).toEqual({
      label: 'Recall lane',
      status: 'info',
      message: `pinned to "${lane}" by SHIELDCORTEX_RECALL_LANE in this environment`,
    });
  });
});
