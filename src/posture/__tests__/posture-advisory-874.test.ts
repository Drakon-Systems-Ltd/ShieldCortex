import { describe, expect, it } from '@jest/globals';
import {
  deriveToolGateRecord,
  parseSelfReport,
  renderPostureLine,
  type LivenessCheck,
  type PostureRecord,
  type SelfReportRead,
} from '../posture-record.js';
import { NOW, denial, reportBody } from './self-report-fixture.js';

/**
 * #874 — the per-instance posture line must not contradict the gate's own
 * record. On 5.10.6 every advisory Claude Code instance printed
 * "posture advisory — warns, does not block" on the same doctor run in which
 * that hook had denied calls. "does not block" is now said only when the
 * instance's own reported deny count is zero and current; otherwise the line
 * gives the count, or says the record cannot be read.
 */

function read(over: Record<string, unknown> = {}): SelfReportRead {
  const text = JSON.stringify(reportBody(over));
  return parseSelfReport(text, Buffer.byteLength(text));
}

function gate(r: SelfReportRead, liveness: LivenessCheck = 'alive'): PostureRecord {
  return deriveToolGateRecord({ runtime: 'hermes', profile: 'default', installed: 'yes', read: r, liveness, nowMs: NOW });
}

describe('#874 advisory posture line is scoped to the instance deny record', () => {
  it('an advisory instance that reported a deny never says "does not block", and gives the count', () => {
    const line = renderPostureLine(gate(read({
      configured_posture: 'advisory',
      denials: { blocked_action: denial({ configured_posture: 'advisory' }), synthetic_probe: null, blocked_action_count: 3 },
    })));
    expect(line).toMatch(/posture advisory/);
    expect(line).not.toMatch(/does not block/);
    expect(line).toMatch(/reported 3 denied calls/);
  });

  it('one deny is singular', () => {
    const line = renderPostureLine(gate(read({
      configured_posture: 'advisory',
      denials: { blocked_action: denial({ configured_posture: 'advisory' }), synthetic_probe: null, blocked_action_count: 1 },
    })));
    expect(line).toMatch(/reported 1 denied call\b/);
    expect(line).not.toMatch(/does not block/);
  });

  it('an advisory instance with a zero deny count may say "does not block", scoped to what it reported', () => {
    const line = renderPostureLine(gate(read({
      configured_posture: 'advisory',
      denials: { blocked_action: null, synthetic_probe: null, blocked_action_count: 0 },
    })));
    expect(line).toMatch(/posture advisory — warns, does not block \(no deny in any decision this instance reported\)/);
  });

  it('a record that is not current says the deny record cannot be relied on, not either claim', () => {
    const line = renderPostureLine(gate(read({ configured_posture: 'advisory' }), 'unsupported'));
    expect(line).toMatch(/posture advisory/);
    expect(line).not.toMatch(/does not block/);
    expect(line).toMatch(/unreadable or not current/);
  });

  it('enforce and off lines are unchanged', () => {
    expect(renderPostureLine(gate(read()))).toMatch(/posture enforce \(self-reported\)/);
    expect(renderPostureLine(gate(read({ configured_posture: 'intentionally-off' })))).toMatch(/posture intentionally off by configuration/);
  });
});
