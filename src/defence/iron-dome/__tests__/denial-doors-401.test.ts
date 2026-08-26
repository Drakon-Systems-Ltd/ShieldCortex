/**
 * #401 — denial→door matrix (design §5: "no deny without a door").
 *
 * Every Action Guard hold class must map to ≥1 door:
 *   work_lane     — reviewed, pinned script the agent can run instead
 *   approve_once  — #310 card or `shieldcortex approve --denial <actionId>`
 *   honest_tty    — honest "run this from a real terminal" copy
 *   hard_stop     — catastrophic: no retry, no approve, and copy that says so
 *
 * No siren-only class: a digest without a lane still carries the approve
 * command, and catastrophic copy must not dangle `approve --denial` as if it
 * were spendable there.
 */
import { describe, expect, it } from '@jest/globals';
import { brokerDecision, type BrokerInput } from '../approval-broker.js';
import { formatDnpDigestText, type DnpDigestFormatOpts, type DnpDigestSummary } from '../dnp-digest.js';
import { formatOperatorNotification, type OperatorNotification } from '../operator-notify.js';
import { suggestWorkLane, WORK_LANE_PACK_V1 } from '../work-lane-hints.js';

const LAN_PIN = '/home/edith/.shieldcortex/work-lanes/lan-diag.sh';
const VITA_PIN = '/home/edith/scripts/vita-site/gh-ci.sh';

function summary(over: Partial<DnpDigestSummary> = {}): DnpDigestSummary {
  return {
    count: 1,
    windowMs: 900_000,
    windowStartMs: 0,
    bySignal: { 'external-egress': 1 },
    byTool: { Bash: 1 },
    lastActionIds: ['act-0123456789abcdef'],
    lastSessionIds: [],
    coalescedAfterNotify: false,
    ...over,
  };
}

function catastrophicInput(over: Partial<BrokerInput['verdict']> = {}): BrokerInput {
  return {
    tool: 'Bash',
    toolInput: { command: 'redacted' },
    verdict: {
      decision: 'block',
      severity: 'catastrophic',
      family: 'exec',
      action: 'exec',
      reason: 'catastrophic-tier rule hit',
      signals: ['recursive-force-delete'],
      ...over,
    },
    judge: null,
  };
}

function notification(event: OperatorNotification['event']): OperatorNotification {
  const shortHash = 'abcdef012345';
  return {
    event,
    hash: `${shortHash}${'0'.repeat(52)}`,
    shortHash,
    tool: 'Bash',
    command: 'redacted-surface',
    signals: ['external-egress'],
    severity: 'dangerous',
    reason: 'external egress held for review',
    judge: null,
    fallbackHint: `shieldcortex approve ${shortHash}`,
  };
}

describe('catastrophic → hard_stop', () => {
  it('is never brokered and can never auto-approve', () => {
    const d = brokerDecision(catastrophicInput());
    expect(d.outcome).toBe('not_brokerable');
    expect(d.canAutoApproveOnTimeout).toBe(false);
  });

  it('hard-stops on severity alone, even without decision block', () => {
    const d = brokerDecision(catastrophicInput({ decision: 'require_approval' }));
    expect(d.outcome).toBe('not_brokerable');
  });

  it('copy does not offer approve --denial as spendable', () => {
    const d = brokerDecision(catastrophicInput());
    expect(d.reason).not.toMatch(/approve --denial/);
    expect(d.reason).not.toMatch(/shieldcortex approve/);
    expect(d.reason).toMatch(/blocked by rule, never brokered/);
  });
});

describe('denied_no_prompt_surface → approve_once + honest_tty', () => {
  const variants: Array<[string, DnpDigestSummary, DnpDigestFormatOpts]> = [
    ['with actionId', summary(), { actionId: 'act-abcdef0123456789' }],
    ['without any actionId', summary({ lastActionIds: [] }), {}],
    ['coalesced', summary({ coalescedAfterNotify: true, count: 4 }), {}],
    ['retry card raised', summary(), { retryCardRaised: true }],
    ['retry card refused', summary(), { retryCardReason: 'budget exhausted' }],
    [
      'with a lane',
      summary(),
      { signals: ['external-egress'], cwd: '/home/edith/lan-checks', reviewedScriptPaths: [LAN_PIN] },
    ],
    ['without a lane (no siren-only class)', summary(), { reviewedScriptPaths: [] }],
  ];

  it.each(variants)('digest %s always carries approve --denial', (_name, sum, opts) => {
    const text = formatDnpDigestText(sum, opts);
    expect(text).toMatch(/shieldcortex approve --denial/);
  });

  it.each(variants)('digest %s always carries the honest-TTY copy', (_name, sum, opts) => {
    const text = formatDnpDigestText(sum, opts);
    expect(text).toMatch(/real terminal/);
    expect(text).toMatch(/not a tappable Approve surface/);
  });

  it('digest opens the work-lane door when a pin matches', () => {
    const text = formatDnpDigestText(summary(), {
      actionId: 'act-abcdef0123456789',
      signals: ['external-egress'],
      cwd: '/home/edith/lan-checks',
      reviewedScriptPaths: [LAN_PIN],
    });
    expect(text).toMatch(/Lane: {2}\S/);
    expect(text).toContain(`${LAN_PIN} status`);
    // The lane never replaces the approve door — both stay open.
    expect(text).toMatch(/approve --denial act-abcdef0123456789/);
  });

  it('denial notification points at YOUR terminal and drops the dead Deny half', () => {
    const text = formatOperatorNotification(notification('denied_no_prompt_surface'));
    expect(text).toMatch(/shieldcortex approve abcdef012345/);
    expect(text).toMatch(/YOUR terminal/);
    expect(text).not.toMatch(/\[Deny\]/);
  });
});

describe('approval_requested → approve_once', () => {
  it('notification offers both approve and deny commands', () => {
    const text = formatOperatorNotification(notification('approval_requested'));
    expect(text).toMatch(/\[Approve\] {2}shieldcortex approve abcdef012345/);
    expect(text).toMatch(/\[Deny\] {5}shieldcortex deny abcdef012345/);
  });
});

describe('lan-diag lane (#401, work-lane pack v1)', () => {
  it('ships in the pack id list', () => {
    expect([...WORK_LANE_PACK_V1]).toEqual(['vita-ci', 'jotform', 'lan-diag']);
  });

  it('hints on pin + lan-shaped cwd', () => {
    const h = suggestWorkLane({
      signals: ['external-egress'],
      cwd: '/home/edith/lan-checks',
      reviewedScriptPaths: [LAN_PIN],
    });
    expect(h?.command).toBe(`${LAN_PIN} status`);
    expect(h?.reason).toMatch(/LAN diagnostics.*pinned script/);
  });

  it('hints on pin + network tool from an unrelated cwd', () => {
    const h = suggestWorkLane({
      signals: ['external-egress'],
      cwd: '/tmp/scratch',
      tool: 'ping',
      reviewedScriptPaths: [LAN_PIN],
    });
    expect(h?.command).toBe(`${LAN_PIN} status`);
  });

  it('accepts a /lan-diag/ directory pin fragment', () => {
    const pin = '/opt/lanes/lan-diag/run.sh';
    const h = suggestWorkLane({
      signals: ['external-egress'],
      cwd: '/home/edith/wifi-triage',
      reviewedScriptPaths: [pin],
    });
    expect(h?.command).toBe(`${pin} status`);
  });

  it('never invents a path without a pin', () => {
    const h = suggestWorkLane({
      signals: ['external-egress'],
      cwd: '/home/edith/lan-checks',
      tool: 'ping',
      reviewedScriptPaths: [],
    });
    expect(h).toBeNull();
  });

  it('does not fire on pin alone (unrelated cwd, non-network tool)', () => {
    const h = suggestWorkLane({
      signals: ['external-egress'],
      cwd: '/tmp/unrelated',
      tool: 'gh',
      reviewedScriptPaths: [LAN_PIN],
    });
    expect(h).toBeNull();
  });

  it('does not treat plan/finland as a lan cwd', () => {
    for (const cwd of ['/tmp/plan', '/home/finland/work', '/opt/planner']) {
      const h = suggestWorkLane({
        signals: ['external-egress'],
        cwd,
        reviewedScriptPaths: [LAN_PIN],
      });
      expect(h).toBeNull();
    }
  });

  it('requires exact external-egress, not secret-egress', () => {
    const h = suggestWorkLane({
      signals: ['secret-egress'],
      cwd: '/home/edith/lan-checks',
      tool: 'ping',
      reviewedScriptPaths: [LAN_PIN],
    });
    expect(h).toBeNull();
  });

  it('does not steal the vita lane on a vita cwd', () => {
    const h = suggestWorkLane({
      signals: ['external-egress'],
      cwd: '/home/edith/.openclaw/workspace/tmp/vita-mobile-hero',
      reviewedScriptPaths: [LAN_PIN, VITA_PIN],
    });
    expect(h?.command).toMatch(/gh-ci\.sh status staging/);
  });
});

describe('denial→door matrix', () => {
  type Door = 'work_lane' | 'approve_once' | 'honest_tty' | 'hard_stop';

  /** Doors derived from ACTUAL behaviour, not from a table someone hand-wrote. */
  function doorsFor(holdClass: string): Door[] {
    const doors: Door[] = [];
    if (holdClass === 'catastrophic') {
      const d = brokerDecision(catastrophicInput());
      if (d.outcome === 'not_brokerable' && !d.canAutoApproveOnTimeout) doors.push('hard_stop');
      return doors;
    }
    if (holdClass === 'denied_no_prompt_surface') {
      const text = formatDnpDigestText(summary(), {
        signals: ['external-egress'],
        cwd: '/home/edith/lan-checks',
        reviewedScriptPaths: [LAN_PIN],
      });
      if (/Lane: {2}\S/.test(text)) doors.push('work_lane');
      if (/shieldcortex approve --denial/.test(text)) doors.push('approve_once');
      if (/real terminal/.test(text)) doors.push('honest_tty');
      return doors;
    }
    if (holdClass === 'approval_requested') {
      const text = formatOperatorNotification(notification('approval_requested'));
      if (/\[Approve\] {2}shieldcortex approve/.test(text)) doors.push('approve_once');
      return doors;
    }
    return doors;
  }

  it('every hold class has at least one door', () => {
    for (const holdClass of ['catastrophic', 'denied_no_prompt_surface', 'approval_requested']) {
      expect(doorsFor(holdClass).length).toBeGreaterThan(0);
    }
  });

  it('catastrophic is exactly a hard stop — no spendable door', () => {
    expect(doorsFor('catastrophic')).toEqual(['hard_stop']);
  });

  it('denied_no_prompt_surface has all three forward doors', () => {
    expect(doorsFor('denied_no_prompt_surface')).toEqual(['work_lane', 'approve_once', 'honest_tty']);
  });
});
