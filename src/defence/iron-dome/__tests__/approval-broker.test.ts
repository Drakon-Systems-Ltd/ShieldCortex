/**
 * Failing-first spec for the AI-assisted approval broker (#143).
 *
 * These tests ARE the security contract. Every one of them encodes an invariant
 * from docs/design/2026-07-31-ai-approval-broker.md; if a future change makes
 * one of them go quiet, the broker has become a bypass rather than a gate.
 */
import { describe, it, expect } from '@jest/globals';
import {
  brokerDecision,
  timeoutOutcome,
  isPreClearable,
  DEFAULT_BROKER_POLICY,
  PRE_CLEARABLE_SIGNALS,
  type JudgeResult,
  type BrokerInput,
} from '../approval-broker.js';

// ── helpers ─────────────────────────────────────────────────────────────────

const dangerous = (signals: string[]): BrokerInput['verdict'] => ({
  decision: 'require_approval',
  severity: 'dangerous',
  family: 'shell',
  action: 'execute_command',
  reason: 'test',
  signals,
});

const judge = (over: Partial<JudgeResult> = {}): JudgeResult => ({
  assessment: 'benign',
  confidence: 0.99,
  inContext: true,
  injectionSuspected: false,
  rationale: 'routine',
  ...over,
});

const input = (over: Partial<BrokerInput> = {}): BrokerInput => ({
  tool: 'Bash',
  toolInput: { command: 'npm install lodash' },
  verdict: dangerous(['local-package-install']),
  judge: judge(),
  policy: DEFAULT_BROKER_POLICY,
  ...over,
});

// ── INVARIANT 1: catastrophic is never brokered ─────────────────────────────

describe('invariant: catastrophic never reaches the broker', () => {
  it('refuses to broker a catastrophic verdict, even with a perfect judge result', () => {
    const d = brokerDecision(
      input({ verdict: { ...dangerous(['recursive-force-delete']), severity: 'catastrophic', decision: 'block' } }),
    );
    expect(d.outcome).toBe('not_brokerable');
    expect(d.canAutoApproveOnTimeout).toBe(false);
  });

  it('refuses even when the judge is maximally confident it is benign', () => {
    const d = brokerDecision(
      input({
        verdict: { ...dangerous(['delete-root-or-home']), severity: 'catastrophic', decision: 'block' },
        judge: judge({ confidence: 1, assessment: 'benign', inContext: true }),
      }),
    );
    expect(d.outcome).toBe('not_brokerable');
  });
});

// ── INVARIANT 2: the judge can only escalate toward caution ─────────────────

describe('invariant: the judge escalates toward caution only', () => {
  it('hardens to deny when the judge suspects injection', () => {
    const d = brokerDecision(input({ judge: judge({ injectionSuspected: true }) }));
    expect(d.outcome).toBe('harden');
  });

  it('hardens when the judge assesses the request as malicious', () => {
    const d = brokerDecision(input({ judge: judge({ assessment: 'malicious' }) }));
    expect(d.outcome).toBe('harden');
  });

  it('hardens on injection even for an otherwise pre-clearable, in-context, confident request', () => {
    const d = brokerDecision(
      input({
        verdict: dangerous(['local-package-install']),
        judge: judge({ injectionSuspected: true, confidence: 1, inContext: true, assessment: 'benign' }),
      }),
    );
    expect(d.outcome).toBe('harden');
    expect(d.canAutoApproveOnTimeout).toBe(false);
  });

  it('a benign judge verdict never turns a block into an allow — it can only reach hold or pre_clear', () => {
    const d = brokerDecision(input({ judge: judge() }));
    expect(['hold', 'pre_clear']).toContain(d.outcome);
    expect(d.outcome).not.toBe('allow');
  });
});

// ── INVARIANT 3: pre-clear requires ALL four conditions ────────────────────

describe('invariant: pre_clear requires reversible signals AND context AND confidence AND no injection', () => {
  it('pre-clears a reversible, in-context, high-confidence, injection-free request', () => {
    const d = brokerDecision(input());
    expect(d.outcome).toBe('pre_clear');
  });

  it('does NOT pre-clear when the action is irreversible, however confident the judge', () => {
    const d = brokerDecision(
      input({ verdict: dangerous(['file-delete']), judge: judge({ confidence: 1 }) }),
    );
    expect(d.outcome).toBe('hold');
  });

  it('does NOT pre-clear when the request is out of context', () => {
    const d = brokerDecision(input({ judge: judge({ inContext: false }) }));
    expect(d.outcome).toBe('hold');
  });

  it('does NOT pre-clear below the confidence threshold', () => {
    const d = brokerDecision(input({ judge: judge({ confidence: DEFAULT_BROKER_POLICY.preClearConfidence - 0.01 }) }));
    expect(d.outcome).toBe('hold');
  });

  it('does NOT pre-clear on an uncertain assessment', () => {
    const d = brokerDecision(input({ judge: judge({ assessment: 'uncertain' }) }));
    expect(d.outcome).toBe('hold');
  });

  it('a mixed signal set is only pre-clearable if EVERY signal is reversible', () => {
    const d = brokerDecision(input({ verdict: dangerous(['local-package-install', 'file-delete']) }));
    expect(d.outcome).toBe('hold');
  });
});

// ── INVARIANT 4: the reversibility allowlist is conservative ────────────────

describe('invariant: only reversible, on-host signals are ever pre-clearable', () => {
  const mustNeverPreClear = [
    'file-delete',
    'recursive-force-delete',
    'delete-root-or-home',
    'privilege-escalation',
    'secret-egress',
    'external-egress',
    'install-package-global',
    'modify-scheduler',
    'stop-process-or-service',
    'registry-code-exec',
    'pipe-download-to-shell',
    'git-force-push',
    'touch-sensitive-path',
    'touch-approval-store',
    'wipe-history-or-logs',
    'modify-network-firewall',
    'shred-device',
    'dd-overwrite',
    'truncate-to-zero',
  ];

  it.each(mustNeverPreClear)('%s is not pre-clearable', (signal) => {
    expect(PRE_CLEARABLE_SIGNALS.has(signal)).toBe(false);
    expect(isPreClearable([signal])).toBe(false);
  });

  it('an unknown/new signal is not pre-clearable (fail closed on the allowlist)', () => {
    expect(isPreClearable(['some-signal-invented-next-year'])).toBe(false);
  });

  it('an empty signal set is not pre-clearable', () => {
    expect(isPreClearable([])).toBe(false);
  });
});

// ── INVARIANT 5: no judge → human only, never pre-clear ────────────────────

describe('invariant: an absent or failed judge falls back to human-only', () => {
  it('holds when the judge is unavailable (model unreachable)', () => {
    const d = brokerDecision(input({ judge: null }));
    expect(d.outcome).toBe('hold');
    expect(d.canAutoApproveOnTimeout).toBe(false);
  });

  it('holds when the judge errored', () => {
    const d = brokerDecision(input({ judge: { error: 'timeout' } as unknown as JudgeResult }));
    expect(d.outcome).toBe('hold');
    expect(d.canAutoApproveOnTimeout).toBe(false);
  });

  it('holds when the judge returns a malformed confidence', () => {
    const d = brokerDecision(input({ judge: judge({ confidence: Number.NaN }) }));
    expect(d.outcome).toBe('hold');
  });

  it('treats an out-of-range confidence as untrustworthy rather than clamping it up', () => {
    const d = brokerDecision(input({ judge: judge({ confidence: 42 }) }));
    expect(d.outcome).toBe('hold');
  });
});

// ── INVARIANT 6: the timeout is asymmetric ─────────────────────────────────

describe('invariant: silence never means yes on anything that matters', () => {
  it('auto-approves on timeout only what the broker already pre-cleared', () => {
    const d = brokerDecision(input());
    expect(d.canAutoApproveOnTimeout).toBe(true);
    expect(timeoutOutcome(d)).toBe('approve');
  });

  it('auto-DENIES on timeout for a held request', () => {
    const d = brokerDecision(input({ verdict: dangerous(['file-delete']) }));
    expect(timeoutOutcome(d)).toBe('deny');
  });

  it('auto-DENIES on timeout when the judge was unavailable', () => {
    const d = brokerDecision(input({ judge: null }));
    expect(timeoutOutcome(d)).toBe('deny');
  });

  it('auto-DENIES on timeout for a hardened request', () => {
    const d = brokerDecision(input({ judge: judge({ injectionSuspected: true }) }));
    expect(timeoutOutcome(d)).toBe('deny');
  });

  it('auto-DENIES on timeout for anything not brokerable', () => {
    const d = brokerDecision(
      input({ verdict: { ...dangerous(['delete-root-or-home']), severity: 'catastrophic', decision: 'block' } }),
    );
    expect(timeoutOutcome(d)).toBe('deny');
  });
});

// ── INVARIANT 7: policy can tighten but never loosen the invariants ────────

describe('invariant: config can tighten, never loosen', () => {
  it('preClear can be disabled entirely by policy', () => {
    const d = brokerDecision(input({ policy: { ...DEFAULT_BROKER_POLICY, allowPreClear: false } }));
    expect(d.outcome).toBe('hold');
    expect(timeoutOutcome(d)).toBe('deny');
  });

  it('raising the confidence threshold tightens pre-clear', () => {
    const d = brokerDecision(
      input({ judge: judge({ confidence: 0.9 }), policy: { ...DEFAULT_BROKER_POLICY, preClearConfidence: 0.95 } }),
    );
    expect(d.outcome).toBe('hold');
  });

  it('a policy cannot make an irreversible signal pre-clearable', () => {
    const d = brokerDecision(
      input({
        verdict: dangerous(['recursive-force-delete']),
        policy: { ...DEFAULT_BROKER_POLICY, preClearConfidence: 0 },
        judge: judge({ confidence: 0 }),
      }),
    );
    expect(d.outcome).not.toBe('pre_clear');
  });

  it('a policy cannot make a catastrophic verdict brokerable', () => {
    const d = brokerDecision(
      input({
        verdict: { ...dangerous(['local-package-install']), severity: 'catastrophic', decision: 'block' },
        policy: { ...DEFAULT_BROKER_POLICY, preClearConfidence: 0, allowPreClear: true },
      }),
    );
    expect(d.outcome).toBe('not_brokerable');
  });
});

// ── INVARIANT 8: the decision is auditable ────────────────────────────────

describe('every broker decision is explainable', () => {
  it('names the reason for a hold', () => {
    const d = brokerDecision(input({ judge: judge({ inContext: false }) }));
    expect(d.reason).toMatch(/context/i);
  });

  it('names the reason for a harden', () => {
    const d = brokerDecision(input({ judge: judge({ injectionSuspected: true }) }));
    expect(d.reason).toMatch(/injection/i);
  });

  it('carries the judge metadata needed for the audit row', () => {
    const d = brokerDecision(input());
    expect(d.audit).toMatchObject({
      outcome: 'pre_clear',
      judgeAssessment: 'benign',
      judgeConfidence: 0.99,
      injectionSuspected: false,
    });
    expect(d.audit.signals).toEqual(['local-package-install']);
  });

  it('records that no judge ran when there was none', () => {
    const d = brokerDecision(input({ judge: null }));
    expect(d.audit.judgeAssessment).toBe('unavailable');
  });
});
