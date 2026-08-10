import { describe, expect, it } from '@jest/globals';
import {
  createSessionTaintStore,
  escalateForTaint,
  TAINT_TTL_MS,
  MAX_TAINTED_SESSIONS,
  type GuardDecision,
  type GuardSeverity,
} from '../../plugins/openclaw/session-taint.js';

/**
 * Issue #233 — a conversation detection at turn 1 must change what the agent is
 * allowed to DO at turn 2.
 *
 * Today the two paths share no state: `scanLlmInput` writes a log line and a
 * JSONL row nothing reads back, and the tool call the injection is steering is
 * evaluated as if the detection never happened.
 *
 * These tests pin the two halves of the fix:
 *   1. The taint store is per-session, expires, and is bounded — a gateway
 *      serves many concurrent chats and runs for weeks.
 *   2. Escalation tightens by exactly one notch, never downgrades, and never
 *      touches benign work (the property that keeps the agent usable).
 */

const T0 = 1_700_000_000_000;

describe('#233 — taint is per session, not per process', () => {
  it('does not leak one conversation\'s taint onto another', () => {
    // A gateway serves many chats at once. A process-global flag would gate
    // every other conversation's tools off one poisoned message.
    const store = createSessionTaintStore();
    store.mark('session-a', { reason: 'injection', nowMs: T0 });
    expect(store.get('session-a', T0)).not.toBeNull();
    expect(store.get('session-b', T0)).toBeNull();
  });

  it('ignores an empty session id rather than creating a catch-all bucket', () => {
    const store = createSessionTaintStore();
    store.mark('', { reason: 'injection', nowMs: T0 });
    expect(store.size()).toBe(0);
    expect(store.get('', T0)).toBeNull();
  });
});

describe('#233 — taint expires', () => {
  it('applies inside the window and stops after it', () => {
    const store = createSessionTaintStore();
    store.mark('s', { reason: 'injection', nowMs: T0 });
    expect(store.get('s', T0 + TAINT_TTL_MS - 1)).not.toBeNull();
    expect(store.get('s', T0 + TAINT_TTL_MS)).toBeNull();
  });

  it('a second detection EXTENDS the window rather than restarting it shorter', () => {
    const store = createSessionTaintStore();
    store.mark('s', { reason: 'first', nowMs: T0 });
    store.mark('s', { reason: 'second', nowMs: T0 + 60_000, ttlMs: 1_000 });
    // The short second mark must not cut the original hold short.
    expect(store.get('s', T0 + 120_000)).not.toBeNull();
  });

  it('keeps the HIGHER severity when re-marked with a milder one', () => {
    const store = createSessionTaintStore();
    store.mark('s', { reason: 'bad', severity: 'critical', nowMs: T0 });
    store.mark('s', { reason: 'meh', severity: 'low', nowMs: T0 + 1_000 });
    expect(store.get('s', T0 + 2_000)?.severity).toBe('critical');
  });

  it('clears on demand — the session_end path', () => {
    const store = createSessionTaintStore();
    store.mark('s', { reason: 'injection', nowMs: T0 });
    store.clear('s');
    expect(store.get('s', T0)).toBeNull();
  });
});

describe('#233 — the store is bounded', () => {
  it('never grows past the cap on a long-lived gateway', () => {
    const store = createSessionTaintStore();
    for (let i = 0; i < MAX_TAINTED_SESSIONS + 250; i++) {
      store.mark(`s${i}`, { reason: 'injection', nowMs: T0 + i });
    }
    expect(store.size()).toBeLessThanOrEqual(MAX_TAINTED_SESSIONS);
  });

  it('evicts the OLDEST marks, keeping the most recent detections', () => {
    // The newest taint is the one whose tool call has not happened yet.
    const store = createSessionTaintStore();
    for (let i = 0; i < MAX_TAINTED_SESSIONS + 10; i++) {
      store.mark(`s${i}`, { reason: 'injection', nowMs: T0 + i });
    }
    const newest = `s${MAX_TAINTED_SESSIONS + 9}`;
    expect(store.get(newest, T0 + MAX_TAINTED_SESSIONS + 20)).not.toBeNull();
    expect(store.get('s0', T0 + MAX_TAINTED_SESSIONS + 20)).toBeNull();
  });

  it('drops expired records without needing a reader to touch them', () => {
    const store = createSessionTaintStore();
    store.mark('old', { reason: 'injection', nowMs: T0 });
    store.mark('new', { reason: 'injection', nowMs: T0 + TAINT_TTL_MS + 1 });
    expect(store.size()).toBe(1);
  });
});

describe('#233 — escalation tightens exactly one notch', () => {
  const cases: Array<[GuardSeverity, GuardDecision, GuardDecision]> = [
    // severity,        normal decision,     tainted decision
    ['benign', 'allow', 'allow'],
    ['sensitive', 'allow', 'require_approval'],
    ['dangerous', 'require_approval', 'block'],
    ['catastrophic', 'block', 'block'],
  ];

  it.each(cases)('%s: %s → %s while tainted', (severity, normal, expected) => {
    expect(escalateForTaint({ decision: normal, severity, tainted: true }).decision).toBe(expected);
  });

  it('changes nothing when the session is clean', () => {
    for (const [severity, normal] of cases) {
      expect(escalateForTaint({ decision: normal, severity, tainted: false })).toEqual({
        decision: normal,
        escalated: false,
      });
    }
  });

  it('leaves BENIGN work alone — the property that keeps the agent usable', () => {
    // An agent that cannot read a file is useless, and a taint response that
    // stops ordinary work is one operators will switch off.
    const r = escalateForTaint({ decision: 'allow', severity: 'benign', tainted: true });
    expect(r.decision).toBe('allow');
    expect(r.escalated).toBe(false);
  });

  it('NEVER downgrades a stricter guard decision', () => {
    // If the guard already blocked, taint must not soften it to an approval.
    expect(escalateForTaint({ decision: 'block', severity: 'sensitive', tainted: true }).decision).toBe('block');
    expect(escalateForTaint({ decision: 'require_approval', severity: 'benign', tainted: true }).decision).toBe('require_approval');
  });

  it('flags whether taint actually changed the answer', () => {
    // The audit row must distinguish an escalated deny from a natively
    // catastrophic one, or the evidence is unreadable after the fact.
    expect(escalateForTaint({ decision: 'require_approval', severity: 'dangerous', tainted: true }).escalated).toBe(true);
    expect(escalateForTaint({ decision: 'block', severity: 'catastrophic', tainted: true }).escalated).toBe(false);
  });
});
