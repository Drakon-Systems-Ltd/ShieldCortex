import { describe, expect, it } from '@jest/globals';
import {
  LOW_TRUST_CLAMP,
  resolveDisposition,
  resolveDispositionV2,
} from '../disposition.js';

/**
 * #402 — 6-way disposition valve. The v2 resolver REFINES resolveDisposition:
 * every base 'quarantine' stays a hold; base 'store' splits on form + signals.
 */
const v2 = (over: Partial<Parameters<typeof resolveDispositionV2>[0]> = {}) =>
  resolveDispositionV2({
    allowed: true,
    firewallResult: 'ALLOW',
    trustScore: 0.9,
    reason: 'r',
    contentForm: 'fact',
    ...over,
  });

describe('resolveDispositionV2 (#402)', () => {
  it('ADMIT: fact form, clean verdict, trust above floor → store, injectable', () => {
    const d = v2();
    expect(d).toMatchObject({ kind: 'admit', action: 'store', injectable: true, contentForm: 'fact' });
  });

  it('ADMIT-LOW-TRUST: fact form but thin provenance → store, trust clamped, not injectable', () => {
    const d = v2({ trustScore: 0.3 });
    expect(d).toMatchObject({ kind: 'admit-low-trust', action: 'store', injectable: false });
    expect(d.trustClamp).toBe(0.3); // clamp never RAISES trust
    const e = v2({ trustScore: 0.49 });
    expect(e.trustClamp).toBeLessThanOrEqual(LOW_TRUST_CLAMP);
  });

  it('ADMIT-LOW-TRUST: soft signals demote a high-trust fact', () => {
    expect(v2({ threatIndicators: ['weird_encoding'] }).kind).toBe('admit-low-trust');
    expect(v2({ anomalyScore: 0.4 }).kind).toBe('admit-low-trust');
    expect(v2({ anomalyScore: 0.1, threatIndicators: [] }).kind).toBe('admit');
  });

  it('INERT: directive / mixed / unknown forms store but are never injectable', () => {
    for (const form of ['directive', 'mixed', 'unknown'] as const) {
      const d = v2({ contentForm: form });
      expect(d).toMatchObject({ kind: 'inert', action: 'store', injectable: false, contentForm: form });
    }
  });

  it('INERT: a missing/invalid classification is fail-closed to unknown — never auto-admit', () => {
    expect(v2({ contentForm: undefined })).toMatchObject({ kind: 'inert', contentForm: 'unknown' });
    expect(v2({ contentForm: null })).toMatchObject({ kind: 'inert', contentForm: 'unknown' });
    expect(v2({ contentForm: 'FACT' as never })).toMatchObject({ kind: 'inert', contentForm: 'unknown' });
  });

  it('REJECT: a BLOCK holds with its flag preserved (forensic, like today)', () => {
    const d = v2({ allowed: false, firewallResult: 'BLOCK', trustScore: 0.2 });
    expect(d).toMatchObject({ kind: 'reject', action: 'quarantine', firewallResult: 'BLOCK', injectable: false });
  });

  it('QUARANTINE: directive-form firewall hold stays a plain quarantine', () => {
    const d = v2({ allowed: false, firewallResult: 'QUARANTINE', contentForm: 'directive' });
    expect(d).toMatchObject({ kind: 'quarantine', action: 'quarantine', firewallResult: 'QUARANTINE' });
  });

  it('ESCALATE: fact-shaped content the firewall flagged is held for operator review', () => {
    const d = v2({ allowed: false, firewallResult: 'QUARANTINE', contentForm: 'fact' });
    expect(d).toMatchObject({ kind: 'escalate', action: 'quarantine', firewallResult: 'QUARANTINE', injectable: false });
    expect(d.reason).toMatch(/^escalate: operator review required/);
  });

  it('sub-agent trust band stays a parent-approval quarantine, not escalate', () => {
    const d = v2({ trustScore: 0.6 });
    expect(d).toMatchObject({ kind: 'quarantine', action: 'quarantine', subAgentHold: true });
  });

  it('B1: attestation grants nothing — same outcome attested or not', () => {
    const attested = v2({ contentForm: 'directive', sourceAttested: true });
    const plain = v2({ contentForm: 'directive', sourceAttested: false });
    expect(attested.kind).toBe(plain.kind);
    expect(attested.injectable).toBe(false);
    const lowTrust = v2({ trustScore: 0.2, sourceAttested: true });
    expect(lowTrust.kind).toBe('admit-low-trust');
  });

  it('never relaxes the base decision: any base quarantine is still a hold in v2', () => {
    const cases = [
      { allowed: false, firewallResult: 'BLOCK', trustScore: 0.2, reason: 'r' },
      { allowed: false, firewallResult: 'QUARANTINE', trustScore: 0.4, reason: 'r' },
      { allowed: true, firewallResult: 'ALLOW', trustScore: 0.55, reason: 'r' },
    ];
    for (const c of cases) {
      expect(resolveDisposition(c).action).toBe('quarantine');
      for (const form of ['fact', 'directive', 'mixed', 'unknown'] as const) {
        expect(resolveDispositionV2({ ...c, contentForm: form }).action).toBe('quarantine');
      }
    }
  });
});
