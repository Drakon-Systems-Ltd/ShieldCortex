import { describe, it, expect } from '@jest/globals';
import { resolveDisposition } from '../disposition.js';

/**
 * P1/WS4 — the one verdict→disposition policy. These cases ARE the contract that
 * store.ts and save-memory.mjs must both obey; a divergence would let a
 * high-confidence poisoning write be disposed of differently per runtime.
 */
const d = (allowed: boolean, firewallResult: string, trustScore: number) =>
  resolveDisposition({ allowed, firewallResult, trustScore, reason: 'r' });

describe('resolveDisposition — shared across runtimes (#61/WS4)', () => {
  it('stores a clean high-trust ALLOW', () => {
    expect(d(true, 'ALLOW', 0.9)).toMatchObject({ action: 'store', firewallResult: 'ALLOW' });
  });

  it('HOLDS a BLOCK (never dropped, never stored) with its BLOCK flag preserved', () => {
    expect(d(false, 'BLOCK', 0.3)).toMatchObject({ action: 'quarantine', firewallResult: 'BLOCK' });
  });

  it('HOLDS a QUARANTINE verdict', () => {
    expect(d(false, 'QUARANTINE', 0.5)).toMatchObject({ action: 'quarantine', firewallResult: 'QUARANTINE' });
  });

  it('coerces a not-allowed ALLOW-labelled result to a BLOCK hold (never stores a disallowed write)', () => {
    expect(d(false, 'ALLOW', 0.3)).toMatchObject({ action: 'quarantine', firewallResult: 'BLOCK' });
  });

  it('HOLDS an ALLOW in the sub-agent trust band [0.5, 0.7) — the fork the hook path was missing', () => {
    expect(d(true, 'ALLOW', 0.5)).toMatchObject({ action: 'quarantine', firewallResult: 'QUARANTINE', subAgentHold: true });
    expect(d(true, 'ALLOW', 0.69)).toMatchObject({ action: 'quarantine', subAgentHold: true });
  });

  it('does not hold at the band boundaries (>=0.7 stores, <0.5 is a genuine block elsewhere)', () => {
    expect(d(true, 'ALLOW', 0.7).action).toBe('store');
    expect(d(true, 'ALLOW', 0.8).action).toBe('store');
    // a trust below 0.5 only reaches here as allowed=true when the pipeline itself allowed it
    expect(d(true, 'ALLOW', 0.49).action).toBe('store');
  });
});
