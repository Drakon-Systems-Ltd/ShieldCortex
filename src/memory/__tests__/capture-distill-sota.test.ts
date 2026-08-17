import { describe, expect, it } from '@jest/globals';
import {
  L1_SALIENCE_CAP,
  allowRegexFallback,
  failClosedDistill,
  resolveCaptureMode,
} from '../../../scripts/lib/capture-distill.mjs';

describe('capture-distill fail-closed', () => {
  it('caps L1 salience at 0.7', () => {
    const r = failClosedDistill(null, [{ title: 't', content: 'c', salience: 0.99 }]);
    expect(r.ok).toBe(true);
    expect(r.memories[0].salience).toBe(L1_SALIENCE_CAP);
  });

  it('skips on error — empty memories', () => {
    const r = failClosedDistill(new Error('timeout'), [{ title: 't', content: 'c' }]);
    expect(r.ok).toBe(false);
    expect(r.memories).toEqual([]);
  });

  it('rejects invalid schema', () => {
    const r = failClosedDistill(null, null);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('invalid-schema');
  });

  it('regex fallback only in explicit regex mode', () => {
    expect(allowRegexFallback('distill')).toBe(false);
    expect(allowRegexFallback('distill_required')).toBe(false);
    expect(allowRegexFallback('regex')).toBe(true);
  });

  it('defaults to distill when provider configured', () => {
    expect(resolveCaptureMode(undefined, { providerConfigured: true })).toBe('distill');
  });
});
