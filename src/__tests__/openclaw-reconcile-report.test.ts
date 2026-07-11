import { describe, expect, it } from '@jest/globals';
import { formatReconcileReport, type ReconcileExecResult } from '../setup/openclaw-reconcile.js';

/**
 * The operator-facing report `shieldcortex repair` prints. It must (a) name the
 * state plainly, (b) never claim success when the self-check did not pass, and
 * (c) tell a dry-run operator exactly how to actually remediate.
 */
function baseResult(over: Partial<ReconcileExecResult>): ReconcileExecResult {
  return {
    verdict: {
      state: 'healthy', severity: 'ok', recommendedAction: 'none',
      enabledInConfig: true, loadedInIndex: true, openClawTracked: true,
      indexWarnsConflict: false, metadataConflict: false,
      indexVersion: '4.47.2', installsJsonVersion: '4.47.2', onDiskVersion: '4.47.2',
      expectedVersion: '4.47.2', reasons: ['healthy'],
    },
    plan: [], applied: false, stepResults: [], ok: true, messages: [],
    ...over,
  };
}

describe('formatReconcileReport', () => {
  it('reports a healthy state as ok', () => {
    const lines = formatReconcileReport(baseResult({ ok: true })).join('\n');
    expect(lines).toMatch(/healthy/i);
  });

  it('a dry-run of the silent drop tells the operator how to remediate', () => {
    const lines = formatReconcileReport(baseResult({
      applied: false, ok: false,
      verdict: { ...baseResult({}).verdict, state: 'enabled-not-loaded', severity: 'fail', recommendedAction: 'update-openclaw-tracked', loadedInIndex: false },
      messages: ['dry-run: computed plan without executing'],
    })).join('\n');
    expect(lines).toMatch(/enabled-not-loaded|not loaded|unprotected/i);
    expect(lines).toMatch(/SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE/);
  });

  it('NEVER prints a success line when the self-check failed after remediation', () => {
    const lines = formatReconcileReport(baseResult({
      applied: true, ok: false,
      messages: ['self-check FAILED after remediation — plugin not confirmed loaded + enforcing'],
    })).join('\n');
    expect(lines).toMatch(/self-check FAILED|not confirmed|FAIL/i);
    expect(lines).not.toMatch(/✓\s*reconciled: plugin confirmed/i);
  });

  it('prints a confirmed-success line only when applied and ok', () => {
    const lines = formatReconcileReport(baseResult({
      applied: true, ok: true,
      messages: ['reconciled: plugin confirmed loaded (roster) and enforcing (canary)'],
    })).join('\n');
    expect(lines).toMatch(/confirmed loaded.*enforcing/i);
  });
});
