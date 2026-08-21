import { describe, expect, it } from '@jest/globals';
import {
  formatReconcileReport,
  protectionLedgerFromReconcile,
  type ReconcileExecResult,
} from '../openclaw-reconcile.js';

/**
 * Friday Mac phone-SSH screenshot class: canary denied+audited, version OK,
 * roster unread after reload. Update must not dump a double FAILED essay.
 */
function fridayClassResult(): ReconcileExecResult {
  return {
    verdict: {
      state: 'duplicate-install',
      severity: 'warn',
      recommendedAction: 'prune',
      enabledInConfig: true,
      loadedInIndex: true,
      openClawTracked: true,
      indexWarnsConflict: false,
      metadataConflict: false,
      indexVersion: '4.54.10',
      installsJsonVersion: '4.54.10',
      onDiskVersion: '4.54.10',
      expectedVersion: '4.54.10',
      reasons: ['3 plugin project dirs on disk'],
    },
    postVerdict: {
      state: 'healthy',
      severity: 'ok',
      recommendedAction: 'none',
      enabledInConfig: true,
      loadedInIndex: true,
      openClawTracked: true,
      indexWarnsConflict: false,
      metadataConflict: false,
      indexVersion: '4.54.10',
      installsJsonVersion: '4.54.10',
      onDiskVersion: '4.54.10',
      expectedVersion: '4.54.10',
      reasons: [
        'enabled and installed, versions agree at the expected build — but the running gateway boot roster could NOT be read, so the plugin is not proven loaded',
      ],
    },
    plan: [],
    applied: true,
    stepResults: [
      { kind: 'prune-duplicate-dirs', ok: true, detail: 'pruned 2 dir(s)' },
      { kind: 'openclaw-update', ok: true, detail: 'shieldcortex-realtime is up to date (4.54.10).' },
      { kind: 'gateway-reload', ok: true, detail: 'reloaded and ready in 3.0s' },
      {
        kind: 'self-check',
        ok: false,
        detail:
          'roster proof FAILED: could not read the running gateway boot roster; canary proof: live probe was denied by the interceptor and audited; version proof: on-disk build 4.54.10 satisfies expected 4.54.10',
      },
    ],
    selfCheck: {
      ok: false,
      rosterProof: false,
      rosterState: 'unproven',
      canaryProof: true,
      versionProof: true,
      reasons: [
        'roster proof FAILED: could not read the running gateway boot roster (log rotated, wiped, or written elsewhere) — cannot confirm the interceptor is loaded; the SQLite install index lists it as enabled, but that is install state, not load state; canary proof: live probe was denied by the interceptor and audited; version proof: on-disk build 4.54.10 satisfies expected 4.54.10',
      ],
      canary: { ran: true, denied: true, auditEntryFound: true },
    },
    ok: false,
    messages: [
      'self-check FAILED after remediation — plugin not confirmed loaded + enforcing: roster proof FAILED…',
    ],
  };
}

describe('formatReconcileReport compact (update footer)', () => {
  it('does not print FAILED / self-check essay for canary-live roster-unread', () => {
    const text = formatReconcileReport(fridayClassResult(), { compact: true }).join('\n');
    expect(text).toMatch(/Enforcement is live|probe denied/i);
    expect(text).toMatch(/guard live/);
    expect(text).toMatch(/roster unread/);
    expect(text).not.toMatch(/✗\s*FAILED/);
    expect(text).not.toMatch(/self-check FAILED after remediation/);
    expect(text).not.toMatch(/SQLite install index/);
    expect(text).not.toMatch(/Applied remediation/);
    // no mid-essay dump of full reasons twice
    expect(text.split('roster').length).toBeLessThan(6);
  });

  it('full mode no longer red-banners protected-unproven as FAILED', () => {
    const text = formatReconcileReport(fridayClassResult()).join('\n');
    expect(text).not.toMatch(/✗\s*FAILED: could not confirm the plugin is loaded AND enforcing/);
    expect(text).toMatch(/Enforcement is live|⚠/);
  });
});

describe('protectionLedgerFromReconcile', () => {
  it('maps friday-class to unproven attention, not failed', () => {
    const ledger = protectionLedgerFromReconcile(fridayClassResult());
    expect(ledger.status).toBe('unproven');
    expect(ledger.outcome).toBe('protected-unproven');
    expect(ledger.summary).toMatch(/guard live|roster unread/i);
  });
});
