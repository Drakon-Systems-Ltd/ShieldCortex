/**
 * Failing-first spec for doctor.ts's `--ai` wiring (#157).
 *
 * This deliberately does NOT call the full `runDoctor()` — no existing test in
 * this suite does, because `getShieldCortexDir()` resolves against the REAL
 * `os.homedir()`/.shieldcortex (unlike the defence pipeline's config dir,
 * doctor's own checks are not sandboxed by scripts/jest-config-sandbox.mjs),
 * and several checks (checkWritePath) perform real DB round-trips. Instead
 * this exercises the two new, independently-exported pieces that make up the
 * `--ai` section: `runDoctorAiSection` (resolution + explainer call, with the
 * model invoker injected so nothing spawns a real process) and
 * `formatAiSection` (pure rendering). Together they cover the same ground an
 * end-to-end run would, without the side effects.
 */
import { describe, it, expect, jest } from '@jest/globals';
import { formatAiSection, runDoctorAiSection, type CheckResult } from '../doctor.js';
import type { ModelInvoker } from '../../defence/iron-dome/approval-judge.js';
import type { DoctorExplainerOutcome } from '../../defence/iron-dome/doctor-explainer.js';

const failResult: CheckResult = {
  label: 'OpenClaw plugin loaded',
  status: 'fail',
  message: 'realtime plugin regressed to v4.47.22 (older than expected v4.47.24) — running stale, refuse the downgrade',
  fix: 'Run `shieldcortex repair` to reconcile the plugin install metadata and verify it actually loads.',
};

const warnResult: CheckResult = {
  label: 'OpenClaw plugin running version',
  status: 'warn',
  message: 'stale plugin loaded (v4.47.22 running, v4.47.24 on disk) — a gateway restart is needed',
};

const passResult: CheckResult = { label: 'Database', status: 'pass', message: 'schema current' };

const goodReply = JSON.stringify({
  hypothesis: 'The gateway never restarted after the last upgrade, so it is still enforcing the older build.',
  citedLabels: [failResult.label, warnResult.label],
  suggestedCommand: 'shieldcortex repair',
  confidence: 'high',
});

describe('runDoctorAiSection — the seam doctor.ts uses to reach the explainer', () => {
  it('never calls the injected invoker when there is nothing to explain', async () => {
    const invoke = jest.fn<ModelInvoker>();
    const { outcome } = await runDoctorAiSection([passResult, warnResult], { invoke });
    expect(invoke).not.toHaveBeenCalled();
    expect(outcome.attempted).toBe(false);
  });

  it('reaches the explainer through the injected invoker and returns a grounded result', async () => {
    const invoke = jest.fn<ModelInvoker>().mockResolvedValue(goodReply);
    const { outcome, lines } = await runDoctorAiSection([failResult, warnResult, passResult], { invoke });
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(outcome.result?.suggestedCommand).toBe('shieldcortex repair');
    expect(lines.join('\n')).toContain('shieldcortex repair');
  });

  it('an explicit null invoker (no model reachable) fails closed without touching the real CLI transport', async () => {
    const { outcome } = await runDoctorAiSection([failResult], { invoke: null });
    expect(outcome.attempted).toBe(true);
    expect(outcome.result).toBeNull();
  });
});

describe('formatAiSection — pure rendering, no verdict language ever appears', () => {
  it('renders "nothing to explain" without ever claiming a hypothesis', () => {
    const outcome: DoctorExplainerOutcome = { attempted: false, result: null, reason: 'no failing checks to explain' };
    const lines = formatAiSection(outcome);
    expect(lines.join('\n')).toMatch(/no failing checks to explain/i);
    expect(lines.join('\n')).not.toMatch(/hypothesis/i);
  });

  it('renders "no AI analysis available" on any failure, not a guess', () => {
    const outcome: DoctorExplainerOutcome = {
      attempted: true,
      result: null,
      reason: 'no AI analysis available (model timed out)',
    };
    const lines = formatAiSection(outcome);
    expect(lines.join('\n')).toMatch(/no ai analysis available/i);
  });

  it('renders a successful hypothesis clearly labelled as a hypothesis, with the suggested command and a disclaimer', () => {
    const outcome: DoctorExplainerOutcome = {
      attempted: true,
      result: {
        hypothesis: 'The gateway is still running the old build.',
        citedLabels: [failResult.label, warnResult.label],
        suggestedCommand: 'shieldcortex repair',
        confidence: 'high',
      },
    };
    const text = formatAiSection(outcome).join('\n');
    expect(text).toMatch(/hypothesis/i);
    expect(text).toContain('shieldcortex repair');
    expect(text).toContain(failResult.label);
    expect(text).toContain(warnResult.label);
    // Requirement #2, made visible to the operator, not just enforced in code:
    // the printed section itself must say this changes nothing.
    expect(text).toMatch(/not a diagnosis|verify before/i);
  });
});

describe('doctor.ts never executes what the explainer suggests (requirement #2)', () => {
  it('the suggestedCommand field is never passed to a process-executing call anywhere in doctor.ts or doctor-explainer.ts', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const here = path.dirname(new URL(import.meta.url).pathname);
    const sources = [
      fs.readFileSync(path.join(here, '..', 'doctor.ts'), 'utf8'),
      fs.readFileSync(path.join(here, '..', '..', 'defence', 'iron-dome', 'doctor-explainer.ts'), 'utf8'),
    ];
    for (const src of sources) {
      // A regression here would look like `exec(result.suggestedCommand)` or
      // similar — assert the string "suggestedCommand" never appears within
      // ~60 chars of an exec/spawn call.
      const execCalls = [...src.matchAll(/exec(?:Sync|File|FileSync)?\s*\(|spawn(?:Sync)?\s*\(/g)];
      for (const m of execCalls) {
        const windowStart = Math.max(0, (m.index ?? 0) - 200);
        const windowEnd = Math.min(src.length, (m.index ?? 0) + 200);
        expect(src.slice(windowStart, windowEnd)).not.toMatch(/suggestedCommand/);
      }
    }
  });
});
