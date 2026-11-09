/**
 * #1014 r3 — the default report classifies a warning by what the check SAID,
 * never by its label or by the absence of a command.
 *
 * Two reviews of #1041 found the first cut filing diagnoses under EXPECTED ON
 * THIS HOST (no action): any Action Guard row without a command became
 * "Action Guard off", any row whose label said dual-plane became "Native agent
 * memory stays primary", a cause in backticks (`sudo shieldcortex …`) printed
 * as a `$` line, and the tampered-config fix printed the forbidden
 * `config --*` as the thing to run while dropping its "Do not re-run".
 *
 * These tests drive the real producers (approve-tap, plane-drift, policy-lock,
 * the database probe) and the one row doctor.ts builds inline (posture read
 * error), and assert each diagnosis keeps its own label, reason and remedy
 * under TO FIX while the positively by-design rows still go to EXPECTED.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  cleanWhy,
  extractFixCommands,
  formatDoctorReport,
  groupItems,
  type DoctorReportItem,
} from '../doctor-report.js';
import { formatDoctorExplain, isByDesignWarning, warnTier } from '../doctor-plain.js';
import { runDatabaseCheck } from '../doctor.js';
import { approveTapDoctorRow } from '../../defence/iron-dome/approve-tap.js';
import { describePolicyLock } from '../../defence/iron-dome/policy-lock.js';
import { evaluatePlaneDrift, type PlaneDriftInput } from '../../memory/plane-drift.js';
import { GUARD_POSTURE_LABEL } from '../../guard/posture-switch.js';

const render = (rows: DoctorReportItem[], verbose = false): string =>
  formatDoctorReport(rows, { width: 100, color: false, verbose }).join('\n');

const PLAIN = { bold: '', reset: '', green: '', yellow: '', red: '', cyan: '', dim: '' };

/** The default report lists the row under TO FIX with its label and its own message. */
function expectUnderToFix(text: string, row: DoctorReportItem): void {
  expect(text).toMatch(/^TO FIX$/m);
  expect(text).toMatch(/1 thing to fix/);
  expect(text).toContain(` 1. ${row.label}  [`);
  // The first clause of the message, as the report prints it (no backticks).
  const clause = cleanWhy(row.message).split(/[—(]/)[0]!.trim().slice(0, 60);
  expect(text.replace(/\s+/g, ' ')).toContain(clause);
  expect(text).not.toMatch(/EXPECTED ON THIS HOST/);
}

describe('#1014 r3 — Action Guard rows that are not "Guard off by choice" stay under TO FIX', () => {
  it('one-tap approve switched on with nobody to approve: own label and reason, not "Action Guard off"', () => {
    const tap = approveTapDoctorRow({ enabled: true }, { agentUid: 1000, platform: 'linux' });
    expect(tap).toMatchObject({ status: 'warn' });
    expect(tap!.message).toMatch(/approverTelegramUid/);
    const row: DoctorReportItem = { label: 'Action guard one-tap approve', ...tap! };
    const text = render([row]);
    expectUnderToFix(text, row);
    expect(text).toMatch(/One-tap approve is OFF: actionGuard\.approveTap\.approverTelegramUid is not set/);
    expect(text).not.toMatch(/Action Guard off|Healthy \| nothing to fix/);
    expect(warnTier(groupItems([row], true)[0]!)).toBe('fix');
  });

  it('one-tap approve switched on but the secret is world-readable: the chmod remedy prints', () => {
    const tap = approveTapDoctorRow(
      { enabled: true, secretPath: '/srv/bridge/approve.secret', approverTelegramUid: 123456 },
      {
        agentUid: 1000,
        platform: 'linux',
        lstat: () => ({ uid: 2000, mode: 0o100644, isFile: true, isSymbolicLink: false }),
      },
    );
    expect(tap).toMatchObject({ status: 'warn', fix: 'chmod 600 the approve secret.' });
    const row: DoctorReportItem = { label: 'Action guard one-tap approve', ...tap! };
    const text = render([row]);
    expectUnderToFix(text, row);
    const flat = text.replace(/\s+/g, ' ');
    expect(flat).toMatch(/can be read or written by other users/);
    expect(flat).toMatch(/chmod 600 the approve secret/);
  });

  it('the posture could not be read: a read error with its errno, not "Action Guard off"', () => {
    // The catch row in doctor.ts checkGuardPosture, verbatim.
    const row: DoctorReportItem = {
      label: GUARD_POSTURE_LABEL,
      status: 'warn',
      message: 'the Action Guard posture could not be read (EACCES)',
    };
    const text = render([row]);
    expectUnderToFix(text, row);
    expect(text).toMatch(/could not be read \(EACCES\)/);
    expect(text).not.toMatch(/Action Guard off/);
    // --explain expected must not list it either.
    expect(formatDoctorExplain([row], 'expected', { width: 100, style: PLAIN }).join('\n')).toMatch(/^No check with id/);
  });

  it('no policy lock is possible on this host: the unsupported reason prints, not "Policy lock not set"', () => {
    const summary = describePolicyLock({
      status: 'unsupported',
      path: null,
      reason: 'running-as-root',
      detail: 'the agent runs as root, so no root-owned file is out of its reach',
    });
    expect(summary.headline).toMatch(/^no policy lock is possible on this host/);
    // The row doctor.ts pushes for summary.status === 'unsupported': no fix on purpose.
    const row: DoctorReportItem = { label: 'Action guard policy lock', status: 'warn', message: summary.headline };
    const text = render([row]);
    expectUnderToFix(text, row);
    expect(text).toMatch(/no policy lock is possible on this host/);
    expect(text).toMatch(/runs as root/);
    expect(text).not.toMatch(/Policy lock not set/);
  });

  it('a Guard-theme warning with no fix at all is never by design', () => {
    for (const label of ['Action guard posture', 'Action guard notify', 'Action guard policy lock', 'Action guard one-tap approve']) {
      const g = groupItems([{ label, status: 'warn', message: 'something doctor could not establish' }], true)[0]!;
      expect({ label, byDesign: isByDesignWarning(g), tier: warnTier(g) }).toEqual({ label, byDesign: false, tier: 'fix' });
    }
  });
});

describe('#1014 r3 — dual-plane drift: by-design dual_legacy versus a failed delivery or missing telemetry', () => {
  const LABEL = 'Memory plane (dual-plane drift)';
  const base: PlaneDriftInput = {
    plane: 'sc_canonical',
    planeSetAt: null,
    injectOn: true,
    requireScope: true,
    counts: { durableAdmits7d: null, durableRows: null, injectable: null, unscopedExcluded: null, activity7d: null },
    native: { touched7d: false, touchedPaths: [], bytes: 0, unattestable: [], busActive: [] },
    nowMs: Date.parse('2026-11-09T00:00:00Z'),
  };
  const rowFor = (input: PlaneDriftInput): DoctorReportItem => {
    const v = evaluatePlaneDrift(input);
    return { label: LABEL, status: v.status, message: v.message, ...(v.fix ? { fix: v.fix } : {}) };
  };

  it('(a) sc_canonical with no telemetry: "cannot determine drift" and its restore-the-telemetry fix stay visible', () => {
    const row = rowFor(base);
    expect(row).toMatchObject({ status: 'warn' });
    expect(row.message).toMatch(/cannot determine drift/);
    const text = render([row]);
    expectUnderToFix(text, row);
    expect(text).toMatch(/cannot determine drift/);
    expect(text).toMatch(/Restore the missing telemetry/);
    expect(text).not.toMatch(/Native agent memory stays primary|Native memory is still the brain/);
    // --verbose prints the row's own fix too, not the canned dual_legacy sentence.
    const verbose = render([row], true);
    expect(verbose).toMatch(/Restore the missing telemetry/);
    expect(verbose).not.toMatch(/Native memory is still the brain/);
  });

  it('(b) dual_legacy holding rows the inject gate admits none of: the delivery defect and its fix stay visible', () => {
    const row = rowFor({
      ...base,
      plane: 'dual_legacy',
      counts: { durableAdmits7d: 5, durableRows: 40, injectable: 0, unscopedExcluded: 0, activity7d: 3 },
    });
    expect(row).toMatchObject({ status: 'warn' });
    expect(row.message).toMatch(/SC holds 40 durable row\(s\) but real inject eligibility admits none/);
    const text = render([row]);
    expectUnderToFix(text, row);
    expect(text).toMatch(/the SC bus delivers nothing/);
    expect(text).toMatch(/Fix the rows, not the doctor/);
    expect(text).not.toMatch(/Native agent memory stays primary|\$ shieldcortex memories import-native/);
  });

  it('(c) dual_legacy with the native brain still growing: the producer says it is expected, so EXPECTED it is', () => {
    const row = rowFor({
      ...base,
      plane: 'dual_legacy',
      counts: { durableAdmits7d: 2, durableRows: 10, injectable: 4, unscopedExcluded: 0, activity7d: 3 },
      native: { ...base.native, touched7d: true, touchedPaths: ['~/.claude/MEMORY.md'] },
    });
    expect(row.fix).toMatch(/Expected on dual_legacy/);
    const text = render([row]);
    expect(text).toMatch(/Healthy \| nothing to fix/);
    expect(text).not.toMatch(/TO FIX/);
    expect(text).toMatch(/EXPECTED ON THIS HOST \(no action\)\n - Native agent memory stays primary/);
  });

  it('the probe-error row doctor.ts builds in its catch (no fix) is a diagnosis', () => {
    const row: DoctorReportItem = { label: LABEL, status: 'warn', message: 'plane=dual_legacy: cannot determine drift — SQLITE_BUSY: database is locked' };
    const text = render([row]);
    expectUnderToFix(text, row);
    expect(text).toMatch(/SQLITE_BUSY/);
  });
});

describe('#1014 r3 — only real remedies print as $ lines', () => {
  it('a truncated cause in backticks is not a command; the restore-ownership steps are', () => {
    const fix = 'Those paths exist but this user cannot read them — almost always ShieldCortex state owned by another '
      + 'user, typically root, left behind by one `sudo shieldcortex …` run. Restore ownership: '
      + '`sudo chown -R "$USER" ~/.shieldcortex` (also `~/.claude-memory` on a legacy install), then re-run `shieldcortex doctor`.';
    expect(extractFixCommands(fix)).toEqual(['sudo chown -R "$USER" ~/.shieldcortex', 'shieldcortex doctor']);
  });

  it('a wildcard over flags is never a command, nor is a command the sentence says not to run', () => {
    expect(extractFixCommands('Do not re-run `shieldcortex config --*` flags. Then `shieldcortex config --resign`.'))
      .toEqual(['shieldcortex config --resign']);
    expect(extractFixCommands("Don't run `shieldcortex repair` for this; run `shieldcortex doctor --verbose` instead."))
      .toEqual(['shieldcortex doctor --verbose']);
    // A "do not" in an EARLIER sentence does not hide the command that follows.
    expect(extractFixCommands('Do not panic. Run `shieldcortex setup claude`.')).toEqual(['shieldcortex setup claude']);
  });

  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const describeUnprivileged = isRoot ? describe.skip : describe;
  describeUnprivileged('the real ownership row', () => {
    let tmp: string;
    let scDir: string;
    beforeEach(() => {
      tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1014-r3-'));
      scDir = path.join(tmp, '.shieldcortex');
      fs.mkdirSync(scDir);
      fs.writeFileSync(path.join(scDir, 'memories.db'), '');
      fs.chmodSync(scDir, 0o000);
    });
    afterEach(() => {
      try { fs.chmodSync(scDir, 0o755); } catch { /* gone */ }
      fs.rmSync(tmp, { recursive: true, force: true });
    });

    it('prints the chown first, never "$ sudo shieldcortex …"', () => {
      const env = { hasClaude: true, hasOpenClaw: false, hasVSCode: false, hasCodex: false, isHeadless: false };
      const row = runDatabaseCheck(path.join(scDir, 'memories.db'), env as Parameters<typeof runDatabaseCheck>[1]);
      expect(row.status).toBe('fail');
      expect(row.fix).toMatch(/sudo shieldcortex …/);
      for (const verbose of [false, true]) {
        const text = formatDoctorReport([row], { width: 100, color: false, verbose }).join('\n');
        const dollar = text.split('\n').filter((l) => /^\s+\$ /.test(l)).map((l) => l.trim());
        expect(dollar).toEqual(['$ sudo chown -R "$USER" ~/.shieldcortex', '$ shieldcortex doctor']);
      }
    });
  });
});
