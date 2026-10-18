/** #795/#834: identify the old startup project backfill and gate the doctor warning on #674. */
import { afterEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { initDatabase, closeDatabase } from '../../../database/init.js';
import { logAudit } from '../../audit/logger.js';
import { __resetLedgerStateForTests } from '../chain.js';
import {
  allProblemsAreLegacyProjectBackfill,
  formatLedgerReport,
  summariseLedgerReport,
  verifyLedger,
} from '../verify.js';
import { checkChainedLedger } from '../../../cli/doctor.js';
import { runLedgerCommand } from '../../../cli/ledger.js';

const dirs: string[] = [];
const oldFix = 'Run `shieldcortex ledger verify` for the full report; the audit history in this database was edited or rows were removed';

afterEach(() => {
  closeDatabase();
  __resetLedgerStateForTests();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function chainedDb(project: string | null = null): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'sc-ledger-795-'));
  dirs.push(dir);
  const dbPath = path.join(dir, 'memories.db');
  initDatabase(dbPath);
  for (let i = 0; i < 3; i++) {
    expect(logAudit({
      memory_id: null, project, timestamp: new Date().toISOString(),
      source_type: 'cli', source_identifier: 'ledger-795', trust_score: 0.9,
      sensitivity_level: 'INTERNAL', firewall_result: 'ALLOW', operation: 'write',
      anomaly_score: 0, threat_indicators: '[]', blocked_patterns: '[]',
      reason: `row ${i}`, fragmentation_score: null, pipeline_duration_ms: null,
    })).toBeGreaterThan(0);
  }
  closeDatabase();
  return dbPath;
}

function edit(dbPath: string, sql: string): void {
  const db = new Database(dbPath);
  try {
    // A current installation protects this column; recreate the state left by
    // the older copy before #674's trigger existed.
    db.exec('DROP TRIGGER trg_defence_audit_chained_project_immutable');
    db.exec(sql);
  } finally {
    db.close();
  }
}

function reopenWithCurrentBuild(dbPath: string): void {
  initDatabase(dbPath);
  closeDatabase();
}

function hasProtectingTrigger(dbPath: string): boolean {
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='trg_defence_audit_chained_project_immutable'").get();
  } finally {
    db.close();
  }
}

function reportFor(dbPath: string) {
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  try { return verifyLedger(db); } finally { db.close(); }
}

function withoutCauses(report: ReturnType<typeof reportFor>): ReturnType<typeof reportFor> {
  const copy = structuredClone(report);
  for (const problem of copy.problems) delete problem.cause;
  if (copy.firstBad) delete copy.firstBad.cause;
  return copy;
}

async function expectMixedOutputMatchesOrdinary(dbPath: string): Promise<void> {
  const report = reportFor(dbPath);
  const ordinary = withoutCauses(report);
  const doctor = await checkChainedLedger({ dbPath });
  expect(allProblemsAreLegacyProjectBackfill(report)).toBe(false);
  for (const problem of report.problems) {
    if (problem.cause === 'legacy-project-backfill') {
      expect(problem.detail).toBe('row content no longer matches its content_digest (defence_audit)');
    }
  }
  expect(summariseLedgerReport(report)).toBe(summariseLedgerReport(ordinary));
  expect(formatLedgerReport(report)).toBe(formatLedgerReport(ordinary));
  expect(doctor.message).toBe(summariseLedgerReport(ordinary));
  expect(doctor.fix).toBe(oldFix);
  for (const output of [summariseLedgerReport(report), formatLedgerReport(report), doctor.message, doctor.fix ?? '']) {
    expect(output).not.toMatch(/legacy|older ShieldCortex|likely cause/i);
  }
}

function jsonCommand(dbPath: string): { code: number; report: ReturnType<typeof reportFor> } {
  const out: string[] = [];
  const code = runLedgerCommand(['verify', '--json', '--db', dbPath], {
    stdout: (s) => out.push(s), stderr: () => undefined,
  });
  return { code, report: JSON.parse(out.join('')) as ReturnType<typeof reportFor> };
}

describe('legacy project backfill diagnosis (#795)', () => {
  it('names every null-to-project edit while keeping the ledger inconsistent and read-only', async () => {
    const dbPath = chainedDb();
    edit(dbPath, "UPDATE defence_audit SET project = 'legacy' WHERE seq IS NOT NULL");
    const before = readFileSync(dbPath);
    const report = reportFor(dbPath);
    expect(report.status).toBe('inconsistent');
    expect(report.problems).toHaveLength(3);
    expect(report.problems.every((p) => p.kind === 'digest-mismatch' && p.cause === 'legacy-project-backfill')).toBe(true);
    expect(report.problems.some((p) => p.kind === 'prev-hash-mismatch')).toBe(false);
    expect(report.problems[0].detail).toBe('row content no longer matches its content_digest (defence_audit)');
    // memory_id is outside AUDIT_CONTENT_FIELDS, so the digest cannot vouch for "nothing else".
    for (const p of report.problems) expect(p.detail).toBe('row content no longer matches its content_digest (defence_audit)');
    expect(allProblemsAreLegacyProjectBackfill(report)).toBe(true);
    expect(summariseLedgerReport(report)).toMatch(/row matches its digest once project is reset to NULL; likely cause: an older ShieldCortex copy/);
    expect(summariseLedgerReport(report)).toMatch(/every problem is likely explained by a legacy project backfill/i);
    expect(summariseLedgerReport(report)).toMatch(/no digest field other than project changed/);
    expect(formatLedgerReport(report)).toContain('[cause: legacy-project-backfill]');
    expect(formatLedgerReport(report)).toMatch(/likely cause: an older ShieldCortex copy/i);
    expect(formatLedgerReport(report)).toMatch(/find and remove or upgrade the old copy before any repair/i);
    expect(formatLedgerReport(report)).toContain('no digest field other than `project` changed in those rows');
    const cli = jsonCommand(dbPath);
    expect(cli.code).toBe(1);
    expect(cli.report.problems.every((p) => p.cause === 'legacy-project-backfill')).toBe(true);
    const doctor = await checkChainedLedger({ dbPath });
    expect(hasProtectingTrigger(dbPath)).toBe(false);
    expect(doctor.status).toBe('fail');
    expect(doctor.message).toMatch(/likely cause: an older ShieldCortex copy/);
    expect(doctor.fix).toMatch(/3 problem\(s\) are explained by a legacy project backfill/i);
    expect(doctor.fix).toMatch(/likely cause: an older ShieldCortex copy/i);
    expect(doctor.fix).toMatch(/older ShieldCortex copy \(5\.2\.1 or earlier\).*global install and npx cache/i);
    expect(doctor.fix).toContain('no digest field other than `project` changed in those rows');
    expect(doctor.fix).toMatch(/protecting trigger is missing.*cause can recur/i);
    expect(doctor.fix).toMatch(/current ShieldCortex \(5\.10\.2 or later\) recreates it/i);
    expect(doctor.fix).not.toBe(oldFix);
    for (const text of [summariseLedgerReport(report), formatLedgerReport(report), doctor.fix ?? '', ...report.problems.map((p) => p.detail)]) {
      expect(text).not.toMatch(/nothing else/i);
    }
    expect(readFileSync(dbPath).equals(before)).toBe(true);
  });

  it('warns for an explained backfill after a current build restores the trigger without changing the database', async () => {
    const dbPath = chainedDb();
    edit(dbPath, "UPDATE defence_audit SET project = 'legacy' WHERE seq IS NOT NULL");
    reopenWithCurrentBuild(dbPath);
    expect(hasProtectingTrigger(dbPath)).toBe(true);
    const before = readFileSync(dbPath);
    const report = reportFor(dbPath);
    expect(report.status).toBe('inconsistent');
    expect(report.problems).toHaveLength(3);
    expect(allProblemsAreLegacyProjectBackfill(report)).toBe(true);
    const doctor = await checkChainedLedger({ dbPath });
    expect(doctor.status).toBe('warn');
    expect(doctor.message).toBe(summariseLedgerReport(report));
    expect(`${doctor.message} ${doctor.fix}`).toMatch(/3 problem\(s\)/i);
    expect(doctor.fix).toMatch(/explained by a legacy project backfill.*older ShieldCortex copy \(5\.2\.1 or earlier\)/i);
    expect(doctor.fix).toMatch(/cannot recur.*trigger now refuses those changes/i);
    expect(doctor.fix).toMatch(/find and remove or upgrade the old copy/i);
    expect(`${doctor.message} ${doctor.fix}`).not.toMatch(/repair command|ledger repair|before running any repair/i);
    expect(readFileSync(dbPath).equals(before)).toBe(true);
  });

  it('keeps the original doctor fix when a non-project column also changed', async () => {
    const dbPath = chainedDb();
    edit(dbPath, "UPDATE defence_audit SET project = 'legacy' WHERE seq IS NOT NULL; UPDATE defence_audit SET reason = 'edited' WHERE seq = 2");
    const report = reportFor(dbPath);
    expect(report.status).toBe('inconsistent');
    expect(report.problems.filter((p) => p.cause === 'legacy-project-backfill')).toHaveLength(2);
    expect(report.problems.find((p) => p.seq === 2)).toMatchObject({ kind: 'digest-mismatch' });
    expect(report.problems.find((p) => p.seq === 2)?.cause).toBeUndefined();
    expect(allProblemsAreLegacyProjectBackfill(report)).toBe(false);
    reopenWithCurrentBuild(dbPath);
    expect(hasProtectingTrigger(dbPath)).toBe(true);
    await expectMixedOutputMatchesOrdinary(dbPath);
  });

  it('uses ordinary output when the first bad row qualifies but a later row does not', async () => {
    const dbPath = chainedDb();
    edit(dbPath, "UPDATE defence_audit SET project = 'legacy' WHERE seq IS NOT NULL; UPDATE defence_audit SET reason = 'edited' WHERE seq = 3");
    const report = reportFor(dbPath);
    expect(report.firstBad).toMatchObject({ seq: 1, cause: 'legacy-project-backfill' });
    expect(report.problems.filter((p) => p.cause === 'legacy-project-backfill')).toHaveLength(2);
    reopenWithCurrentBuild(dbPath);
    expect(hasProtectingTrigger(dbPath)).toBe(true);
    await expectMixedOutputMatchesOrdinary(dbPath);
  });

  it('does not attribute a change to project when it was non-null at write time', () => {
    const dbPath = chainedDb('original');
    edit(dbPath, "UPDATE defence_audit SET project = 'changed' WHERE seq = 1");
    const report = reportFor(dbPath);
    expect(report.status).toBe('inconsistent');
    expect(report.problems).toHaveLength(1);
    expect(report.problems[0]).toMatchObject({ kind: 'digest-mismatch', seq: 1 });
    expect(report.problems[0].cause).toBeUndefined();
    expect(allProblemsAreLegacyProjectBackfill(report)).toBe(false);
  });

  it('fails for a non-backfill edit with the protecting trigger present', async () => {
    const dbPath = chainedDb();
    const db = new Database(dbPath);
    try { db.exec("UPDATE defence_audit SET reason = 'edited' WHERE seq = 1"); } finally { db.close(); }
    const report = reportFor(dbPath);
    expect(hasProtectingTrigger(dbPath)).toBe(true);
    expect(report.status).toBe('inconsistent');
    expect(allProblemsAreLegacyProjectBackfill(report)).toBe(false);
    const doctor = await checkChainedLedger({ dbPath });
    expect(doctor.status).toBe('fail');
    expect(doctor.fix).toBe(oldFix);
  });

  it('still reports a bad row hash when the project-null digest matches', () => {
    const dbPath = chainedDb();
    edit(dbPath, "UPDATE defence_audit SET project = 'legacy' WHERE seq = 1; UPDATE defence_audit SET row_hash = 'broken' WHERE seq = 1");
    const report = reportFor(dbPath);
    expect(report.problems.filter((p) => p.seq === 1)).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'digest-mismatch', cause: 'legacy-project-backfill' }),
      expect.objectContaining({ kind: 'row-hash-mismatch' }),
    ]));
    expect(report.problems.find((p) => p.kind === 'row-hash-mismatch')?.cause).toBeUndefined();
    expect(allProblemsAreLegacyProjectBackfill(report)).toBe(false);
  });

  it('does not assign the cause to a null-project audit edit or a marker edit', () => {
    const dbPath = chainedDb();
    const db = new Database(dbPath);
    try {
      db.exec("UPDATE defence_audit SET reason = 'edited' WHERE seq = 1; UPDATE ledger_marker SET payload = '{\"reason\":\"edited\"}' WHERE seq = 0");
    } finally {
      db.close();
    }
    const report = reportFor(dbPath);
    expect(report.problems.filter((p) => p.kind === 'digest-mismatch')).toHaveLength(2);
    expect(report.problems.every((p) => p.cause === undefined)).toBe(true);
    expect(allProblemsAreLegacyProjectBackfill(report)).toBe(false);
  });

  it('leaves a clean ledger and its output unchanged', async () => {
    const dbPath = chainedDb();
    const report = reportFor(dbPath);
    expect(report.status).toBe('consistent');
    expect(report.problems).toEqual([]);
    expect(allProblemsAreLegacyProjectBackfill(report)).toBe(false);
    expect(summariseLedgerReport(report)).toMatch(/^consistent —/);
    expect(formatLedgerReport(report)).toMatch(/^Chained ledger: CONSISTENT/);
    expect(formatLedgerReport(report)).not.toContain('legacy-project-backfill');
    expect(jsonCommand(dbPath).report.problems).toEqual([]);
    expect((await checkChainedLedger({ dbPath })).status).toBe('pass');
  });
});
