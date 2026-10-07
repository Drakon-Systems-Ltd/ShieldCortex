/**
 * #649 — the DISK row names the largest measured consumer, even when it is not
 * a majority, and says about it only what the measurement supports.
 *
 * THE REPORT. `117 MB / 100 MB limit — at limit!` with DB 62.1 MB (20 KB of
 * free pages), audit 50.1 MB, repair logs 1.4 MB, other logs 445 KB, backups
 * 320 KB — and the remedy said "No single measured consumer", because only a
 * ≥50% repair-log or audit share ever got its own text. A database holding
 * over half the budget fell through to the same line as a three-way tie.
 *
 * What must hold, and what must NOT be "fixed" along the way:
 *   - the biggest budgeted term is named whether or not it is a majority, and
 *     ties name every tied term;
 *   - backups and the model cache stay exempt and are never "the" consumer;
 *   - free pages are reusable space inside the file, not filesystem space —
 *     nothing claims the disk is full or that saves will fail;
 *   - no consolidate / deletion / archive advice, and nothing offered against
 *     audit evidence (#579 has no supported prune);
 *   - the ≥20% free-page `vacuum` guard and the dry-run-first `logs prune`
 *     advice are unchanged.
 *
 * Fixtures are scaled from the report's ratios to KB rather than written at
 * 100 MB, using the `limitBytes` parameter the other disk suites use.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import { checkDiskUsage } from '../doctor.js';
import { formatDoctorReport } from '../doctor-report.js';

const KB = 1024;
let scDir: string;

/** Every remedy the row must never reach for on these fixtures. */
const UNSAFE_ADVICE = /memories prune|memories dedupe|memories clear|sessions prune|consolidat|archive|rotate|rm -|delete (the|your|old)/i;
/** The claim a small freelist does not support. */
const FALSE_EXHAUSTION = /may fail to save|disk is full|out of (disk )?space|no space left/i;

beforeEach(() => {
  scDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-649-disk-'));
});

afterEach(() => {
  try { fs.rmSync(scDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

function writeBytes(rel: string, bytes: number): void {
  const full = path.join(scDir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, Buffer.alloc(bytes, 0x61));
}

function repairLogs(count: number, bytesEach: number): void {
  for (let i = 0; i < count; i++) {
    writeBytes(
      path.join('logs', `project-key-repair-2026-01-01T00-00-${String(i).padStart(2, '0')}-000Z.json`),
      bytesEach,
    );
  }
}

/** A real SQLite file of ~`bytes` content; `freedBytes` written then deleted. */
function buildDb(bytes: number, freedBytes = 0): number {
  const dbPath = path.join(scDir, 'memories.db');
  const db = new Database(dbPath);
  db.prepare('BEGIN').run();
  db.prepare('CREATE TABLE memories (id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT NOT NULL)').run();
  const ins = db.prepare('INSERT INTO memories (content) VALUES (?)');
  const chunk = 2048;
  for (let written = 0; written < bytes; written += chunk) ins.run('m'.repeat(chunk));
  if (freedBytes > 0) {
    const before = db.prepare('SELECT MAX(id) AS m FROM memories').get() as { m: number };
    for (let written = 0; written < freedBytes; written += chunk) ins.run('f'.repeat(chunk));
    db.prepare('DELETE FROM memories WHERE id > ?').run(before.m);
  }
  db.prepare('COMMIT').run();
  db.close();
  return fs.statSync(dbPath).size;
}

function expectSafe(fix: string | undefined): void {
  expect(fix).toBeDefined();
  expect(fix).not.toMatch(UNSAFE_ADVICE);
  expect(fix).not.toMatch(FALSE_EXHAUSTION);
  // Bounded: one paragraph, not a listing.
  expect((fix ?? '').length).toBeLessThan(900);
}

describe('#649 the issue shape: a majority database with almost no free pages', () => {
  it('names the database as the largest consumer instead of "No single measured consumer"', async () => {
    const db = buildDb(400 * KB);
    // Scale every other term from the report's MB figures, relative to DB 62.1.
    const unit = db / 62.1;
    writeBytes('audit/realtime-2026-01-01.jsonl', Math.round(50.1 * unit));
    repairLogs(2, Math.round((1.4 * unit) / 2));
    writeBytes('logs/other.log', Math.round(0.445 * unit));
    writeBytes('memories.db.bak.2026-01-01T00-00-00-000Z', Math.round(0.32 * unit));

    const result = await checkDiskUsage(scDir, Math.round(100 * unit));

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(/No single measured consumer/);
    expect(result.fix).toMatch(/^Largest measured consumer: the database, .* counted against the limit \(5\d%\)\./);
    // The free-page figure is reported as what it is, and does not draw vacuum.
    expect(result.fix).toMatch(/free pages/);
    expect(result.fix).toMatch(/not free disk space/);
    expect(result.fix).not.toMatch(/shieldcortex vacuum/);
    // The budget is not the filesystem.
    expect(result.fix).toMatch(/not a measurement of free space on the filesystem/);
    // Audit is the runner-up at ~44%: named, with #579, and no command.
    expect(result.fix).toContain('#579');
    expect(result.fix).not.toMatch(/logs prune/);
    // Backups are visible and exempt, never blamed.
    expect(result.fix).toMatch(/Backups \(.*\) are exempt from the limit/);
    expect(result.fix).toMatch(/inspect before removing anything/);
    expectSafe(result.fix);
  });

  it('reports a small but non-zero freelist without calling it reclaimable disk space', async () => {
    buildDb(300 * KB, 8 * KB);

    const result = await checkDiskUsage(scDir, 200 * KB);

    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/DB .*\((?!0 B)\d+(\.\d)? KB free\)/);
    expect(result.fix).toMatch(/^Largest measured consumer: the database/);
    expect(result.fix).toMatch(/below the 20% where compacting is worth a full rewrite/);
    expect(result.fix).not.toMatch(/shieldcortex vacuum/);
    expectSafe(result.fix);
  });

  it('reports a zero freelist honestly', async () => {
    buildDb(300 * KB);

    const result = await checkDiskUsage(scDir, 200 * KB);

    expect(result.fix).toMatch(/Only 0 B of the database \(0% of its pages\) is free pages/);
    expect(result.fix).not.toMatch(/shieldcortex vacuum/);
    expectSafe(result.fix);
  });
});

describe('#649 biggest bucket is not the same thing as majority', () => {
  it('names the largest term even when it holds under half', async () => {
    writeBytes('memories.db', 40 * KB);
    writeBytes('audit/realtime-2026-01-01.jsonl', 30 * KB);
    writeBytes('state/worker.json', 30 * KB);

    const result = await checkDiskUsage(scDir, 64 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/^Largest measured consumer: the database, 40\.0 KB of the 100\.0 KB .*\(40%\)/);
    expect(result.fix).toMatch(/Then audit evidence 30\.0 KB, everything else 30\.0 KB\./);
    expectSafe(result.fix);
  });

  it('names every tied term, not an arbitrary one', async () => {
    writeBytes('memories.db', 20 * KB);
    writeBytes('audit/realtime-2026-01-01.jsonl', 20 * KB);
    writeBytes('state/worker.json', 20 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.fix).toMatch(
      /^Largest measured consumers, tied: the database and audit evidence and everything else, 20\.0 KB each .*\(33% each\)/,
    );
    expect(result.fix).toContain('#579');
    expect(result.fix).not.toMatch(/shieldcortex vacuum|logs prune/);
    expectSafe(result.fix);
  });
});

describe('#649 unmeasurable and exempt terms', () => {
  it('says the free pages could not be read when the DB does not open, and names no command', async () => {
    writeBytes('memories.db', 60 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.fix).toMatch(/^Largest measured consumer: the database/);
    expect(result.fix).toMatch(/free pages could not be read/);
    expect(result.fix).not.toMatch(/shieldcortex vacuum|logs prune|sqlite3 /);
    expectSafe(result.fix);
  });

  it('never makes a huge exempt backup or model cache "the" consumer', async () => {
    writeBytes('memories.db', 40 * KB);
    writeBytes('memories.db.pre-backfill-1700000000000', 1000 * KB);
    writeBytes('models/embed/model.onnx', 2000 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/^Largest measured consumer: the database, 40\.0 KB of the 40\.0 KB/);
    expect(result.fix).toMatch(/Backups \(1000\.0 KB\) are exempt from the limit/);
    expect(result.fix).not.toMatch(/models/);
    expectSafe(result.fix);
  });
});

describe('#649 audit evidence: reported, never acted on', () => {
  it('audit-only keeps the #579 text and offers no command', async () => {
    writeBytes('audit/realtime-2026-01-01.jsonl', 60 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.fix).toContain('#579');
    expect(result.fix).not.toMatch(/logs prune|shieldcortex vacuum/);
    expectSafe(result.fix);
  });

  it('a largest-but-not-majority audit plane gets #579 and no command', async () => {
    writeBytes('memories.db', 25 * KB);
    writeBytes('audit/realtime-2026-01-01.jsonl', 40 * KB);
    writeBytes('state/worker.json', 35 * KB);

    const result = await checkDiskUsage(scDir, 64 * KB);

    expect(result.fix).toMatch(/^Largest measured consumer: audit evidence/);
    expect(result.fix).toMatch(/no automatic retention yet \(#579\), and nothing here deletes it/);
    expect(result.fix).not.toMatch(/logs prune|shieldcortex vacuum/);
    expectSafe(result.fix);
  });
});

describe('#649 the existing command-backed remedies are unchanged', () => {
  it('a genuine ≥20% free-page database still gets vacuum', async () => {
    buildDb(100 * KB, 400 * KB);

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.fix).toMatch(/shieldcortex vacuum/);
    expect(result.fix).not.toMatch(/^Largest measured consumer/);
    expectSafe(result.fix);
  });

  it('majority repair logs still get dry-run, then --execute', async () => {
    writeBytes('memories.db', 4 * KB);
    repairLogs(30, 2 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.fix).toMatch(/Run `shieldcortex logs prune` to see what retention would remove, then `shieldcortex logs prune --execute`/);
    expectSafe(result.fix);
  });

  it('largest-but-not-majority repair logs get the dry run only', async () => {
    writeBytes('memories.db', 25 * KB);
    writeBytes('state/worker.json', 30 * KB);
    repairLogs(20, 2 * KB);

    const result = await checkDiskUsage(scDir, 64 * KB);

    expect(result.fix).toMatch(/^Largest measured consumer: repair logs/);
    expect(result.fix).toMatch(/`shieldcortex logs prune` \(without --execute\)/);
    expect(result.fix).not.toMatch(/logs prune --execute/);
    expect(result.fix).toMatch(/never touches audit evidence/);
    expectSafe(result.fix);
  });

  it('a footprint under the limit gets no remedy at all', async () => {
    writeBytes('memories.db', 10 * KB);

    const result = await checkDiskUsage(scDir, 100 * KB);

    expect(result.status).toBe('pass');
    expect(result.fix).toBeUndefined();
  });
});

/**
 * #649 round 2 — the paragraph above has to reach the human report. The
 * formatter lifts backticked commands out of `fix` and, when it finds any,
 * prints ONLY those. The fallback's dry-run note made it find one, so the
 * operator saw `$ shieldcortex logs prune` and none of the attribution, ties,
 * free-page or scope text. These go through the real renderer, color off,
 * in both the default (collapsed) and --verbose layouts.
 */
describe('#649 the fallback survives the human report', () => {
  function render(result: Awaited<ReturnType<typeof checkDiskUsage>>, verbose: boolean): string {
    return formatDoctorReport([result], { verbose, width: 200, color: false })
      .join('\n');
  }
  /** Rendered text with wrapping and indentation collapsed. */
  function flat(text: string): string {
    return text.replace(/\s+/g, ' ');
  }

  for (const verbose of [false, true]) {
    const mode = verbose ? 'verbose' : 'default';

    it(`${mode}: non-majority repair logs keep attribution, scope and the dry run`, async () => {
      writeBytes('memories.db', 25 * KB);
      writeBytes('state/worker.json', 30 * KB);
      repairLogs(20, 2 * KB);

      const result = await checkDiskUsage(scDir, 64 * KB);
      expect(result.fix).toMatch(/^Largest measured consumer: repair logs/);
      const out = render(result, verbose);
      const text = flat(out);

      expect(text).toMatch(/Largest measured consumer: repair logs, 40\.0 KB of the 95\.0 KB counted against the limit \(42%\)\./);
      expect(text).toMatch(/Then everything else 30\.0 KB, the database 25\.0 KB\./);
      expect(text).toMatch(/shieldcortex logs prune \(without --execute\) lists which project-key repair logs retention would remove; it never touches audit evidence/);
      expect(text).toMatch(/not a measurement of free space on the filesystem — inspect before removing anything/);
      // The copy-paste line is the dry run, never the destructive form.
      expect(out).toMatch(/^\s*\$ shieldcortex logs prune$/m);
      expect(text).not.toMatch(/logs prune --execute/);
      expect(text).not.toMatch(UNSAFE_ADVICE);
      expect(text).not.toMatch(FALSE_EXHAUSTION);
    });

    it(`${mode}: a warn-level non-majority repair row keeps the same paragraph`, async () => {
      writeBytes('memories.db', 25 * KB);
      writeBytes('state/worker.json', 30 * KB);
      repairLogs(20, 2 * KB);

      const result = await checkDiskUsage(scDir, 110 * KB);
      expect(result.status).toBe('warn');
      const out = render(result, verbose);
      const text = flat(out);

      expect(text).toMatch(/Largest measured consumer: repair logs/);
      expect(text).toMatch(/shieldcortex logs prune \(without --execute\)/);
      expect(text).toMatch(/inspect before removing anything/);
      expect(out).toMatch(/^\s*\$ shieldcortex logs prune$/m);
      expect(text).not.toMatch(/logs prune --execute/);
    });

    it(`${mode}: a database/repair tie names both, the free-page note and the audit line`, async () => {
      writeBytes('memories.db', 40 * KB);
      repairLogs(20, 2 * KB);
      writeBytes('audit/realtime-2026-01-01.jsonl', 30 * KB);
      writeBytes('state/worker.json', 5 * KB);

      const result = await checkDiskUsage(scDir, 64 * KB);
      expect(result.status).toBe('fail');
      const out = render(result, verbose);
      const text = flat(out);

      expect(text).toMatch(/Largest measured consumers, tied: the database and repair logs, 40\.0 KB each of the 115\.0 KB counted against the limit \(35% each\)\./);
      expect(text).toMatch(/Then audit evidence 30\.0 KB, everything else 5\.0 KB\./);
      expect(text).toMatch(/free pages could not be read, so nothing about what fills it was measured and no command is named for it/);
      expect(text).toMatch(/shieldcortex logs prune \(without --execute\)/);
      expect(text).toMatch(/Audit evidence \(26%\) has no automatic retention yet \(#579\), and nothing here deletes it/);
      expect(text).toMatch(/not a measurement of free space on the filesystem — inspect before removing anything/);
      expect(out).toMatch(/^\s*\$ shieldcortex logs prune$/m);
      expect(text).not.toMatch(/logs prune --execute|shieldcortex vacuum/);
      expect(text).not.toMatch(UNSAFE_ADVICE);
      expect(text).not.toMatch(FALSE_EXHAUSTION);
    });

    it(`${mode}: majority repair logs still render as the two commands only`, async () => {
      writeBytes('memories.db', 4 * KB);
      repairLogs(30, 2 * KB);

      const result = await checkDiskUsage(scDir, 32 * KB);
      const out = render(result, verbose);

      expect(out).toMatch(/^\s*\$ shieldcortex logs prune$/m);
      expect(out).toMatch(/^\s*\$ shieldcortex logs prune --execute$/m);
      expect(flat(out)).not.toMatch(/Largest measured consumer/);
    });

    it(`${mode}: a ≥20% free-page database still renders vacuum as the command`, async () => {
      buildDb(100 * KB, 400 * KB);

      const result = await checkDiskUsage(scDir, 256 * KB);
      const out = render(result, verbose);

      expect(out).toMatch(/^\s*\$ shieldcortex vacuum$/m);
      expect(flat(out)).not.toMatch(/Largest measured consumer/);
    });
  }
});
