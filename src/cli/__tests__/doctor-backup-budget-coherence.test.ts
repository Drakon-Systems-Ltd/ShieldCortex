/**
 * Failing-first spec for #153 — the planner and the doctor must agree.
 *
 * Field evidence, 1 Aug 2026 (Edith). Her live DB is 48.9 MB against a 100 MB
 * accounted budget. A repair took ONE legitimate safety copy — correctly, and
 * exactly one, since 4.47.22 made the prune unconditional — and that took the
 * directory to 98.8 MB. Doctor then reported:
 *
 *     ❌ Disk: 98.8 MB / 100 MB limit — at limit!
 *
 * Two internally-consistent rules that are incoherent together: the planner
 * treats the limit as a ceiling it may fill to, and doctor treats being at that
 * ceiling as a failure. Between them they hand an operator a state the product
 * calls broken, produced by an operation the product recommended.
 *
 * The tell for where the real fault lies is doctor's own remedy, which advised
 * "move them outside ~/.shieldcortex to keep them without spending the budget"
 * — the exact workaround that had to be performed by hand, twice, on two
 * different hosts. When the documented fix is "move our file out of our own
 * folder", the accounting is wrong, not the operator.
 *
 * So a safety backup no longer spends the memory-system budget. It is reported
 * separately, as cached models already are, and bounded by the keep-1 prune
 * rather than by a limit it can deadlock against.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkDiskUsage } from '../doctor.js';

const MB = 1024 * 1024;
const LIMIT = 100 * MB;

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'sc-disk-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

function write(name: string, bytes: number): void {
  writeFileSync(join(dir, name), Buffer.alloc(bytes));
}

describe('#153 — a safety backup must not spend the memory-system budget', () => {
  it('passes on Edith\'s exact state: 48.9 MB DB + one 48.9 MB safety copy', async () => {
    write('memories.db', 49 * MB);
    write('memories.db.bak.2026-08-01T03-39-00-000Z', 49 * MB);

    const r = await checkDiskUsage(dir, LIMIT) as unknown as { status: string; message: string };
    // 98 MB of files, but only 49 MB of it is budgeted data.
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/backups/i);
  });

  it('still FAILS when the live database itself fills the budget', async () => {
    // The condition the budget exists to catch must keep firing.
    write('memories.db', 99 * MB);
    const r = await checkDiskUsage(dir, LIMIT) as unknown as { status: string };
    expect(r.status).toBe('fail');
  });

  it('reports backups separately rather than silently hiding them', async () => {
    write('memories.db', 10 * MB);
    write('memories.db.bak.2026-08-01T03-39-00-000Z', 40 * MB);
    const r = await checkDiskUsage(dir, LIMIT) as unknown as { message: string };
    // An operator must still be able to see the space is in use.
    expect(r.message).toMatch(/40(\.0)? MB backups/i);
  });

  it('never tells the operator to move our own files out of our own directory', async () => {
    // That advice was the symptom that located this bug.
    write('memories.db', 20 * MB);
    write('memories.db.bak.2026-08-01T03-39-00-000Z', 60 * MB);
    const r = await checkDiskUsage(dir, LIMIT) as unknown as { fix?: string; message: string };
    const text = `${r.fix ?? ''} ${r.message}`;
    expect(text).not.toMatch(/move them outside/i);
  });

  it('counts logs and audit against the budget as before', async () => {
    // Only backups are exempted; everything else still spends the budget.
    write('memories.db', 10 * MB);
    mkdirSync(join(dir, 'audit'), { recursive: true });
    writeFileSync(join(dir, 'audit', 'realtime-2026-08-01.jsonl'), Buffer.alloc(95 * MB));
    const r = await checkDiskUsage(dir, LIMIT) as unknown as { status: string };
    expect(r.status).toBe('fail');
  });

  it('legacy in-place snapshots are exempted too, not just newly-named ones', async () => {
    // Hosts upgraded from older builds carry these names; they must not keep
    // failing after the fix lands.
    write('memories.db', 30 * MB);
    write('memories.db.pre-backfill', 60 * MB);
    const r = await checkDiskUsage(dir, LIMIT) as unknown as { status: string };
    expect(r.status).toBe('pass');
  });
});
