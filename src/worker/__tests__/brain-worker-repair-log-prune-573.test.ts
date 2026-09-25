/**
 * #573 — automatic repair-log retention in the brain worker.
 *
 * A valve an operator has to know to pull is not a valve: the incident host
 * accumulated 3,508 repair logs and the operator's first sight of the problem
 * was a doctor failure. So the same bound `shieldcortex logs prune` applies
 * runs from the light tick, throttled to ~24h.
 *
 * The three properties that matter, and why:
 *   - ONCE PER 24H. The light tick fires every 5–15 minutes; a directory
 *     listing and a handful of unlinks per day is the whole job.
 *   - ERRORS ARE CONTAINED. Retention is housekeeping. It may never take down
 *     a tick that also drains the sync queue and projects the threat graph.
 *   - NO DATABASE. The pass cannot sit inside the projector's transaction or
 *     hold its lease, because it never opens a database at all — which is also
 *     why it still works on a host whose DB is at the hard size block.
 */

import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { BrainWorker } from '../brain-worker.js';
import { REPAIR_LOG_PRUNE_INTERVAL_MS } from '../../logs/retention.js';

let root: string;
let logsDir: string;

function seedLogs(count: number): void {
  fs.mkdirSync(logsDir, { recursive: true });
  for (let i = 0; i < count; i++) {
    const full = path.join(
      logsDir,
      `project-key-repair-2026-01-01T00-00-${String(i).padStart(2, '0')}-000Z.json`,
    );
    fs.writeFileSync(full, '{}');
    fs.utimesSync(full, new Date(1_700_000_000_000 + i * 1000), new Date(1_700_000_000_000 + i * 1000));
  }
}

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-573-worker-'));
  logsDir = path.join(root, '.shieldcortex', 'logs');
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe('#573 the worker prunes repair logs at most once per 24h', () => {
  it('prunes on the first pass', () => {
    seedLogs(25);
    const worker = new BrainWorker({ repairLogDir: logsDir });

    const result = worker.runDueRepairLogPrune(new Date('2026-09-25T12:00:00Z'));

    expect(result).not.toBeNull();
    expect(result?.deleted).toHaveLength(5);
    expect(result?.dryRun).toBe(false);
    expect(fs.readdirSync(logsDir)).toHaveLength(20);
  });

  it('does nothing on a second pass inside the same day', () => {
    seedLogs(25);
    const worker = new BrainWorker({ repairLogDir: logsDir });
    worker.runDueRepairLogPrune(new Date('2026-09-25T12:00:00Z'));
    // Re-seed so a second pass would have work to do if it ran.
    seedLogs(40);

    const second = worker.runDueRepairLogPrune(new Date('2026-09-25T18:00:00Z'));

    expect(second).toBeNull();
    expect(fs.readdirSync(logsDir)).toHaveLength(40);
  });

  it('prunes again once a full interval has passed', () => {
    seedLogs(25);
    const first = new Date('2026-09-25T12:00:00Z');
    const worker = new BrainWorker({ repairLogDir: logsDir });
    worker.runDueRepairLogPrune(first);
    seedLogs(40);

    const later = worker.runDueRepairLogPrune(
      new Date(first.getTime() + REPAIR_LOG_PRUNE_INTERVAL_MS),
    );

    expect(later).not.toBeNull();
    expect(fs.readdirSync(logsDir)).toHaveLength(20);
  });
});

describe('#573 the worker never fails a tick over housekeeping', () => {
  it('contains a throw from the retention pass and reports it on stderr', () => {
    // A host passing a bad config value from JavaScript is the realistic way
    // this throws rather than returning a refusal: path.resolve on a non-string
    // is a TypeError, raised before any of the pass's own guards.
    const worker = new BrainWorker({ repairLogDir: 42 as unknown as string });

    expect(() => worker.runDueRepairLogPrune(new Date())).not.toThrow();
    expect(worker.runDueRepairLogPrune(new Date())).toBeNull();

    const stderr = (console.error as jest.Mock).mock.calls.map((c) => c.map(String).join(' ')).join('\n');
    expect(stderr).toContain('[BrainWorker]');
    expect(stderr).toMatch(/repair.log/i);
  });

  it('reports a refused plane without throwing, and still arms the throttle', () => {
    const real = path.join(root, 'elsewhere');
    fs.mkdirSync(real, { recursive: true });
    fs.writeFileSync(path.join(real, 'project-key-repair-2026-01-01T00-00-00-000Z.json'), '{}');
    const linked = path.join(root, '.shieldcortex', 'logs-link');
    fs.mkdirSync(path.join(root, '.shieldcortex'), { recursive: true });
    fs.symlinkSync(real, linked);
    const worker = new BrainWorker({ repairLogDir: linked });

    const result = worker.runDueRepairLogPrune(new Date('2026-09-25T12:00:00Z'));

    expect(result?.refused).toMatch(/symlink/i);
    expect(fs.readdirSync(real)).toHaveLength(1);
    // Refusing is a conclusion, not a crash: don't re-refuse every 5 minutes.
    expect(worker.runDueRepairLogPrune(new Date('2026-09-25T13:00:00Z'))).toBeNull();
  });

  // The worker runs IN-PROCESS inside the MCP stdio server, where stdout is
  // the JSON-RPC channel. console.log there corrupts the protocol stream.
  it('logs via console.error, never console.log', () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    seedLogs(25);
    const worker = new BrainWorker({ repairLogDir: logsDir });

    worker.runDueRepairLogPrune(new Date('2026-09-25T12:00:00Z'));

    expect(logSpy.mock.calls.map((c) => c.map(String).join(' ')).join('\n')).not.toContain('[BrainWorker]');
  });
});

describe('#573 the retention pass cannot sit inside a database transaction', () => {
  it('imports nothing but the filesystem, so it holds no handle, no lease and no txn', () => {
    // Structural, deliberately: "never inside the projector transaction or
    // lease" is guaranteed by the pass having no database to be inside one of.
    // An import of ../database/*, a getDatabase(), or a projector lease would
    // break that guarantee, and this is what notices.
    const source = fs.readFileSync(
      path.join(process.cwd(), 'src', 'logs', 'retention.ts'), 'utf-8',
    );
    const imports = [...source.matchAll(/^import .*? from '([^']+)';$/gm)].map((m) => m[1]);
    expect(imports.sort()).toEqual(['fs', 'os', 'path']);
    expect(source).not.toContain('getDatabase');
    expect(source).not.toContain('transaction');
  });
});
