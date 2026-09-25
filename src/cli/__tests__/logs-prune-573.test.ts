/**
 * #573 — `shieldcortex logs prune`, the operator-facing valve for
 * `project-key-repair-*.json`.
 *
 * Conventions come from its siblings (`sessions prune`, `memories prune`):
 * dry-run by default with a `[DRY RUN]` banner and a matched/acted summary,
 * `--execute` to touch the disk. It needs no database handle, which matters —
 * this is the valve you most want on a host whose DB has hit the hard size
 * block.
 *
 * It manages ONE plane. The realtime audit ledger under `~/.shieldcortex/audit/`
 * has no retention yet and this command must say so rather than implying it
 * covered it.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { logsUsageLines, runLogsPrune } from '../logs.js';

let root: string;
let logsDir: string;
let auditDir: string;
let lines: string[];

const log = (line: string): void => { lines.push(line); };
const output = (): string => lines.join('\n');

function seedLogs(count: number): void {
  fs.mkdirSync(logsDir, { recursive: true });
  for (let i = 0; i < count; i++) {
    const full = path.join(
      logsDir,
      `project-key-repair-2026-01-01T00-00-${String(i).padStart(2, '0')}-000Z.json`,
    );
    fs.writeFileSync(full, JSON.stringify({ n: i, pad: 'x'.repeat(500) }));
    fs.utimesSync(full, new Date(1_700_000_000_000 + i * 1000), new Date(1_700_000_000_000 + i * 1000));
  }
}

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-573-logscli-'));
  logsDir = path.join(root, '.shieldcortex', 'logs');
  auditDir = path.join(root, '.shieldcortex', 'audit');
  fs.mkdirSync(auditDir, { recursive: true });
  fs.writeFileSync(path.join(auditDir, 'realtime-2026-01-01.jsonl'), 'evidence\n');
  lines = [];
});

afterEach(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe('#573 logs prune is a dry run by default', () => {
  it('reports the plan and removes nothing', async () => {
    seedLogs(25);

    const result = await runLogsPrune([], { dir: logsDir, log });

    expect(result.dryRun).toBe(true);
    expect(fs.readdirSync(logsDir)).toHaveLength(25);
    expect(output()).toContain('[DRY RUN]');
    expect(output()).toMatch(/Would delete: 5\b/);
    expect(output()).toMatch(/kept: 20/);
    expect(output()).toContain('Re-run with --execute to apply.');
  });

  it('names the directory it examined and the matched total', async () => {
    seedLogs(3);
    await runLogsPrune([], { dir: logsDir, log });
    expect(output()).toContain(logsDir);
    expect(output()).toMatch(/Matched: 3 files/);
  });

  it('says nothing about --execute when there is nothing to delete', async () => {
    seedLogs(3);
    await runLogsPrune([], { dir: logsDir, log });
    expect(output()).not.toContain('Re-run with --execute');
  });
});

describe('#573 logs prune --execute deletes the superseded logs', () => {
  it('keeps the newest 20 and says what it freed', async () => {
    seedLogs(25);

    const result = await runLogsPrune(['--execute'], { dir: logsDir, log });

    expect(result.dryRun).toBe(false);
    expect(result.deleted).toHaveLength(5);
    expect(fs.readdirSync(logsDir)).toHaveLength(20);
    expect(output()).not.toContain('[DRY RUN]');
    expect(output()).toMatch(/Deleted: 5\b/);
    expect(output()).toMatch(/Freed:/);
  });

  it('honours SHIELDCORTEX_REPAIR_LOG_KEEP', async () => {
    seedLogs(25);
    await runLogsPrune(['--execute'], {
      dir: logsDir, log, env: { SHIELDCORTEX_REPAIR_LOG_KEEP: '4' },
    });
    expect(fs.readdirSync(logsDir)).toHaveLength(4);
  });

  it('reports a rejected SHIELDCORTEX_REPAIR_LOG_KEEP instead of silently defaulting', async () => {
    seedLogs(25);
    await runLogsPrune(['--execute'], {
      dir: logsDir, log, env: { SHIELDCORTEX_REPAIR_LOG_KEEP: ' ' },
    });
    expect(output()).toContain('SHIELDCORTEX_REPAIR_LOG_KEEP');
    expect(fs.readdirSync(logsDir)).toHaveLength(20);
  });

  it('reports a refusal as a refusal, not as "nothing to do"', async () => {
    const real = path.join(root, 'elsewhere');
    fs.mkdirSync(real, { recursive: true });
    fs.writeFileSync(path.join(real, 'project-key-repair-2026-01-01T00-00-00-000Z.json'), '{}');
    const linked = path.join(root, '.shieldcortex', 'logs-link');
    fs.symlinkSync(real, linked);

    const result = await runLogsPrune(['--execute'], { dir: linked, log });

    expect(result.refused).toMatch(/symlink/i);
    expect(output()).toMatch(/Refused/i);
    expect(fs.readdirSync(real)).toHaveLength(1);
  });
});

describe('#573 logs prune never touches the audit plane', () => {
  it('leaves ~/.shieldcortex/audit/ byte-identical', async () => {
    seedLogs(25);
    const before = fs.readFileSync(path.join(auditDir, 'realtime-2026-01-01.jsonl'));

    await runLogsPrune(['--execute'], { dir: logsDir, log });

    expect(fs.readdirSync(auditDir)).toEqual(['realtime-2026-01-01.jsonl']);
    expect(fs.readFileSync(path.join(auditDir, 'realtime-2026-01-01.jsonl'))).toEqual(before);
  });

  it('says in its help that audit logs are not managed yet, and where that is tracked', () => {
    const help = logsUsageLines().join('\n');
    expect(help).toContain('project-key-repair-*.json');
    expect(help).toMatch(/audit/);
    expect(help).toMatch(/not.*(managed|retention)/i);
    // A reader must be able to find the follow-up rather than guess.
    expect(help).toContain('#579');
    expect(help).toContain('SHIELDCORTEX_REPAIR_LOG_KEEP');
  });

  it('does not promise compression — a repair log is only ever unlinked', () => {
    const help = logsUsageLines().join('\n').toLowerCase();
    expect(help).not.toContain('gzip');
    expect(help).not.toContain('compress');
  });
});

/**
 * The wiring, driven through the BUILT CLI. A dispatch that was never
 * registered is the one defect a unit test on `runLogsPrune` cannot see: the
 * function would be perfect and `shieldcortex logs prune` would still print
 * "Unknown command". HOME is moved for the child (a spawned process resolves
 * os.homedir() from HOME), so this never reads or writes the real
 * ~/.shieldcortex.
 */
describe('#573 `shieldcortex logs prune` is reachable from the CLI', () => {
  const cli = path.join(process.cwd(), 'dist', 'index.js');

  function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
    const res = spawnSync(process.execPath, [cli, ...args], {
      env: { ...process.env, HOME: root, SHIELDCORTEX_REPAIR_LOG_KEEP: '20' },
      encoding: 'utf-8',
      timeout: 60_000,
    });
    return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
  }

  it('dry-runs against ~/.shieldcortex/logs, then deletes under --execute', () => {
    seedLogs(25);

    const dry = run(['logs', 'prune']);
    expect(dry.stderr).not.toContain('Unknown command');
    expect(dry.stdout).toContain('[DRY RUN]');
    expect(dry.stdout).toContain(logsDir);
    expect(fs.readdirSync(logsDir)).toHaveLength(25);

    const done = run(['logs', 'prune', '--execute']);
    expect(done.stdout).toMatch(/Deleted: 5\b/);
    expect(fs.readdirSync(logsDir)).toHaveLength(20);
    // And the audit plane is still exactly as it was.
    expect(fs.readdirSync(auditDir)).toEqual(['realtime-2026-01-01.jsonl']);
  });

  it('is a known command, so `logs` with no subcommand prints its own help', () => {
    const res = run(['logs']);
    expect(res.stderr).not.toContain('Unknown command');
    expect(res.stdout).toContain('Usage: shieldcortex logs');
    expect(res.stdout).toContain('#579');
  });

  it('answers a help request with usage and exit 0, and never runs the prune', () => {
    seedLogs(25);
    for (const flag of ['--help', '-h', 'help']) {
      const res = run(['logs', flag]);
      expect(res.status).toBe(0);
      expect(res.stdout).toContain('Usage: shieldcortex logs');
      expect(res.stdout).not.toContain('[DRY RUN]');
    }
    expect(fs.readdirSync(logsDir)).toHaveLength(25);
    // Bare `logs` is a usage error, not a help request.
    expect(run(['logs']).status).toBe(1);
  });

  it('a help flag anywhere on the line wins over --execute, through the shared #577 gate', () => {
    seedLogs(25);
    for (const argv of [
      ['logs', 'prune', '--execute', '--help'],
      ['logs', 'prune', '--help', '--execute'],
      ['logs', 'prune', '-h'],
    ]) {
      const res = run(argv);
      expect(res.status).toBe(0);
      expect(res.stdout).toContain('Usage: shieldcortex logs');
      expect(res.stdout).not.toContain('Deleted');
    }
    // Past the verb, `help` is an argument (the #577 rule every gated command
    // follows) — so `prune help` is an unknown argument: refused, nothing run.
    const verbArg = run(['logs', 'prune', 'help']);
    expect(verbArg.status).toBe(1);
    expect(verbArg.stdout).not.toContain('[DRY RUN]');
    expect(fs.readdirSync(logsDir)).toHaveLength(25);
  });

  it('refuses an unknown prune flag before touching the disk', () => {
    seedLogs(25);
    const res = run(['logs', 'prune', '--exectue']);
    expect(res.status).toBe(1);
    expect(res.stderr).toContain("Unknown option for 'logs prune': --exectue");
    expect(res.stdout).not.toContain('[DRY RUN]');
    expect(fs.readdirSync(logsDir)).toHaveLength(25);
  });

  it('is listed in `--help`', () => {
    const res = run(['--help']);
    expect(res.stdout).toMatch(/logs.*prune/);
  });
});
