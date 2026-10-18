/**
 * #798 — `shieldcortex maintain --json` goes through `stringifyJsonTerminalSafe`.
 *
 * The report embeds the storage doctor rows verbatim. The three doctor checks
 * are replaced here, in this file only, so a row message carrying class code
 * points proves the emitter escapes them; the real `runMaintain` handler runs
 * the dry-run against a temp database and does the printing.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

const CODES = [0x9b, 0x202e, 0x2028, 0x200b];
const UNSAFE = String.fromCharCode(...CODES);
const ESCAPES = CODES.map((c) => `\\u${c.toString(16).padStart(4, '0')}`);

let message = '';

jest.unstable_mockModule('../doctor.js', () => ({
  VACUUM_FREE_SHARE: 0.2,
  runMemoryStatsCheck: () => ({ label: 'Memories', status: 'pass', message }),
  runSemanticCoverageCheck: () => ({ label: 'Semantic coverage', status: 'pass', message: 'no memories stored yet' }),
  checkDiskUsage: async () => ({ label: 'Disk', status: 'pass', message: 'within limit' }),
}));

const { runMaintain } = await import('../maintain.js');
const { closeDatabase } = await import('../../database/init.js');
const { stringifyJsonTerminalSafe } = await import('../term-ui.js');

function hasLiteralUnsafe(raw: string): boolean {
  return [...raw].some((ch) => {
    const cp = ch.codePointAt(0)!;
    return (cp >= 0x80 && cp <= 0x9f) || cp === 0x61c || (cp >= 0x200b && cp <= 0x200f)
      || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2064)
      || (cp >= 0x2066 && cp <= 0x2069) || cp === 0xfeff;
  });
}

type Report = { steps: { doctor: { results: Array<{ label: string; message: string }> } }; exitCode: number };

let root: string;
let saved: NodeJS.ProcessEnv;
let savedExitCode: typeof process.exitCode;
let logs: string[];

beforeEach(() => {
  saved = { ...process.env };
  savedExitCode = process.exitCode;
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-798-maintain-')));
  process.env.HOME = root;
  process.env.CLAUDE_MEMORY_DB = path.join(root, 'memories.db');
  process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = '1';
  logs = [];
  jest.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { logs.push(args.map(String).join(' ')); });
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  try { closeDatabase(); } catch { /* already closed */ }
  process.env = saved;
  process.exitCode = savedExitCode;
  fs.rmSync(root, { recursive: true, force: true });
});

describe('maintain --json (#798)', () => {
  it('escapes a doctor row message and round-trips it', async () => {
    message = `0 total ${UNSAFE}`;
    await runMaintain(['--dry-run', '--json']);
    expect(process.exitCode).toBe(0);
    expect(logs).toHaveLength(1);
    const raw = logs[0];
    expect(hasLiteralUnsafe(raw)).toBe(false);
    for (const esc of ESCAPES) expect(raw).toContain(esc);
    const report = JSON.parse(raw) as Report;
    expect(report.steps.doctor.results.find((r) => r.label === 'Memories')?.message).toBe(message);
    expect(raw).toBe(stringifyJsonTerminalSafe(report));
  });

  it('clean ASCII report: byte-identical to plain compact JSON.stringify', async () => {
    message = '0 total (0 STM, 0 LTM)';
    await runMaintain(['--dry-run', '--json']);
    expect(process.exitCode).toBe(0);
    expect(logs).toHaveLength(1);
    expect(logs[0]).toBe(JSON.stringify(JSON.parse(logs[0])));
  });
});
