/**
 * #798 — `shieldcortex scan --json` goes through `stringifyJsonTerminalSafe`.
 *
 * Every field the real pipeline puts in the scan report is fixed vocabulary
 * today (the `--identifier` value is pattern-restricted, reasons are templated),
 * so no CLI input reaches it with a class code point. The pipeline is replaced
 * here, in this file only, so a verdict reason carrying them proves the
 * emitter itself escapes; the real `runScanArgv` handler does the printing.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

const CODES = [0x9b, 0x202e, 0x2028, 0x200b];
const UNSAFE = String.fromCharCode(...CODES);
const ESCAPES = CODES.map((c) => `\\u${c.toString(16).padStart(4, '0')}`);

let reason = '';

jest.unstable_mockModule('../../defence/pipeline.js', () => ({
  runDefencePipeline: () => ({
    allowed: false,
    firewall: { result: 'QUARANTINE', reason, anomalyScore: 0, threatIndicators: [], blockedPatterns: [] },
    trust: { score: 0.9 },
    sensitivity: { level: 'PUBLIC' },
  }),
}));

const { runScanArgv } = await import('../scan-command.js');
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

let root: string;
let saved: NodeJS.ProcessEnv;
let logs: string[];

beforeEach(() => {
  saved = { ...process.env };
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-798-scan-')));
  process.env.HOME = root;
  process.env.CLAUDE_MEMORY_DB = path.join(root, 'memories.db');
  logs = [];
  jest.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { logs.push(args.map(String).join(' ')); });
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  try { closeDatabase(); } catch { /* already closed */ }
  process.env = saved;
  fs.rmSync(root, { recursive: true, force: true });
});

describe('scan --json (#798)', () => {
  it('escapes the verdict reason and round-trips it', async () => {
    reason = `Quarantined: ${UNSAFE}`;
    expect(await runScanArgv(['--json', 'payload'])).toBe(1);
    expect(logs).toHaveLength(1);
    const raw = logs[0];
    expect(hasLiteralUnsafe(raw)).toBe(false);
    for (const esc of ESCAPES) expect(raw).toContain(esc);
    const body = JSON.parse(raw) as { reason: string };
    expect(body.reason).toBe(reason);
    expect(raw).toBe(stringifyJsonTerminalSafe(body));
  });

  it('clean ASCII report: byte-identical to plain compact JSON.stringify', async () => {
    reason = 'Quarantined: plain';
    expect(await runScanArgv(['--json', 'payload'])).toBe(1);
    expect(logs).toHaveLength(1);
    expect(logs[0]).toBe(JSON.stringify(JSON.parse(logs[0])));
    expect((JSON.parse(logs[0]) as { reason: string }).reason).toBe(reason);
  });
});
