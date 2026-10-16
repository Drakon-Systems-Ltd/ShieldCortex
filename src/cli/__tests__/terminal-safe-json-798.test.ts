/**
 * #798 — the remaining user-facing `--json` outputs go through
 * `stringifyJsonTerminalSafe` (#786), so an attacker-influenced string (a path,
 * a flag, a project name) reaches the terminal as `\uXXXX` escapes rather than
 * as a live C1 control, bidi override, line separator or zero-width character.
 *
 * In-process here: `ledger verify --json`, `guard readiness --json` and the
 * three `memories import-native --json` emitters, each driven through its real
 * handler. The scan, maintain and built-CLI families live in sibling files.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { closeDatabase, initDatabase } from '../../database/init.js';
import { __resetLedgerStateForTests } from '../../defence/ledger/index.js';
import { clearCloudConfigCache } from '../../cloud/config.js';
import { runLedgerCommand } from '../ledger.js';
import { runGuardCommand } from '../guard.js';
import { runNativeImportCli } from '../import-native.js';
import { stringifyJsonTerminalSafe } from '../term-ui.js';

// U+009B (8-bit CSI), U+202E (RLO), U+2028 (LINE SEPARATOR), U+200B (ZWSP).
const CODES = [0x9b, 0x202e, 0x2028, 0x200b];
const UNSAFE = String.fromCharCode(...CODES);
const ESCAPES = CODES.map((c) => `\\u${c.toString(16).padStart(4, '0')}`);

function isTerminalUnsafe(cp: number): boolean {
  return (cp >= 0x80 && cp <= 0x9f) || cp === 0x61c || (cp >= 0x200b && cp <= 0x200f)
    || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2064)
    || (cp >= 0x2066 && cp <= 0x2069) || cp === 0xfeff;
}

function literalUnsafe(raw: string): string[] {
  return [...raw].filter((ch) => isTerminalUnsafe(ch.codePointAt(0)!))
    .map((ch) => `U+${ch.codePointAt(0)!.toString(16).padStart(4, '0')}`);
}

/** No literal class code point; each probe character present as its escape; same parse. */
function expectTerminalSafe(raw: string, indent?: number): unknown {
  expect(literalUnsafe(raw)).toEqual([]);
  for (const esc of ESCAPES) expect(raw).toContain(esc);
  const parsed = JSON.parse(raw);
  expect(raw).toBe(stringifyJsonTerminalSafe(parsed, indent));
  return parsed;
}

/** Clean ASCII output is byte-identical to what raw `JSON.stringify` printed before. */
function expectPlainJsonBytes(raw: string, indent?: number): void {
  expect(literalUnsafe(raw)).toEqual([]);
  expect(raw).toBe(JSON.stringify(JSON.parse(raw), null, indent));
}

let root: string;
let saved: NodeJS.ProcessEnv;
let logs: string[];

beforeEach(() => {
  saved = { ...process.env };
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-798-')));
  logs = [];
  jest.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { logs.push(args.map(String).join(' ')); });
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  try { closeDatabase(); } catch { /* already closed */ }
  __resetLedgerStateForTests();
  process.env = saved;
  clearCloudConfigCache();
  fs.rmSync(root, { recursive: true, force: true });
});

describe('ledger verify --json (#798)', () => {
  function ledgerJson(dirName: string): { code: number; out: string; dbPath: string } {
    const dir = path.join(root, dirName);
    fs.mkdirSync(dir);
    const dbPath = path.join(dir, 'memories.db');
    initDatabase(dbPath);
    closeDatabase();
    const out: string[] = [];
    const code = runLedgerCommand(['verify', '--json', '--db', dbPath], { stdout: (s) => out.push(s), stderr: () => {} });
    return { code, out: out.join(''), dbPath };
  }

  it('escapes the database path and round-trips it', () => {
    const { code, out, dbPath } = ledgerJson(`db${UNSAFE}`);
    expect(code).toBe(0);
    expect(out.endsWith('}\n')).toBe(true);
    const body = expectTerminalSafe(out.slice(0, -1), 2) as { database: string };
    expect(body.database).toBe(dbPath);
  });

  it('clean ASCII path: byte-identical to plain JSON.stringify, trailing newline kept', () => {
    const { code, out, dbPath } = ledgerJson('db-plain');
    expect(code).toBe(0);
    expect(out.endsWith('}\n')).toBe(true);
    expectPlainJsonBytes(out.slice(0, -1), 2);
    expect((JSON.parse(out) as { database: string }).database).toBe(dbPath);
  });
});

describe('guard readiness --json (#798)', () => {
  async function readinessJson(homeName: string): Promise<{ code: number; raw: string; home: string }> {
    const home = path.join(root, homeName);
    fs.mkdirSync(path.join(home, '.shieldcortex'), { recursive: true });
    process.env.HOME = home;
    process.env.SHIELDCORTEX_CONFIG_DIR = path.join(home, '.shieldcortex');
    process.env.OPENCLAW_HOME = path.join(home, 'openclaw-home');
    clearCloudConfigCache();
    const code = await runGuardCommand(['readiness', '--json'], { home });
    expect(logs).toHaveLength(1);
    return { code, raw: logs[0], home };
  }

  it('escapes each surface journal path and round-trips it', async () => {
    const { raw, home } = await readinessJson(`home${UNSAFE}`);
    const body = expectTerminalSafe(raw, 2) as { surfaces: Array<{ journalPath: string }> };
    expect(body.surfaces.length).toBeGreaterThan(0);
    for (const s of body.surfaces) expect(s.journalPath.startsWith(home)).toBe(true);
  });

  it('clean ASCII home: byte-identical to plain JSON.stringify', async () => {
    const { raw } = await readinessJson('home-plain');
    expectPlainJsonBytes(raw, 2);
  });
});

describe('memories import-native --json (#798)', () => {
  beforeEach(() => {
    process.env.NODE_ENV = 'test';
    process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = '1';
    process.env.HOME = path.join(root, 'home');
    fs.mkdirSync(process.env.HOME, { mode: 0o700 });
    process.env.CLAUDE_MEMORY_DB = path.join(root, 'memories.db');
    process.env.SHIELDCORTEX_CONFIG_DIR = path.join(root, 'config');
  });

  function note(): string {
    const file = path.join(root, 'note.md');
    fs.writeFileSync(file, '# Note\n\nThe team prefers metric units in reports.\n');
    return file;
  }

  it('usage-error envelope escapes the offending flag and round-trips it', async () => {
    const flag = `--x${UNSAFE}`;
    const code = await runNativeImportCli([note(), flag, '--json']);
    expect(code).toBe(2);
    expect(logs).toHaveLength(1);
    const body = expectTerminalSafe(logs[0]) as { error: string };
    expect(body.error).toBe(`unknown flag: ${flag}`);
  });

  it('usage-error envelope with a clean flag is byte-identical to plain JSON.stringify', async () => {
    const code = await runNativeImportCli([note(), '--x', '--json']);
    expect(code).toBe(2);
    expectPlainJsonBytes(logs[0]);
  });

  it('missing-scope envelope escapes the project and round-trips it', async () => {
    const project = `p${UNSAFE}x`;
    const code = await runNativeImportCli([note(), '--project', project, '--json']);
    expect(code).toBe(2);
    expect(logs).toHaveLength(1);
    const body = expectTerminalSafe(logs[0]) as { project: string; error: string };
    expect(body.project).toBe(project);
    expect(body.error).toMatch(/requires --host-id and --agent-id/);
  });

  it('import result escapes the project and round-trips it', async () => {
    const project = `p${UNSAFE}x`;
    await runNativeImportCli([note(), '--host-id', 'host-a', '--agent-id', 'agent-a', '--project', project, '--json']);
    expect(logs).toHaveLength(1);
    const body = expectTerminalSafe(logs[0]) as { project: string };
    expect(body.project).toBe(project);
  });

  it('import result with a clean project is byte-identical to plain JSON.stringify', async () => {
    await runNativeImportCli([note(), '--host-id', 'host-a', '--agent-id', 'agent-a', '--project', 'plain', '--json']);
    expect(logs).toHaveLength(1);
    expectPlainJsonBytes(logs[0]);
    expect((JSON.parse(logs[0]) as { project: string }).project).toBe('plain');
  });
});
