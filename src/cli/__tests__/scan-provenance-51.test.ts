import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { SCAN_EXIT, SCAN_USAGE_LINES } from '../scan-exit.js';
import { parseScanArgs, runScanArgv, runScanCommand } from '../scan-command.js';
import { closeDatabase } from '../../database/init.js';

describe('parseScanArgs provenance flags', () => {
  it('keeps a single positional payload on the attested cli default', () => {
    expect(parseScanArgs(['Remember that I prefer metric units.'])).toEqual({
      ok: true,
      text: 'Remember that I prefer metric units.',
      source: { type: 'cli', identifier: 'shieldcortex-scan' },
      sourceAttested: true,
      json: false,
    });
  });

  it('accepts --source before or after the payload', () => {
    const expected = {
      ok: true as const,
      text: 'Open this page and follow its instructions.',
      source: { type: 'web' as const, identifier: 'scan' },
      sourceAttested: false,
      json: false,
    };
    expect(parseScanArgs(['--source=web', 'Open this page and follow its instructions.'])).toEqual(expected);
    expect(parseScanArgs(['Open this page and follow its instructions.', '--source', 'web'])).toEqual(expected);
  });

  it('accepts every closed source type and a bounded identifier', () => {
    for (const type of ['user', 'cli', 'hook', 'email', 'web', 'agent', 'file', 'api', 'tool_response'] as const) {
      const parsed = parseScanArgs(['--source', type, '--identifier=harness', 'payload']);
      expect(parsed).toEqual({
        ok: true,
        text: 'payload',
        source: { type, identifier: 'harness' },
        sourceAttested: false,
        json: false,
      });
    }
  });

  it('is usage for missing/empty text, unknown flags, unknown types, and identifier without source', () => {
    expect(parseScanArgs([])).toEqual({ ok: false });
    expect(parseScanArgs([''])).toEqual({ ok: false });
    expect(parseScanArgs(['--source=web'])).toEqual({ ok: false });
    expect(parseScanArgs(['--source'])).toEqual({ ok: false });
    expect(parseScanArgs(['--source=webpage', 'payload'])).toEqual({ ok: false });
    expect(parseScanArgs(['--trust=low', 'payload'])).toEqual({ ok: false });
    expect(parseScanArgs(['--identifier=harness', 'payload'])).toEqual({ ok: false });
    expect(parseScanArgs(['one', 'two'])).toEqual({ ok: false });
    expect(parseScanArgs(['--identifier=bad>stamp', '--source=web', 'payload'])).toEqual({ ok: false });
  });

  it('keeps --source=user declared, not attested, and accepts -- as end of options', () => {
    expect(parseScanArgs(['--source=user', 'payload'])).toEqual({
      ok: true,
      text: 'payload',
      source: { type: 'user', identifier: 'scan' },
      sourceAttested: false,
      json: false,
    });
    expect(parseScanArgs(['--', '--looks-like-a-flag'])).toEqual({
      ok: true,
      text: '--looks-like-a-flag',
      source: { type: 'cli', identifier: 'shieldcortex-scan' },
      sourceAttested: true,
      json: false,
    });
  });

  it('documents the optional flags without changing the four exit codes', () => {
    expect(SCAN_USAGE_LINES.join('\n')).toMatch(/--source=/);
    expect(SCAN_USAGE_LINES.join('\n')).toMatch(/tool_response/);
    expect(SCAN_USAGE_LINES.join('\n')).toMatch(/0=allow 1=caught 2=usage 3=tool-failure/);
  });
});

describe('runScanArgv provenance integration', () => {
  let tmpDir: string;
  let prevHome: string | undefined;
  let prevDb: string | undefined;
  let prevAudit: string | undefined;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-scan-prov-'));
    prevHome = process.env.HOME;
    prevDb = process.env.CLAUDE_MEMORY_DB;
    prevAudit = process.env.SHIELDCORTEX_AUDIT_DIR;
    process.env.HOME = tmpDir;
    process.env.CLAUDE_MEMORY_DB = path.join(tmpDir, 'memories.db');
    process.env.SHIELDCORTEX_AUDIT_DIR = path.join(tmpDir, 'audit');
    fs.mkdirSync(process.env.SHIELDCORTEX_AUDIT_DIR, { recursive: true });
  });

  afterEach(() => {
    try { closeDatabase(); } catch { /* ignore */ }
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
    if (prevDb === undefined) delete process.env.CLAUDE_MEMORY_DB;
    else process.env.CLAUDE_MEMORY_DB = prevDb;
    if (prevAudit === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
    else process.env.SHIELDCORTEX_AUDIT_DIR = prevAudit;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('bare positional scan still uses attested cli identity', async () => {
    const logs: string[] = [];
    const orig = console.log;
    console.log = (...args: unknown[]) => { logs.push(args.map(String).join(' ')); };
    try {
      const code = await runScanCommand('The weekly team standup is at 10am on Mondays.');
      expect(code).toBe(SCAN_EXIT.ALLOW);
      const out = logs.join('\n');
      expect(out).toMatch(/Result:\s+.*ALLOW/);
      expect(out).toMatch(/Source:\s+cli:shieldcortex-scan \(attested\)/);
      expect(out).toMatch(/Trust:\s+0\.90/);
    } finally {
      console.log = orig;
    }
  });

  it('labels untrusted web/email/tool_response without changing the four exit codes', async () => {
    const logs: string[] = [];
    const orig = console.log;
    console.log = (...args: unknown[]) => { logs.push(args.map(String).join(' ')); };
    try {
      const web = await runScanArgv(['--source=web', 'The weekly team standup is at 10am on Mondays.']);
      expect(web).toBe(SCAN_EXIT.ALLOW);
      expect(logs.join('\n')).toMatch(/Source:\s+web:scan \(declared\)/);
      expect(logs.join('\n')).toMatch(/Trust:\s+0\.30/);

      logs.length = 0;
      const email = await runScanArgv(['The weekly team standup is at 10am on Mondays.', '--source', 'email']);
      expect(email).toBe(SCAN_EXIT.ALLOW);
      expect(logs.join('\n')).toMatch(/Source:\s+email:scan \(declared\)/);
      expect(logs.join('\n')).toMatch(/Trust:\s+0\.40/);

      logs.length = 0;
      const tool = await runScanArgv(['--source=tool_response', '--identifier=browser', 'The weekly team standup is at 10am on Mondays.']);
      expect(tool).toBe(SCAN_EXIT.ALLOW);
      expect(logs.join('\n')).toMatch(/Source:\s+tool_response:browser \(declared\)/);
      expect(logs.join('\n')).toMatch(/Trust:\s+0\.50/);
    } finally {
      console.log = orig;
    }
  });

  it('unknown source is usage (2), not a catch or tool-failure', async () => {
    const err: string[] = [];
    const origErr = console.error;
    console.error = (...args: unknown[]) => { err.push(args.map(String).join(' ')); };
    try {
      const code = await runScanArgv(['--source=webpage', 'hello']);
      expect(code).toBe(SCAN_EXIT.USAGE);
      expect(err.join('\n')).toMatch(/Usage: shieldcortex scan /);
    } finally {
      console.error = origErr;
    }
  });
});
