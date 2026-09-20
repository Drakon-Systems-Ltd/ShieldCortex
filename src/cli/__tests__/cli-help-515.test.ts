/**
 * #515: `--help` / `-h` must never execute an action.
 *
 * Control on 5.0.5: `audit --help` ran the full environment scan;
 * `allowlist --help` was rejected as an unknown subcommand.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from '@jest/globals';
import { wantsHelp } from '../wants-help.js';
import { ALLOWLIST_HELP, runAllowlist } from '../allowlist.js';
import { AUDIT_HELP, handleAuditCommand } from '../audit.js';

describe('wantsHelp (#515)', () => {
  it('matches --help, -h, and a bare help token anywhere in argv', () => {
    expect(wantsHelp(['--help'])).toBe(true);
    expect(wantsHelp(['-h'])).toBe(true);
    expect(wantsHelp(['help'])).toBe(true);
    expect(wantsHelp(['scan', '--help'])).toBe(true);
    expect(wantsHelp(['--json', '-h'])).toBe(true);
  });

  it('does not treat unrelated flags or paths as help', () => {
    expect(wantsHelp([])).toBe(false);
    expect(wantsHelp(['--json'])).toBe(false);
    expect(wantsHelp(['add', '/tmp/help.sh'])).toBe(false);
    expect(wantsHelp(['--help-me'])).toBe(false);
  });
});

describe('shieldcortex allowlist --help (#515)', () => {
  it('prints usage and does not read or write the allowlist', () => {
    const logs: string[] = [];
    const errs: string[] = [];
    let reads = 0;
    let writes = 0;
    const code = runAllowlist(['--help'], {
      interactive: false,
      log: (m) => logs.push(m),
      error: (m) => errs.push(m),
      readEntries: () => {
        reads += 1;
        return [{ path: '/should-not-read', sha256: 'x' }];
      },
      writeEntries: () => {
        writes += 1;
      },
    });
    expect(code).toBe(0);
    expect(reads).toBe(0);
    expect(writes).toBe(0);
    expect(errs).toEqual([]);
    expect(logs.join('\n')).toBe(ALLOWLIST_HELP);
    expect(logs.join('\n')).toContain('Usage: shieldcortex allowlist');
    expect(logs.join('\n')).not.toMatch(/Unknown subcommand/);
  });

  it('treats -h and scan --help the same — never starts a scan', () => {
    const logs: string[] = [];
    expect(runAllowlist(['-h'], { log: (m) => logs.push(m), readEntries: () => { throw new Error('read'); } })).toBe(0);
    expect(runAllowlist(['scan', '--help'], { log: (m) => logs.push(m), readEntries: () => { throw new Error('read'); } })).toBe(0);
    expect(logs.join('\n')).toContain('Usage: shieldcortex allowlist');
  });
});

describe('shieldcortex audit --help (#515)', () => {
  const homes: string[] = [];

  afterEach(() => {
    for (const h of homes.splice(0)) {
      rmSync(h, { recursive: true, force: true });
    }
  });

  it('prints usage and does not scan or exit', async () => {
    const home = mkdtempSync(join(tmpdir(), 'sc-515-audit-help-'));
    homes.push(home);
    const prevHome = process.env.HOME;
    const prevConfig = process.env.SHIELDCORTEX_CONFIG_DIR;
    const prevAudit = process.env.SHIELDCORTEX_AUDIT_DIR;
    process.env.HOME = home;
    process.env.SHIELDCORTEX_CONFIG_DIR = join(home, 'cfg');
    process.env.SHIELDCORTEX_AUDIT_DIR = join(home, 'audit');

    const logs: string[] = [];
    const writes: string[] = [];
    const origLog = console.log;
    const origWrite = process.stdout.write.bind(process.stdout);
    const origExit = process.exit;
    console.log = ((msg?: unknown) => {
      logs.push(String(msg ?? ''));
    }) as typeof console.log;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    process.exit = ((code?: number) => {
      throw new Error(`process.exit(${code})`);
    }) as typeof process.exit;

    try {
      await handleAuditCommand(['--help']);
      await handleAuditCommand(['-h']);
    } finally {
      console.log = origLog;
      process.stdout.write = origWrite;
      process.exit = origExit;
      if (prevHome === undefined) delete process.env.HOME;
      else process.env.HOME = prevHome;
      if (prevConfig === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
      else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfig;
      if (prevAudit === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
      else process.env.SHIELDCORTEX_AUDIT_DIR = prevAudit;
    }

    const text = [...logs, ...writes].join('\n');
    expect(text).toContain(AUDIT_HELP.trim());
    expect(text).toContain('Usage: shieldcortex audit');
    expect(text).not.toMatch(/Scanning agent environment/);
    expect(text).not.toMatch(/Memory files/);
  });
});
