import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { stepOpenClawPlugin } from '../cli/update.js';

/**
 * #248 item 5 — a denied legacy-extension purge (`fs.rmSync` on a root-owned
 * dir, EPERM) was caught and silently ignored: `try { fs.rmSync(...) } catch
 * { }`. The duplicate stayed in place and the next `doctor` run reported a
 * dup install with no hint that a purge was even attempted, let alone denied.
 */

let home: string;
let extDir: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-248-purge-'));
  extDir = join(home, '.openclaw', 'extensions', 'shieldcortex-realtime');
  mkdirSync(extDir, { recursive: true });
  // Registered too, so the step reaches the install branch either way.
  mkdirSync(join(home, '.openclaw', 'plugins'), { recursive: true });
  writeFileSync(
    join(home, '.openclaw', 'plugins', 'installs.json'),
    JSON.stringify({ installRecords: { 'shieldcortex-realtime': {} } }),
  );
});

afterEach(() => rmSync(home, { recursive: true, force: true }));

describe('#248 — a denied legacy purge is surfaced, not swallowed', () => {
  it('reports the purge denial when the underlying install succeeds', async () => {
    const r = await stepOpenClawPlugin(home, {
      run: (() => Promise.resolve({ stdout: '', stderr: '' })) as never,
      rm: (() => { throw Object.assign(new Error('EPERM: operation not permitted'), { code: 'EPERM' }); }) as never,
    });

    expect(r.status).toBe('warn');
    const shown = [r.summary ?? '', ...(r.detail ?? [])].join('\n');
    expect(shown).toContain('EPERM');
    expect(shown).toContain(extDir);
  });

  it('folds the purge denial into the failure report when the install ALSO fails', async () => {
    const r = await stepOpenClawPlugin(home, {
      run: (() => Promise.reject(Object.assign(new Error('exit 1'), { exitCode: 1, stdout: '', stderr: '' }))) as never,
      rm: (() => { throw Object.assign(new Error('EPERM: operation not permitted'), { code: 'EPERM' }); }) as never,
    });

    expect(r.status).toBe('warn');
    const shown = [r.summary ?? '', ...(r.detail ?? [])].join('\n');
    expect(shown).toContain('EPERM');
  });

  it('stays quiet about the purge when it succeeds (no behaviour change on the happy path)', async () => {
    const r = await stepOpenClawPlugin(home, {
      run: (() => Promise.resolve({ stdout: '', stderr: '' })) as never,
      rm: (() => {}) as never,
    });

    expect(r.status).toBe('ok');
    const shown = [r.summary ?? '', ...(r.detail ?? [])].join('\n');
    expect(shown).not.toContain('EPERM');
    expect(shown).not.toContain('left behind');
  });
});
