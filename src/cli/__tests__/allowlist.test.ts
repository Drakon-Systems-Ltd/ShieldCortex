/**
 * Spec for `shieldcortex allowlist` (#189). The load-bearing property is the
 * TTY gate on every MUTATING verb — same threat model as approve/deny: an
 * agent shelling out must not pin its own payload as reviewed. Listing and
 * verifying stay scriptable.
 */
import { mkdtempSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runAllowlist } from '../allowlist.js';
import { hashScriptSource } from '../../defence/iron-dome/reviewed-scripts.js';

describe('shieldcortex allowlist', () => {
  let dir: string;
  let scriptPath: string;
  let stored: unknown[];
  let logs: string[];
  let errs: string[];
  const SOURCE = '#!/bin/sh\necho audit\n';

  const deps = (interactive: boolean) => ({
    interactive,
    log: (m: string) => logs.push(m),
    error: (m: string) => errs.push(m),
    readEntries: () => stored,
    writeEntries: (e: Array<Record<string, unknown>>) => {
      stored = e;
    },
  });

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-cli-189-'));
    scriptPath = join(dir, 'sentry.sh');
    writeFileSync(scriptPath, SOURCE);
    stored = [];
    logs = [];
    errs = [];
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test('add: TTY-gated — refused without a terminal, nothing written', () => {
    expect(runAllowlist(['add', scriptPath], deps(false))).toBe(1);
    expect(stored).toEqual([]);
    expect(errs.join('\n')).toContain('interactive terminal');
  });

  test('add: pins canonical path + content hash, with note and timestamp', () => {
    const code = runAllowlist(['add', scriptPath, '--note', 'daily sentry'], { ...deps(true), now: 1234 });
    expect(code).toBe(0);
    expect(stored).toEqual([
      {
        path: realpathSync(scriptPath),
        sha256: hashScriptSource(SOURCE),
        note: 'daily sentry',
        addedAt: 1234,
      },
    ]);
  });

  test('add twice: re-pins (replaces) rather than duplicating', () => {
    runAllowlist(['add', scriptPath], deps(true));
    writeFileSync(scriptPath, SOURCE + '# v2\n');
    runAllowlist(['add', scriptPath], deps(true));
    expect(stored).toHaveLength(1);
    expect((stored[0] as Record<string, unknown>).sha256).toBe(hashScriptSource(SOURCE + '# v2\n'));
  });

  test('add: refuses a missing file and an oversized file', () => {
    expect(runAllowlist(['add', join(dir, 'nope.sh')], deps(true))).toBe(1);
    const big = join(dir, 'big.sh');
    writeFileSync(big, 'x'.repeat(262_145));
    expect(runAllowlist(['add', big], deps(true))).toBe(1);
    expect(stored).toEqual([]);
  });

  test('remove: TTY-gated, then removes by path', () => {
    runAllowlist(['add', scriptPath], deps(true));
    expect(runAllowlist(['remove', scriptPath], deps(false))).toBe(1);
    expect(stored).toHaveLength(1);
    expect(runAllowlist(['remove', scriptPath], deps(true))).toBe(0);
    expect(stored).toEqual([]);
  });

  test('verify: exit 0 when clean, 1 on drift — scriptable for doctor/cron use', () => {
    runAllowlist(['add', scriptPath], deps(true));
    expect(runAllowlist(['verify'], deps(false))).toBe(0);
    writeFileSync(scriptPath, SOURCE + 'rm -rf /\n');
    expect(runAllowlist(['verify'], deps(false))).toBe(1);
    expect(logs.join('\n')).toContain('EDITED');
  });

  test('list: harmless without a TTY, shows drift state', () => {
    runAllowlist(['add', scriptPath], deps(true));
    logs = [];
    expect(runAllowlist([], deps(false))).toBe(0);
    expect(logs.join('\n')).toContain(realpathSync(scriptPath));
  });
});
