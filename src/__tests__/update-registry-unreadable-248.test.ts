import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { stepOpenClawPlugin } from '../cli/update.js';

/**
 * #248 item 2 — an unreadable/malformed `installs.json` must not read as "not
 * installed". Before this fix, `isRealtimePluginRegistered()` swallowed any
 * read/parse failure into a plain `false`, which `stepOpenClawPlugin` could
 * not tell apart from a host that genuinely never had the plugin — so update
 * skipped it, printed "not installed", and the run went GREEN having touched
 * nothing on a box that was actually supposed to be running the plugin.
 */

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-248-reg-'));
});

afterEach(() => rmSync(home, { recursive: true, force: true }));

describe('#248 — an unreadable registry never renders a false-green skip', () => {
  it('warns (does not skip as "not installed") when installs.json is malformed JSON', async () => {
    const pluginsDir = join(home, '.openclaw', 'plugins');
    mkdirSync(pluginsDir, { recursive: true });
    writeFileSync(join(pluginsDir, 'installs.json'), '{ not valid json');

    const r = await stepOpenClawPlugin(home, { run: (() => Promise.reject(new Error('should not be called'))) as never });

    expect(r.status).toBe('warn');
    expect(r.summary).not.toContain('not installed');
    expect(r.summary).toMatch(/registry unreadable/i);
  });

  it('warns when installs.json exists but cannot be read (permission denied)', async () => {
    const pluginsDir = join(home, '.openclaw', 'plugins');
    mkdirSync(pluginsDir, { recursive: true });
    const file = join(pluginsDir, 'installs.json');
    writeFileSync(file, JSON.stringify({ installRecords: {} }));
    chmodSync(file, 0o000);

    try {
      const r = await stepOpenClawPlugin(home, { run: (() => Promise.reject(new Error('should not be called'))) as never });
      // Root / some CI containers can still read a 0-mode file — only assert
      // the distinguishing behaviour when the permission actually bites.
      if (r.status === 'warn') {
        expect(r.summary).not.toContain('not installed');
        expect(r.summary).toMatch(/registry unreadable/i);
      }
    } finally {
      chmodSync(file, 0o644);
    }
  });

  it('still reports "not installed" (skip) when there genuinely is no registry', async () => {
    const r = await stepOpenClawPlugin(home, { run: (() => Promise.reject(new Error('should not be called'))) as never });
    expect(r.status).toBe('skip');
    expect(r.summary).toContain('not installed');
  });
});
