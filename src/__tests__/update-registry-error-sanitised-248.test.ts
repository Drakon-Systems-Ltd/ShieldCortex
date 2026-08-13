import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { readRealtimePluginRegistration } from '../cli/update.js';
import { sanitiseForReport } from '../integrations/child-output.js';

/**
 * #248 (review round 2) — the strings `readRealtimePluginRegistration` built
 * by hand (`could not read installs.json: ${err.message}`, `installs.json is
 * malformed JSON: ${err.message}`) bypassed every redaction/scrubbing this
 * codebase already has for exactly this purpose. Node formats a read error
 * with the absolute path (`/Users/<name>/.openclaw/plugins/installs.json`),
 * and V8 embeds up to ~30 raw bytes of the file in one of its two JSON
 * parse-error forms — so an unreadable or corrupt registry echoed the
 * operator's home directory, or the file's own head bytes, straight into a
 * report that #248 itself says gets pasted into issues and support threads.
 */

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-248-sanitise-'));
});

afterEach(() => rmSync(home, { recursive: true, force: true }));

describe('#248 — sanitiseForReport is exported from child-output.ts', () => {
  it('scrubs a supplied home directory to ~', () => {
    const out = sanitiseForReport(`error at ${home}/plugins/installs.json`, { home });
    expect(out).not.toContain(home);
    expect(out).toContain('~/plugins/installs.json');
  });

  it('redacts a secret-looking env value handed to the child', () => {
    const env = { NPM_TOKEN: 'totally-not-a-recognised-token-shape-999999' };
    const out = sanitiseForReport(`rejected: ${env.NPM_TOKEN}`, { env });
    expect(out).not.toContain(env.NPM_TOKEN);
    expect(out).toContain('[redacted:$NPM_TOKEN]');
  });
});

describe('#248 — a malformed installs.json never echoes the raw parse error', () => {
  it('drops err.message (and any raw file content) entirely, using a generic reason', () => {
    const pluginsDir = join(home, '.openclaw', 'plugins');
    mkdirSync(pluginsDir, { recursive: true });
    // A distinctive marker: JSON parse errors are known to echo back the
    // raw file's head bytes verbatim in their message.
    writeFileSync(join(pluginsDir, 'installs.json'), '{ "SECRET-MARKER-DO-NOT-LEAK": ');

    const r = readRealtimePluginRegistration(home);

    expect(r.unreadable).toBe(true);
    expect(r.detail).not.toContain('SECRET-MARKER-DO-NOT-LEAK');
    expect(r.detail).toMatch(/malformed JSON/i);
  });
});

describe('#248 — an unreadable installs.json never echoes the raw absolute path', () => {
  it('scrubs the home directory out of the read-failure detail', () => {
    const pluginsDir = join(home, '.openclaw', 'plugins');
    mkdirSync(pluginsDir, { recursive: true });
    const file = join(pluginsDir, 'installs.json');
    writeFileSync(file, JSON.stringify({ installRecords: {} }));
    chmodSync(file, 0o000);

    try {
      const r = readRealtimePluginRegistration(home);
      // Root / some CI containers can still read a 0-mode file — only assert
      // the scrubbing when the permission actually bites.
      if (r.unreadable) {
        expect(r.detail).not.toContain(home);
        expect(r.detail).toContain('~/.openclaw/plugins/installs.json');
      }
    } finally {
      chmodSync(file, 0o644);
    }
  });
});
