import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { stepVerifyProtection } from '../cli/update.js';

/**
 * #248 (review round 2) — `stepVerifyProtection` gated on the collapsing
 * `isRealtimePluginRegistered(home)` boolean, so an unreadable registry
 * (denied permission, malformed JSON) returned `false` the exact same way
 * "genuinely not installed" does — and the function did a bare, silent
 * `return`. The protection self-check — #248's own "most consequential"
 * item — never ran, and the run still ended green with nothing printed to
 * say the check had even been attempted.
 */

function captureWrites(stream: NodeJS.WriteStream): { calls: string[]; restore: () => void } {
  const calls: string[] = [];
  const original = stream.write.bind(stream);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (stream as any).write = (chunk: any, ...rest: any[]) => {
    calls.push(typeof chunk === 'string' ? chunk : String(chunk));
    return true;
  };
  return { calls, restore: () => { (stream as any).write = original; } };
}

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-248-verify-'));
});

afterEach(() => rmSync(home, { recursive: true, force: true }));

describe('#248 — stepVerifyProtection surfaces an unreadable registry, not a silent skip', () => {
  it('prints a skipped-not-silent message when installs.json is malformed', async () => {
    const pluginsDir = join(home, '.openclaw', 'plugins');
    mkdirSync(pluginsDir, { recursive: true });
    writeFileSync(join(pluginsDir, 'installs.json'), '{ not valid json');

    const stdout = captureWrites(process.stdout);
    try {
      await stepVerifyProtection(home);
    } finally {
      stdout.restore();
    }

    const shown = stdout.calls.join('');
    expect(shown).toMatch(/protection check skipped/i);
    expect(shown).toMatch(/unreadable/i);
  });

  it('stays truly silent when there genuinely is no registry (a Claude-Code-only box is not an error)', async () => {
    const stdout = captureWrites(process.stdout);
    try {
      await stepVerifyProtection(home);
    } finally {
      stdout.restore();
    }

    expect(stdout.calls.join('')).toBe('');
  });
});
