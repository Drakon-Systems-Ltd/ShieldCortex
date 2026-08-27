/**
 * Failing-first spec for #146 — hook commands must RESOLVE, not merely exist.
 *
 * Fleet evidence, 31 Jul 2026: three of four boxes could not resolve a bare
 * `shieldcortex` from the non-interactive shell a harness spawns hooks in. Two
 * of them were running zero Claude Code enforcement — installed, configured,
 * and reported healthy by our own doctor the entire time.
 *
 * The root cause is that we wrote a bare command name, making enforcement
 * depend on the operator's shell config: something we neither control nor
 * inspect. These tests pin the three halves of the fix.
 */
import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, chmodSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  resolveHookBinary,
  buildHookCommand,
  hookCommandResolves,
  hookCommandTrust,
  needsAbsolutePathRepair,
  repairHookCommand,
} from '../hook-command-resolution.js';

let dir: string;
let trustedDir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sc-hookres-'));
  // hookCommandTrust treats /tmp as a world-writable staging root, so trust
  // fixtures need a bin OUTSIDE it — the repo tree qualifies.
  trustedDir = mkdtempSync(join(process.cwd(), '.jest-scbin-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(trustedDir, { recursive: true, force: true });
});

function fakeBin(name = 'shieldcortex'): string {
  const binDir = join(dir, 'bin');
  mkdirSync(binDir, { recursive: true });
  const p = join(binDir, name);
  writeFileSync(p, '#!/bin/sh\nexit 0\n');
  chmodSync(p, 0o755);
  return p;
}

// ── 1. The installer must write an absolute path ───────────────────────────

describe('#146 — the installer writes a resolvable absolute command', () => {
  it('builds a command with an absolute path, not a bare name', () => {
    const bin = fakeBin();
    const cmd = buildHookCommand(bin, 'pre-tool');
    expect(cmd.startsWith('/')).toBe(true);
    expect(cmd).toBe(`${bin} hook pre-tool`);
    expect(cmd).not.toMatch(/^shieldcortex\b/);
  });

  it('quotes a path containing spaces so the command survives sh -c', () => {
    const spaced = join(dir, 'my tools', 'shieldcortex');
    mkdirSync(join(dir, 'my tools'), { recursive: true });
    writeFileSync(spaced, '#!/bin/sh\nexit 0\n');
    chmodSync(spaced, 0o755);
    const cmd = buildHookCommand(spaced, 'pre-tool');
    expect(cmd).toContain('"');
    expect(cmd).toMatch(/hook pre-tool$/);
  });

  it('falls back to the bare name only when no binary can be located', () => {
    // Degrading to today's behaviour is acceptable; silently writing a path
    // that does not exist is not.
    expect(buildHookCommand(null, 'pre-tool')).toBe('shieldcortex hook pre-tool');
  });

  it('resolveHookBinary prefers an explicit npm prefix bin over PATH guesswork', () => {
    const bin = fakeBin();
    expect(resolveHookBinary({ npmPrefixBin: join(dir, 'bin') })).toBe(bin);
  });

  it('resolveHookBinary rejects a candidate that is not executable', () => {
    const binDir = join(dir, 'bin');
    mkdirSync(binDir, { recursive: true });
    writeFileSync(join(binDir, 'shieldcortex'), 'not executable');
    chmodSync(join(binDir, 'shieldcortex'), 0o644);
    expect(resolveHookBinary({ npmPrefixBin: binDir })).toBeNull();
  });

  it('returns null rather than a guess when nothing resolves', () => {
    expect(resolveHookBinary({ npmPrefixBin: join(dir, 'nope') })).toBeNull();
  });
});

// ── 2. The doctor check must be behavioural ────────────────────────────────

describe('#146 — a hook command is verified by RUNNING it', () => {
  it('reports an absolute, executable command as resolving', () => {
    const bin = fakeBin();
    expect(hookCommandResolves(`${bin} hook pre-tool`)).toBe(true);
  });

  it('reports a bare name that is not on the subprocess PATH as NOT resolving', () => {
    // The exact live failure: present to an interactive shell, absent to `sh -c`.
    expect(hookCommandResolves('definitely-not-a-real-binary-xyz hook pre-tool')).toBe(false);
  });

  it('reports an absolute path that does not exist as NOT resolving', () => {
    expect(hookCommandResolves(`${join(dir, 'ghost')} hook pre-tool`)).toBe(false);
  });

  it('sees through an env-var prefix — the form our first fixer missed', () => {
    const bin = fakeBin();
    expect(hookCommandResolves(`SHIELDCORTEX_RECALL_ENFORCE=1 ${bin} hook prompt-recall`)).toBe(true);
    expect(hookCommandResolves('SHIELDCORTEX_RECALL_ENFORCE=1 not-a-real-binary-xyz hook prompt-recall')).toBe(false);
  });

  it('treats an empty or malformed command as not resolving', () => {
    expect(hookCommandResolves('')).toBe(false);
    expect(hookCommandResolves('   ')).toBe(false);
  });
});

// ── 2b. #393 SOL r2 B3 — where the command lands matters, not just whether ──

describe('#393 — hookCommandTrust classifies the resolved executable', () => {
  function trustedBin(name = 'shieldcortex'): string {
    const p = join(trustedDir, name);
    writeFileSync(p, '#!/bin/sh\nexit 0\n');
    chmodSync(p, 0o755);
    return p;
  }

  it('reports a clean absolute executable as resolves', () => {
    expect(hookCommandTrust(`${trustedBin()} hook session-start`)).toBe('resolves');
  });

  it('reports a missing absolute path and a dead bare name as unresolvable', () => {
    expect(hookCommandTrust(`${join(trustedDir, 'ghost')} hook session-start`)).toBe('unresolvable');
    expect(hookCommandTrust('definitely-not-a-real-binary-xyz hook session-start')).toBe('unresolvable');
    expect(hookCommandTrust('')).toBe('unresolvable');
  });

  it('caps an executable under a world-writable staging root at suspicious — /tmp/shieldcortex is not proof (SOL r2 B3)', () => {
    const planted = join(dir, 'shieldcortex'); // dir lives under os.tmpdir()
    writeFileSync(planted, '#!/bin/sh\nexit 0\n');
    chmodSync(planted, 0o755);
    expect(hookCommandTrust(`${planted} hook session-start`)).toBe('suspicious');
  });

  it('classifies where a bare name RESOLVES — a PATH hit inside /tmp is the same plant', () => {
    // searchPath injection, not process.env.PATH mutation: jest's process.env
    // is a copy that never reaches a spawned child.
    const planted = join(dir, 'shieldcortex');
    writeFileSync(planted, '#!/bin/sh\nexit 0\n');
    chmodSync(planted, 0o755);
    expect(hookCommandTrust('shieldcortex hook session-start', { searchPath: dir })).toBe('suspicious');
    trustedBin();
    expect(hookCommandTrust('shieldcortex hook session-start', { searchPath: trustedDir })).toBe('resolves');
    expect(hookCommandTrust('shieldcortex hook session-start', { searchPath: join(dir, 'empty') })).toBe('unresolvable');
  });

  it('follows a symlink out of a clean prefix into /tmp — one hop does not launder the plant', () => {
    const planted = join(dir, 'shieldcortex');
    writeFileSync(planted, '#!/bin/sh\nexit 0\n');
    chmodSync(planted, 0o755);
    const link = join(trustedDir, 'shieldcortex');
    symlinkSync(planted, link);
    expect(hookCommandTrust(`${link} hook session-start`)).toBe('suspicious');
  });
});

// ── 3. Upgrade must repair installs that are already wrong ─────────────────

describe('#146 — upgrade repairs existing broken installs', () => {
  it('flags a bare command as needing repair', () => {
    expect(needsAbsolutePathRepair('shieldcortex hook pre-tool')).toBe(true);
  });

  it('flags the env-prefixed bare form as needing repair', () => {
    expect(needsAbsolutePathRepair('SHIELDCORTEX_RECALL_ENFORCE=1 shieldcortex hook prompt-recall')).toBe(true);
  });

  it('leaves an already-absolute command alone', () => {
    expect(needsAbsolutePathRepair('/usr/local/bin/shieldcortex hook pre-tool')).toBe(false);
    expect(needsAbsolutePathRepair('VAR=1 /usr/local/bin/shieldcortex hook prompt-recall')).toBe(false);
  });

  it('ignores commands that are nothing to do with us', () => {
    expect(needsAbsolutePathRepair('some-other-tool hook pre-tool')).toBe(false);
  });

  it('repairs a bare command in place', () => {
    const bin = fakeBin();
    expect(repairHookCommand('shieldcortex hook pre-tool', bin)).toBe(`${bin} hook pre-tool`);
  });

  it('repairs the env-prefixed form while preserving the prefix', () => {
    const bin = fakeBin();
    expect(repairHookCommand('SHIELDCORTEX_RECALL_ENFORCE=1 shieldcortex hook prompt-recall', bin))
      .toBe(`SHIELDCORTEX_RECALL_ENFORCE=1 ${bin} hook prompt-recall`);
  });

  it('preserves trailing arguments', () => {
    const bin = fakeBin();
    expect(repairHookCommand('shieldcortex hook pre-tool --verbose', bin))
      .toBe(`${bin} hook pre-tool --verbose`);
  });

  it('is idempotent — repairing an already-repaired command changes nothing', () => {
    const bin = fakeBin();
    const once = repairHookCommand('shieldcortex hook pre-tool', bin);
    expect(repairHookCommand(once, bin)).toBe(once);
  });

  it('refuses to repair when it has no binary to point at', () => {
    expect(repairHookCommand('shieldcortex hook pre-tool', null)).toBe('shieldcortex hook pre-tool');
  });
});
