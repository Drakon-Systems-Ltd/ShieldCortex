import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  readDecisionsLedger,
  acquireOrRefreshLease,
  releaseLease,
  evaluateToolCallLease,
} from '../session-lease-store.js';

/**
 * #227 — the fs layer that turns the pure lease arithmetic into a control:
 * a real ledger location, a real lease store with acquire/refresh/release and
 * crash recovery, and the single entry point both enforcement planes call.
 *
 * Storage is flat JSON under ~/.shieldcortex (approvals-store pattern), NOT
 * SQLite: the Claude Code hook deliberately has no DB on its hot path, and a
 * lease store one plane cannot read is a plane that silently does not bind —
 * the exact dishonesty this PR was blocked over.
 */

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sc-lease-'));
});
afterEach(() => {
  try { chmodSync(join(dir, 'DECISIONS.md'), 0o644); } catch { /* absent */ }
  rmSync(dir, { recursive: true, force: true });
});

const NOW = Date.parse('2026-08-13T12:00:00Z');

describe('readDecisionsLedger — absent vs unreadable are different answers', () => {
  it('a missing ledger reads as empty (nothing ever frozen) — allow-shaped', () => {
    expect(readDecisionsLedger(dir)).toBe('');
  });

  it('a readable ledger returns its text', () => {
    writeFileSync(join(dir, 'DECISIONS.md'), '| FROZEN | npm publish until review |');
    expect(readDecisionsLedger(dir)).toContain('FROZEN');
  });

  it('an unreadable ledger returns null (refuse-shaped), never empty', () => {
    const p = join(dir, 'DECISIONS.md');
    writeFileSync(p, '| FROZEN | npm publish |');
    chmodSync(p, 0o000);
    let bites = false;
    try { readFileSync(p, 'utf-8'); } catch { bites = true; }
    if (bites) {
      expect(readDecisionsLedger(dir)).toBeNull();
    }
    chmodSync(p, 0o644);
  });
});

describe('acquire / refresh / release / crash recovery', () => {
  it('acquires a free lease and verifies ownership by re-read', () => {
    const r = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-a', nowMs: NOW });
    expect(r.acquired).toBe(true);
    expect(r.record?.holder).toBe('session-a');
    expect(r.record?.expiresAtMs).toBeGreaterThan(NOW);
  });

  it('a second session cannot acquire a live lease; the holder can refresh', () => {
    acquireOrRefreshLease({ dir, scope: 'install', self: 'session-a', nowMs: NOW });
    const b = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-b', nowMs: NOW + 1000 });
    expect(b.acquired).toBe(false);
    expect(b.record?.holder).toBe('session-a');

    const refreshed = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-a', nowMs: NOW + 2000 });
    expect(refreshed.acquired).toBe(true);
    expect(refreshed.record?.expiresAtMs).toBeGreaterThan(NOW + 2000);
  });

  it('an expired lease is recoverable by anyone — a crashed holder self-heals', () => {
    acquireOrRefreshLease({ dir, scope: 'install', self: 'session-a', nowMs: NOW, ttlMs: 1000 });
    const later = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-b', nowMs: NOW + 5000 });
    expect(later.acquired).toBe(true);
    expect(later.record?.holder).toBe('session-b');
  });

  it('release frees the lease for the holder only', () => {
    const a = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-a', nowMs: NOW });
    // Another identity cannot release someone else's lease.
    expect(releaseLease({ dir, scope: 'install', self: 'session-b' })).toBe(false);
    expect(releaseLease({ dir, scope: 'install', self: 'session-a' })).toBe(true);
    const b = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-b', nowMs: NOW + 1 });
    expect(b.acquired).toBe(true);
    expect(a.record?.holder).toBe('session-a');
  });

  it('a corrupt lease store reads as free (freeze still governs separately)', () => {
    mkdirSync(join(dir, 'leases'), { recursive: true });
    writeFileSync(join(dir, 'leases', 'leases.json'), '{ not json');
    const r = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-a', nowMs: NOW });
    expect(r.acquired).toBe(true);
  });
});

describe('evaluateToolCallLease — the single entry point both planes call', () => {
  it('an unscoped tool call is a fast null — no state read, no tax', () => {
    const r = evaluateToolCallLease('Bash', { command: 'git status' }, { self: 'session-a', dir, nowMs: NOW });
    expect(r).toBeNull();
  });

  it('a frozen scope refuses with the freeze quoted, and acquires nothing', () => {
    writeFileSync(join(dir, 'DECISIONS.md'), '| FROZEN | no npm publish until independent review |');
    const r = evaluateToolCallLease('Bash', { command: 'npm publish' }, { self: 'session-a', dir, nowMs: NOW });
    expect(r?.decision.verdict).toBe('frozen');
    // No lease record must have been minted for a refused action.
    const again = acquireOrRefreshLease({ dir, scope: 'npm-publish', self: 'session-b', nowMs: NOW });
    expect(again.acquired).toBe(true);
  });

  it('an allowed scoped call acquires the lease; a second session is then held', () => {
    const a = evaluateToolCallLease('Bash', { command: 'npm install -g shieldcortex' }, { self: 'session-a', dir, nowMs: NOW });
    expect(a?.decision.verdict).toBe('allow');
    const b = evaluateToolCallLease('Bash', { command: 'npm i --global x' }, { self: 'session-b', dir, nowMs: NOW + 1000 });
    expect(b?.decision.verdict).toBe('held');
    expect(b?.decision.reason).toContain('session-a');
  });

  it('the holder re-enters its own lease across multiple calls', () => {
    evaluateToolCallLease('Bash', { command: 'npm install -g x' }, { self: 'session-a', dir, nowMs: NOW });
    const again = evaluateToolCallLease('Bash', { command: 'npm install -g y' }, { self: 'session-a', dir, nowMs: NOW + 1000 });
    expect(again?.decision.verdict).toBe('allow');
  });

  it('an unreadable ledger refuses scoped actions (unknown), not unscoped ones', () => {
    const p = join(dir, 'DECISIONS.md');
    writeFileSync(p, '| FROZEN | anything |');
    chmodSync(p, 0o000);
    let bites = false;
    try { readFileSync(p, 'utf-8'); } catch { bites = true; }
    if (bites) {
      const scoped = evaluateToolCallLease('Bash', { command: 'npm publish' }, { self: 'session-a', dir, nowMs: NOW });
      expect(scoped?.decision.verdict).toBe('unknown');
    }
    const unscoped = evaluateToolCallLease('Bash', { command: 'ls' }, { self: 'session-a', dir, nowMs: NOW });
    expect(unscoped).toBeNull();
    chmodSync(p, 0o644);
  });

  it('reports a ledger content change since the last evaluation (tamper evidence)', () => {
    writeFileSync(join(dir, 'DECISIONS.md'), 'original');
    evaluateToolCallLease('Bash', { command: 'npm publish' }, { self: 'session-a', dir, nowMs: NOW });
    writeFileSync(join(dir, 'DECISIONS.md'), 'edited behind our back');
    const r = evaluateToolCallLease('Bash', { command: 'npm publish' }, { self: 'session-a', dir, nowMs: NOW + 1000 });
    expect(r?.ledgerChanged).toBeDefined();
    expect(r?.ledgerChanged?.fromHash).not.toBe(r?.ledgerChanged?.toHash);
  });

  it('a blank identity gets a stable non-blank fallback, never empty string', () => {
    const r = evaluateToolCallLease('Bash', { command: 'npm install -g x' }, { self: '', dir, nowMs: NOW });
    expect(r?.decision.verdict).toBe('allow');
    const rec = acquireOrRefreshLease({ dir, scope: 'install', self: 'probe', nowMs: NOW + 1 });
    expect(rec.record?.holder).not.toBe('');
  });
});
