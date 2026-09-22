import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  readDecisionsLedger,
  acquireOrRefreshLease,
  releaseLease,
  evaluateToolCallLease,
  isHolderPidAlive,
  isSpawningRuntimePid,
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

function unusedDeadPid(): number {
  for (let pid = 4_000_000; pid > 100_000; pid -= 97) {
    try {
      process.kill(pid, 0);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ESRCH') return pid;
    }
  }
  throw new Error('could not find an unused pid for #438');
}

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

  it('#438: a lease whose recorded PID is confirmed dead is recoverable before TTL', () => {
    const deadPid = unusedDeadPid();
    const first = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-a', nowMs: NOW });
    expect(first.acquired).toBe(true);
    const file = JSON.parse(readFileSync(join(dir, 'leases', 'leases.json'), 'utf-8')) as {
      leases: { install: { holder: string; pid: number; expiresAtMs: number } };
    };
    file.leases.install.pid = deadPid;
    writeFileSync(join(dir, 'leases', 'leases.json'), JSON.stringify(file, null, 2));

    const later = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-b', nowMs: NOW + 1000 });
    expect(later.acquired).toBe(true);
    expect(later.record?.holder).toBe('session-b');
  });

  it('#438: a live recorded PID still blocks the other session', () => {
    const first = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-a', nowMs: NOW });
    expect(first.acquired).toBe(true);
    const file = JSON.parse(readFileSync(join(dir, 'leases', 'leases.json'), 'utf-8')) as {
      leases: { install: { holder: string; pid: number; expiresAtMs: number } };
    };
    file.leases.install.pid = process.pid;
    writeFileSync(join(dir, 'leases', 'leases.json'), JSON.stringify(file, null, 2));

    const later = acquireOrRefreshLease({ dir, scope: 'install', self: 'session-b', nowMs: NOW + 1000 });
    expect(later.acquired).toBe(false);
    expect(later.record?.holder).toBe('session-a');
  });

  it('#438: evaluateToolCallLease also reaps a dead-PID install lease', () => {
    const deadPid = unusedDeadPid();
    acquireOrRefreshLease({ dir, scope: 'install', self: 'session-a', nowMs: NOW });
    const file = JSON.parse(readFileSync(join(dir, 'leases', 'leases.json'), 'utf-8')) as {
      leases: { install: { holder: string; pid: number } };
    };
    file.leases.install.pid = deadPid;
    writeFileSync(join(dir, 'leases', 'leases.json'), JSON.stringify(file, null, 2));

    const r = evaluateToolCallLease(
      'Bash',
      { command: 'npm install -g shieldcortex' },
      { self: 'session-b', dir, nowMs: NOW + 1000 },
    );
    expect(r?.decision.verdict).toBe('allow');
  });

  it('#438: isHolderPidAlive fails closed on missing/non-positive PIDs', () => {
    expect(isHolderPidAlive(undefined)).toBeUndefined();
    expect(isHolderPidAlive(null)).toBeUndefined();
    expect(isHolderPidAlive(0)).toBeUndefined();
    expect(isHolderPidAlive(-1)).toBeUndefined();
    expect(isHolderPidAlive(1.5)).toBeUndefined();
    expect(isHolderPidAlive(process.pid)).toBe(true);
    expect(isHolderPidAlive(unusedDeadPid())).toBe(false);
  });

  it('#438: missing /proc after kill(0) stays alive; Z/X reaps', () => {
    expect(isHolderPidAlive(process.pid, () => null)).toBe(true);
    expect(isHolderPidAlive(process.pid, () => '1 (node) R 1')).toBe(true);
    expect(isHolderPidAlive(process.pid, () => '1 (node) S 1')).toBe(true);
    expect(isHolderPidAlive(process.pid, () => '1 (node) Z 1')).toBe(false);
    expect(isHolderPidAlive(process.pid, () => '1 (node) X 1')).toBe(false);
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

describe('#550 — cross-plane re-entry through the spawning runtime', () => {
  const leasesPath = () => join(dir, 'leases', 'leases.json');
  const setPid = (scope: string, pid: number) => {
    const file = JSON.parse(readFileSync(leasesPath(), 'utf-8')) as { leases: Record<string, { pid: number }> };
    file.leases[scope]!.pid = pid;
    writeFileSync(leasesPath(), JSON.stringify(file, null, 2));
  };
  const WRITE = 'echo x > ~/.openclaw/openclaw.json';

  it('isSpawningRuntimePid: parent or grandparent only; never self, init, depth three or unreadable', () => {
    // hook 500 ← claude 400 ← gateway 300 ← systemd 200 ← init 1
    const chain: Record<number, number> = { 500: 400, 400: 300, 300: 200, 200: 1 };
    const read = (p: number) => chain[p] ?? null;
    expect(isSpawningRuntimePid(400, 500, read)).toBe(true);
    expect(isSpawningRuntimePid(300, 500, read)).toBe(true);
    // depth three: a nested `claude -p` under a Bash tool must not inherit a peer's lease
    expect(isSpawningRuntimePid(200, 500, read)).toBe(false);
    expect(isSpawningRuntimePid(500, 500, read)).toBe(false);
    expect(isSpawningRuntimePid(1, 500, read)).toBe(false);
    expect(isSpawningRuntimePid(0, 500, read)).toBe(false);
    expect(isSpawningRuntimePid(undefined, 500, read)).toBe(false);
    expect(isSpawningRuntimePid(400, 500, () => null)).toBe(false);
  });

  it('the default reader walks the real process table on this host', () => {
    expect(isSpawningRuntimePid(process.ppid)).toBe(true);
    expect(isSpawningRuntimePid(process.pid)).toBe(false);
  });

  it('the hook plane re-enters a lease the gateway plane holds under the OpenClaw session id, writing nothing', () => {
    // Gateway plane: the OpenClaw session id, allowed and acquired (pid = gateway).
    const gw = evaluateToolCallLease('Bash', { command: WRITE }, { self: 'openclaw-session-uuid', dir, nowMs: NOW });
    expect(gw?.decision.verdict).toBe('allow');
    expect(gw?.acquired).toBe(true);
    // In this test the "gateway" is our parent process.
    setPid('security-config', process.ppid);
    const before = readFileSync(leasesPath(), 'utf-8');

    // Hook plane: the same call, 400 ms later, under the hashed Claude session id.
    const hook = evaluateToolCallLease('Bash', { command: WRITE }, { self: 'sc-0123456789abcdef', dir, nowMs: NOW + 400, spawnedRuntimeReentry: true });
    expect(hook?.decision.verdict).toBe('allow');
    expect(hook?.acquired).toBe(false);
    expect(hook?.decision.reason).toContain('openclaw-session-uuid');
    expect(readFileSync(leasesPath(), 'utf-8')).toBe(before);

    // A plane that did not opt in (the interceptor, evaluateAction, a host
    // adapter) keeps the strict match even from the same process tree.
    const other = evaluateToolCallLease('Bash', { command: WRITE }, { self: 'other-openclaw-session', dir, nowMs: NOW + 800 });
    expect(other?.decision.verdict).toBe('held');
    expect(readFileSync(leasesPath(), 'utf-8')).toBe(before);
  });

  it('a live holder that did not spawn this process still binds, and the refusal leaves the record byte-identical', () => {
    const first = evaluateToolCallLease('Bash', { command: 'npm install -g x' }, { self: 'session-a', dir, nowMs: NOW });
    expect(first?.acquired).toBe(true);
    // pid = this very process: alive, not our parent, not our grandparent.
    setPid('install', process.pid);
    const before = readFileSync(leasesPath(), 'utf-8');
    const r = evaluateToolCallLease('Bash', { command: 'npm install -g y' }, { self: 'sc-0123456789abcdef', dir, nowMs: NOW + 1, spawnedRuntimeReentry: true });
    expect(r?.decision.verdict).toBe('held');
    expect(readFileSync(leasesPath(), 'utf-8')).toBe(before);
  });

  it('a dead spawning-runtime pid is reaped by #438 before re-entry is even asked', () => {
    evaluateToolCallLease('Bash', { command: WRITE }, { self: 'openclaw-session-uuid', dir, nowMs: NOW });
    setPid('security-config', unusedDeadPid());
    const r = evaluateToolCallLease('Bash', { command: WRITE }, { self: 'sc-0123456789abcdef', dir, nowMs: NOW + 1, spawnedRuntimeReentry: true });
    expect(r?.decision.verdict).toBe('allow');
    expect(r?.acquired).toBe(true);
  });
});
