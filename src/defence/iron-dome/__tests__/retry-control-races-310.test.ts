/**
 * #310 — the races, run as REAL concurrent processes.
 *
 * The design's whole reason for one lock plane is that this hook is one
 * process per tool call, and a detached waiter is a third party writing the
 * same file. An in-process `Promise.all` proves nothing about that (the store
 * is synchronous), so these tests fan out actual `node` subprocesses against
 * the COMPILED store in `dist` and check the properties that matter:
 *
 *   - a grant is spent exactly ONCE, no matter how many callers race for it;
 *   - concurrent denial writes never lose an update;
 *   - two waiters cannot both hold a launch claim for one identity;
 *   - a deny racing a tap leaves the store readable, with the deny winning.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from '@jest/globals';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  canonicaliseCwd,
  claimCardLaunch,
  fingerprintId,
  grantRetry,
  hashToolCall,
  recordDenialFingerprint,
} from '../retry-control.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
const DIST_STORE = join(repoRoot, 'dist', 'defence', 'iron-dome', 'retry-control.js');
const HASH = hashToolCall('Bash', { command: 'sudo modprobe softdog' });

interface RaceStore {
  rows: Array<{
    actionIds: string[];
    claim?: unknown;
    suppression?: { until: number };
    grant?: { consumedAt?: number };
  }>;
}

describe('#310 — concurrency on the one lock plane', () => {
  let home: string;
  let cwd: string;

  beforeAll(() => {
    if (!existsSync(DIST_STORE)) {
      spawnSync('npm', ['run', 'build:ts'], { cwd: repoRoot, stdio: 'ignore' });
    }
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-retry-race-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    cwd = mkdtempSync(join(tmpdir(), 'sc-retry-race-cwd-'));
  });

  afterEach(() => {
    for (const dir of [home, cwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  /**
   * Run one snippet against the COMPILED store, in its own process — ASYNC on
   * purpose. `spawnSync` in a loop would serialise the very thing under test
   * and every assertion below would pass for the wrong reason.
   */
  function child(body: string): Promise<{ stdout: string; stderr: string; status: number | null }> {
    const script = [
      `const store = await import(${JSON.stringify(pathToFileURL(DIST_STORE).href)});`,
      `const home = ${JSON.stringify(home)};`,
      `const cwd = ${JSON.stringify(cwd)};`,
      `const hash = ${JSON.stringify(HASH)};`,
      body,
    ].join('\n');
    return new Promise((resolvePromise) => {
      const proc = spawn('node', ['--input-type=module', '-e', script], {
        env: { ...process.env, HOME: home, USERPROFILE: home } as NodeJS.ProcessEnv,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '';
      let stderr = '';
      proc.stdout.on('data', (c) => { stdout += String(c); });
      proc.stderr.on('data', (c) => { stderr += String(c); });
      proc.on('close', (status) => resolvePromise({ stdout, stderr, status }));
    });
  }

  /** Fan out N snippets and let them collide. */
  function race(bodies: string[]): Promise<Array<{ stdout: string; stderr: string; status: number | null }>> {
    return Promise.all(bodies.map((b) => child(b)));
  }

  function storeFile(): RaceStore {
    return JSON.parse(
      readFileSync(join(home, '.shieldcortex', 'approvals', 'retry-control.json'), 'utf8'),
    ) as RaceStore;
  }

  function seedDenial(actionId: string): void {
    recordDenialFingerprint(
      { hash: HASH, tool: 'Bash', actionId, signals: ['dangerous-shell'], redactedSurface: 'surface', cwd },
      { home },
    );
  }

  it('a live grant is spent by exactly ONE of eight racing tool calls', async () => {
    seedDenial('act-0000000000000001');
    const claim = claimCardLaunch(
      { id: fingerprintId(HASH, canonicaliseCwd(cwd)) },
      { home, windowStartMs: Date.now(), windowMs: 900_000 },
    );
    expect(claim.ok).toBe(true);
    expect(grantRetry({ hash: HASH, cwd }, { nonce: claim.ok ? claim.nonce : '' }, { home }).ok).toBe(true);

    const results = await race(Array.from({ length: 8 }, () =>
      "const spent = store.consumeRetryGrant({ hash, origin: { cwd, tool: 'Bash' } }, { home });\n"
      + 'process.stdout.write(spent ? "SPENT" : "none");'));

    expect(results.filter((r) => r.stdout.includes('SPENT'))).toHaveLength(1);
    expect(results.every((r) => r.status === 0)).toBe(true);
    expect(storeFile().rows[0].grant?.consumedAt).toBeGreaterThan(0);
  });

  it('concurrent denial writes never lose an update', async () => {
    const ids = Array.from({ length: 8 }, (_, i) => `act-00000000000000${String(i).padStart(2, '0')}`);
    const results = await race(ids.map((actionId) =>
      `store.recordDenialFingerprint({ hash, tool: 'Bash', actionId: ${JSON.stringify(actionId)},`
      + " signals: ['dangerous-shell'], redactedSurface: 'surface', cwd }, { home });\n"
      + 'process.stdout.write("ok");'));

    expect(results.every((r) => r.stdout === 'ok')).toBe(true);
    const rows = storeFile().rows;
    expect(rows).toHaveLength(1);
    // Every writer's actionId survived: no last-writer-wins truncation.
    for (const id of ids) expect(rows[0].actionIds).toContain(id);
  });

  it('two racing waiters cannot both hold a launch claim for one identity', async () => {
    seedDenial('act-0000000000000009');
    const windowStartMs = Date.now();
    const results = await race(Array.from({ length: 6 }, () =>
      'const c = store.claimCardLaunch({ hash, cwd }, { home, windowStartMs: '
      + `${windowStartMs}, windowMs: 900000 });\n`
      + 'process.stdout.write(c.ok ? "CLAIMED" : "refused:" + c.reason);'));

    // Security invariant: exactly one mint. Losers must be fail-closed.
    // Under CI contention a loser can time out the lock spin (`locked`)
    // instead of observing the committed claim (`already-claimed`). Both
    // mint nothing. A crash / empty stdout / not-found is still a fail.
    const dump = results.map((r) => ({ status: r.status, stdout: r.stdout, stderr: r.stderr.slice(0, 200) }));
    expect(results.every((r) => r.status === 0)).toBe(true);
    const claimed = results.filter((r) => r.stdout.includes('CLAIMED'));
    const failClosed = results.filter((r) =>
      r.stdout.includes('refused:already-claimed') || r.stdout.includes('refused:locked'));
    expect({ claimed: claimed.length, failClosed: failClosed.length, dump }).toEqual({
      claimed: 1,
      failClosed: 5,
      dump,
    });
    expect(storeFile().rows[0].claim).toBeDefined();
  });

  it('a deny racing a tap leaves the store readable, and the deny wins', async () => {
    seedDenial('act-000000000000000a');
    const claim = claimCardLaunch(
      { id: fingerprintId(HASH, canonicaliseCwd(cwd)) },
      { home, windowStartMs: Date.now(), windowMs: 900_000 },
    );
    const nonce = claim.ok ? claim.nonce : '';

    const results = await race([
      "store.recordDenialFingerprint({ hash, tool: 'Bash', actionId: 'act-000000000000000b', signals: ['dangerous-shell'], redactedSurface: 'surface', cwd }, { home });\nprocess.stdout.write('reminted');",
      "store.recordDenySuppression({ hash, cwd }, { home, suppressionMs: 900000, via: 'card' });\nprocess.stdout.write('denied');",
      `const g = store.grantRetry({ hash, cwd }, { nonce: ${JSON.stringify(nonce)} }, { home });\nprocess.stdout.write(g.ok ? 'granted' : 'refused:' + g.reason);`,
    ]);

    expect(results.every((r) => r.status === 0)).toBe(true);

    // Whatever the interleaving, the file is intact — and once a deny has
    // landed, nothing spendable can survive it.
    const rows = storeFile().rows;
    expect(rows).toHaveLength(1);
    if (rows[0].suppression) {
      const spend = await child(
        "const spent = store.consumeRetryGrant({ hash, origin: { cwd, tool: 'Bash' } }, { home });\n"
        + 'process.stdout.write(spent ? "SPENT" : "none");',
      );
      expect(spend.stdout).toContain('none');
    }
  });
});
