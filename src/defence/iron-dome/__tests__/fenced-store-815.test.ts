/**
 * #815 B — the fenced store (fenced-store.ts): one authority, one migration.
 *
 * The first half reads and commits in-process. The second half runs REAL
 * processes against `dist`, because pausing a writer between its generation
 * claim and its publication, or failing that publication, needs Node's own
 * ESM builtins interposed (`syncBuiltinESMExports`) — the same seam as
 * approve-tap-interleave-815.
 *
 * The migration cases start from the store an existing install already has:
 * the pre-fence layout, no fence and no generations, holding a live terminal
 * retry grant. That is fixture preparation, done before the operation under
 * test begins. Fixture commands are data; nothing here executes them.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  CORRUPT_STORE, acquireStoreLock, commitFencedJson, fencedGenerationDir, readFencedJson,
} from '../fenced-store.js';
import {
  consumeRetryGrant, exactCallDigest, grantRetry, hashToolCall, pruneRetryControl, recordDenialFingerprint, retryControlPath,
} from '../retry-control.js';
import { fencedStateFile } from './fenced-state-fixture.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
const DIST = join(repoRoot, 'dist', 'defence', 'iron-dome');

let dir: string;
let store: string;

/** What an older release (and anything else outside this module) does: a
 *  temp file renamed over the copy — a new inode, no fence. */
function renameOver(path: string, value: unknown): void {
  const tmp = `${path}.other.tmp`;
  writeFileSync(tmp, JSON.stringify(value), { mode: 0o600 });
  renameSync(tmp, path);
}

describe('#815 B — the newest generation is the only authority', () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-fence-'));
    store = join(dir, 'store.json');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('an unfenced copy written over an existing generation is never read', () => {
    expect(commitFencedJson(store, 0, { state: 'committed' })).toBe(true);
    renameOver(store, { state: 'unfenced-after-migration' });
    expect(readFencedJson(store)).toMatchObject({ value: { state: 'committed', fence: 1 }, base: 1, fenced: true });
  });

  it('a published copy older than the newest generation is never read', () => {
    expect(commitFencedJson(store, 0, { state: 'one' })).toBe(true);
    const old = readFileSync(store, 'utf8');
    expect(commitFencedJson(store, 1, { state: 'two' })).toBe(true);
    renameOver(store, JSON.parse(old));
    expect(readFencedJson(store)).toMatchObject({ value: { state: 'two', fence: 2 }, base: 2 });
  });

  it('a pre-fence copy is read as written until the first commit claims generation 1, and never after', () => {
    writeFileSync(store, JSON.stringify({ state: 'legacy' }), { mode: 0o600 });
    const legacy = readFencedJson(store);
    expect(legacy).toEqual({ value: { state: 'legacy' }, base: 0, fenced: false, preFence: JSON.stringify({ state: 'legacy' }) });
    expect(commitFencedJson(store, legacy.base, { state: 'migrated' }, legacy.preFence)).toBe(true);
    // A second import of the same pre-fence state is refused…
    expect(commitFencedJson(store, legacy.base, { state: 'imported-again' }, legacy.preFence)).toBe(false);
    // …and the pre-fence copy put back is not read again.
    renameOver(store, { state: 'legacy' });
    expect(readFencedJson(store)).toMatchObject({ value: { state: 'migrated' }, base: 1 });
  });

  it('a published copy whose generations are gone reads as corrupt, never as the state it shows', () => {
    expect(commitFencedJson(store, 0, { state: 'published' })).toBe(true);
    rmSync(fencedGenerationDir(store), { recursive: true, force: true });
    expect(readFencedJson(store)).toMatchObject({ value: CORRUPT_STORE, base: 0, fenced: false });
  });

  it('no copy and no generation is an empty store; a missing copy beside a generation changes nothing', () => {
    expect(readFencedJson(store)).toEqual({ value: undefined, base: 0, fenced: false, preFence: null });
    expect(commitFencedJson(store, 0, { state: 'kept' })).toBe(true);
    rmSync(store);
    expect(readFencedJson(store)).toMatchObject({ value: { state: 'kept' }, base: 1 });
  });

  it('the copy at the store path is a pointer that holds no state', () => {
    expect(commitFencedJson(store, 0, { rows: [{ grant: { approvedAt: 1 } }] })).toBe(true);
    expect(commitFencedJson(store, 1, { rows: [{ grant: { approvedAt: 2 } }] })).toBe(true);
    expect(JSON.parse(readFileSync(store, 'utf8'))).toEqual({ fence: 2, state: 'store.json.gen/2' });
    expect(readFencedJson(store)).toMatchObject({ value: { rows: [{ grant: { approvedAt: 2 } }], fence: 2 }, base: 2, fenced: true });
  });

  it('a first commit withdraws the pre-fence copy, and refuses unless it is the copy that was read', () => {
    writeFileSync(store, JSON.stringify({ state: 'legacy' }), { mode: 0o600 });
    const legacy = readFencedJson(store);
    // Replaced after the read, as an older release's writer would (a rename).
    renameOver(store, { state: 'replaced' });
    expect(commitFencedJson(store, legacy.base, { state: 'built-on-legacy' }, legacy.preFence)).toBe(false);
    expect(existsSync(join(fencedGenerationDir(store), '1'))).toBe(false);
    // The withdrawn copy is dropped, never put back: the store is now empty.
    expect(existsSync(store)).toBe(false);
    expect(readFencedJson(store)).toEqual({ value: undefined, base: 0, fenced: false, preFence: null });
    // A first commit that read no copy refuses over one that exists.
    writeFileSync(store, JSON.stringify({ state: 'appeared' }), { mode: 0o600 });
    expect(commitFencedJson(store, 0, { state: 'blind' })).toBe(false);
    expect(existsSync(join(fencedGenerationDir(store), '1'))).toBe(false);
  });
});

describe('#815 B — the store lock waits for a bounded time', () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-fence-lock-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  /** A clock whose every wait overruns by `overrunMs`, as on a starved runner. */
  function slowClock(overrunMs: number) {
    const clock = { t: Date.now(), waits: 0, now: () => clock.t, sleep: (ms: number) => { clock.waits += 1; clock.t += ms + overrunMs; } };
    return clock;
  }

  it('a lock that was fresh when the wait began is never taken over, however long each wait overruns', () => {
    const lockPath = join(dir, 'store.lock');
    mkdirSync(lockPath);
    writeFileSync(join(lockPath, 'owner'), 'holder');
    const clock = slowClock(5_000);
    expect(acquireStoreLock(lockPath, { attempts: 100, sleepMs: 20, staleMs: 10_000, clock })).toBeNull();
    expect(readFileSync(join(lockPath, 'owner'), 'utf8')).toBe('holder');
    // One overrun wait used the whole budget; the call gave up instead of
    // waiting into the stale threshold.
    expect(clock.waits).toBe(1);
  });

  it('the wait ends well inside the stale threshold even when tries times sleep would not', () => {
    const lockPath = join(dir, 'store.lock');
    mkdirSync(lockPath);
    writeFileSync(join(lockPath, 'owner'), 'holder');
    const clock = slowClock(0);
    const start = clock.t;
    expect(acquireStoreLock(lockPath, { attempts: 1_000, sleepMs: 20, staleMs: 10_000, clock })).toBeNull();
    expect(readFileSync(join(lockPath, 'owner'), 'utf8')).toBe('holder');
    expect(clock.t - start).toBeLessThanOrEqual(5_000);
  });

  it('a lock already past the stale threshold at the first look is still taken over', () => {
    const lockPath = join(dir, 'store.lock');
    mkdirSync(lockPath);
    const old = new Date(Date.now() - 60_000);
    utimesSync(lockPath, old, old);
    const lock = acquireStoreLock(lockPath, { attempts: 100, sleepMs: 20, staleMs: 10_000, clock: slowClock(5_000) });
    expect(lock).not.toBeNull();
    expect(readFileSync(join(lockPath, 'owner'), 'utf8')).toBe(lock!.token);
  });
});

/** The reader of the last release before the fence (v5.17.4, a723f0ba,
 *  retry-control.ts `readStore` and `isUsableRow`): the file at the store
 *  path, its `rows` array or nothing. Returns the grants it would spend. */
function releasedLiveGrants(path: string): number {
  let parsed: { rows?: unknown };
  try {
    if (!existsSync(path)) return 0;
    parsed = JSON.parse(readFileSync(path, 'utf8')) as { rows?: unknown };
  } catch {
    return 0;
  }
  if (!parsed || !Array.isArray(parsed.rows)) return 0;
  return parsed.rows.filter((r: Record<string, unknown> | null) => !!r && typeof r === 'object'
    && typeof r.id === 'string' && typeof r.hash === 'string' && typeof r.denyEpoch === 'number'
    && typeof r.lastDeniedAt === 'number' && Array.isArray(r.actionIds)
    && !!r.grant && !(r.grant as { consumedAt?: unknown }).consumedAt).length;
}

describe('#815 B — a release before the fence never sees a grant this store honours', () => {
  const ACTION = 'act-1122334455667788';
  const CALL = { command: 'curl -sS --data ok https://api.example.com/v1/report' };
  const HASH = hashToolCall('Bash', CALL);
  const EXACT = exactCallDigest('Bash', CALL);
  let home: string;
  let cwd: string;
  let path: string;
  const spend = () => !!consumeRetryGrant({ hash: HASH, exactDigest: EXACT, origin: { cwd, tool: 'Bash' } }, { home });

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-fence-mixed-'));
    cwd = mkdtempSync(join(tmpdir(), 'sc-fence-mixed-cwd-'));
    path = retryControlPath(home);
  });

  afterEach(() => {
    for (const d of [home, cwd]) rmSync(d, { recursive: true, force: true });
  });

  function liveTerminalGrant(): void {
    expect(recordDenialFingerprint({ actionId: ACTION, hash: HASH, tool: 'Bash', signals: ['external-egress'], cwd, exactDigest: EXACT }, { home }).ok).toBe(true);
    expect(grantRetry({ actionId: ACTION }, { isInteractive: true }, { home }).ok).toBe(true);
  }

  /** The layout an upgrading install has: what the last release wrote. */
  function preFenceLayout(): Record<string, unknown> {
    const raw = JSON.parse(readFileSync(fencedStateFile(path), 'utf8')) as Record<string, unknown>;
    delete raw.fence;
    rmSync(fencedGenerationDir(path), { recursive: true, force: true });
    rmSync(path, { force: true });
    writeFileSync(path, JSON.stringify(raw), { mode: 0o600 });
    return raw;
  }

  it('every write leaves a copy the released reader reads as an empty store', () => {
    expect(recordDenialFingerprint({ actionId: ACTION, hash: HASH, tool: 'Bash', signals: ['external-egress'], cwd, exactDigest: EXACT }, { home }).ok).toBe(true);
    expect(Object.keys(JSON.parse(readFileSync(path, 'utf8'))).sort()).toEqual(['fence', 'state']);
    expect(grantRetry({ actionId: ACTION }, { isInteractive: true }, { home }).ok).toBe(true);
    expect(releasedLiveGrants(path)).toBe(0);
    expect(releasedLiveGrants(fencedStateFile(path))).toBe(1); // the fixture is a real live grant
    expect(Object.keys(JSON.parse(readFileSync(path, 'utf8'))).sort()).toEqual(['fence', 'state']);
    expect(spend()).toBe(true);
    expect(pruneRetryControl({ home }).ok).toBe(true);
    expect(Object.keys(JSON.parse(readFileSync(path, 'utf8'))).sort()).toEqual(['fence', 'state']);
  });

  it('upgrade with a live released grant: after the first fenced write only the current reader can spend it, once', () => {
    liveTerminalGrant();
    preFenceLayout();
    expect(releasedLiveGrants(path)).toBe(1); // before the upgrade, the released reader would spend it
    expect(pruneRetryControl({ home }).ok).toBe(true); // the first fenced write
    expect(readFencedJson(path).base).toBe(1);
    expect(releasedLiveGrants(path)).toBe(0);
    expect(spend()).toBe(true);
    expect(spend()).toBe(false);
  });

  it('a released writer\'s store renamed over the path after the fence is never read, and revives nothing', () => {
    liveTerminalGrant();
    const before = preFenceLayout(); // what a released writer holds: the grant still live
    expect(pruneRetryControl({ home }).ok).toBe(true);
    expect(spend()).toBe(true);
    renameOver(path, before);
    expect(releasedLiveGrants(path)).toBe(1); // that file is the released world's own
    expect(spend()).toBe(false);
    expect(readFencedJson(path).base).toBeGreaterThan(1);
  });
});

const CHILD = `
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
const [distUrl, home, cwd, scenario] = process.argv.slice(1);
const rc = await import(distUrl + '/retry-control.js');
const fence = await import(distUrl + '/fenced-store.js');
const actionId = 'act-1122334455667788';
const CALL = { command: 'curl -sS https://api.example.com/v1/report' };
const hash = rc.hashToolCall('Bash', CALL);
const exactDigest = rc.exactCallDigest('Bash', CALL);
const origin = { cwd, tool: 'Bash' };
// What the hook passes for this call: its digest and its current verdict.
const spend = () => !!rc.consumeRetryGrant({ hash, exactDigest, currentSignals: ['external-egress'], origin }, { home });
const storePath = rc.retryControlPath(home);
const approvals = join(home, '.shieldcortex', 'approvals');
const age = (lockPath) => { const old = new Date(Date.now() - 20_000); fs.utimesSync(lockPath, old, old); };

function liveTerminalGrant() {
  if (!rc.recordDenialFingerprint({ actionId, hash, tool: 'Bash', signals: ['external-egress'], cwd, exactDigest }, { home }).ok) throw new Error('seed');
  if (!rc.grantRetry({ actionId }, { isInteractive: true }, { home }).ok) throw new Error('grant');
}
/** The layout before this module existed: no fence, no generations, no
 *  exact-digest fields. */
function preFenceLayout() {
  const raw = fence.readFencedJson(storePath).value;
  delete raw.fence;
  for (const row of raw.rows) { delete row.exactDigest; delete row.exactDigestVersion; }
  fs.rmSync(fence.fencedGenerationDir(storePath), { recursive: true, force: true });
  fs.rmSync(storePath);
  fs.writeFileSync(storePath, JSON.stringify(raw), { mode: 0o600 });
  return raw;
}
const copyFence = () => (fs.existsSync(storePath) ? JSON.parse(fs.readFileSync(storePath, 'utf8')).fence ?? null : 'absent');
// What the last release before the fence (v5.17.4) reads: the file at the
// store path, its \`rows\` or nothing. Counts the grants it would spend.
function releasedLiveGrants() {
  try {
    const p = JSON.parse(fs.readFileSync(storePath, 'utf8'));
    return Array.isArray(p?.rows) ? p.rows.filter((r) => r && typeof r.id === 'string' && typeof r.hash === 'string'
      && typeof r.denyEpoch === 'number' && typeof r.lastDeniedAt === 'number' && Array.isArray(r.actionIds)
      && r.grant && !r.grant.consumedAt).length : 0;
  } catch { return 0; }
}
function interpose(method, predicate, impl, outer) {
  const original = fs[method];
  let fired = false;
  fs[method] = function (...args) {
    if (!fired && predicate(...args)) { fired = true; return impl(original, args); }
    return original.apply(fs, args);
  };
  syncBuiltinESMExports();
  try { return { fired: () => fired, value: outer() }; }
  finally { fs[method] = original; syncBuiltinESMExports(); }
}

const out = { scenario };
if (scenario === 'interleave' || scenario === 'interleave-pre-fence') {
  // The first consumer has claimed its generation and is paused before it
  // publishes the copy, long enough for its lock to be taken over.
  liveTerminalGrant();
  if (scenario === 'interleave-pre-fence') preFenceLayout();
  out.fenceBefore = copyFence();
  const r = interpose('renameSync', (_a, b) => b === storePath, (original, args) => {
    out.releasedLiveGrantsAtPause = releasedLiveGrants();
    age(join(approvals, 'retry-control.lock'));
    out.innerSpend = spend();
    return original.apply(fs, args);
  }, () => spend());
  out.fired = r.fired();
  out.outerSpend = r.value;
  out.thirdSpend = spend();
} else if (scenario === 'publish-fails' || scenario === 'publish-fails-pre-fence') {
  // Every publication of the copy fails; the generation claim succeeds.
  liveTerminalGrant();
  if (scenario === 'publish-fails-pre-fence') preFenceLayout();
  out.fenceBefore = copyFence();
  const original = fs.renameSync;
  fs.renameSync = function (a, b) {
    if (b === storePath) throw Object.assign(new Error('fixture publication failure'), { code: 'EACCES' });
    return original.call(fs, a, b);
  };
  syncBuiltinESMExports();
  try { out.firstSpend = spend(); out.secondSpend = spend(); out.copyFenceWhileFailing = copyFence(); }
  finally { fs.renameSync = original; syncBuiltinESMExports(); }
  out.thirdSpendAfterRestore = spend();
} else if (scenario === 'pre-claim-pre-fence') {
  // The first consumer is about to claim generation 1. What can a reader of
  // the last release before the fence spend at that instant?
  liveTerminalGrant();
  preFenceLayout();
  out.releasedBefore = releasedLiveGrants();
  const r = interpose('linkSync', (_a, b) => b === join(fence.fencedGenerationDir(storePath), '1'), (original, args) => {
    out.releasedLiveGrantsAtClaim = releasedLiveGrants();
    return original.apply(fs, args);
  }, () => spend());
  out.fired = r.fired();
  out.outerSpend = r.value;
  out.releasedAfter = releasedLiveGrants();
  out.secondSpend = spend();
} else if (scenario === 'released-spend-before-withdrawal') {
  // The first consumer read the pre-fence store; before it withdraws that
  // copy, a released consumer (lock taken over as stale) spends the grant
  // and renames its store over the path, as v5.17.4 does.
  liveTerminalGrant();
  const legacy = preFenceLayout();
  const r = interpose('renameSync', (a) => a === storePath, (original, args) => {
    const spent = JSON.parse(JSON.stringify(legacy));
    spent.rows[0].grant.consumedAt = Date.now();
    fs.writeFileSync(storePath + '.released.tmp', JSON.stringify(spent), { mode: 0o600 });
    original.call(fs, storePath + '.released.tmp', storePath);
    out.releasedSpent = true;
    return original.apply(fs, args);
  }, () => spend());
  out.fired = r.fired();
  out.outerSpend = r.value;
  out.claimed = fs.existsSync(join(fence.fencedGenerationDir(storePath), '1'));
  out.thirdSpend = spend();
} else if (scenario === 'pruned-generation') {
  // A writer that read generation 1 and stalled until it was pruned.
  const p = join(home, 'store.json');
  if (!fence.commitFencedJson(p, 0, { state: 1 })) throw new Error('first');
  const stale = fence.readFencedJson(p);
  for (let i = 2; i <= 10; i++) if (!fence.commitFencedJson(p, i - 1, { state: i })) throw new Error('commit ' + i);
  out.staleCommit = fence.commitFencedJson(p, stale.base, { state: 'resurrected' });
  const now = fence.readFencedJson(p);
  out.base = now.base;
  out.state = now.value.state;
} else if (scenario === 'release-aba') {
  // A holder paused between its owner-token check and the removal, while its
  // lock is taken over as stale: the removal takes the successor's lock.
  const p = join(home, 'store.json');
  const lockPath = join(home, 'store.lock');
  const opts = { attempts: 3, sleepMs: 1, staleMs: 10_000 };
  if (!fence.commitFencedJson(p, 0, { holder: 'none' })) throw new Error('seed');
  const first = fence.acquireStoreLock(lockPath, opts);
  let second = null;
  const r = interpose('rmSync', (q) => q === join(lockPath, 'owner'), (original, args) => {
    age(lockPath);
    second = fence.acquireStoreLock(lockPath, opts);
    return original.apply(fs, args);
  }, () => fence.releaseStoreLock(first));
  out.fired = r.fired();
  out.secondAcquired = !!second;
  out.successorLockRemoved = !fs.existsSync(lockPath);
  const third = fence.acquireStoreLock(lockPath, opts);
  out.thirdAcquired = !!third;
  // Both believe they hold the lock and build on the same state.
  const s2 = fence.readFencedJson(p);
  const s3 = fence.readFencedJson(p);
  out.secondCommit = fence.commitFencedJson(p, s2.base, { holder: 'second' });
  out.thirdCommit = fence.commitFencedJson(p, s3.base, { holder: 'third' });
  out.holder = fence.readFencedJson(p).value.holder;
  fence.releaseStoreLock(third);
}
process.stdout.write(JSON.stringify(out));
`;

function run(home: string, cwd: string, scenario: string): Record<string, unknown> {
  const res = spawnSync(process.execPath, ['--input-type=module', '-e', CHILD, pathToFileURL(DIST).href, home, cwd, scenario], {
    encoding: 'utf8', timeout: 60_000, env: { PATH: process.env.PATH ?? '/usr/bin:/bin' },
  });
  if (res.status !== 0) throw new Error(`child failed: ${String(res.stderr).slice(0, 800)}`);
  return JSON.parse(res.stdout) as Record<string, unknown>;
}

describe('#815 B — the fenced store across processes', () => {
  let home: string;
  let cwd: string;

  beforeAll(() => {
    if (!existsSync(join(DIST, 'fenced-store.js'))) spawnSync('npm', ['run', 'build:ts'], { cwd: repoRoot, stdio: 'ignore' });
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-fence-il-'));
    cwd = mkdtempSync(join(tmpdir(), 'sc-fence-il-cwd-'));
  });

  afterEach(() => {
    for (const d of [home, cwd]) rmSync(d, { recursive: true, force: true });
  });

  it('first migration: a consumer paused after its claim, before publishing — exactly one spend, and nothing a released reader can spend', () => {
    expect(run(home, cwd, 'interleave-pre-fence')).toEqual({
      scenario: 'interleave-pre-fence', fenceBefore: null, fired: true, releasedLiveGrantsAtPause: 0,
      outerSpend: true, innerSpend: false, thirdSpend: false,
    });
  }, 60_000);

  it('first migration: at the claim the pre-fence copy is already out of a released reader\'s sight', () => {
    expect(run(home, cwd, 'pre-claim-pre-fence')).toEqual({
      scenario: 'pre-claim-pre-fence', releasedBefore: 1, fired: true, releasedLiveGrantsAtClaim: 0,
      outerSpend: true, releasedAfter: 0, secondSpend: false,
    });
  }, 60_000);

  it('first migration: a released consumer that spent the grant before the withdrawal — the import is refused, one spend in all', () => {
    expect(run(home, cwd, 'released-spend-before-withdrawal')).toEqual({
      scenario: 'released-spend-before-withdrawal', releasedSpent: true, fired: true,
      outerSpend: false, claimed: false, thirdSpend: false,
    });
  }, 60_000);

  it('first migration: the publication fails — exactly one spend, including after it is restored', () => {
    expect(run(home, cwd, 'publish-fails-pre-fence')).toEqual({
      scenario: 'publish-fails-pre-fence', fenceBefore: null,
      firstSpend: true, secondSpend: false, copyFenceWhileFailing: 'absent', thirdSpendAfterRestore: false,
    });
  }, 60_000);

  it('already fenced: a consumer paused after its claim, before publishing — exactly one spend', () => {
    expect(run(home, cwd, 'interleave')).toMatchObject({ fired: true, outerSpend: true, innerSpend: false, thirdSpend: false });
  }, 60_000);

  it('already fenced: the publication fails — exactly one spend, including after it is restored', () => {
    expect(run(home, cwd, 'publish-fails')).toMatchObject({ firstSpend: true, secondSpend: false, thirdSpendAfterRestore: false });
  }, 60_000);

  it('a writer stalled until its base generation was pruned cannot commit over the newer state', () => {
    expect(run(home, cwd, 'pruned-generation')).toEqual({ scenario: 'pruned-generation', staleCommit: false, base: 10, state: 10 });
  }, 60_000);

  it('the lock is advisory: a release can remove a successor\'s lock, and the fence still lets only one of two holders commit', () => {
    expect(run(home, cwd, 'release-aba')).toEqual({
      scenario: 'release-aba', fired: true, secondAcquired: true, successorLockRemoved: true, thirdAcquired: true,
      secondCommit: true, thirdCommit: false, holder: 'second',
    });
  }, 60_000);
});
