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
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { CORRUPT_STORE, commitFencedJson, fencedGenerationDir, readFencedJson } from '../fenced-store.js';

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
    expect(legacy).toEqual({ value: { state: 'legacy' }, base: 0, fenced: false });
    expect(commitFencedJson(store, legacy.base, { state: 'migrated' })).toBe(true);
    // A second import of the same pre-fence state is refused by the claim…
    expect(commitFencedJson(store, legacy.base, { state: 'imported-again' })).toBe(false);
    // …and the pre-fence copy put back is not read again.
    renameOver(store, { state: 'legacy' });
    expect(readFencedJson(store)).toMatchObject({ value: { state: 'migrated' }, base: 1 });
  });

  it('a published copy whose generations are gone reads as corrupt, never as the state it shows', () => {
    expect(commitFencedJson(store, 0, { state: 'published' })).toBe(true);
    rmSync(fencedGenerationDir(store), { recursive: true, force: true });
    expect(readFencedJson(store)).toEqual({ value: CORRUPT_STORE, base: 0, fenced: false });
  });

  it('no copy and no generation is an empty store; a missing copy beside a generation changes nothing', () => {
    expect(readFencedJson(store)).toEqual({ value: undefined, base: 0, fenced: false });
    expect(commitFencedJson(store, 0, { state: 'kept' })).toBe(true);
    rmSync(store);
    expect(readFencedJson(store)).toMatchObject({ value: { state: 'kept' }, base: 1 });
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
  const raw = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  delete raw.fence;
  for (const row of raw.rows) { delete row.exactDigest; delete row.exactDigestVersion; }
  fs.rmSync(fence.fencedGenerationDir(storePath), { recursive: true, force: true });
  fs.rmSync(storePath);
  fs.writeFileSync(storePath, JSON.stringify(raw), { mode: 0o600 });
}
const copyFence = () => JSON.parse(fs.readFileSync(storePath, 'utf8')).fence ?? null;
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

  it('first migration: a consumer paused after its claim, before publishing — exactly one spend', () => {
    expect(run(home, cwd, 'interleave-pre-fence')).toEqual({
      scenario: 'interleave-pre-fence', fenceBefore: null, fired: true, outerSpend: true, innerSpend: false, thirdSpend: false,
    });
  }, 60_000);

  it('first migration: the publication fails — exactly one spend, including after it is restored', () => {
    expect(run(home, cwd, 'publish-fails-pre-fence')).toEqual({
      scenario: 'publish-fails-pre-fence', fenceBefore: null,
      firstSpend: true, secondSpend: false, copyFenceWhileFailing: null, thirdSpendAfterRestore: false,
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
