import { afterEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import { createRequire } from 'module';
import os from 'os';
import path from 'path';
import { reclaimStaleCacheLock, vetPackages, type FetchLike, type PackageRef } from '../package-vetting.js';

// All FIFO behaviour is simulated by openSync mocks. This file never makes a FIFO.
const NOW = Date.parse('2026-11-16T12:00:00Z');
const OLD = new Date(NOW - 40 * 86_400_000).toISOString();
const NEW = new Date(NOW - 3_600_000).toISOString();
const ref = (name: string, spec: string | null = null): PackageRef => ({ ecosystem: 'npm', name, spec, installer: 'npm' });
const reply = (body: unknown) => ({ ok: true, status: 200, json: async () => body });
const dirs: string[] = [];
const state = () => { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc1091-')); dirs.push(dir); return dir; };
afterEach(() => { jest.restoreAllMocks(); for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });

function registry(versions: Record<string, Record<string, unknown>>, tags: Record<string, string>, time: Record<string, string>, opts: { abbreviatedVersions?: Record<string, Record<string, unknown>>; manifestTime?: string; nameOnlyMal?: boolean } = {}) {
  const calls: string[] = [];
  const osvVersions: string[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push(`${init?.method ?? 'GET'} ${url}`);
    if (url.endsWith('/v1/querybatch')) {
      const queries = JSON.parse(init!.body!).queries as unknown[];
      return reply({ results: queries.map(() => opts.nameOnlyMal ? { vulns: [{ id: 'MAL-1091' }] } : {}) });
    }
    if (url.endsWith('/v1/query')) {
      const version = JSON.parse(init!.body!).version;
      osvVersions.push(version);
      return reply(opts.nameOnlyMal && version === '1.0.0' ? { vulns: [{ id: 'MAL-1091' }] } : {});
    }
    if (url.startsWith('https://registry.npmjs.org/')) {
      const tail = url.slice('https://registry.npmjs.org/'.length);
      if (tail.includes('/')) {
        const version = tail.slice(tail.lastIndexOf('/') + 1);
        return reply({ ...versions[version], version, time: opts.manifestTime });
      }
      return reply({ 'dist-tags': tags, versions: init?.headers?.accept === 'application/vnd.npm.install-v1+json' ? opts.abbreviatedVersions ?? versions : versions, time: init?.headers?.accept === 'application/vnd.npm.install-v1+json' ? undefined : time });
    }
    throw new Error(`unexpected URL: ${url}`);
  };
  return { fetchImpl, calls, osvVersions };
}

describe('PR #1091 npm resolution and publication facts', () => {
  it.each([
    ['deprecated latest', { '1.0.0': {}, '2.0.0': { deprecated: 'old' } }, '1.0.0'],
    ['incompatible latest', { '1.0.0': {}, '2.0.0': { engines: { node: '<1' } } }, '1.0.0'],
    ['healthy latest below highest', { '1.0.0': {}, '2.0.0': {} }, '1.0.0'],
  ])('%s: range and bare installs query OSV for the npm-selected exact version', async (_label, versions, selected) => {
    const r = registry(versions, { latest: _label === 'healthy latest below highest' ? '1.0.0' : '2.0.0' }, { '1.0.0': OLD, '2.0.0': OLD }, { nameOnlyMal: true });
    for (const spec of [null, '*']) {
      const result = await vetPackages([ref('choice', spec)], { ...r, stateDir: state(), nowMs: NOW, minAgeDays: 0 });
      expect(result.packages[0].version).toBe(selected);
      expect(r.osvVersions.at(-1)).toBe(selected);
      expect(result.malicious).toBe(selected === '1.0.0');
      expect(result.packages[0].unconfirmedVersion).not.toBe(true);
    }
  });

  it('an explicitly requested tag still selects its deprecated manifest', async () => {
    const r = registry({ '1.0.0': {}, '2.0.0': { deprecated: 'old' } }, { latest: '1.0.0', beta: '2.0.0' }, {}, { nameOnlyMal: true });
    const result = await vetPackages([ref('choice', 'beta')], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW, minAgeDays: 0 });
    expect(result.packages[0].version).toBe('2.0.0');
    expect(result.malicious).toBe(false);
  });

  it('a forged fresh manifest.time cannot override an old packument time', async () => {
    const r = registry({ '1.0.0': {} }, { latest: '1.0.0' }, { '1.0.0': OLD }, { manifestTime: NEW });
    const result = await vetPackages([ref('age', '1.0.0')], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW });
    expect(result.packages[0].publishedAt).toBe(OLD);
    expect(result.packages[0].ageUncheckedReason).toBeUndefined();
  });

  it('a forged old manifest.time cannot suppress a fresh packument age finding', async () => {
    const r = registry({ '1.0.0': {} }, { latest: '1.0.0' }, { '1.0.0': NEW }, { manifestTime: OLD });
    const result = await vetPackages([ref('age', '1.0.0')], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW });
    expect(result.packages[0].publishedAt).toBe(NEW);
    expect(result.packages[0].findings).toEqual(expect.arrayContaining([expect.objectContaining({ kind: 'new-version', reason: 'published 1 h ago' })]));
  });

  it('manifest.time cannot supply missing top-level publication time', async () => {
    const r = registry({ '1.0.0': {} }, { latest: '1.0.0' }, {}, { manifestTime: NEW });
    const result = await vetPackages([ref('age', '1.0.0')], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW });
    expect(result.packages[0].publishedAt).toBeUndefined();
    expect(result.packages[0].ageUncheckedReason).toBe('publication time absent from registry metadata');
    expect(result.reasons.join(' ')).not.toContain('published 1 h ago');
  });

  it('a missing manifest reports a resolution limit, separately from an age limit', async () => {
    const versions = { '1.0.0': {}, '2.0.0': {} };
    const r = registry(versions, { latest: '2.0.0' }, { '1.0.0': OLD, '2.0.0': OLD }, { abbreviatedVersions: {} });
    const result = await vetPackages([ref('age', '1.0.0'), ref('choice')], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW });
    expect(result.packages[0].ageUncheckedReason).toBeUndefined();
    expect(result.packages[1].uncheckedReason).toMatch(/version resolution metadata lookup limit/);
  });

  it('a resolved version reports the publication-age limit when the full metadata allowance was used', async () => {
    const r = registry({ '1.0.0': {}, '2.0.0': {} }, { latest: '2.0.0' }, { '1.0.0': OLD, '2.0.0': OLD });
    const result = await vetPackages([ref('age', '1.0.0'), ref('age', '2.0.0')], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW });
    expect(result.packages[0].publishedAt).toBe(OLD);
    expect(result.packages[1].version).toBe('2.0.0');
    expect(result.packages[1].ageUncheckedReason).toMatch(/publication time lookup limit/);
  });

  it('prepare alone is not a registry tarball install-hook finding', async () => {
    const r = registry({ '1.0.0': { scripts: { prepare: 'node build.js' } } }, { latest: '1.0.0' }, {});
    const result = await vetPackages([ref('prepared', '1.0.0')], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW, minAgeDays: 0 });
    expect(result.packages[0].hooks).toEqual([]);
    expect(result.packages[0].findings.some((f) => f.kind === 'install-hook')).toBe(false);
  });

  it.each([null, '^1', 'beta'])('install hooks are read from the selected manifest for %s', async (spec) => {
    const r = registry({ '1.0.0': { scripts: { prepare: 'node build.js' } }, '1.1.0': { scripts: { postinstall: 'node setup.js' } } }, { latest: '1.1.0', beta: '1.1.0' }, {});
    const result = await vetPackages([ref('hooked', spec)], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW, minAgeDays: 0 });
    expect(result.packages[0].version).toBe('1.1.0');
    expect(result.packages[0].hooks).toEqual(['postinstall']);
  });
});

describe('PR #1091 cache descriptor and reclaim interleavings', () => {
  it('a simulated FIFO cache never reaches a blocking read', async () => {
    const dir = state();
    const open = fs.openSync.bind(fs);
    const seenFlags: number[] = [];
    const spy = jest.spyOn(fs, 'openSync').mockImplementation(((file: fs.PathLike, flags: string | number, mode?: number) => {
      if (file === path.join(dir, 'package-vetting-cache.json')) {
        seenFlags.push(flags as number);
        throw Object.assign(new Error('simulated FIFO unavailable'), { code: 'EAGAIN' });
      }
      return open(file, flags, mode);
    }) as typeof fs.openSync);
    const r = registry({ '1.0.0': {} }, { latest: '1.0.0' }, {});
    const result = await vetPackages([ref('cache', '1.0.0')], { fetchImpl: r.fetchImpl, stateDir: dir, nowMs: NOW, minAgeDays: 0 });
    expect(result.packages[0].version).toBe('1.0.0');
    expect(spy).toHaveBeenCalled();
    expect(seenFlags.length).toBeGreaterThan(0);
    expect(seenFlags.every((flags) => !!(flags & fs.constants.O_NONBLOCK) && !!(flags & fs.constants.O_NOFOLLOW))).toBe(true);
  });

  it('a simulated FIFO lock never reaches a blocking read', () => {
    const lock = path.join(state(), 'cache.lock');
    const open = fs.openSync.bind(fs);
    const seenFlags: number[] = [];
    const spy = jest.spyOn(fs, 'openSync').mockImplementation(((file: fs.PathLike, flags: string | number, mode?: number) => {
      if (file === lock) {
        seenFlags.push(flags as number);
        throw Object.assign(new Error('simulated FIFO unavailable'), { code: 'EAGAIN' });
      }
      return open(file, flags, mode);
    }) as typeof fs.openSync);
    expect(reclaimStaleCacheLock(lock)).toBe(false);
    expect(spy).toHaveBeenCalled();
    expect(seenFlags).toHaveLength(1);
    expect(seenFlags.every((flags) => !!(flags & fs.constants.O_NONBLOCK) && !!(flags & fs.constants.O_NOFOLLOW))).toBe(true);
    expect(fs.existsSync(`${lock}.recovery`)).toBe(false);
  });

  it('a second reclaimer cannot replace the stale lock between inode check and unlink', () => {
    const lock = path.join(state(), 'cache.lock');
    fs.writeFileSync(lock, JSON.stringify({ pid: 1234567 }));
    const past = new Date(Date.now() - 60_000);
    fs.utimesSync(lock, past, past);
    jest.spyOn(process, 'kill').mockImplementation((() => { throw Object.assign(new Error('dead'), { code: 'ESRCH' }); }) as typeof process.kill);
    const lstat = fs.lstatSync.bind(fs);
    let nested: boolean | undefined;
    let injected = false;
    jest.spyOn(fs, 'lstatSync').mockImplementation(((file: fs.PathLike, options?: any) => {
      const stat = lstat(file, options);
      if (file === lock && !injected) {
        injected = true;
        nested = reclaimStaleCacheLock(lock);
        // A second reclaimer that removed the old lock would let a new writer
        // acquire this name before the first reclaimer's unlink.
        if (nested) fs.writeFileSync(lock, JSON.stringify({ pid: process.pid }), { flag: 'wx' });
      }
      return stat;
    }) as typeof fs.lstatSync);
    expect(reclaimStaleCacheLock(lock)).toBe(true);
    expect(nested).toBe(false);
    fs.writeFileSync(lock, JSON.stringify({ pid: process.pid }), { flag: 'wx' });
    expect(reclaimStaleCacheLock(lock)).toBe(false);
    expect(fs.existsSync(lock)).toBe(true);
  });
});


// ── B1/B2: differential against npm's own selection ─────────────────────────
// Each case states what npm-pick-manifest selects. Require the real module (set
// NPM_PICK_MANIFEST to its directory, or use the npm bundled next to this Node):
// an absent npm cannot silently turn the differential into a no-op.
type PickFn = (packument: unknown, wanted: string | undefined, opts: { nodeVersion?: string; npmVersion?: string | null }) => { version: string };
const pickManifest: PickFn | null = (() => {
  const req = createRequire(import.meta.url);
  const candidates = [
    process.env.NPM_PICK_MANIFEST,
    path.join(path.dirname(path.dirname(process.execPath)), 'lib', 'node_modules', 'npm', 'node_modules', 'npm-pick-manifest'),
    path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'node_modules', 'npm-pick-manifest'),
  ];
  for (const dir of candidates) {
    if (!dir) continue;
    try { return req(dir) as PickFn; } catch { /* not here */ }
  }
  return null;
})();

// npm versions the installer could be: one that satisfies `engines.npm: ">=99"`, one that does not.
const NPM_OK = '99.0.0';
const NPM_OLD = '10.0.0';

interface PickCase {
  label: string;
  spec: string | null;
  versions: Record<string, Record<string, unknown>>;
  tags: Record<string, string>;
  /** npm's pick with an installer npm that satisfies every engines.npm here, and with one that does not. Null: npm finds no version. */
  npm: { ok: string | null; old: string | null };
}

const CASES: PickCase[] = [
  // B1: bare and `*` take a prerelease dist-tags.latest, as npm does.
  { label: 'bare, prerelease latest', spec: null, versions: { '1.0.0': {}, '2.0.0-beta.1': {} }, tags: { latest: '2.0.0-beta.1' }, npm: { ok: '2.0.0-beta.1', old: '2.0.0-beta.1' } },
  { label: '*, prerelease latest', spec: '*', versions: { '1.0.0': {}, '2.0.0-beta.1': {} }, tags: { latest: '2.0.0-beta.1' }, npm: { ok: '2.0.0-beta.1', old: '2.0.0-beta.1' } },
  { label: 'bare, prerelease-only', spec: null, versions: { '1.0.0-rc.1': {}, '1.0.0-rc.2': {} }, tags: { latest: '1.0.0-rc.2' }, npm: { ok: '1.0.0-rc.2', old: '1.0.0-rc.2' } },
  { label: '*, prerelease-only', spec: '*', versions: { '1.0.0-rc.1': {}, '1.0.0-rc.2': {} }, tags: { latest: '1.0.0-rc.2' }, npm: { ok: '1.0.0-rc.2', old: '1.0.0-rc.2' } },
  { label: 'bare, prerelease latest deprecated', spec: null, versions: { '1.0.0': {}, '2.0.0-beta.1': { deprecated: 'x' } }, tags: { latest: '2.0.0-beta.1' }, npm: { ok: '1.0.0', old: '1.0.0' } },
  { label: 'bare, prerelease latest Node-incompatible', spec: null, versions: { '1.0.0': {}, '2.0.0-beta.1': { engines: { node: '<1' } } }, tags: { latest: '2.0.0-beta.1' }, npm: { ok: '1.0.0', old: '1.0.0' } },
  { label: 'bare, prerelease-only, deprecated latest', spec: null, versions: { '1.0.0-rc.1': {}, '1.0.0-rc.2': { deprecated: 'x' } }, tags: { latest: '1.0.0-rc.2' }, npm: { ok: null, old: null } },
  // Exact tags stay exact, deprecated, prerelease or engines.npm-restricted.
  { label: 'explicit latest tag, deprecated', spec: 'latest', versions: { '1.0.0': {}, '2.0.0': { deprecated: 'x' } }, tags: { latest: '2.0.0' }, npm: { ok: '2.0.0', old: '2.0.0' } },
  { label: 'explicit beta tag, prerelease', spec: 'beta', versions: { '1.0.0': {}, '2.0.0-beta.1': {} }, tags: { latest: '1.0.0', beta: '2.0.0-beta.1' }, npm: { ok: '2.0.0-beta.1', old: '2.0.0-beta.1' } },
  { label: 'explicit next tag, engines.npm', spec: 'next', versions: { '1.0.0': {}, '2.0.0': { engines: { npm: '>=99' } } }, tags: { latest: '1.0.0', next: '2.0.0' }, npm: { ok: '2.0.0', old: '2.0.0' } },
  // Real ranges: a prerelease latest is not taken unless the range admits it.
  { label: 'x range, prerelease latest', spec: 'x', versions: { '1.0.0': {}, '2.0.0-beta.1': {} }, tags: { latest: '2.0.0-beta.1' }, npm: { ok: '1.0.0', old: '1.0.0' } },
  { label: '>=1 range, prerelease latest', spec: '>=1', versions: { '1.0.0': {}, '1.1.0': {}, '2.0.0-beta.1': {} }, tags: { latest: '2.0.0-beta.1' }, npm: { ok: '1.1.0', old: '1.1.0' } },
  { label: '^2.0.0-beta.0 range, prerelease latest', spec: '^2.0.0-beta.0', versions: { '1.0.0': {}, '2.0.0-beta.1': {}, '2.0.0-beta.2': {} }, tags: { latest: '2.0.0-beta.1' }, npm: { ok: '2.0.0-beta.1', old: '2.0.0-beta.1' } },
  { label: '^1 range, deprecated latest', spec: '^1', versions: { '1.0.0': {}, '1.1.0': {}, '1.2.0': { deprecated: 'x' } }, tags: { latest: '1.2.0' }, npm: { ok: '1.1.0', old: '1.1.0' } },
  // B2: engines.npm on the clean selected manifest; npm's pick depends on the installing npm.
  { label: 'bare, latest engines.npm', spec: null, versions: { '1.0.0': {}, '2.0.0': { engines: { npm: '>=99' } } }, tags: { latest: '2.0.0' }, npm: { ok: '2.0.0', old: '1.0.0' } },
  { label: '*, latest engines.npm', spec: '*', versions: { '1.0.0': {}, '2.0.0': { engines: { npm: '>=99' } } }, tags: { latest: '2.0.0' }, npm: { ok: '2.0.0', old: '1.0.0' } },
  { label: '^1 range, latest engines.npm', spec: '^1', versions: { '1.0.0': {}, '1.1.0': { engines: { npm: '>=99' } } }, tags: { latest: '1.1.0' }, npm: { ok: '1.1.0', old: '1.0.0' } },
  { label: '^1 range, highest fallback engines.npm', spec: '^1', versions: { '1.0.0': {}, '1.1.0': { engines: { npm: '>=99' } }, '2.0.0': {} }, tags: { latest: '2.0.0' }, npm: { ok: '1.1.0', old: '1.0.0' } },
  { label: 'bare, sole version engines.npm', spec: null, versions: { '1.0.0': { engines: { npm: '>=99' } } }, tags: { latest: '1.0.0' }, npm: { ok: '1.0.0', old: '1.0.0' } },
  { label: '^1 range, lower version engines.npm', spec: '^1', versions: { '1.0.0': { engines: { npm: '>=99' } }, '1.1.0': {} }, tags: { latest: '1.1.0' }, npm: { ok: '1.1.0', old: '1.1.0' } },
];

function packument(c: PickCase) {
  const versions = Object.fromEntries(Object.entries(c.versions).map(([v, m]) => [v, { name: 'pick', version: v, ...m }]));
  return { name: 'pick', 'dist-tags': c.tags, versions, time: Object.fromEntries(Object.keys(c.versions).map((v) => [v, NEW])) };
}

/** Registry + OSV double: the name-only batch answer is MAL-, the exact answer is MAL- only for `malVersions`. */
function pickRegistry(c: PickCase, malVersions: ReadonlySet<string>) {
  const doc = packument(c);
  const registryCalls: string[] = [];
  const osvVersions: string[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    if (url.endsWith('/v1/querybatch')) {
      const queries = JSON.parse(init!.body!).queries as unknown[];
      return reply({ results: queries.map(() => ({ vulns: [{ id: 'MAL-PICK' }] })) });
    }
    if (url.endsWith('/v1/query')) {
      const version = JSON.parse(init!.body!).version as string;
      osvVersions.push(version);
      return reply(malVersions.has(version) ? { vulns: [{ id: 'MAL-PICK' }] } : {});
    }
    if (url === 'https://registry.npmjs.org/pick') {
      const abbreviated = init?.headers?.accept === 'application/vnd.npm.install-v1+json';
      registryCalls.push(abbreviated ? 'abbreviated' : 'full');
      return reply(abbreviated ? { name: doc.name, 'dist-tags': doc['dist-tags'], versions: doc.versions } : doc);
    }
    throw new Error(`unexpected URL: ${url}`);
  };
  return { fetchImpl, registryCalls, osvVersions };
}

describe('PR #1091 B1/B2: npm selection differential', () => {
  it.each(CASES.map((c) => [c.label, c] as const))('%s: stated npm picks match npm-pick-manifest', (_label, c) => {
    expect(pickManifest).not.toBeNull();
    const pick = (npmVersion: string) => { try { return pickManifest!(packument(c), c.spec ?? undefined, { npmVersion }).version; } catch { return null; } };
    expect({ ok: pick(NPM_OK), old: pick(NPM_OLD) }).toEqual(c.npm);
  });

  // Trap 1: npm's own pick is the malicious version, and every other version is clean.
  // Trap 2: only a version npm would not pick is malicious (name-only hit covers it).
  it.each(CASES.flatMap((c) => [[c.label, 'npm pick malicious', c] as const, [c.label, 'decoy malicious', c] as const]))('%s, %s', async (_label, trap, c) => {
    const picks = [...new Set([c.npm.ok, c.npm.old])];
    const all = Object.keys(c.versions);
    const mal = new Set(trap === 'npm pick malicious' ? picks.filter((v): v is string => !!v) : all.filter((v) => !picks.includes(v)));
    const r = pickRegistry(c, mal);
    const result = await vetPackages([ref('pick', c.spec)], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW, minAgeDays: 7 });
    const vet = result.packages[0];
    const npmCouldInstallMalicious = picks.some((v) => v !== null && mal.has(v));
    if (picks.length === 1 && picks[0] === null) {
      // npm finds no version: nothing is cleared, and the name-only hit stays in force.
      expect(vet.status).toBe('unchecked');
      expect(result.malicious).toBe(true);
      return;
    }
    // One registry document, one exact OSV query, for the version checked: no dual lookup.
    expect(r.osvVersions).toHaveLength(1);
    expect(r.registryCalls.filter((k) => k === 'full').length).toBeLessThanOrEqual(1);
    expect(vet.status).toBe('checked');
    expect(vet.version).toBe(c.npm.ok);
    expect(r.osvVersions[0]).toBe(c.npm.ok);
    expect(vet.publishedAt).toBe(NEW);
    expect(vet.findings).toEqual(expect.arrayContaining([expect.objectContaining({ kind: 'new-version' })]));
    // Never falsely cleared: blocked whenever npm could install a malicious version.
    if (npmCouldInstallMalicious) expect(result.malicious).toBe(true);
    if (picks.length === 2) {
      expect(vet.npmEngineDependent).toBe(true);
      // The name-only hit is kept even when the checked version is clean.
      expect(result.malicious).toBe(true);
    } else {
      expect(vet.npmEngineDependent).toBeUndefined();
      expect(result.malicious).toBe(npmCouldInstallMalicious);
    }
  });
});

describe('PR #1091 B2: engines.npm-dependent selection keeps evidence', () => {
  const c: PickCase = {
    label: 'hooks', spec: null,
    versions: { '1.0.0': {}, '2.0.0': { engines: { npm: '>=99' }, scripts: { postinstall: 'node setup.js' } } },
    tags: { latest: '2.0.0' }, npm: { ok: '2.0.0', old: '1.0.0' },
  };

  it('a clean latest with engines.npm keeps its version, age, hooks and the name-only MAL- block', async () => {
    const r = pickRegistry(c, new Set(['1.0.0']));
    const result = await vetPackages([ref('pick', null)], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW, minAgeDays: 7 });
    const vet = result.packages[0];
    expect(vet).toEqual(expect.objectContaining({ status: 'checked', version: '2.0.0', publishedAt: NEW, hooks: ['postinstall'], malicious: ['MAL-PICK'], unconfirmedVersion: true, npmEngineDependent: true }));
    expect(vet.uncheckedReason).toBeUndefined();
    expect(r.osvVersions).toEqual(['2.0.0']);
    expect(r.registryCalls).toEqual(['abbreviated', 'full']);
    expect(result.malicious).toBe(true);
    expect(result.reasons).toEqual(expect.arrayContaining([
      expect.stringMatching(/^OSV lists a malicious release of pick \(MAL-PICK\); npm may fetch another version \(engines\.npm\)/),
      'published 1 h ago',
      'runs a postinstall script on install',
    ]));
  });

  it('a malicious selected version keeps its own exact reason', async () => {
    const r = pickRegistry(c, new Set(['2.0.0']));
    const result = await vetPackages([ref('pick', null)], { fetchImpl: r.fetchImpl, stateDir: state(), nowMs: NOW, minAgeDays: 0 });
    expect(result.packages[0].unconfirmedVersion).toBeUndefined();
    expect(result.reasons[0]).toBe('OSV lists pick@2.0.0 as known malicious (MAL-PICK)');
  });

  it('a pinned version is exact: engines.npm on it does not keep a name-only hit', async () => {
    const r = pickRegistry(c, new Set(['1.0.0']));
    const fetchImpl: FetchLike = async (url, init) => url === 'https://registry.npmjs.org/pick/2.0.0'
      ? reply(packument(c).versions['2.0.0'])
      : r.fetchImpl(url, init);
    const result = await vetPackages([ref('pick', '2.0.0')], { fetchImpl, stateDir: state(), nowMs: NOW, minAgeDays: 0 });
    expect(result.malicious).toBe(false);
    expect(result.packages[0].npmEngineDependent).toBeUndefined();
  });
});
