import { afterEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
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
