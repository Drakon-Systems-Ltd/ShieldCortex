import { afterEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn } from 'child_process';
import { fileURLToPath, pathToFileURL } from 'url';
import { vetPackages, type FetchLike, type PackageRef } from '../package-vetting.js';

const nowMs = Date.parse('2026-11-05T12:00:00Z');
const dirs: string[] = [];
const stateDir = () => { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc1028-')); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
const ref = (name: string, spec: string | null): PackageRef => ({ ecosystem: 'npm', name, spec, installer: 'npm install' });
const response = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body });
const registry = 'https://registry.npmjs.org/';
const osv: FetchLike = async (url) => url.endsWith('/querybatch') ? response({ results: [{}] }) : response({});

describe('#1028 npm metadata resolution', () => {
  it('finds a newly published exact pin when its version manifest omits time', async () => {
    const calls: string[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      if (url.startsWith(registry)) {
        calls.push(`${url} ${init?.headers?.accept}`);
        return response(url.endsWith('/1.2.3')
          ? { version: '1.2.3' }
          : { time: { '1.2.3': '2026-11-05T01:00:00Z' } });
      }
      return osv(url, init);
    };
    const out = await vetPackages([ref('fresh-pin', '1.2.3')], { fetchImpl, nowMs, stateDir: stateDir() });
    expect(out.packages[0].publishedAt).toBe('2026-11-05T01:00:00Z');
    expect(out.packages[0].findings).toEqual(expect.arrayContaining([expect.objectContaining({ kind: 'new-version', reason: 'published 11 h ago' })]));
    expect(calls).toEqual([`${registry}fresh-pin/1.2.3 application/json`, `${registry}fresh-pin application/json`]);
  });

  it('uses only a per-version manifest for an exact scoped pin, retaining hooks and the exact OSV version', async () => {
    const calls: Array<{ url: string; accept?: string }> = [];
    const fetchImpl: FetchLike = async (url, init) => {
      calls.push({ url, accept: init?.headers?.accept });
      if (url === `${registry}@scope%2Fpkg/1.2.3`) return response({ version: '1.2.3', scripts: { postinstall: 'run' } });
      return osv(url, init);
    };
    const out = await vetPackages([ref('@scope/pkg', '1.2.3')], { fetchImpl, nowMs, stateDir: stateDir(), minAgeDays: 0 });
    expect(out.packages[0]).toMatchObject({ status: 'checked', version: '1.2.3', hooks: ['postinstall'] });
    expect(calls.filter((c) => c.url.startsWith(registry))).toEqual([{ url: `${registry}@scope%2Fpkg/1.2.3`, accept: 'application/json' }]);
  });

  it('uses abbreviated metadata, prefers satisfying latest, then uses maxSatisfying', async () => {
    const calls: string[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      if (url.startsWith(registry)) {
        calls.push(init?.headers?.accept ?? '');
        return response({ 'dist-tags': { latest: '1.2.0' }, versions: { '1.2.0': { hasInstallScript: true }, '1.9.0': {}, '2.0.0': {} } });
      }
      return osv(url, init);
    };
    const dir = stateDir();
    const latest = await vetPackages([ref('range-pkg', '^1.0.0')], { fetchImpl, nowMs, stateDir: dir, minAgeDays: 0 });
    const max = await vetPackages([ref('range-pkg', '>=1.5.0 <2')], { fetchImpl, nowMs, stateDir: dir, minAgeDays: 0 });
    expect(latest.packages[0]).toMatchObject({ version: '1.2.0', hooks: ['install'] });
    expect(max.packages[0].version).toBe('1.9.0');
    expect(latest.packages[0].findings.some((finding) => finding.kind === 'unchecked')).toBe(false);
    expect(max.packages[0].findings.some((finding) => finding.kind === 'unchecked')).toBe(false);
    expect(calls).toEqual(['application/vnd.npm.install-v1+json', 'application/vnd.npm.install-v1+json']);
  });

  it('falls back to full metadata only when abbreviated metadata lacks the selected manifest', async () => {
    const calls: string[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      if (url.startsWith(registry)) {
        calls.push(init?.headers?.accept ?? '');
        return response(calls.length === 1
          ? { 'dist-tags': { latest: '1.0.0' }, versions: {} }
          : { 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': { scripts: { prepare: 'run' } } }, time: { '1.0.0': '2026-11-01T00:00:00Z' } });
      }
      return osv(url, init);
    };
    const out = await vetPackages([ref('fallback-pkg', null)], { fetchImpl, nowMs, stateDir: stateDir() });
    // A registry tarball does not execute prepare by itself.
    expect(out.packages[0]).toMatchObject({ version: '1.0.0', hooks: [], publishedAt: '2026-11-01T00:00:00Z' });
    expect(calls).toEqual(['application/vnd.npm.install-v1+json', 'application/json']);
  });

  it('an exact endpoint error stays unchecked and a MAL batch hit still blocks', async () => {
    const registryCalls: string[] = [];
    const fetchImpl: FetchLike = async (url, init) => url.startsWith(registry) ? (registryCalls.push(url), response({}, 503))
      : url.endsWith('/querybatch') ? response({ results: [{ vulns: [{ id: 'MAL-2026-1028', modified: '2026-11-05T00:00:00Z' }] }] }) : osv(url, init);
    const out = await vetPackages([ref('bad-pkg', '1.0.0')], { fetchImpl, nowMs, stateDir: stateDir() });
    expect(out.malicious).toBe(true);
    expect(out.packages[0].malicious).toContain('MAL-2026-1028');
    expect(registryCalls).toEqual([`${registry}bad-pkg/1.0.0`]);
  });

  it('aborts an abbreviated request under the shared registry budget', async () => {
    const accepts: string[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      if (!url.startsWith(registry)) return osv(url, init);
      accepts.push(init?.headers?.accept ?? '');
      return new Promise<never>((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
    };
    const out = await vetPackages([ref('slow-pkg', '^1.0.0')], { fetchImpl, nowMs, stateDir: stateDir(), budgetMs: 20 });
    expect(out.packages[0]).toMatchObject({ status: 'unchecked', uncheckedReason: 'timed out' });
    expect(accepts).toEqual(['application/vnd.npm.install-v1+json']);
  });

  it('limits full age lookups for exact pins and reports the age gap', async () => {
    const full: string[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      if (url.startsWith(registry)) {
        if (!/\/1\.0\.0$/.test(url)) { full.push(url); return response({ time: { '1.0.0': '2026-11-05T01:00:00Z' } }); }
        return response({ version: '1.0.0' });
      }
      return osv(url, init);
    };
    const out = await vetPackages([ref('one', '1.0.0'), ref('two', '1.0.0')], { fetchImpl, nowMs, stateDir: stateDir() });
    expect(full).toHaveLength(1);
    expect(out.packages.filter((p) => p.findings.some((f) => f.kind === 'new-version'))).toHaveLength(1);
    expect(out.packages.filter((p) => p.findings.some((f) => f.kind === 'unchecked' && f.reason.includes('publication time lookup limit')))).toHaveLength(1);
  });

  it('checks range age after abbreviated resolution and shares the one full lookup with exact pins', async () => {
    const full: string[] = [];
    const osvVersions: string[] = [];
    let releaseExact: (() => void) | undefined;
    const fetchImpl: FetchLike = async (url, init) => {
      if (url.startsWith(registry)) {
        if (url.endsWith('/1.0.0')) {
          await Promise.race([new Promise<void>((resolve) => { releaseExact = resolve; }), new Promise<void>((resolve) => setTimeout(resolve, 100))]);
          return response({ version: '1.0.0', scripts: { postinstall: 'run' } });
        }
        if (init?.headers?.accept === 'application/vnd.npm.install-v1+json') {
          return response({ name: 'range-one', 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': { hasInstallScript: true } }, modified: '2026-11-05T01:00:00Z' });
        }
        full.push(url);
        releaseExact?.();
        return response({ time: { '1.0.0': '2026-11-05T01:00:00Z' } });
      }
      if (url.endsWith('/query')) {
        const body = JSON.parse(init?.body as string) as { version: string };
        osvVersions.push(body.version);
        return response({ vulns: [{ id: 'MAL-2026-1028' }] });
      }
      return osv(url, init);
    };
    const out = await vetPackages([ref('range-one', '^1.0.0'), ref('exact-two', '1.0.0')], { fetchImpl, nowMs, stateDir: stateDir() });
    expect(full).toHaveLength(1);
    expect(osvVersions).toEqual(['1.0.0', '1.0.0']);
    expect(out.malicious).toBe(true);
    expect(out.packages[0]).toMatchObject({ status: 'checked', version: '1.0.0', publishedAt: '2026-11-05T01:00:00Z', hooks: ['install'] });
    expect(out.packages[0].findings).toEqual(expect.arrayContaining([expect.objectContaining({ kind: 'new-version', reason: 'published 11 h ago' })]));
    expect(out.packages[1]).toMatchObject({ status: 'checked', version: '1.0.0', hooks: ['postinstall'] });
    expect(out.packages[1].findings).toEqual(expect.arrayContaining([expect.objectContaining({ kind: 'unchecked', reason: expect.stringContaining('publication time lookup limit') }), expect.objectContaining({ kind: 'malicious' })]));
  });

  it('keeps resolved version, hooks and MAL block when range age lookup fails', async () => {
    const fetchImpl: FetchLike = async (url, init) => {
      if (url.startsWith(registry)) return init?.headers?.accept === 'application/vnd.npm.install-v1+json'
        ? response({ 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': { hasInstallScript: true } } })
        : response({}, 503);
      return url.endsWith('/query') ? response({ vulns: [{ id: 'MAL-2026-1028' }] }) : osv(url, init);
    };
    const out = await vetPackages([ref('range-fail', '^1.0.0')], { fetchImpl, nowMs, stateDir: stateDir() });
    expect(out.malicious).toBe(true);
    expect(out.packages[0]).toMatchObject({ status: 'checked', version: '1.0.0', hooks: ['install'] });
    expect(out.packages[0].findings).toEqual(expect.arrayContaining([expect.objectContaining({ kind: 'unchecked', reason: 'unchecked: publication time lookup failed: registry answered HTTP 503' }), expect.objectContaining({ kind: 'malicious' })]));
  });
});

describe('#1028 cache file safety', () => {
  it('reads the opened malicious cache file even if its path is replaced before the read', async () => {
    const dir = stateDir();
    const file = path.join(dir, 'package-vetting-cache.json');
    const replacement = path.join(dir, 'replacement.json');
    const key = 'npm@cached-pkg@1.0.0';
    fs.writeFileSync(file, JSON.stringify({ v: 1, entries: { [key]: { at: nowMs, ecosystem: 'npm', name: 'cached-pkg', version: '1.0.0', osvIds: ['MAL-2026-3'], hooks: [], sdistOnly: false } } }));
    fs.writeFileSync(replacement, JSON.stringify({ v: 1, entries: {} }));
    const original = fs.readFileSync;
    let replaced = false;
    const spy = jest.spyOn(fs, 'readFileSync').mockImplementation(((...args: unknown[]) => {
      if (!replaced) { fs.renameSync(replacement, file); replaced = true; }
      return Reflect.apply(original, fs, args);
    }) as typeof fs.readFileSync);
    try {
      const out = await vetPackages([ref('cached-pkg', '1.0.0')], { fetchImpl: async () => { throw new Error('offline'); }, nowMs, stateDir: dir });
      expect(replaced).toBe(true);
      expect(out.malicious).toBe(true);
      expect(out.packages[0].cached).toBe(true);
    } finally { spy.mockRestore(); }
  });

  it('a held writer lock leaves the existing malicious record intact', async () => {
    const dir = stateDir();
    const file = path.join(dir, 'package-vetting-cache.json');
    const key = 'npm@prior-pkg@1.0.0';
    const entries = { [key]: { at: nowMs, ecosystem: 'npm', name: 'prior-pkg', version: '1.0.0', osvIds: ['MAL-2026-1'], hooks: [], sdistOnly: false } };
    fs.writeFileSync(file, JSON.stringify({ v: 1, entries }));
    fs.writeFileSync(`${file}.lock`, 'held');
    const fetchImpl: FetchLike = async (url, init) => url.endsWith('/query') || url.endsWith('/querybatch')
      ? url.endsWith('/querybatch') ? response({ results: [{ vulns: [{ id: 'MAL-2026-2', modified: '2026-11-05T00:00:00Z' }] }] }) : response({ vulns: [{ id: 'MAL-2026-2', modified: '2026-11-05T00:00:00Z' }] })
      : response({ version: '1.0.0' });
    const out = await vetPackages([ref('new-pkg', '1.0.0')], { fetchImpl, nowMs, stateDir: dir });
    expect(out.malicious).toBe(true);
    expect(JSON.parse(fs.readFileSync(file, 'utf8')).entries).toEqual(entries);
  });

  it('recovers an old dead-owner lock and preserves both malicious records', async () => {
    const dir = stateDir();
    const file = path.join(dir, 'package-vetting-cache.json');
    const prior = { at: nowMs, ecosystem: 'npm', name: 'prior', version: '1.0.0', osvIds: ['MAL-2026-1'], hooks: [], sdistOnly: false };
    fs.writeFileSync(file, JSON.stringify({ v: 1, entries: { 'npm@prior@1.0.0': prior } }));
    const lockPath = `${file}.lock`;
    fs.writeFileSync(lockPath, JSON.stringify({ pid: 99999999 }));
    const old = new Date(Date.now() - 60_000);
    fs.utimesSync(lockPath, old, old);
    const fetchImpl: FetchLike = async (url) => url.startsWith(registry) ? response({ version: '1.0.0' })
      : url.endsWith('/querybatch') ? response({ results: [{}] }) : response({ vulns: [{ id: 'MAL-2026-2' }] });
    await vetPackages([ref('new', '1.0.0')], { fetchImpl, nowMs, stateDir: dir, minAgeDays: 0 });
    const entries = JSON.parse(fs.readFileSync(file, 'utf8')).entries;
    expect(Object.keys(entries).sort()).toEqual(['npm@new@1.0.0', 'npm@prior@1.0.0']);
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it('does not reclaim an old lock held by a live process', async () => {
    const dir = stateDir();
    const file = path.join(dir, 'package-vetting-cache.json');
    const lockPath = `${file}.lock`;
    fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid }));
    const old = new Date(Date.now() - 60_000);
    fs.utimesSync(lockPath, old, old);
    const fetchImpl: FetchLike = async (url) => url.startsWith(registry) ? response({ version: '1.0.0' })
      : url.endsWith('/querybatch') ? response({ results: [{}] }) : response({ vulns: [{ id: 'MAL-2026-2' }] });
    const out = await vetPackages([ref('new', '1.0.0')], { fetchImpl, nowMs, stateDir: dir, minAgeDays: 0 });
    expect(out.malicious).toBe(true);
    expect(fs.readFileSync(lockPath, 'utf8')).toBe(JSON.stringify({ pid: process.pid }));
    expect(fs.existsSync(file)).toBe(false);
  });

  it('leaves a replacement lock path owned by another writer', async () => {
    const dir = stateDir();
    const file = path.join(dir, 'package-vetting-cache.json');
    const lockPath = `${file}.lock`;
    const original = fs.renameSync;
    const spy = jest.spyOn(fs, 'renameSync').mockImplementation(((from: string, to: string) => {
      if (to === file) {
        fs.unlinkSync(lockPath);
        fs.writeFileSync(lockPath, 'replacement');
      }
      return original(from, to);
    }) as typeof fs.renameSync);
    try {
      const fetchImpl: FetchLike = async (url) => url.startsWith(registry) ? response({ version: '1.0.0' })
        : url.endsWith('/querybatch') ? response({ results: [{}] }) : response({ vulns: [{ id: 'MAL-2026-2' }] });
      await vetPackages([ref('new', '1.0.0')], { fetchImpl, nowMs, stateDir: dir, minAgeDays: 0 });
      expect(fs.readFileSync(lockPath, 'utf8')).toBe('replacement');
    } finally { spy.mockRestore(); }
  });
});

describe('#1028 cross-process cache writes', () => {
  it('merges two malicious records written by concurrent processes', async () => {
    const dir = stateDir();
    const moduleUrl = pathToFileURL(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'package-vetting.ts')).href;
    const childCode = `
      const [url, dir, name] = process.argv.slice(1);
      const fs = await import('node:fs');
      const path = await import('node:path');
      const { vetPackages } = await import(url);
      fs.writeFileSync(path.join(dir, name + '.ready'), '1');
      while (!fs.existsSync(path.join(dir, 'go'))) await new Promise((r) => setTimeout(r, 2));
      const fetchImpl = async (target) => ({ ok: true, status: 200, json: async () =>
        target.startsWith('https://registry.npmjs.org/') ? { version: '1.0.0' }
        : target.endsWith('/querybatch') ? { results: [{}] }
        : { vulns: [{ id: 'MAL-2026-' + (name === 'one' ? '1' : '2') }] } });
      await vetPackages([{ ecosystem: 'npm', name, spec: '1.0.0', installer: 'npm install' }],
        { fetchImpl, stateDir: dir, minAgeDays: 0 });
    `;
    const run = (name: string) => new Promise<void>((resolve, reject) => {
      const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', childCode, moduleUrl, dir, name], { stdio: ['ignore', 'ignore', 'pipe'] });
      let error = '';
      child.stderr.on('data', (chunk) => { error += String(chunk); });
      child.on('error', reject);
      child.on('close', (code) => code === 0 ? resolve() : reject(new Error(error || `child exited ${code}`)));
    });
    const writers = [run('one'), run('two')];
    const until = Date.now() + 10_000;
    while ((!fs.existsSync(path.join(dir, 'one.ready')) || !fs.existsSync(path.join(dir, 'two.ready'))) && Date.now() < until) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    fs.writeFileSync(path.join(dir, 'go'), '1');
    await Promise.all(writers);
    const entries = JSON.parse(fs.readFileSync(path.join(dir, 'package-vetting-cache.json'), 'utf8')).entries;
    expect(Object.keys(entries).sort()).toEqual(['npm@one@1.0.0', 'npm@two@1.0.0']);
  }, 20_000);
});
