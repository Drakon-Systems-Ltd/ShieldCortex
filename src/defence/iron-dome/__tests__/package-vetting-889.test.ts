import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  parseInstallCommands,
  parseMcpServerEntry,
  vetPackages,
  vetToolCall,
  vetMcpServers,
  applyVettingToVerdict,
  normalisePackageVettingConfig,
  pySatisfies,
  type FetchLike,
  type PackageRef,
} from '../package-vetting.js';

/**
 * #889 phase 1 — pre-install package vetting.
 *
 * No live network: every registry/OSV answer below is a fixture. The response
 * SHAPES follow the public npm registry, PyPI JSON and OSV v1/query APIs; the
 * package contents are invented except the one advisory id, MAL-2026-18603,
 * which is the real OSV entry for the malicious MCP package that prompted the
 * work. No test installs or runs any package: commands are only parsed, and
 * installer command lines are assembled from parts at run time.
 */

const NOW = Date.parse('2026-11-05T12:00:00Z');
const hoursAgo = (h: number) => new Date(NOW - h * 3_600_000).toISOString();

let home: string;
let stateDir: string;
let prevHome: string | undefined;
beforeAll(() => {
  prevHome = process.env.HOME;
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc889-home-'));
  process.env.HOME = home;
});
afterAll(() => {
  process.env.HOME = prevHome;
  fs.rmSync(home, { recursive: true, force: true });
});
beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(home, 'state-'));
});

// ── fixture world ──────────────────────────────────────────────────────────

interface NpmFix { tags?: Record<string, string>; versions: Record<string, { scripts?: Record<string, string>; hasInstallScript?: boolean; time: string }> }
interface PyFix { latest: string; releases: Record<string, Array<{ packagetype: 'sdist' | 'bdist_wheel'; upload_time_iso_8601: string }>> }

interface World {
  npm: Record<string, NpmFix>;
  pypi: Record<string, PyFix>;
  osv: Record<string, string[]>; // `${ecosystem}@${name}@${version}` -> ids
  /** OSV record id -> aliases (only /v1/query and /v1/vulns/<id> return these; querybatch never does). */
  aliases?: Record<string, string[]>;
  calls: string[];
}

const world = (over: Partial<World> = {}): World => ({ npm: {}, pypi: {}, osv: {}, calls: [], ...over });

function fetchFor(w: World): FetchLike {
  return async (url, init) => {
    w.calls.push(`${init?.method ?? 'GET'} ${url}`);
    const json = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body });
    if (url === 'https://api.osv.dev/v1/query') {
      const q = JSON.parse(init!.body!);
      const ids = w.osv[`${q.package.ecosystem}@${q.package.name}@${q.version}`] ?? [];
      return json(ids.length ? { vulns: ids.map((id) => ({ id, modified: '2026-11-05T00:00:00Z', aliases: w.aliases?.[id] })) } : {});
    }
    if (url === 'https://api.osv.dev/v1/querybatch') {
      const { queries } = JSON.parse(init!.body!) as { queries: Array<{ package: { name: string; ecosystem: string }; version?: string }> };
      return json({
        results: queries.map((q) => {
          const prefix = `${q.package.ecosystem}@${q.package.name}@`;
          const ids = [...new Set(Object.entries(w.osv).filter(([k]) => (q.version ? k === `${prefix}${q.version}` : k.startsWith(prefix))).flatMap(([, v]) => v))];
          return ids.length ? { vulns: ids.map((id) => ({ id, modified: '2026-11-05T00:00:00Z' })) } : {};
        }),
      });
    }
    const vuln = /^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/.exec(url);
    if (vuln) return json({ id: decodeURIComponent(vuln[1]), aliases: w.aliases?.[decodeURIComponent(vuln[1])] ?? [] });
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const f = w.npm[name];
      if (!f) return json({}, 404);
      return json({
        'dist-tags': f.tags ?? { latest: Object.keys(f.versions).pop()! },
        versions: Object.fromEntries(Object.entries(f.versions).map(([v, m]) => [v, { name, version: v, scripts: m.scripts, hasInstallScript: m.hasInstallScript }])),
        time: Object.fromEntries(Object.entries(f.versions).map(([v, m]) => [v, m.time])),
      });
    }
    const py = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/(?:([^/]+)\/)?json$/.exec(url);
    if (py) {
      const f = w.pypi[decodeURIComponent(py[1])];
      if (!f) return json({}, 404);
      const ver = py[2] ? decodeURIComponent(py[2]) : null;
      if (ver) return f.releases[ver] ? json({ info: { version: ver }, urls: f.releases[ver] }) : json({}, 404);
      return json({ info: { version: f.latest }, urls: f.releases[f.latest], releases: f.releases });
    }
    throw new Error(`unexpected URL in test: ${url}`);
  };
}

const offline: FetchLike = async () => { throw Object.assign(new Error('getaddrinfo'), { code: 'ENOTFOUND' }); };

const npmRef = (name: string, spec: string | null = null): PackageRef => ({ ecosystem: 'npm', name, spec, installer: 'npm install' });
const pyRef = (name: string, spec: string | null = null): PackageRef => ({ ecosystem: 'PyPI', name, spec, installer: 'pip install' });

const MAL_ID = 'MAL-2026-18603';
const MAL_NAME = '@ifasn/ms-doc-mcp';

const fixtureWorld = (): World => world({
  npm: {
    [MAL_NAME]: { versions: { '1.0.3': { time: hoursAgo(24 * 40) } } },
    'legacy-lib': { versions: { '2.0.0': { time: hoursAgo(24 * 300) }, '2.1.0': { time: hoursAgo(24 * 200) } } },
    'fresh-lib': { versions: { '3.4.0': { time: hoursAgo(24 * 100) }, '3.5.0': { time: hoursAgo(11) } } },
    'hooky-lib': { versions: { '1.0.0': { time: hoursAgo(24 * 90), scripts: { postinstall: 'node setup.js', test: 'jest' } } } },
    'clean-lib': { versions: { '4.2.1': { time: hoursAgo(24 * 400), scripts: { test: 'jest' } } } },
    'ranged-lib': { versions: { '1.0.0': { time: hoursAgo(24 * 90) }, '1.4.2': { time: hoursAgo(24 * 60) }, '2.0.0': { time: hoursAgo(24 * 30) } } },
  },
  pypi: {
    'src-only': { latest: '0.9.0', releases: { '0.9.0': [{ packagetype: 'sdist', upload_time_iso_8601: hoursAgo(24 * 50) }] } },
    'wheel-lib': { latest: '2.2.0', releases: { '2.2.0': [{ packagetype: 'sdist', upload_time_iso_8601: hoursAgo(24 * 50) }, { packagetype: 'bdist_wheel', upload_time_iso_8601: hoursAgo(24 * 50) }] } },
    'vuln-py': { latest: '1.1.0', releases: { '1.0.0': [{ packagetype: 'bdist_wheel', upload_time_iso_8601: hoursAgo(24 * 200) }], '1.1.0': [{ packagetype: 'bdist_wheel', upload_time_iso_8601: hoursAgo(24 * 100) }] } },
  },
  osv: {
    [`npm@${MAL_NAME}@1.0.3`]: [MAL_ID],
    'npm@legacy-lib@2.1.0': ['GHSA-abcd-1234-wxyz'],
    'PyPI@vuln-py@1.0.0': ['GHSA-pypy-0000-test', 'PYSEC-2026-1'],
  },
});

const opts = (w: World, extra: Record<string, unknown> = {}) => ({ fetchImpl: fetchFor(w), nowMs: NOW, stateDir, ...extra });

// ── installer parsing ──────────────────────────────────────────────────────

const j = (...parts: string[]) => parts.join(' ');
const tuple = (r: PackageRef) => [r.ecosystem, r.name, r.spec];

describe('parseInstallCommands — installer forms', () => {
  const cases: Array<[string, string, Array<[string, string, string | null]>]> = [
    ['npm install pinned', j('npm', 'install', 'left-pad@1.3.0'), [['npm', 'left-pad', '1.3.0']]],
    ['npm i unpinned', j('npm', 'i', 'left-pad'), [['npm', 'left-pad', null]]],
    ['npm add scoped pinned', j('npm', 'add', '@scope/pkg@^2.1.0'), [['npm', '@scope/pkg', '^2.1.0']]],
    ['npm install scoped unpinned + flags', j('npm', 'install', '--save-dev', '-w', 'apps/web', '@scope/pkg'), [['npm', '@scope/pkg', null]]],
    ['npm install two packages', j('npm', 'install', 'a-pkg', 'b-pkg@2'), [['npm', 'a-pkg', null], ['npm', 'b-pkg', '2']]],
    ['npm install dist-tag', j('npm', 'install', 'some-pkg@next'), [['npm', 'some-pkg', 'next']]],
    ['pnpm add', j('pnpm', 'add', '-D', 'some-pkg@1.2.3'), [['npm', 'some-pkg', '1.2.3']]],
    ['yarn add', j('yarn', 'add', 'some-pkg'), [['npm', 'some-pkg', null]]],
    ['yarn global add', j('yarn', 'global', 'add', 'some-pkg@3'), [['npm', 'some-pkg', '3']]],
    ['bun add', j('bun', 'add', 'some-pkg@1.0.0'), [['npm', 'some-pkg', '1.0.0']]],
    ['npx -y', j('npx', '-y', 'some-pkg@1.0.0', '--flag', 'value'), [['npm', 'some-pkg', '1.0.0']]],
    ['npx scoped unpinned', j('npx', '@scope/tool'), [['npm', '@scope/tool', null]]],
    ['npx --package form', j('npx', '--package=some-pkg@2', 'run-it'), [['npm', 'some-pkg', '2']]],
    ['npx -p form', j('npx', '-p', 'some-pkg', 'run-it', 'arg'), [['npm', 'some-pkg', null]]],
    ['bunx', j('bunx', 'some-pkg@latest'), [['npm', 'some-pkg', 'latest']]],
    ['pnpm dlx', j('pnpm', 'dlx', 'some-pkg@1.2.3', 'arg'), [['npm', 'some-pkg', '1.2.3']]],
    ['yarn dlx', j('yarn', 'dlx', 'some-pkg'), [['npm', 'some-pkg', null]]],
    ['npm exec', j('npm', 'exec', '--', 'some-pkg@1.0.0'), [['npm', 'some-pkg', '1.0.0']]],
    ['pip install pinned', j('pip', 'install', 'requests==2.31.0'), [['PyPI', 'requests', '==2.31.0']]],
    ['pip3 install unpinned', j('pip3', 'install', 'requests'), [['PyPI', 'requests', null]]],
    ['pip install range + extras', j('pip', 'install', '"requests[socks]>=2.0,<3"'), [['PyPI', 'requests', '>=2.0,<3']]],
    ['pip install flags', j('pip', 'install', '--upgrade', '--no-cache-dir', 'a_pkg', 'b-pkg~=1.4'), [['PyPI', 'a-pkg', null], ['PyPI', 'b-pkg', '~=1.4']]],
    ['python -m pip', j('python3', '-m', 'pip', 'install', 'some-pkg==1.0'), [['PyPI', 'some-pkg', '==1.0']]],
    ['uv add', j('uv', 'add', 'some-pkg==1.0.0'), [['PyPI', 'some-pkg', '==1.0.0']]],
    ['uv pip install', j('uv', 'pip', 'install', 'some-pkg'), [['PyPI', 'some-pkg', null]]],
    ['uvx pinned', j('uvx', 'some-tool@1.2.3', 'arg'), [['PyPI', 'some-tool', '==1.2.3']]],
    ['uvx unpinned', j('uvx', 'some-tool'), [['PyPI', 'some-tool', null]]],
    ['uvx --from', j('uvx', '--from', 'some-pkg==2.0', 'cmd'), [['PyPI', 'some-pkg', '==2.0']]],
    ['uv tool run', j('uv', 'tool', 'run', 'some-tool'), [['PyPI', 'some-tool', null]]],
    ['pipx install', j('pipx', 'install', 'some-pkg==1.0'), [['PyPI', 'some-pkg', '==1.0']]],
    ['pipx run', j('pipx', 'run', 'some-pkg'), [['PyPI', 'some-pkg', null]]],
    ['wrapped in sudo/env', j('sudo', 'FOO=1', 'npm', 'install', 'some-pkg@1'), [['npm', 'some-pkg', '1']]],
    ['chained statements', j('cd', 'x', '&&', 'npm', 'i', 'one-pkg', ';', 'pip', 'install', 'two-pkg'), [['npm', 'one-pkg', null], ['PyPI', 'two-pkg', null]]],
    ['trailing comment is not an argument', 'pip install real-pkg # not-a-pkg other', [['PyPI', 'real-pkg', null]]],
    ['inside sh -c', `bash -c '${j('npm', 'install', 'inner-pkg@1.0.0')}'`, [['npm', 'inner-pkg', '1.0.0']]],
  ];
  it.each(cases)('%s', (_label, command, expected) => {
    expect(parseInstallCommands(command).map(tuple)).toEqual(expected);
  });

  const none: Array<[string, string]> = [
    ['bare npm install (lockfile)', j('npm', 'install')],
    ['npm ci', j('npm', 'ci')],
    ['yarn install', j('yarn', 'install')],
    ['path install', j('npm', 'install', './local-dir')],
    ['git url', j('npm', 'install', 'git+https://example.com/x.git')],
    ['github shorthand', j('npm', 'install', 'someuser/somerepo')],
    ['tarball', j('npm', 'install', 'thing-1.0.0.tgz')],
    ['pip -r file', j('pip', 'install', '-r', 'requirements.txt')],
    ['pip editable', j('pip', 'install', '-e', '.')],
    ['run a script', j('npm', 'run', 'build')],
    ['echo mentioning an installer', j('echo', '"npm install foo"')],
    ['unrelated', j('ls', '-la')],
    ['words in a trailing shell comment', 'ls -la # npm install some-pkg'],
  ];
  it.each(none)('names nothing: %s', (_label, command) => {
    expect(parseInstallCommands(command)).toEqual([]);
  });

  it('flags a custom index', () => {
    const [r] = parseInstallCommands(j('pip', 'install', '--index-url', 'https://private.example/simple', 'some-pkg'));
    expect(r.customIndex).toBe(true);
    const [n] = parseInstallCommands(j('npm', 'install', '--registry=https://private.example', 'some-pkg'));
    expect(n.customIndex).toBe(true);
  });

  it('reads an MCP server entry that launches a package', () => {
    expect(parseMcpServerEntry({ command: 'npx', args: ['-y', `${MAL_NAME}@1.0.3`] }).map(tuple)).toEqual([['npm', MAL_NAME, '1.0.3']]);
    expect(parseMcpServerEntry({ command: 'uvx', args: ['some-tool'] }).map(tuple)).toEqual([['PyPI', 'some-tool', null]]);
    expect(parseMcpServerEntry({ command: '/usr/bin/node', args: ['server.js'] })).toEqual([]);
    expect(parseMcpServerEntry({ url: 'https://x' })).toEqual([]);
  });

  it('pySatisfies handles the specifier operators', () => {
    expect(pySatisfies('1.4.2', '>=1.0,<2')).toBe(true);
    expect(pySatisfies('2.0.0', '>=1.0,<2')).toBe(false);
    expect(pySatisfies('1.4.9', '~=1.4.2')).toBe(true);
    expect(pySatisfies('1.5.0', '~=1.4.2')).toBe(false);
    expect(pySatisfies('1.2.3', '==1.2.*')).toBe(true);
    expect(pySatisfies('1.3.0', '!=1.3.0')).toBe(false);
  });
});

// ── vetting ────────────────────────────────────────────────────────────────

describe('vetPackages — OSV, age, hooks', () => {
  it('flags a known-malicious package (MAL- id) as malicious', async () => {
    const w = fixtureWorld();
    const res = await vetPackages([npmRef(MAL_NAME, '1.0.3')], opts(w));
    expect(res.malicious).toBe(true);
    expect(res.packages[0].malicious).toEqual([MAL_ID]);
    expect(res.reasons[0]).toContain('known malicious');
    expect(res.reasons[0]).toContain(MAL_ID);
  });

  it('resolves an unpinned install to the latest version before asking OSV', async () => {
    const w = fixtureWorld();
    const res = await vetPackages([npmRef(MAL_NAME)], opts(w));
    expect(res.packages[0].version).toBe('1.0.3');
    expect(res.malicious).toBe(true);
    expect(w.calls.some((c) => c.startsWith('POST https://api.osv.dev'))).toBe(true);
  });

  it('reports an advisory (GHSA) hit for the exact version, not as malicious', async () => {
    const w = fixtureWorld();
    const res = await vetPackages([npmRef('legacy-lib', '2.1.0')], opts(w));
    expect(res.malicious).toBe(false);
    expect(res.packages[0].osvIds).toEqual(['GHSA-abcd-1234-wxyz']);
    expect(res.reasons).toContain('OSV: GHSA-abcd-1234-wxyz affects this version');
  });

  it('does not report an advisory that targets a different version', async () => {
    const w = fixtureWorld();
    const res = await vetPackages([npmRef('legacy-lib', '2.0.0')], opts(w));
    expect(res.reasons).toEqual([]);
  });

  it('flags a freshly published version with its age', async () => {
    const res = await vetPackages([npmRef('fresh-lib')], opts(fixtureWorld()));
    expect(res.packages[0].version).toBe('3.5.0');
    expect(res.reasons).toEqual(['published 11 h ago']);
  });

  it('does not flag the same package pinned to an older version', async () => {
    const res = await vetPackages([npmRef('fresh-lib', '3.4.0')], opts(fixtureWorld()));
    expect(res.reasons).toEqual([]);
  });

  it('honours a configurable minimum age', async () => {
    const w = fixtureWorld();
    expect((await vetPackages([npmRef('clean-lib')], opts(w, { minAgeDays: 1000 }))).reasons[0]).toMatch(/^published \d+ days ago$/);
    expect((await vetPackages([npmRef('fresh-lib')], opts(w, { minAgeDays: 0 }))).reasons).toEqual([]);
  });

  it('flags an npm lifecycle hook', async () => {
    const res = await vetPackages([npmRef('hooky-lib')], opts(fixtureWorld()));
    expect(res.packages[0].hooks).toEqual(['postinstall']);
    expect(res.reasons).toEqual(['runs a postinstall script on install']);
  });

  it('a clean, old, hook-free package has no findings (control)', async () => {
    const res = await vetPackages([npmRef('clean-lib', '4.2.1')], opts(fixtureWorld()));
    expect(res.packages[0].status).toBe('checked');
    expect(res.reasons).toEqual([]);
    expect(res.malicious).toBe(false);
  });

  it('resolves an npm range to the highest matching version', async () => {
    const res = await vetPackages([npmRef('ranged-lib', '^1.0.0')], opts(fixtureWorld()));
    expect(res.packages[0].version).toBe('1.4.2');
  });

  it('flags a source-only PyPI release and passes one with a wheel', async () => {
    const w = fixtureWorld();
    const src = await vetPackages([pyRef('src-only')], opts(w));
    expect(src.packages[0].sdistOnly).toBe(true);
    expect(src.reasons[0]).toContain('source only');
    const wheel = await vetPackages([pyRef('wheel-lib')], opts(w));
    expect(wheel.packages[0].sdistOnly).toBe(false);
    expect(wheel.reasons).toEqual([]);
  });

  it('PyPI: exact pin hits OSV for that version; a range picks the highest match', async () => {
    const w = fixtureWorld();
    const pinned = await vetPackages([pyRef('vuln-py', '==1.0.0')], opts(w));
    expect(pinned.reasons[0]).toBe('OSV: GHSA-pypy-0000-test, PYSEC-2026-1 affect this version');
    const ranged = await vetPackages([pyRef('vuln-py', '<1.1')], opts(w));
    expect(ranged.packages[0].version).toBe('1.0.0');
  });
});

describe('vetPackages — failure posture', () => {
  it('offline is "unchecked: …", never clean, and not malicious', async () => {
    const res = await vetPackages([npmRef('clean-lib', '4.2.1')], { fetchImpl: offline, nowMs: NOW, stateDir });
    expect(res.packages[0].status).toBe('unchecked');
    expect(res.malicious).toBe(false);
    expect(res.reasons).toHaveLength(1);
    expect(res.reasons[0]).toMatch(/^unchecked: network error/);
  });

  it('an OSV outage after a good registry answer is unchecked, not clean', async () => {
    const w = fixtureWorld();
    const inner = fetchFor(w);
    const f: FetchLike = async (url, init) => (url.includes('osv.dev') ? { ok: false, status: 503, json: async () => ({}) } : inner(url, init));
    const res = await vetPackages([npmRef('clean-lib', '4.2.1')], { fetchImpl: f, nowMs: NOW, stateDir });
    expect(res.packages[0].status).toBe('unchecked');
    expect(res.reasons[0]).toBe('unchecked: OSV answered HTTP 503');
  });

  it('an unknown package is unchecked with a reason', async () => {
    const res = await vetPackages([npmRef('does-not-exist')], opts(fixtureWorld()));
    expect(res.reasons[0]).toMatch(/^unchecked: package not found/);
  });

  it('enforces the total time budget', async () => {
    const hang: FetchLike = (_url, init) => new Promise((_res, rej) => {
      init?.signal?.addEventListener('abort', () => rej(new Error('aborted')));
    });
    const t0 = Date.now();
    const res = await vetPackages([npmRef('a-pkg'), pyRef('b-pkg')], { fetchImpl: hang, nowMs: NOW, stateDir, budgetMs: 80 });
    expect(Date.now() - t0).toBeLessThan(1500);
    expect(res.packages.every((p) => p.status === 'unchecked')).toBe(true);
    expect(res.reasons).toEqual(['unchecked: timed out']);
  });

  it('a custom index is unchecked, with no lookups made', async () => {
    const w = fixtureWorld();
    const res = await vetPackages([{ ...npmRef('clean-lib'), customIndex: true }], opts(w));
    expect(res.reasons[0]).toMatch(/^unchecked: installs from a custom package index/);
    expect(w.calls).toEqual([]);
  });
});

describe('vetPackages — cache', () => {
  it('caches only MAL- hits, per ecosystem@name@version, with owner-only permissions', async () => {
    const w = fixtureWorld();
    await vetPackages([npmRef('legacy-lib', '2.1.0'), npmRef('clean-lib', '4.2.1'), npmRef(MAL_NAME, '1.0.3')], opts(w));
    const file = path.join(stateDir, 'package-vetting-cache.json');
    expect(Object.keys(JSON.parse(fs.readFileSync(file, 'utf-8')).entries)).toEqual([`npm@${MAL_NAME}@1.0.3`]);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(fs.statSync(stateDir).mode & 0o777).toBe(0o700);
  });

  it('never serves a clean answer from cache: a MAL- id added later is seen on the next vet (review item 3)', async () => {
    const w = fixtureWorld();
    const first = await vetPackages([npmRef('clean-lib', '4.2.1')], opts(w));
    expect(first.malicious).toBe(false);
    // OSV publishes a MAL- report for that exact version two hours later.
    w.osv['npm@clean-lib@4.2.1'] = ['MAL-2026-99999'];
    const second = await vetPackages([npmRef('clean-lib', '4.2.1')], { ...opts(w), nowMs: NOW + 2 * 3_600_000 });
    expect(second.malicious).toBe(true);
    expect(second.packages[0].cached).toBeUndefined();
  });

  it('a fresh clean answer evicts a stale cached MAL- hit for the same version', async () => {
    const w = fixtureWorld();
    await vetPackages([npmRef(MAL_NAME, '1.0.3')], opts(w));
    delete w.osv[`npm@${MAL_NAME}@1.0.3`]; // report withdrawn
    await vetPackages([npmRef(MAL_NAME, '1.0.3')], { ...opts(w), nowMs: NOW + 3_600_000 });
    const off = await vetPackages([npmRef(MAL_NAME, '1.0.3')], { fetchImpl: offline, nowMs: NOW + 4 * 3_600_000, stateDir });
    expect(off.malicious).toBe(false);
  });

  it('a cached MAL- hit still blocks while offline (exact, unpinned and matching range)', async () => {
    const w = fixtureWorld();
    await vetPackages([npmRef(MAL_NAME, '1.0.3')], opts(w));
    for (const spec of ['1.0.3', null, '^1.0.0']) {
      const res = await vetPackages([npmRef(MAL_NAME, spec)], { fetchImpl: offline, nowMs: NOW + 3_600_000, stateDir });
      expect(res.malicious).toBe(true);
      expect(res.packages[0].cached).toBe(true);
    }
    // a different, non-matching version is not covered by that record
    const other = await vetPackages([npmRef(MAL_NAME, '2.0.0')], { fetchImpl: offline, nowMs: NOW + 3_600_000, stateDir });
    expect(other.malicious).toBe(false);
    expect(other.packages[0].status).toBe('unchecked');
  });

  it('an expired cached MAL- hit no longer blocks offline', async () => {
    const w = fixtureWorld();
    await vetPackages([npmRef(MAL_NAME, '1.0.3')], opts(w));
    const res = await vetPackages([npmRef(MAL_NAME, '1.0.3')], { fetchImpl: offline, nowMs: NOW + 7 * 3_600_000, stateDir });
    expect(res.malicious).toBe(false);
    expect(res.packages[0].status).toBe('unchecked');
  });

  it('a cached clean answer does not turn an offline run into "clean" for an unseen package', async () => {
    const w = fixtureWorld();
    await vetPackages([npmRef('clean-lib', '4.2.1')], opts(w));
    const res = await vetPackages([npmRef('hooky-lib', '1.0.0')], { fetchImpl: offline, nowMs: NOW, stateDir });
    expect(res.packages[0].status).toBe('unchecked');
  });
});

// ── tool-call entry + policy ───────────────────────────────────────────────

describe('vetToolCall + applyVettingToVerdict', () => {
  const base = { decision: 'allow' as const, severity: 'sensitive', family: 'exec', action: 'execute_command', reason: 'Workspace package install', signals: ['local-package-install'] };

  it('returns null for a command that installs nothing by name', async () => {
    expect(await vetToolCall('Bash', { command: 'ls -la' }, opts(world()))).toBeNull();
    expect(await vetToolCall('Bash', { command: j('npm', 'install') }, opts(world()))).toBeNull();
    expect(await vetToolCall('Read', { file_path: '/etc/hosts' }, opts(world()))).toBeNull();
  });

  it('respects enabled:false', async () => {
    const w = fixtureWorld();
    expect(await vetToolCall('Bash', { command: j('npm', 'install', MAL_NAME) }, opts(w, { enabled: false }))).toBeNull();
    expect(w.calls).toEqual([]);
  });

  it('known malicious → catastrophic block, even from an allow verdict (the advisory-mode floor)', async () => {
    const out = await vetToolCall('Bash', { command: j('npm', 'install', `${MAL_NAME}@1.0.3`) }, opts(fixtureWorld()));
    const v = applyVettingToVerdict(base, out);
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
    expect(v.signals).toEqual(expect.arrayContaining(['local-package-install', 'package-vetting', 'known-malicious-package']));
    expect(v.reason).toContain(MAL_ID);
  });

  it('advisory / new version / hook findings never change the decision or severity', async () => {
    const w = fixtureWorld();
    for (const [pkg, expected] of [
      [j('legacy-lib@2.1.0'), 'GHSA-abcd-1234-wxyz'],
      [j('fresh-lib'), 'published 11 h ago'],
      [j('hooky-lib'), 'postinstall'],
    ]) {
      const out = await vetToolCall('Bash', { command: j('npm', 'install', pkg) }, opts(w));
      const v = applyVettingToVerdict({ ...base, decision: 'require_approval' as const, severity: 'dangerous' }, out);
      expect(v.decision).toBe('require_approval');
      expect(v.severity).toBe('dangerous');
      expect(v.reason).toContain(expected);
      expect(v.signals).toContain('package-vetting');
      expect(v.signals).not.toContain('known-malicious-package');
    }
  });

  it('unchecked only annotates; it never blocks', async () => {
    const out = await vetToolCall('Bash', { command: j('npm', 'install', 'clean-lib') }, { fetchImpl: offline, nowMs: NOW, stateDir });
    const v = applyVettingToVerdict(base, out);
    expect(v.decision).toBe('allow');
    expect(v.reason).toContain('unchecked: network error');
    // No signal: a network blip must not stop the approval broker pre-clearing.
    expect(v.signals).toEqual(base.signals);
  });

  it('a clean install leaves the verdict untouched', async () => {
    const out = await vetToolCall('Bash', { command: j('npm', 'install', 'clean-lib@4.2.1') }, opts(fixtureWorld()));
    expect(applyVettingToVerdict(base, out)).toBe(base);
  });

  it('audit summary carries package names and finding kinds, not the command', async () => {
    const out = await vetToolCall('Bash', { command: j('npm', 'install', 'hooky-lib', '--token=abc123') }, opts(fixtureWorld()));
    expect(out!.audit).toEqual([{ ecosystem: 'npm', name: 'hooky-lib', version: '1.0.0', status: 'checked', kinds: ['install-hook'], reasons: ['runs a postinstall script on install'] }]);
    expect(JSON.stringify(out)).not.toContain('abc123');
  });

  it('vets an MCP server entry report-only', async () => {
    const hits = await vetMcpServers([
      { name: 'docs', entry: { command: 'npx', args: ['-y', `${MAL_NAME}@1.0.3`] } },
      { name: 'local', entry: { command: 'node', args: ['x.js'] } },
      { name: 'ok', entry: { command: 'npx', args: ['clean-lib@4.2.1'] } },
    ], opts(fixtureWorld()));
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ name: 'docs', malicious: true });
  });

  it('normalises config defensively', () => {
    expect(normalisePackageVettingConfig({ enabled: false, minAgeDays: 3 })).toEqual({ enabled: false, minAgeDays: 3 });
    expect(normalisePackageVettingConfig({ enabled: 'no', minAgeDays: -1 })).toEqual({});
    expect(normalisePackageVettingConfig(null)).toEqual({});
  });
});

// ── review round 1 (TARS 5781824574): bypass regressions ───────────────────

const CTRL = /[\x00-\x1f\x7f]/;

describe('review item 1 — the MAL- check does not depend on the cap or the registry', () => {
  const decoys = ['a1', 'b2', 'c3', 'd4', 'e5', 'f6', 'g7', 'h8'];

  it('a MAL- package listed ninth is still malicious', async () => {
    const w = fixtureWorld();
    const cmd = j('npm', 'i', ...decoys, `${MAL_NAME}@1.0.3`);
    const out = await vetToolCall('Bash', { command: cmd }, opts(w));
    expect(out!.malicious).toBe(true);
    expect(out!.reasons.join(' ')).toContain(MAL_ID);
    // decoys stay "unchecked: more than 8 packages…"; the MAL package is reported with its id
    const mal = out!.audit.find((a) => a.name === MAL_NAME)!;
    expect(mal.kinds).toContain('malicious');
    const v = applyVettingToVerdict({ decision: 'allow', severity: 'sensitive', signals: [], reason: 'x' }, out);
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
  });

  it('a ninth UNPINNED MAL- package is caught by the name-only batch query', async () => {
    const w = fixtureWorld();
    const res = await vetPackages([...decoys.map((d) => npmRef(d)), npmRef(MAL_NAME)], opts(w));
    expect(res.malicious).toBe(true);
  });

  it('issues one querybatch covering every package, separate from the registry lookups', async () => {
    const w = fixtureWorld();
    await vetPackages([...decoys.map((d) => npmRef(d, '1.0.0')), npmRef(MAL_NAME, '1.0.3')], opts(w));
    expect(w.calls.filter((c) => c === 'POST https://api.osv.dev/v1/querybatch')).toHaveLength(1);
  });

  it('registry exhaustion (every packument hangs) cannot hide a pinned MAL- package', async () => {
    const w = fixtureWorld();
    const inner = fetchFor(w);
    const f: FetchLike = (url, init) => url.includes('registry.npmjs.org')
      ? new Promise((_r, rej) => init?.signal?.addEventListener('abort', () => rej(new Error('aborted'))))
      : inner(url, init);
    const res = await vetPackages([npmRef('big-lib'), npmRef(MAL_NAME, '1.0.3')], { fetchImpl: f, nowMs: NOW, stateDir, budgetMs: 100 });
    expect(res.malicious).toBe(true);
    expect(res.packages.find((p) => p.ref.name === 'big-lib')!.status).toBe('unchecked');
  });

  it('batch failure on a ninth package is reported, not silently clean', async () => {
    const w = fixtureWorld();
    const inner = fetchFor(w);
    const f: FetchLike = async (url, init) => (url.endsWith('/querybatch') ? { ok: false, status: 500, json: async () => ({}) } : inner(url, init));
    const res = await vetPackages([...decoys.map((d) => npmRef(d)), npmRef(MAL_NAME, '1.0.3')], { fetchImpl: f, nowMs: NOW, stateDir });
    expect(res.malicious).toBe(false);
    expect(res.reasons.join(' ')).toMatch(/malicious-package check was unavailable/);
  });

  it('a name-only hit does not override a clean version-specific answer (unpinned compromised-version case)', async () => {
    const w = fixtureWorld();
    w.osv['npm@clean-lib@9.9.9'] = ['MAL-2026-1']; // an OLD/other version is malicious; the latest is 4.2.1
    const res = await vetPackages([npmRef('clean-lib')], opts(w));
    expect(res.malicious).toBe(false);
  });
});

describe('review item 2 — npm aliases are vetted by their target', () => {
  it('parses alias forms to the target package', () => {
    const t = (c: string) => parseInstallCommands(c).map(tuple);
    expect(t(j('npm', 'i', `foo@npm:${MAL_NAME}@1.0.3`))).toEqual([['npm', MAL_NAME, '1.0.3']]);
    expect(t(j('npm', 'i', 'foo@npm:badpkg'))).toEqual([['npm', 'badpkg', null]]);
    expect(t(j('npm', 'i', '@my/alias@npm:badpkg@^1.0.0'))).toEqual([['npm', 'badpkg', '^1.0.0']]);
    expect(t(j('pnpm', 'add', 'npm:badpkg@2.0.0'))).toEqual([['npm', 'badpkg', '2.0.0']]);
    expect(t(j('npm', 'i', 'foo@npm:npm:badpkg'))).toEqual([]);
  });

  it('an aliased MAL- package is blocked end to end', async () => {
    const out = await vetToolCall('Bash', { command: j('npm', 'i', `foo@npm:${MAL_NAME}@1.0.3`) }, opts(fixtureWorld()));
    expect(out!.malicious).toBe(true);
  });
});

describe('review item 4 — raw spec text never reaches reasons, audit rows or the verdict', () => {
  const evil = `1.0.0\x1b[31mX\nLINE2SENTINEL`;

  it('npm: an unresolvable spec with ESC and newline is not echoed', async () => {
    const w = fixtureWorld();
    const out = await vetToolCall('Bash', { command: ['npm i ', `'legacy-lib@${evil}'`].join('') }, opts(w));
    expect(out).not.toBeNull();
    const blob = JSON.stringify(out) + out!.reasons.join('\n');
    expect(blob).not.toContain('SENTINEL');
    for (const r of out!.reasons) expect(r).not.toMatch(CTRL);
    for (const a of out!.audit) for (const r of a.reasons) expect(r).not.toMatch(CTRL);
    const v = applyVettingToVerdict({ decision: 'allow', severity: 'sensitive', signals: [], reason: 'base' }, out);
    expect(v.reason).not.toMatch(CTRL);
    expect(v.reason).not.toContain('SENTINEL');
  });

  it('uvx: an unresolvable @version with control characters is not echoed', async () => {
    const out = await vetToolCall('Bash', { command: `uvx 'wheel-lib@${evil}'` }, opts(fixtureWorld()));
    expect(out).not.toBeNull();
    expect(out!.reasons.join('\n')).not.toContain('SENTINEL');
    for (const r of out!.reasons) expect(r).not.toMatch(CTRL);
  });

  it('a registry that returns a control-character version string is rejected, not echoed', async () => {
    const w = fixtureWorld();
    const inner = fetchFor(w);
    const f: FetchLike = async (url, init) => {
      if (url.includes('registry.npmjs.org/evil-ver')) {
        return { ok: true, status: 200, json: async () => ({ 'dist-tags': { latest: '1.0.0\x1b[31m' }, versions: { '1.0.0\x1b[31m': {} }, time: {} }) };
      }
      return inner(url, init);
    };
    const res = await vetPackages([npmRef('evil-ver')], { fetchImpl: f, nowMs: NOW, stateDir });
    for (const r of res.reasons) expect(r).not.toMatch(CTRL);
    expect(res.packages[0].status).toBe('unchecked');
  });
});

describe('review item 5 — custom index detection', () => {
  const custom = (c: string) => parseInstallCommands(c).map((r) => r.customIndex === true);
  it.each([
    ['flag before the verb (npm)', j('npm', '--registry', 'https://r.example', 'install', 'foo')],
    ['flag before the verb, = form (npm)', j('npm', '--registry=https://r.example', 'install', 'foo')],
    ['npm_config_registry env prefix', j('npm_config_registry=https://r.example', 'npm', 'i', 'foo')],
    ['NPM_CONFIG_REGISTRY via env wrapper', j('env', 'NPM_CONFIG_REGISTRY=https://r.example', 'npm', 'i', 'foo')],
    ['PIP_INDEX_URL env prefix', j('PIP_INDEX_URL=https://i.example', 'pip', 'install', 'foo')],
    ['PIP_EXTRA_INDEX_URL env prefix', j('PIP_EXTRA_INDEX_URL=https://i.example', 'pip', 'install', 'foo')],
    ['pip --index-url before the verb', j('pip', '--index-url', 'https://i.example', 'install', 'foo')],
    ['pip3 -i before the verb', j('pip3', '-i', 'https://i.example', 'install', 'foo')],
    ['UV_INDEX_URL env on uvx', j('UV_INDEX_URL=https://i.example', 'uvx', 'foo')],
    ['uv --index-url before pip', j('uv', '--index-url', 'https://i.example', 'pip', 'install', 'foo')],
    ['env prefix on a bash -c payload', j('PIP_INDEX_URL=https://i.example', 'bash', '-c', `'${j('pip', 'install', 'foo')}'`)],
    ['pnpm dlx with registry before the verb', j('pnpm', '--registry', 'https://r.example', 'dlx', 'foo')],
  ])('%s → customIndex', (_label, cmd) => {
    expect(custom(cmd)).toEqual([true]);
  });

  it('an unrelated env var or a plain install is not customIndex (control)', () => {
    expect(custom(j('FOO=bar', 'npm', 'i', 'foo'))).toEqual([false]);
    expect(custom(j('npm', 'i', 'foo'))).toEqual([false]);
    expect(custom(j('pip', 'install', 'foo'))).toEqual([false]);
  });

  it('is reported unchecked with no lookups', async () => {
    const w = fixtureWorld();
    const res = await vetCommandViaTool(w, j('npm_config_registry=https://r.example', 'npm', 'i', 'clean-lib'));
    expect(res!.reasons[0]).toMatch(/^unchecked: installs from a custom package index/);
    expect(w.calls).toEqual([]);
  });
});

async function vetCommandViaTool(w: World, command: string) {
  return vetToolCall('Bash', { command }, opts(w));
}

describe('review item 7 — MAL ids carried only as aliases', () => {
  it('per-version query: a GHSA record aliasing a MAL- id is malicious', async () => {
    const w = fixtureWorld();
    w.osv['npm@clean-lib@4.2.1'] = ['GHSA-aaaa-bbbb-cccc'];
    w.aliases = { 'GHSA-aaaa-bbbb-cccc': ['MAL-2026-9'] };
    const res = await vetPackages([npmRef('clean-lib', '4.2.1')], opts(w));
    expect(res.malicious).toBe(true);
    expect(res.packages[0].malicious).toContain('MAL-2026-9');
  });

  it('batch path (ninth package): the alias is resolved through /v1/vulns/<id>', async () => {
    const w = fixtureWorld();
    w.osv['npm@clean-lib@4.2.1'] = ['GHSA-aaaa-bbbb-cccc'];
    w.aliases = { 'GHSA-aaaa-bbbb-cccc': ['MAL-2026-9'] };
    const decoys = ['a1', 'b2', 'c3', 'd4', 'e5', 'f6', 'g7', 'h8'].map((d) => npmRef(d, '1.0.0'));
    const res = await vetPackages([...decoys, npmRef('clean-lib', '4.2.1')], opts(w));
    expect(res.malicious).toBe(true);
  });
});
