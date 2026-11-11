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
  UNRECOGNISED_OPTION,
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
    // Every OSV endpoint is down here, the batch included: the reason says both (panel correction, rubric A).
    expect(res.reasons[0]).toBe('unchecked: OSV answered HTTP 503, and the malicious-package check was unavailable');
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
    expect(res.reasons).toEqual(['unchecked: timed out, and the malicious-package check was unavailable']);
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
    const out = await vetToolCall('Bash', { command: j('npm', 'install', 'hooky-lib', '--otp=abc123') }, opts(fixtureWorld()));
    expect(out!.audit).toEqual([{ ecosystem: 'npm', name: 'hooky-lib', version: '1.0.0', status: 'checked', kinds: ['install-hook'], reasons: ['runs a postinstall script on install'] }]);
    expect(JSON.stringify(out)).not.toContain('abc123');
    // An option npm does not define (`--token`) leaves the version unconfirmed; its text is never echoed.
    const unknown = await vetToolCall('Bash', { command: j('npm', 'install', 'hooky-lib', '--token=abc123') }, opts(fixtureWorld()));
    expect(unknown!.audit[0].status).toBe('unchecked');
    expect(JSON.stringify(unknown)).not.toContain('abc123');
    expect(JSON.stringify(unknown)).not.toContain('token');
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

// ── Fable 1920Z closed rubric A–C (second panel round) ─────────────────────

const batchCalls = (w: World) => w.calls.filter((c) => c === 'POST https://api.osv.dev/v1/querybatch');
const customRef = (name: string, spec: string | null = null): PackageRef => ({ ...npmRef(name, spec), customIndex: true });

describe('rubric A — the OSV batch covers every package, in chunks', () => {
  const pad = (n: number, prefix = 'pad') => Array.from({ length: n }, (_, i) => npmRef(`${prefix}-${i}`, '1.0.0'));

  it('a MAL- package at position 501 blocks', async () => {
    const w = fixtureWorld();
    const res = await vetPackages([...pad(500), npmRef(MAL_NAME, '1.0.3')], opts(w));
    expect(res.malicious).toBe(true);
    expect(res.reasons.join(' ')).toContain(MAL_ID);
    expect(batchCalls(w)).toHaveLength(2);
  });

  it('every chunk carries at most 500 queries and none is dropped', async () => {
    const w = fixtureWorld();
    const sizes: number[] = [];
    const inner = fetchFor(w);
    const f: FetchLike = (url, init) => {
      if (url.endsWith('/querybatch')) sizes.push((JSON.parse(init!.body!) as { queries: unknown[] }).queries.length);
      return inner(url, init);
    };
    await vetPackages(pad(1203), { fetchImpl: f, nowMs: NOW, stateDir });
    expect(sizes.sort((a, b) => a - b)).toEqual([203, 500, 500]);
  });

  it('second chunk fails: the first chunk MAL- still blocks and the second chunk refs say unavailable', async () => {
    const w = fixtureWorld();
    const inner = fetchFor(w);
    const f: FetchLike = async (url, init) => {
      if (url.endsWith('/querybatch') && (JSON.parse(init!.body!) as { queries: Array<{ package: { name: string } }> }).queries.some((q) => q.package.name === 'late-0')) {
        return { ok: false, status: 500, json: async () => ({}) };
      }
      return inner(url, init);
    };
    const refs = [...pad(20), npmRef(MAL_NAME, '1.0.3'), ...pad(479, 'mid'), ...pad(5, 'late')];
    const res = await vetPackages(refs, { fetchImpl: f, nowMs: NOW, stateDir });
    expect(res.malicious).toBe(true);
    expect(res.packages.find((p) => p.ref.name === MAL_NAME)!.malicious).toEqual([MAL_ID]);
    const late = res.packages.find((p) => p.ref.name === 'late-0')!;
    expect(late.status).toBe('unchecked');
    expect(late.malicious).toEqual([]);
    expect(late.uncheckedReason).toMatch(/malicious-package check was unavailable/);
    const early = res.packages.find((p) => p.ref.name === 'mid-30')!;
    expect(early.uncheckedReason).not.toMatch(/malicious-package check was unavailable/);
  });

  it('a chunk whose results length differs from its queries is unavailable, never clean', async () => {
    const w = fixtureWorld();
    const inner = fetchFor(w);
    const f: FetchLike = async (url, init) => (url.endsWith('/querybatch')
      ? { ok: true, status: 200, json: async () => ({ results: [{}] }) }
      : inner(url, init));
    const res = await vetPackages([...pad(8), npmRef(MAL_NAME, '1.0.3')], { fetchImpl: f, nowMs: NOW, stateDir });
    expect(res.malicious).toBe(false);
    expect(res.reasons.join(' ')).toMatch(/malicious-package check was unavailable/);
  });

  it('a cached MAL- hit stays in force when the batch is unavailable', async () => {
    const w = fixtureWorld();
    await vetPackages([npmRef(MAL_NAME, '1.0.3')], opts(w)); // records the MAL- hit
    const f: FetchLike = async () => { throw Object.assign(new Error('x'), { code: 'ENOTFOUND' }); };
    const res = await vetPackages([...pad(8), npmRef(MAL_NAME, '1.0.3')], { fetchImpl: f, nowMs: NOW, stateDir });
    expect(res.malicious).toBe(true);
  });
});

describe('rubric B — custom-index and public refs are different installs', () => {
  it('custom first, public second: the public ref is vetted and a MAL- hit blocks', async () => {
    const w = fixtureWorld();
    const res = await vetPackages([customRef(MAL_NAME, '1.0.3'), npmRef(MAL_NAME, '1.0.3')], opts(w));
    expect(res.packages).toHaveLength(2);
    expect(res.malicious).toBe(true);
    expect(res.packages.find((p) => !p.ref.customIndex)!.malicious).toEqual([MAL_ID]);
  });

  it('public first, custom second: same result', async () => {
    const w = fixtureWorld();
    const res = await vetPackages([npmRef(MAL_NAME, '1.0.3'), customRef(MAL_NAME, '1.0.3')], opts(w));
    expect(res.packages).toHaveLength(2);
    expect(res.malicious).toBe(true);
  });

  it('identical refs still collapse to one', async () => {
    const w = fixtureWorld();
    const res = await vetPackages([npmRef('clean-lib', '4.2.1'), npmRef('clean-lib', '4.2.1')], opts(w));
    expect(res.packages).toHaveLength(1);
  });
});

describe('rubric C — name-only MAL- hits', () => {
  const decoys = ['a1', 'b2', 'c3', 'd4', 'e5', 'f6', 'g7', 'h8'].map((d) => npmRef(d, '1.0.0'));
  const multi = (name: string) => ({ [name]: { versions: { '1.0.0': { time: hoursAgo(24 * 400) }, '2.0.0': { time: hoursAgo(24 * 300) } } } });
  const UNCONFIRMED = /OSV lists a malicious release of [^;]+; the version this install would fetch could not be checked, so it is blocked until you pin a version/;

  it('rule 1: a version-specific answer (record withdrawn) is final for a pinned ref even though the batch still lists the id', async () => {
    const w = fixtureWorld();
    const inner = fetchFor(w);
    const f: FetchLike = async (url, init) => (url === 'https://api.osv.dev/v1/query'
      ? { ok: true, status: 200, json: async () => ({ vulns: [{ id: MAL_ID, withdrawn: '2026-11-06T00:00:00Z' }] }) }
      : inner(url, init));
    const res = await vetPackages([npmRef(MAL_NAME, '1.0.3')], { fetchImpl: f, nowMs: NOW, stateDir });
    expect(batchCalls(w)).toHaveLength(1);
    expect(res.malicious).toBe(false);
  });

  it('rule 2: a ninth unpinned package with a MAL- on another version resolves clean and is not blocked', async () => {
    const w = fixtureWorld();
    w.npm['multi-lib'] = multi('multi-lib')['multi-lib'];
    w.osv['npm@multi-lib@1.0.0'] = ['MAL-2025-1'];
    const res = await vetPackages([...decoys, npmRef('multi-lib')], opts(w));
    expect(res.malicious).toBe(false);
    expect(res.reasons.join(' ')).not.toMatch(/malicious/);
  });

  it('rule 2: a ninth unpinned package whose resolved version is malicious is blocked as known malicious', async () => {
    const w = fixtureWorld();
    w.npm['multi-lib'] = multi('multi-lib')['multi-lib'];
    w.osv['npm@multi-lib@2.0.0'] = ['MAL-2025-2'];
    const res = await vetPackages([...decoys, npmRef('multi-lib')], opts(w));
    expect(res.malicious).toBe(true);
    expect(res.reasons.join(' ')).toContain('multi-lib@2.0.0 as known malicious');
  });

  it('rule 2: at most 8 extra lookups; the ninth extra is unconfirmed (rule 3), not clean', async () => {
    const w = fixtureWorld();
    const names = Array.from({ length: 9 }, (_, i) => `multi-${i}`);
    for (const n of names) {
      w.npm[n] = multi(n)[n];
      w.osv[`npm@${n}@1.0.0`] = ['MAL-2025-3'];
    }
    const res = await vetPackages([...decoys, ...names.map((n) => npmRef(n))], opts(w));
    const blocked = res.packages.filter((p) => p.malicious.length);
    expect(blocked.map((p) => p.ref.name)).toEqual(['multi-8']);
    expect(res.reasons.join(' ')).toMatch(UNCONFIRMED);
    expect(res.reasons.join(' ')).not.toContain('as known malicious');
  });

  it('rule 3: no version resolved (registry 404) keeps the install blocked, with the accurate wording', async () => {
    const w = fixtureWorld();
    w.osv['npm@ghost-lib@1.0.0'] = ['MAL-2025-4']; // not in the registry fixture: the version cannot be resolved
    const res = await vetPackages([...decoys, npmRef('ghost-lib')], opts(w));
    expect(res.malicious).toBe(true);
    const pkg = res.packages.find((p) => p.ref.name === 'ghost-lib')!;
    expect(pkg.findings.find((f) => f.kind === 'malicious')!.reason).toMatch(UNCONFIRMED);
    expect(pkg.findings.find((f) => f.kind === 'malicious')!.reason).not.toContain('as known malicious');
  });

  it('rule 3: the version query did not answer keeps the install blocked, with the accurate wording (first eight too)', async () => {
    const w = fixtureWorld();
    w.npm['multi-lib'] = multi('multi-lib')['multi-lib'];
    w.osv['npm@multi-lib@1.0.0'] = ['MAL-2025-5'];
    const inner = fetchFor(w);
    const f: FetchLike = async (url, init) => (url === 'https://api.osv.dev/v1/query'
      ? { ok: false, status: 503, json: async () => ({}) }
      : inner(url, init));
    const res = await vetPackages([npmRef('multi-lib')], { fetchImpl: f, nowMs: NOW, stateDir });
    expect(res.malicious).toBe(true);
    expect(res.reasons.join(' ')).toMatch(UNCONFIRMED);
    expect(res.reasons.join(' ')).not.toContain('as known malicious');
  });

  it('rule 3: pinning the clean version of the same package passes', async () => {
    const w = fixtureWorld();
    w.npm['multi-lib'] = multi('multi-lib')['multi-lib'];
    w.osv['npm@multi-lib@1.0.0'] = ['MAL-2025-6'];
    const res = await vetPackages([...decoys, npmRef('multi-lib', '2.0.0')], opts(w));
    expect(res.malicious).toBe(false);
  });

  it('rule 3 wording reaches the verdict reason and stays printable ASCII', async () => {
    const w = fixtureWorld();
    w.osv['npm@ghost-lib@1.0.0'] = ['MAL-2025-4'];
    const out = await vetToolCall('Bash', { command: j('npm', 'i', 'a1', 'b2', 'c3', 'd4', 'e5', 'f6', 'g7', 'h8', 'ghost-lib') }, opts(w));
    expect(out!.malicious).toBe(true);
    expect(out!.reasons.join(' ')).toMatch(UNCONFIRMED);
    expect(out!.reasons.join(' ')).not.toMatch(CTRL);
  });
});

// Final panel at 14adad1c (Sol), two rubric defects as implemented.
describe('panel correction — rubric A: a head ref whose registry lookup and batch chunk both failed', () => {
  const UNAVAILABLE = ', and the malicious-package check was unavailable';
  const batchDown = (w: World, registry: 'fixture' | 'offline' = 'fixture'): FetchLike => {
    const inner = fetchFor(w);
    return async (url, init) => {
      if (url.endsWith('/querybatch')) return { ok: false, status: 500, json: async () => ({}) };
      if (registry === 'offline' && !url.includes('osv.dev')) throw Object.assign(new Error('getaddrinfo'), { code: 'ENOTFOUND' });
      return inner(url, init);
    };
  };
  const batchMisaligned = (w: World): FetchLike => {
    const inner = fetchFor(w);
    return async (url, init) => (url.endsWith('/querybatch')
      ? { ok: true, status: 200, json: async () => ({ results: [{}, {}, {}] }) }
      : inner(url, init));
  };

  it('registry 404 + failed chunk: the head ref says the malicious-package check was unavailable', async () => {
    const res = await vetPackages([npmRef('does-not-exist')], { fetchImpl: batchDown(fixtureWorld()), nowMs: NOW, stateDir });
    expect(res.malicious).toBe(false);
    expect(res.packages[0].status).toBe('unchecked');
    expect(res.packages[0].uncheckedReason).toBe(`package not found in the public registry${UNAVAILABLE}`);
    expect(res.reasons).toEqual([`unchecked: package not found in the public registry${UNAVAILABLE}`]);
  });

  it('registry network failure + failed chunk, pinned and unpinned head refs alike', async () => {
    const res = await vetPackages([npmRef('clean-lib'), npmRef('hooky-lib', '1.0.0')], { fetchImpl: batchDown(fixtureWorld(), 'offline'), nowMs: NOW, stateDir });
    expect(res.malicious).toBe(false);
    for (const p of res.packages) {
      expect(p.status).toBe('unchecked');
      expect(p.uncheckedReason).toBe(`network error (ENOTFOUND)${UNAVAILABLE}`);
    }
  });

  it('registry 404 + a chunk whose results do not line up: unavailable, never clean', async () => {
    const res = await vetPackages([npmRef('does-not-exist')], { fetchImpl: batchMisaligned(fixtureWorld()), nowMs: NOW, stateDir });
    expect(res.malicious).toBe(false);
    expect(res.packages[0].uncheckedReason).toBe(`package not found in the public registry${UNAVAILABLE}`);
  });

  it('the cached MAL- hit stays in force for a head ref when registry and batch both fail', async () => {
    const w = fixtureWorld();
    await vetPackages([npmRef(MAL_NAME, '1.0.3')], opts(w)); // records the MAL- hit
    for (const f of [batchDown(fixtureWorld(), 'offline'), offline]) {
      const res = await vetPackages([npmRef(MAL_NAME, '1.0.3')], { fetchImpl: f, nowMs: NOW + 3_600_000, stateDir });
      expect(res.malicious).toBe(true);
      expect(res.packages[0].cached).toBe(true);
      expect(res.packages[0].malicious).toEqual([MAL_ID]);
    }
  });

  it('control: the registry failed but the batch answered, so nothing is called unavailable', async () => {
    const res = await vetPackages([npmRef('does-not-exist')], opts(fixtureWorld()));
    expect(res.reasons).toEqual(['unchecked: package not found in the public registry']);
  });

  it('control: a version-specific answer is unaffected by a failed chunk', async () => {
    const res = await vetPackages([npmRef('clean-lib', '4.2.1')], { fetchImpl: batchDown(fixtureWorld()), nowMs: NOW, stateDir });
    expect(res.packages[0].status).toBe('checked');
    expect(res.reasons.join(' ')).not.toMatch(/unavailable/);
  });
});

describe('panel correction — rubric C3: the unconfirmed-version explanation is never cut', () => {
  const TAIL = '; the version this install would fetch could not be checked, so it is blocked until you pin a version';
  const LONG = `ghost-${'a'.repeat(114)}`; // 120 characters, the longest name a reason will show
  const IDS = ['MAL-2025-10001', 'MAL-2025-10002', 'MAL-2025-10003', 'MAL-2025-10004', 'MAL-2025-10005'];

  it('a long name with several ids keeps the whole explanation and the pin instruction through vetToolCall', async () => {
    const w = fixtureWorld();
    w.osv[`npm@${LONG}@1.0.0`] = IDS; // not in the registry fixture: the version cannot be resolved
    const out = await vetToolCall('Bash', { command: j('npm', 'install', LONG) }, opts(w));
    expect(out!.malicious).toBe(true);
    const reason = out!.reasons[0];
    expect(reason.startsWith('OSV lists a malicious release of ghost-aaaa')).toBe(true);
    expect(reason.endsWith(TAIL)).toBe(true);
    expect(reason).toContain('(MAL-2025-10001');
    expect(reason.length).toBeLessThanOrEqual(240);
    expect(reason).not.toContain(LONG); // the name is what gives way, not the explanation
    expect(out!.audit[0].reasons.find((r) => r.startsWith('OSV lists'))!.endsWith(TAIL)).toBe(true);
    expect(reason).not.toMatch(CTRL);
  });

  it('an ordinary name is worded exactly as before', async () => {
    const w = fixtureWorld();
    w.osv['npm@ghost-lib@1.0.0'] = ['MAL-2025-4'];
    const res = await vetPackages([npmRef('ghost-lib')], opts(w));
    expect(res.reasons[0]).toBe(`OSV lists a malicious release of ghost-lib (MAL-2025-4)${TAIL}`);
  });

  it('a long name on a confirmed hit still names the version and says known malicious', async () => {
    const w = fixtureWorld();
    w.npm[LONG] = { versions: { '1.0.0': { time: hoursAgo(24 * 400) } } };
    w.osv[`npm@${LONG}@1.0.0`] = IDS;
    const out = await vetToolCall('Bash', { command: j('npm', 'install', `${LONG}@1.0.0`) }, opts(w));
    const reason = out!.reasons[0];
    expect(reason).toMatch(/^OSV lists ghost-a+\.\.\.@1\.0\.0 as known malicious \(MAL-2025-10001, MAL-2025-10002, MAL-2025-10003 \+2 more\)$/);
    expect(reason.length).toBeLessThanOrEqual(240);
  });
});

// Release review (v5.20.0, Astra B1): `--tag` / `--before` were consumed as value
// flags and then ignored, so the registry lookup resolved `latest`, got a clean
// exact answer for it and discarded the name-only MAL- hit for the version npm
// actually selects. Fixture: npm-pick-manifest 10 picks 2.0.0-beta.1 for
// `--tag beta` and 0.9.0 for `--before 2020-06-01`; both are malicious, latest
// (1.0.0) is clean.
describe('release review B1 — version-selection options are never resolved as if absent', () => {
  const TAGPKG = 'synth-tagpkg';
  const TAG_MAL = 'MAL-2026-90003';
  const UNCONFIRMED = /OSV lists a malicious release of synth-tagpkg \(MAL-2026-90003\); the version this install would fetch could not be checked, so it is blocked until you pin a version/;
  const tagWorld = (): World => {
    const w = fixtureWorld();
    w.npm[TAGPKG] = {
      tags: { latest: '1.0.0', beta: '2.0.0-beta.1' },
      versions: {
        '0.9.0': { time: '2019-01-01T00:00:00Z' },
        '1.0.0': { time: '2021-01-01T00:00:00Z' },
        '2.0.0-beta.1': { time: hoursAgo(24 * 30) },
      },
    };
    w.osv[`npm@${TAGPKG}@0.9.0`] = [TAG_MAL];
    w.osv[`npm@${TAGPKG}@2.0.0-beta.1`] = [TAG_MAL];
    return w;
  };
  const vet = (w: World, command: string) => vetToolCall('Bash', { command }, opts(w));

  it('parses the option onto the ref, wherever it is spelled (after, before the verb, inline, env)', () => {
    const cases: Array<[string, string]> = [
      [j('npm', 'install', TAGPKG, '--tag', 'beta'), '--tag'],
      [j('npm', 'install', '--tag', 'beta', TAGPKG), '--tag'],
      [j('npm', 'install', '--tag=beta', TAGPKG), '--tag'],
      [j('npm', '--tag', 'beta', 'install', TAGPKG), '--tag'],
      [j('npm', 'install', TAGPKG, '--before', '2020-06-01'), '--before'],
      [j('npm', 'install', '--before=2020-06-01', TAGPKG), '--before'],
      [j('npx', '--tag', 'beta', TAGPKG), '--tag'],
      [j('pnpm', 'add', '--resolution-mode', 'lowest-direct', `${TAGPKG}@^1.0.0`), '--resolution-mode'],
      [j('npm_config_tag=beta', 'npm', 'i', TAGPKG), 'npm_config_tag'],
      [j('pip', 'install', '--pre', 'some-pkg'), '--pre'],
      [j('uv', 'pip', 'install', '--prerelease', 'allow', 'some-pkg'), '--prerelease'],
      [j('uvx', '--exclude-newer', '2020-01-01', 'some-tool'), '--exclude-newer'],
      [j('PIP_PRE=1', 'pip', 'install', 'some-pkg'), 'pip_pre'],
    ];
    for (const [command, option] of cases) {
      const refs = parseInstallCommands(command);
      expect(refs).toHaveLength(1);
      expect(refs[0].versionOption).toBe(option);
    }
    // The option's value is never read as a package.
    expect(parseInstallCommands(j('npm', 'install', TAGPKG, '--tag', 'beta')).map((r) => r.name)).toEqual([TAGPKG]);
    expect(parseInstallCommands(j('uv', 'pip', 'install', '--prerelease', 'allow', 'some-pkg')).map((r) => r.name)).toEqual(['some-pkg']);
    // Control: no option, no mark.
    expect(parseInstallCommands(j('npm', 'install', TAGPKG))[0].versionOption).toBeUndefined();
  });

  it('npm install <pkg> --tag beta: the selected (malicious) beta is not hidden behind a clean latest', async () => {
    const w = tagWorld();
    const out = await vet(w, j('npm', 'install', TAGPKG, '--tag', 'beta'));
    expect(out!.malicious).toBe(true);
    expect(out!.reasons.join(' ')).toMatch(UNCONFIRMED);
    expect(out!.audit[0].version).toBeUndefined(); // never reported as having checked latest
    // latest (1.0.0) was never asked about as if it were the install's version
    expect(w.calls.filter((c) => c === 'POST https://api.osv.dev/v1/query')).toEqual([]);
  });

  it('npm install <pkg> --before <date>: the selected (malicious) older version is not hidden behind a clean latest', async () => {
    for (const command of [j('npm', 'install', TAGPKG, '--before', '2020-06-01'), j('npm', 'install', '--before=2020-06-01', TAGPKG)]) {
      const out = await vet(tagWorld(), command);
      expect(out!.malicious).toBe(true);
      expect(out!.reasons.join(' ')).toMatch(UNCONFIRMED);
    }
  });

  it('the env-var and pre-verb spellings block the same way', async () => {
    for (const command of [j('npm_config_tag=beta', 'npm', 'i', TAGPKG), j('npm', '--tag', 'beta', 'install', TAGPKG), j('npx', '--tag', 'beta', TAGPKG)]) {
      const out = await vet(tagWorld(), command);
      expect(out!.malicious).toBe(true);
    }
  });

  it('without a MAL- record for the name, the option makes the check unchecked (fail open), never clean', async () => {
    const w = tagWorld();
    delete w.osv[`npm@${TAGPKG}@0.9.0`];
    delete w.osv[`npm@${TAGPKG}@2.0.0-beta.1`];
    const out = await vet(w, j('npm', 'install', TAGPKG, '--tag', 'beta'));
    expect(out!.malicious).toBe(false);
    expect(out!.audit[0].status).toBe('unchecked');
    expect(out!.reasons).toEqual(['unchecked: the install chooses its version with --tag, which this check does not follow, so the version it would fetch could not be confirmed']);
  });

  it('control: an explicit dist-tag spec (pkg@beta, no option) resolves the tag and is blocked as known malicious', async () => {
    const out = await vet(tagWorld(), j('npm', 'install', `${TAGPKG}@beta`));
    expect(out!.malicious).toBe(true);
    expect(out!.reasons.join(' ')).toContain(`${TAGPKG}@2.0.0-beta.1 as known malicious`);
  });

  it('control: an exact pin is exact whatever the option, so the clean pinned version passes', async () => {
    const out = await vet(tagWorld(), j('npm', 'install', `${TAGPKG}@1.0.0`, '--tag', 'beta'));
    expect(out!.malicious).toBe(false);
    expect(out!.audit[0]).toMatchObject({ status: 'checked', version: '1.0.0' });
  });

  it('control: the same command without the option still vets latest (clean) and is not blocked', async () => {
    const out = await vet(tagWorld(), j('npm', 'install', TAGPKG));
    expect(out!.malicious).toBe(false);
    expect(out!.audit[0]).toMatchObject({ status: 'checked', version: '1.0.0' });
  });

  it('a cached MAL- hit still blocks offline for a ref carrying the option', async () => {
    const w = tagWorld();
    await vet(w, j('npm', 'install', `${TAGPKG}@2.0.0-beta.1`)); // caches the MAL- hit
    const out = await vetToolCall('Bash', { command: j('npm', 'install', TAGPKG, '--tag', 'beta') }, { fetchImpl: offline, nowMs: NOW + 3_600_000, stateDir });
    expect(out!.malicious).toBe(true);
  });

  it('pip --pre: the pre-release pip would pick is not hidden behind the clean final release', async () => {
    const w = fixtureWorld();
    w.pypi['pre-lib'] = { latest: '1.0.0', releases: { '1.0.0': [{ packagetype: 'bdist_wheel', upload_time_iso_8601: hoursAgo(24 * 300) }], '2.0.0rc1': [{ packagetype: 'bdist_wheel', upload_time_iso_8601: hoursAgo(24 * 3) }] } };
    w.osv['PyPI@pre-lib@2.0.0rc1'] = ['MAL-2026-90004'];
    const out = await vet(w, j('pip', 'install', '--pre', 'pre-lib'));
    expect(out!.malicious).toBe(true);
    const control = await vet(w, j('pip', 'install', 'pre-lib'));
    expect(control!.malicious).toBe(false);
  });

  it('a public ref and the same ref with an option are separate installs (not deduplicated)', async () => {
    const out = await vet(tagWorld(), j('npm', 'install', TAGPKG, ';', 'npm', 'install', TAGPKG, '--tag', 'beta'));
    expect(out!.audit).toHaveLength(2);
    expect(out!.malicious).toBe(true);
  });
});

// Same review, same class: runner forms (`npx`, `bunx`, `pnpm dlx`, `yarn dlx`,
// `uvx`, `uv tool run`, `pipx run`) read their own options only up to the
// command (npm's npx-cli.js inserts `--` before the first positional). Reading
// later words as installer options vetted the wrong package or skipped the
// malicious-package check entirely.
describe('release review B1 — runner forms stop reading installer options at the command', () => {
  it('words after the command are the command\'s arguments, not -p / --registry / --tag', () => {
    expect(parseInstallCommands(j('npx', 'evil-pkg', '-p', 'clean-pkg')).map(tuple)).toEqual([['npm', 'evil-pkg', null]]);
    expect(parseInstallCommands(j('npx', 'evil-pkg', '--package=clean-pkg')).map(tuple)).toEqual([['npm', 'evil-pkg', null]]);
    const [reg] = parseInstallCommands(j('npx', 'evil-pkg', '--registry=https://private.example'));
    expect(reg.customIndex).toBeUndefined();
    const [tag] = parseInstallCommands(j('npx', 'evil-pkg', '--tag', 'next'));
    expect(tag.versionOption).toBeUndefined();
    expect(parseInstallCommands(j('bunx', 'evil-pkg', '-p', 'clean-pkg')).map(tuple)).toEqual([['npm', 'evil-pkg', null]]);
    expect(parseInstallCommands(j('pnpm', 'dlx', 'evil-pkg', '-p', 'clean-pkg')).map(tuple)).toEqual([['npm', 'evil-pkg', null]]);
    expect(parseInstallCommands(j('uvx', 'evil-tool', '--from', 'clean-pkg')).map(tuple)).toEqual([['PyPI', 'evil-tool', null]]);
    expect(parseInstallCommands(j('pipx', 'run', 'evil-tool', '--spec', 'clean-pkg')).map(tuple)).toEqual([['PyPI', 'evil-tool', null]]);
  });

  it('uv\'s -p (python) takes a value, so the package after it is the one vetted', () => {
    expect(parseInstallCommands(j('uvx', '-p', '3.11', 'evil-tool')).map(tuple)).toEqual([['PyPI', 'evil-tool', null]]);
  });

  it('controls: options BEFORE the command still apply, and npm exec reads them anywhere before --', () => {
    expect(parseInstallCommands(j('npx', '-p', 'clean-pkg', 'run-it')).map(tuple)).toEqual([['npm', 'clean-pkg', null]]);
    const [reg] = parseInstallCommands(j('npx', '--registry=https://private.example', 'some-pkg'));
    expect(reg.customIndex).toBe(true);
    expect(parseInstallCommands(j('npm', 'exec', 'run-it', '--package=clean-pkg')).map(tuple)).toEqual([['npm', 'clean-pkg', null]]);
    // For npm itself (not npx) `-p` is `--parseable`: npm exec then installs the command it runs.
    expect(parseInstallCommands(j('npm', 'exec', 'run-it', '-p', 'clean-pkg')).map(tuple)).toEqual([['npm', 'run-it', null]]);
    expect(parseInstallCommands(j('uvx', '--from', 'some-pkg==2.0', 'cmd')).map(tuple)).toEqual([['PyPI', 'some-pkg', '==2.0']]);
  });

  it('end to end: npx <malicious> --registry=<x> is still checked and blocked', async () => {
    const out = await vetToolCall('Bash', { command: j('npx', `${MAL_NAME}@1.0.3`, '--registry=https://private.example') }, opts(fixtureWorld()));
    expect(out!.malicious).toBe(true);
  });
});

// Release review round 2 (v5.20.0, Astra B1): flags were matched by exact
// string, but npm reads its command line with nopt over its own option table:
// `--enjoy-by` is an alias of `--before`, `-e` abbreviates that alias, and any
// unique prefix (`--bef`, `--befor`) names the option. Those spellings were
// neither marked as selecting the version nor consumed as value flags, so the
// clean `latest` answer discarded the name-only MAL- hit for the version npm
// selects, and `npm --enjoy-by D install pkg` produced no ref at all. npm is now
// read the way npm 10 reads it (checked against npm's own parser during the
// fix), and an option the check does not recognise, for any installer, leaves
// the version unconfirmed. Fixture as above: npm 10.9 picks 0.9.0 (malicious)
// for `--before 2020-06-01`, 2.0.0-beta.1 (malicious) for `--tag beta`, latest
// (1.0.0) is clean.
describe('release review round 2 B1 — installer option aliases, abbreviations and unknown options', () => {
  const PKG = 'synth-tagpkg';
  const MAL = 'MAL-2026-90003';
  const UNCONFIRMED = /OSV lists a malicious release of synth-tagpkg \(MAL-2026-90003\); the version this install would fetch could not be checked, so it is blocked until you pin a version/;
  const tagWorld = (): World => {
    const w = fixtureWorld();
    w.npm[PKG] = {
      tags: { latest: '1.0.0', beta: '2.0.0-beta.1' },
      versions: { '0.9.0': { time: '2019-01-01T00:00:00Z' }, '1.0.0': { time: '2021-01-01T00:00:00Z' }, '2.0.0-beta.1': { time: hoursAgo(24 * 30) } },
    };
    w.osv[`npm@${PKG}@0.9.0`] = [MAL];
    w.osv[`npm@${PKG}@2.0.0-beta.1`] = [MAL];
    return w;
  };
  const vet = (w: World, command: string) => vetToolCall('Bash', { command }, opts(w));
  const exactQueries = (w: World) => w.calls.filter((c) => c === 'POST https://api.osv.dev/v1/query');

  it('the reviewer\'s npm spellings select --before (after the package, inline, before the verb)', () => {
    const cases = [
      j('npm', 'install', PKG, '--enjoy-by=2020-06-01'),
      j('npm', 'install', PKG, '--enjoy-by', '2020-06-01'),
      j('npm', 'install', PKG, '--bef=2020-06-01'),
      j('npm', 'install', PKG, '--bef', '2020-06-01'),
      j('npm', 'install', PKG, '--befor=2020-06-01'),
      j('npm', 'install', PKG, '--enjoy=2020-06-01'),
      j('npm', 'install', PKG, '-e', '2020-06-01'),
      j('npm', '--enjoy-by', '2020-06-01', 'install', PKG),
      j('npm', '--bef', '2020-06-01', 'i', PKG),
      j('npm', '--enjoy-by=2020-06-01', 'add', PKG),
      j('npx', '--enjoy-by', '2020-06-01', PKG),
      j('npx', '--bef=2020-06-01', '-y', PKG),
      j('npm', 'exec', '--bef', '2020-06-01', '--', PKG),
    ];
    for (const command of cases) {
      const refs = parseInstallCommands(command);
      expect({ command, refs: refs.map((r) => [r.name, r.versionOption]) }).toEqual({ command, refs: [[PKG, '--before']] });
    }
  });

  it('controls: literal --tag / --before still mark; an exact pin and a plain install do not', () => {
    expect(parseInstallCommands(j('npm', 'install', PKG, '--tag', 'beta'))[0].versionOption).toBe('--tag');
    expect(parseInstallCommands(j('npm', 'install', PKG, '--before=2020-06-01'))[0].versionOption).toBe('--before');
    expect(parseInstallCommands(j('npm', 'install', PKG))[0].versionOption).toBeUndefined();
    // Recognised everyday options are not "unrecognised".
    expect(parseInstallCommands(j('npm', 'install', '-D', '--save-exact', '--legacy-peer-deps', '--no-audit', '--no-fund', '-g', PKG))[0].versionOption).toBeUndefined();
    expect(parseInstallCommands(j('npm', 'i', '--prefer-offline', '--loglevel', 'error', '--omit=dev', PKG)).map((r) => [r.name, r.versionOption])).toEqual([[PKG, undefined]]);
    expect(parseInstallCommands(j('npx', '-y', PKG, '--bef', '2020-06-01'))[0].versionOption).toBeUndefined(); // the command's own argument
  });

  it('end to end: --enjoy-by= / --bef= / pre-verb --enjoy-by block as unconfirmed and never ask OSV about latest', async () => {
    for (const command of [
      j('npm', 'install', PKG, '--enjoy-by=2020-06-01'),
      j('npm', 'install', PKG, '--bef=2020-06-01'),
      j('npm', '--enjoy-by', '2020-06-01', 'install', PKG),
    ]) {
      const w = tagWorld();
      const out = await vet(w, command);
      expect(out!.malicious).toBe(true);
      expect(out!.reasons.join(' ')).toMatch(UNCONFIRMED);
      expect(out!.audit[0].version).toBeUndefined();
      expect(exactQueries(w)).toEqual([]);
    }
  });

  it('end to end controls: --tag / --before block the same way; no option vets latest (clean)', async () => {
    for (const command of [j('npm', 'install', PKG, '--tag', 'beta'), j('npm', 'install', PKG, '--before', '2020-06-01')]) {
      const out = await vet(tagWorld(), command);
      expect(out!.malicious).toBe(true);
      expect(out!.reasons.join(' ')).toMatch(UNCONFIRMED);
    }
    const plain = await vet(tagWorld(), j('npm', 'install', PKG));
    expect(plain!.malicious).toBe(false);
    expect(plain!.audit[0]).toMatchObject({ status: 'checked', version: '1.0.0' });
  });

  it('an option npm does not define leaves the version unconfirmed (never exact-clean), wherever it is', async () => {
    for (const command of [
      j('npm', 'install', PKG, '--min-release-age=3'),
      j('npm', 'install', '--min-release-age', '3', PKG),
      j('npm', '--min-release-age', '3', 'install', PKG), // a newer npm might read 3 as its value
      j('npm', 'install', PKG, '--ta=beta'), // ambiguous prefix: npm 10 does not read it as --tag, but it is not clean either
    ]) {
      const refs = parseInstallCommands(command);
      expect(refs.find((r) => r.name === PKG)?.versionOption).toBe(UNRECOGNISED_OPTION);
      const w = tagWorld();
      const out = await vet(w, command);
      expect(out!.malicious).toBe(true);
      expect(out!.reasons.join(' ')).toMatch(UNCONFIRMED);
    }
    // Without a MAL- record for the name it is unchecked (fail open), with a fixed reason.
    const w = tagWorld();
    delete w.osv[`npm@${PKG}@0.9.0`];
    delete w.osv[`npm@${PKG}@2.0.0-beta.1`];
    const out = await vet(w, j('npm', 'install', PKG, '--min-release-age=3'));
    expect(out!.malicious).toBe(false);
    expect(out!.audit[0].status).toBe('unchecked');
    expect(out!.reasons).toEqual([`unchecked: the install has ${UNRECOGNISED_OPTION}, which may choose the version it fetches, so that version could not be confirmed`]);
    // An exact pin is exact whatever the options.
    const pinned = await vet(tagWorld(), j('npm', 'install', `${PKG}@1.0.0`, '--min-release-age=3'));
    expect(pinned!.audit[0]).toMatchObject({ status: 'checked', version: '1.0.0' });
  });

  it('npm commands resolve by npm\'s own aliases and prefixes', () => {
    for (const verb of ['install', 'i', 'add', 'isnta', 'isntal', 'insta', 'it', 'install-test', 'installTest']) {
      expect({ verb, refs: parseInstallCommands(j('npm', verb, PKG)).map((r) => r.name) }).toEqual({ verb, refs: [PKG] });
    }
    expect(parseInstallCommands(j('npm', 'exe', PKG)).map((r) => r.name)).toEqual([PKG]);
    // Not installs: ci takes no packages, uninstall removes, ambiguous prefixes are not commands.
    for (const verb of ['ci', 'uninstall', 'un', 'in-x', 'ex']) expect(parseInstallCommands(j('npm', verb, PKG))).toEqual([]);
  });

  it('pnpm / yarn / bun read npm aliases and prefixes conservatively; their own options are recognised', () => {
    expect(parseInstallCommands(j('pnpm', 'add', PKG, '--bef', '2020-06-01')).find((r) => r.name === PKG)?.versionOption).toBe('--before');
    expect(parseInstallCommands(j('pnpm', '--enjoy-by', '2020-06-01', 'add', PKG)).map((r) => [r.name, r.versionOption])).toEqual([[PKG, '--before']]);
    expect(parseInstallCommands(j('bun', 'add', '--minimum-release-age', '3', PKG)).find((r) => r.name === PKG)?.versionOption).toBe(UNRECOGNISED_OPTION);
    for (const command of [j('pnpm', 'add', '-D', '--save-exact', PKG), j('yarn', 'add', '--dev', '--exact', PKG), j('bun', 'add', '-d', PKG), j('pnpm', 'add', '-w', PKG), j('pnpm', 'add', '--workspace', PKG), j('pnpm', 'add', '--reporter', 'silent', PKG)]) {
      expect({ command, refs: parseInstallCommands(command).map((r) => [r.name, r.versionOption]) }).toEqual({ command, refs: [[PKG, undefined]] });
    }
  });

  it('Python installers: unrecognised options (pip prefixes, uv --exclude-newer-package) are never resolved as if absent', () => {
    expect(parseInstallCommands(j('pip', 'install', '--prefer', 'some-pkg'))[0].versionOption).toBe(UNRECOGNISED_OPTION); // pip: unique prefix of --prefer-binary
    expect(parseInstallCommands(j('pip', 'install', '--only-b', ':all:', 'some-pkg')).find((r) => r.name === 'some-pkg')?.versionOption).toBe(UNRECOGNISED_OPTION);
    expect(parseInstallCommands(j('uv', 'pip', 'install', '--exclude-newer-package', 'some-pkg=2020-01-01', 'some-pkg')).map((r) => [r.name, r.versionOption])).toEqual([['some-pkg', '--exclude-newer-package']]);
    expect(parseInstallCommands(j('pip', 'install', '--python-version', '3.8', 'some-pkg')).map((r) => [r.name, r.versionOption])).toEqual([['some-pkg', '--python-version']]);
    expect(parseInstallCommands(j('pipx', 'install', '--pip-args=--pre', 'some-tool')).map((r) => [r.name, r.versionOption])).toEqual([['some-tool', '--pip-args']]);
    // Controls: everyday options are recognised; short clusters too.
    for (const command of [j('pip', 'install', '-U', '--user', '--no-deps', 'some-pkg'), j('pip', 'install', '-qU', 'some-pkg'), j('uv', 'pip', 'install', '--system', 'some-pkg'), j('uv', 'add', '--dev', 'some-pkg'), j('pipx', 'install', '-f', 'some-tool')]) {
      expect({ command, refs: parseInstallCommands(command).map((r) => r.versionOption) }).toEqual({ command, refs: [undefined] });
    }
    // pipx -f is --force, not pip's --find-links: the package after it is vetted, on the public index.
    expect(parseInstallCommands(j('pipx', 'install', '-f', 'some-tool'))[0].customIndex).toBeUndefined();
  });

  it('variables exported earlier in the command apply to later installs (review nits N1, N2)', () => {
    expect(parseInstallCommands(j('export', 'NPM_CONFIG_TAG=beta;', 'npm', 'i', PKG))[0].versionOption).toBe('npm_config_tag');
    expect(parseInstallCommands(j('export', 'PIP_PRE=1', '&&', 'pip', 'install', 'some-pkg'))[0].versionOption).toBe('pip_pre');
    expect(parseInstallCommands(j('export', 'UV_PRERELEASE=allow;', 'uvx', 'some-tool'))[0].versionOption).toBe('uv_prerelease');
    expect(parseInstallCommands(j('export', 'npm_config_registry=https://private.example;', 'npm', 'i', PKG))[0].customIndex).toBe(true);
    expect(parseInstallCommands(j('npm_config_include-staged=true', 'npm', 'i', PKG))[0].versionOption).toBe('npm_config_include-staged');
    // Controls: an unrelated export, and an export after the install, change nothing.
    expect(parseInstallCommands(j('export', 'FOO=1;', 'npm', 'i', PKG))[0].versionOption).toBeUndefined();
    expect(parseInstallCommands(j('npm', 'i', PKG, ';', 'export', 'NPM_CONFIG_TAG=beta'))[0].versionOption).toBeUndefined();
  });
});

// Release review (v5.20.0, Astra B2): an HTTP-200 OSV answer that is not in the
// documented shape (JSON null, an array, an error body, a non-array `vulns`, a
// malformed entry, …) was read as `{ vulns: [] }`: a clean version-specific
// answer that was final for the version, evicted the cached MAL- hit and
// overrode a valid malicious batch answer. It is now unavailable/unchecked.
// Legitimate `{}` / `{ vulns: [] }` stay clean.
describe('release review B2 — malformed OSV answers are never clean', () => {
  const NAME = 'synth-cachedpkg';
  const VER = '1.2.3';
  const MAL = 'MAL-2026-90002';
  const KEY = `npm@${NAME}@${VER}`;
  const cacheFile = () => path.join(stateDir, 'package-vetting-cache.json');
  const seed = () => fs.writeFileSync(cacheFile(), JSON.stringify({ v: 1, entries: { [KEY]: { at: NOW - 3_600_000, ecosystem: 'npm', name: NAME, version: VER, osvIds: [MAL], hooks: [], sdistOnly: false } } }));
  const cacheKeys = () => Object.keys(JSON.parse(fs.readFileSync(cacheFile(), 'utf-8')).entries);
  type Shape = { body?: unknown; status?: number; badJson?: boolean; throws?: boolean };
  const reply = (r: Shape) => {
    if (r.throws) throw Object.assign(new Error('reset'), { code: 'ECONNRESET' });
    const status = r.status ?? 200;
    return { ok: status < 400, status, json: async () => { if (r.badJson) throw new SyntaxError('Unexpected token'); return structuredClone(r.body); } };
  };
  const mkFetch = (query: Shape, batch: (n: number) => Shape): FetchLike => {
    const w = world({ npm: { [NAME]: { versions: { [VER]: { time: hoursAgo(24 * 400) } } } } });
    const inner = fetchFor(w);
    return async (url, init) => {
      if (url === 'https://api.osv.dev/v1/query') return reply(query);
      if (url === 'https://api.osv.dev/v1/querybatch') return reply(batch(JSON.parse(init!.body!).queries.length));
      return inner(url, init);
    };
  };
  const vet = (f: FetchLike) => vetPackages([npmRef(NAME, VER)], { fetchImpl: f, nowMs: NOW, stateDir });
  const each = (n: number, r: unknown) => Array.from({ length: n }, () => r);
  const batchClean = (n: number): Shape => ({ body: { results: each(n, {}) } });
  const batchMal = (n: number): Shape => ({ body: { results: each(n, { vulns: [{ id: MAL, modified: '2026-11-05T00:00:00Z' }] }) } });

  const MALFORMED: Array<[string, unknown]> = [
    ['JSON null', null],
    ['an array', []],
    ['an error body', { error: 'internal', code: 13 }],
    ['a gRPC-style error', { code: 13, message: 'internal', details: [] }],
    ['vulns: null', { vulns: null }],
    ['vulns as a string', { vulns: MAL }],
    ['vulns as an object', { vulns: {} }],
    ['a null entry', { vulns: [null] }],
    ['an entry with a numeric id', { vulns: [{ id: 123 }] }],
    ['an entry with no id', { vulns: [{ modified: '2026-11-05T00:00:00Z' }] }],
    ['an entry with non-array aliases', { vulns: [{ id: 'GHSA-aaaa-bbbb-cccc', aliases: MAL }] }],
    ['a string', 'oops'],
    ['a number', 42],
    ['more pages to fetch', { vulns: [], next_page_token: 'abc' }],
  ];

  it.each(MALFORMED)('exact query answering %s: unchecked, the cached MAL- hit is kept and still blocks', async (_label, body) => {
    seed();
    const res = await vet(mkFetch({ body }, batchClean));
    expect(res.malicious).toBe(true);
    expect(res.packages[0].cached).toBe(true);
    expect(cacheKeys()).toEqual([KEY]);
  });

  it.each(MALFORMED)('exact query answering %s with no cache: unchecked (fail open), never checked-clean', async (_label, body) => {
    const res = await vet(mkFetch({ body }, batchClean));
    expect(res.malicious).toBe(false);
    expect(res.packages[0].status).toBe('unchecked');
    expect(res.reasons).toEqual(['unchecked: OSV answer was not in the expected shape']);
  });

  it.each(MALFORMED.filter(([, b]) => b !== null && typeof b === 'object' && !Array.isArray(b)))(
    'exact query answering %s cannot override a valid version-specific MAL- batch answer', async (_label, body) => {
      const res = await vet(mkFetch({ body }, batchMal));
      expect(res.malicious).toBe(true);
      expect(res.reasons[0]).toBe(`OSV lists ${NAME} as known malicious (${MAL})`);
      expect(cacheKeys()).toEqual([KEY]); // and the hit is remembered for the offline block
    });

  const BATCH_MALFORMED: Array<[string, (n: number) => Shape]> = [
    ['results: [null]', (n) => ({ body: { results: each(n, null) } })],
    ['results: [[]]', (n) => ({ body: { results: each(n, []) } })],
    ['results: ["x"]', (n) => ({ body: { results: each(n, 'x') } })],
    ['results: [{ vulns: null }]', (n) => ({ body: { results: each(n, { vulns: null }) } })],
    ['results: [{ vulns: "x" }]', (n) => ({ body: { results: each(n, { vulns: 'x' }) } })],
    ['results: [{ error }]', (n) => ({ body: { results: each(n, { error: 'x' }) } })],
    ['results: [{ vulns: [{ id: 1 }] }]', (n) => ({ body: { results: each(n, { vulns: [{ id: 1 }] }) } })],
    ['results: null', () => ({ body: { results: null } })],
    ['JSON null', () => ({ body: null })],
    ['{}', () => ({ body: {} })],
    ['an error body beside results', (n) => ({ body: { error: 'x', results: each(n, {}) } })],
  ];

  it.each(BATCH_MALFORMED)('both endpoints malformed (batch %s): the cached MAL- hit is kept and still blocks', async (_label, batch) => {
    seed();
    const res = await vet(mkFetch({ body: { vulns: null } }, batch));
    expect(res.malicious).toBe(true);
    expect(res.packages[0].cached).toBe(true);
    expect(cacheKeys()).toEqual([KEY]);
  });

  it.each(BATCH_MALFORMED)('batch %s with the exact query down: reported as the malicious-package check unavailable', async (_label, batch) => {
    const res = await vet(mkFetch({ throws: true }, batch));
    expect(res.malicious).toBe(false);
    expect(res.reasons[0]).toMatch(/and the malicious-package check was unavailable$/);
  });

  it('a ninth (batch-only) package whose batch result is malformed is unavailable, never clean', async () => {
    const decoys = ['a1', 'b2', 'c3', 'd4', 'e5', 'f6', 'g7', 'h8'].map((d) => npmRef(d, '1.0.0'));
    const w = fixtureWorld();
    const inner = fetchFor(w);
    const f: FetchLike = async (url, init) => {
      if (url !== 'https://api.osv.dev/v1/querybatch') return inner(url, init);
      const n = JSON.parse(init!.body!).queries.length;
      return { ok: true, status: 200, json: async () => ({ results: [...each(n - 1, {}), { vulns: null }] }) };
    };
    const res = await vetPackages([...decoys, npmRef('ninth-lib', '1.0.0')], { fetchImpl: f, nowMs: NOW, stateDir });
    const ninth = res.packages.find((p) => p.ref.name === 'ninth-lib')!;
    expect(ninth.findings[0].reason).toMatch(/and the malicious-package check was unavailable$/);
  });

  it('a malformed result beside a valid MAL- result in the same chunk does not hide that MAL- (per-query, not per-chunk)', async () => {
    const decoys = ['a1', 'b2', 'c3', 'd4', 'e5', 'f6', 'g7', 'h8'].map((d) => npmRef(d, '1.0.0'));
    const w = fixtureWorld();
    const inner = fetchFor(w);
    const f: FetchLike = async (url, init) => {
      if (url !== 'https://api.osv.dev/v1/querybatch') return inner(url, init);
      const n = JSON.parse(init!.body!).queries.length;
      return { ok: true, status: 200, json: async () => ({ results: [{ vulns: null }, ...each(n - 2, {}), { vulns: [{ id: MAL }] }] }) };
    };
    const res = await vetPackages([...decoys, npmRef('ninth-lib', '1.0.0')], { fetchImpl: f, nowMs: NOW, stateDir });
    expect(res.malicious).toBe(true);
    expect(res.packages.find((p) => p.ref.name === 'ninth-lib')!.malicious).toEqual([MAL]);
  });

  it('a malformed exact answer that still names a MAL- id in a well-formed entry is malicious', async () => {
    const res = await vet(mkFetch({ body: { vulns: [{ id: MAL }, null] } }, batchClean));
    expect(res.malicious).toBe(true);
    expect(res.reasons[0]).toContain('as known malicious');
  });

  it('controls: legitimate {} and { vulns: [] } are clean and evict a stale cached hit (as before)', async () => {
    for (const body of [{}, { vulns: [] }]) {
      seed();
      const res = await vet(mkFetch({ body }, batchClean));
      expect(res.malicious).toBe(false);
      expect(res.packages[0].status).toBe('checked');
      expect(cacheKeys()).toEqual([]);
    }
  });

  it('controls: invalid JSON, a network error and HTTP 500 keep the cached hit (as before)', async () => {
    for (const query of [{ badJson: true }, { throws: true }, { status: 500, body: {} }] as Shape[]) {
      seed();
      const res = await vet(mkFetch(query, batchClean));
      expect(res.malicious).toBe(true);
      expect(res.packages[0].cached).toBe(true);
      expect(cacheKeys()).toEqual([KEY]);
    }
  });
});

// Release review (v5.20.0) nits. Astra N1: a NAMED remote spec
// (`name@git+https://…`, `name@https://…`) was looked up by name although the
// docs say URL/git installs are skipped. Astra N2: an MCP server entry's `env`
// (a custom registry/index, or a version-selection variable) was ignored.
describe('release review nits — named remote specs and MCP entry env', () => {
  it('a named URL, git, github or file spec names nothing to look up', () => {
    for (const spec of [
      'synth-gitpkg@git+https://example.invalid/r.git', '@synthscope/synth-gitpkg@git+https://example.invalid/r.git',
      'synth-urlpkg@https://example.invalid/pkg/download', '@synthscope/synth-urlpkg@https://example.invalid/x',
      'synth-gitpkg@github:synthuser/synthrepo', '@synthscope/synth-gitpkg@github:synthuser/synthrepo',
      'synth-gitpkg@synthuser/synthrepo', 'synth-filepkg@file:../local',
    ]) {
      expect(parseInstallCommands(j('npm', 'install', spec))).toEqual([]);
    }
    // controls: registry specs keep working, including a tilde range and an npm alias
    expect(parseInstallCommands(j('npm', 'install', 'some-pkg@~1.2.3', '@scope/pkg@next', 'x@npm:real-pkg@1.0.0')).map(tuple))
      .toEqual([['npm', 'some-pkg', '~1.2.3'], ['npm', '@scope/pkg', 'next'], ['npm', 'real-pkg', '1.0.0']]);
  });

  it('an MCP entry env that sets a custom registry/index makes the package unchecked, with no lookups', async () => {
    expect(parseMcpServerEntry({ command: 'npx', args: ['-y', 'some-mcp'], env: { npm_config_registry: 'https://npm.internal.example' } })[0].customIndex).toBe(true);
    expect(parseMcpServerEntry({ command: 'uvx', args: ['some-tool'], env: { UV_INDEX_URL: 'https://pypi.internal.example/simple' } })[0].customIndex).toBe(true);
    const w = fixtureWorld();
    const out = await vetMcpServers([{ name: 'internal', entry: { command: 'npx', args: ['-y', 'clean-lib'], env: { NPM_CONFIG_REGISTRY: 'https://npm.internal.example' } } }], opts(w));
    expect(out).toEqual([{ name: 'internal', malicious: false, reasons: [expect.stringMatching(/^unchecked: installs from a custom package index/)] }]);
    expect(w.calls).toEqual([]);
  });

  it('an MCP entry env that sets a version-selection variable is carried; unrelated env (secrets included) is ignored', () => {
    expect(parseMcpServerEntry({ command: 'npx', args: ['-y', 'some-mcp'], env: { npm_config_tag: 'beta' } })[0].versionOption).toBe('npm_config_tag');
    const [plain] = parseMcpServerEntry({ command: 'npx', args: ['-y', 'some-mcp'], env: { API_TOKEN: "x' ; npm i other-pkg '", HOME: '/tmp' } });
    expect(plain).toMatchObject({ name: 'some-mcp' });
    expect(plain.customIndex).toBeUndefined();
    expect(plain.versionOption).toBeUndefined();
    expect(parseMcpServerEntry({ command: 'npx', args: ['-y', 'some-mcp'], env: { API_TOKEN: "x' ; npm i other-pkg '" } })).toHaveLength(1);
  });
});
