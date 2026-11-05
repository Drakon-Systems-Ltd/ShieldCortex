import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

/**
 * #889 phase 1 — the Claude Code hook surface of pre-install package vetting.
 *
 * The REAL built hook and the REAL built vetting module run in a child
 * process; the only substitute is `globalThis.fetch`, replaced by a preloaded
 * stub that serves recorded-shape registry/OSV answers (no live network). The
 * one real identifier is MAL-2026-18603. Nothing is installed: the hook only
 * reads the command and answers allow/ask/deny.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HOOK_PATH = path.resolve(__dirname, '..', '..', 'scripts', 'pre-tool-hook.mjs');

const STUB = `
const hoursAgo = (h) => new Date(Date.now() - h * 3600000).toISOString();
const npm = {
  '@ifasn/ms-doc-mcp': { latest: '1.0.3', versions: { '1.0.3': { time: hoursAgo(24 * 40) } } },
  'fresh-lib': { latest: '3.5.0', versions: { '3.5.0': { time: hoursAgo(11) } } },
  'clean-lib': { latest: '4.2.1', versions: { '4.2.1': { time: hoursAgo(24 * 400) } } },
};
const osv = { 'npm@@ifasn/ms-doc-mcp@1.0.3': ['MAL-2026-18603'] };
const pypi = { 'fresh-py': { latest: '1.0.0', files: [{ packagetype: 'bdist_wheel', upload_time_iso_8601: hoursAgo(5) }] } };
const res = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
globalThis.fetch = async (url, init) => {
  if (process.env.SC889_OFFLINE === '1') throw Object.assign(new Error('offline'), { code: 'ENOTFOUND' });
  if (url === 'https://api.osv.dev/v1/query') {
    const q = JSON.parse(init.body);
    const ids = osv[q.package.ecosystem + '@' + q.package.name + '@' + q.version] || [];
    return res(ids.length ? { vulns: ids.map((id) => ({ id })) } : {});
  }
  const m = /^https:\\/\\/registry\\.npmjs\\.org\\/(.+)$/.exec(url);
  if (m) {
    const name = decodeURIComponent(m[1]);
    const p = npm[name];
    if (!p) return res({}, 404);
    return res({ 'dist-tags': { latest: p.latest }, versions: Object.fromEntries(Object.keys(p.versions).map((v) => [v, { name, version: v }])), time: Object.fromEntries(Object.entries(p.versions).map(([v, x]) => [v, x.time])) });
  }
  const py = /^https:\\/\\/pypi\\.org\\/pypi\\/([^/]+)\\/json$/.exec(url);
  if (py && pypi[py[1]]) { const p = pypi[py[1]]; return res({ info: { version: p.latest }, urls: p.files, releases: { [p.latest]: p.files } }); }
  return res({}, 404);
};
`;

type HookResult = { stdout: string; stderr: string; code: number };

describe('pre-tool hook — #889 package vetting', () => {
  const originalHome = process.env.HOME;
  const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
  let tempHome: string;
  let stubPath: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-889-'));
    process.env.HOME = tempHome;
    process.env.SHIELDCORTEX_CONFIG_DIR = path.join(tempHome, '.shieldcortex');
    stubPath = path.join(tempHome, 'fetch-stub.mjs');
    fs.writeFileSync(stubPath, STUB);
  });
  afterEach(() => {
    process.env.HOME = originalHome;
    if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  const writeConfig = (actionGuard: Record<string, unknown>) => {
    const dir = path.join(tempHome, '.shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ actionGuard }));
  };

  function runHook(command: string, env: Record<string, string> = {}): Promise<HookResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--import', stubPath, HOOK_PATH], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, ...env },
      });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (c) => { stdout += c.toString(); });
      child.stderr.on('data', (c) => { stderr += c.toString(); });
      child.on('error', reject);
      child.on('close', (code) => resolve({ stdout, stderr, code: code ?? 0 }));
      child.stdin.write(JSON.stringify({
        session_id: 'sc889', cwd: '/tmp', permission_mode: 'default', hook_event_name: 'PreToolUse',
        tool_name: 'Bash', tool_input: { command },
      }));
      child.stdin.end();
    });
  }

  const decisionOf = (r: HookResult) => {
    const line = r.stdout.trim().split('\n').filter(Boolean).pop();
    return line ? JSON.parse(line).hookSpecificOutput as { permissionDecision: string; permissionDecisionReason: string } : null;
  };
  const auditRows = () => {
    const dir = path.join(tempHome, '.shieldcortex', 'audit');
    if (!fs.existsSync(dir)) return [] as Array<Record<string, any>>;
    return fs.readdirSync(dir).filter((f) => f.startsWith('realtime-')).flatMap((f) => fs.readFileSync(path.join(dir, f), 'utf-8').split('\n').filter(Boolean).map((l) => JSON.parse(l)));
  };
  const install = (pkg: string) => ['npm', 'install', pkg].join(' ');

  it('blocks a known-malicious package even in advisory mode (enforce:false), and records why', async () => {
    writeConfig({ enabled: true, enforce: false });
    const r = await runHook(install('@ifasn/ms-doc-mcp@1.0.3'));
    const d = decisionOf(r);
    expect(d?.permissionDecision).toBe('deny');
    expect(d?.permissionDecisionReason).toContain('MAL-2026-18603');
    const row = auditRows().find((x) => x.outcome === 'auto_denied');
    expect(row).toBeDefined();
    expect(row!.threats).toEqual(expect.arrayContaining(['known-malicious-package', 'package-vetting']));
    expect(row!.packageVetting[0]).toMatchObject({ name: '@ifasn/ms-doc-mcp', version: '1.0.3', kinds: ['malicious'] });
  });

  it('a fresh version in advisory mode is allowed, with the finding on the audit row', async () => {
    writeConfig({ enabled: true, enforce: false });
    const r = await runHook(install('fresh-lib'));
    expect(decisionOf(r)?.permissionDecision ?? 'allow').not.toBe('deny');
    const row = auditRows().find((x) => Array.isArray(x.packageVetting));
    expect(row).toBeDefined();
    expect(row!.packageVetting[0]).toMatchObject({ name: 'fresh-lib', version: '3.5.0', kinds: ['new-version'] });
    expect(row!.packageVetting[0].reasons).toEqual(['published 11 h ago']);
  });

  it('puts the findings on the approval prompt for an install that already asks', async () => {
    writeConfig({ enabled: true, enforce: true });
    const r = await runHook(['pip', 'install', 'fresh-py'].join(' '));
    const d = decisionOf(r);
    expect(d?.permissionDecision).toBe('ask');
    expect(d?.permissionDecisionReason).toContain('Package check: published 5 h ago');
  });

  it('offline: the install is unchecked (named as such), never blocked and never reported clean', async () => {
    writeConfig({ enabled: true, enforce: false });
    const r = await runHook(install('clean-lib'), { SC889_OFFLINE: '1' });
    expect(decisionOf(r)?.permissionDecision ?? 'allow').not.toBe('deny');
    const row = auditRows().find((x) => Array.isArray(x.packageVetting));
    expect(row!.packageVetting[0].status).toBe('unchecked');
    expect(row!.packageVetting[0].reasons[0]).toMatch(/^unchecked: /);
  });

  it('offline after a recorded malicious answer: the cached hit still blocks', async () => {
    writeConfig({ enabled: true, enforce: false });
    await runHook(install('@ifasn/ms-doc-mcp@1.0.3'));
    const r = await runHook(install('@ifasn/ms-doc-mcp@1.0.3'), { SC889_OFFLINE: '1' });
    expect(decisionOf(r)?.permissionDecision).toBe('deny');
    const cache = path.join(tempHome, '.shieldcortex', 'state', 'package-vetting-cache.json');
    expect(fs.statSync(cache).mode & 0o777).toBe(0o600);
  });

  it('packageVetting.enabled:false turns the check off', async () => {
    writeConfig({ enabled: true, enforce: false, packageVetting: { enabled: false } });
    const r = await runHook(install('@ifasn/ms-doc-mcp@1.0.3'));
    expect(decisionOf(r)?.permissionDecision ?? 'allow').not.toBe('deny');
    expect(auditRows().some((x) => Array.isArray(x.packageVetting))).toBe(false);
  });
});
