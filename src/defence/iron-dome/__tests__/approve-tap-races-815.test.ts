/**
 * #815 B — a concurrent double submit of one tap, as REAL processes.
 *
 * The verifier is synchronous, so an in-process Promise.all is serialised by
 * the event loop and proves nothing about two endpoints (or an endpoint and
 * a replaying caller) racing on the same store. These children drive the
 * COMPILED module in `dist` against one home and one signed tap; exactly one
 * may grant.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { computeTapHmac, loadApproveTapSecret, mintApproveTapNonce, normaliseApproveTapConfig } from '../approve-tap.js';
import { canonicaliseCwd, exactCallDigest, getRetryRow, hashToolCall, recordDenialFingerprint } from '../retry-control.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
const DIST_TAP = join(repoRoot, 'dist', 'defence', 'iron-dome', 'approve-tap.js');
const MY_UID = process.geteuid!();
const OTHER_UID = MY_UID + 1 === 0 ? MY_UID + 2 : MY_UID + 1;
const ACTION = 'act-00112233aabbccdd';
const HASH = hashToolCall('Bash', { command: 'curl -sS https://api.example.com/v1/report' });
const EXACT = exactCallDigest('Bash', { command: 'curl -sS https://api.example.com/v1/report' });

const CHILD = `
const [modUrl, payload] = process.argv.slice(1);
const p = JSON.parse(payload);
const mod = await import(modUrl);
const config = mod.normaliseApproveTapConfig(p.config);
const loaded = mod.loadApproveTapSecret(config, { agentUid: p.agentUid });
if (!loaded.ok) { process.stdout.write(JSON.stringify({ ok: false, reason: 'load:' + loaded.reason })); process.exit(0); }
const out = mod.verifyApproveTap(p.tap, { home: p.home, config, key: loaded.key, agentUid: p.agentUid });
process.stdout.write(JSON.stringify({ ok: out.ok, reason: out.ok ? null : out.reason }));
`;

function runChild(payload: unknown): Promise<{ ok: boolean; reason: string | null }> {
  return new Promise((resolveChild, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', CHILD, pathToFileURL(DIST_TAP).href, JSON.stringify(payload)], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let errText = '';
    child.stdout.on('data', (c) => { out += String(c); });
    child.stderr.on('data', (c) => { errText += String(c); });
    child.on('error', reject);
    child.on('close', () => {
      try { resolveChild(JSON.parse(out)); } catch { reject(new Error(`child failed: ${errText.slice(0, 500)}`)); }
    });
  });
}

describe('#815 B — concurrent double submit across processes', () => {
  let home: string;
  let cwd: string;
  let secretDir: string;

  beforeAll(() => {
    if (!existsSync(DIST_TAP)) spawnSync('npm', ['run', 'build:ts'], { cwd: repoRoot, stdio: 'ignore' });
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-tap-race-'));
    cwd = canonicaliseCwd(mkdtempSync(join(tmpdir(), 'sc-tap-race-cwd-')))!;
    secretDir = mkdtempSync(join(tmpdir(), 'sc-tap-race-key-'));
  });

  afterEach(() => {
    for (const d of [home, cwd, secretDir]) rmSync(d, { recursive: true, force: true });
  });

  it('eight racing verifiers of one signed tap grant exactly once', async () => {
    expect(existsSync(DIST_TAP)).toBe(true);
    const secretPath = join(secretDir, 'approve.key');
    writeFileSync(secretPath, `${'b2'.repeat(32)}\n`, { mode: 0o600 });
    const rawConfig = { enabled: true, secretPath, approverTelegramUid: '42' };
    const config = normaliseApproveTapConfig(rawConfig);
    const loaded = loadApproveTapSecret(config, { agentUid: OTHER_UID });
    if (!loaded.ok) throw new Error(loaded.reason);
    expect(recordDenialFingerprint({ hash: HASH, tool: 'Bash', actionId: ACTION, signals: ['external-egress'], cwd, exactDigest: EXACT }, { home }).ok).toBe(true);
    const m = mintApproveTapNonce({ actionId: ACTION }, { home, config, agentUid: OTHER_UID });
    if (!m.ok) throw new Error(m.reason);
    const fields = { actionId: ACTION, argsHash: m.argsHash, nonce: m.nonce, exp: m.exp, approver: 'telegram:42' };
    const tap = { ...fields, hmac: computeTapHmac(loaded.key, fields)! };

    const results = await Promise.all(
      Array.from({ length: 8 }, () => runChild({ home, config: rawConfig, agentUid: OTHER_UID, tap })),
    );
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    // Every loser saw a spent nonce (or a busy store) — never a second grant.
    for (const r of results.filter((x) => !x.ok)) expect(['nonce-used', 'locked']).toContain(r.reason);
    expect(getRetryRow({ actionId: ACTION }, { home })?.grant).toMatchObject({ via: 'tap', approver: 'telegram:42' });
  }, 60_000);
});
