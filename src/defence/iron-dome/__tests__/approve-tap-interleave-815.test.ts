/**
 * #815 B — deterministic interleavings, as REAL processes against `dist`.
 *
 * Each child stops one writer at its temp-file write (the instant between
 * "I hold the lock and have read the store" and "my new state is in place")
 * and runs the competing operation there. The stale-lock cases also age the
 * lock past the takeover threshold first, which is what a holder paused for
 * longer than that looks like to everyone else. The fs interposition needs
 * Node's own ESM builtins (`syncBuiltinESMExports`), hence plain children.
 *
 * Fixture commands are data; nothing here executes them.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
const DIST = join(repoRoot, 'dist', 'defence', 'iron-dome');

const CHILD = `
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
const [distUrl, home, cwd, secretPath, scenario] = process.argv.slice(1);
const tap = await import(distUrl + '/approve-tap.js');
const rc = await import(distUrl + '/retry-control.js');
const key = Buffer.from(fs.readFileSync(secretPath, 'utf8').trim());
const config = tap.normaliseApproveTapConfig({ enabled: true, secretPath, approverTelegramUid: '777' });
const agentUid = process.getuid() + 1;
const actionId = 'act-1122334455667788';
const CALL = { command: 'curl -sS https://api.example.com/v1/report' };
const hash = rc.hashToolCall('Bash', CALL);
const exactDigest = rc.exactCallDigest('Bash', CALL);
const origin = { cwd, tool: 'Bash' };
const opts = { home, config, key, agentUid };
const spend = () => !!rc.consumeRetryGrant({ hash, exactDigest, origin, currentSignals: ['external-egress'] }, { home });

if (!rc.recordDenialFingerprint({ actionId, hash, tool: 'Bash', signals: ['external-egress'], cwd, exactDigest }, { home }).ok) throw new Error('seed');
const grantOnFile = () => rc.getRetryRow({ actionId }, { home })?.grant ?? null;
let signedTap = null;
if (scenario !== 'retry-consume') {
  const m = tap.mintApproveTapNonce({ actionId }, { home, config, agentUid });
  if (!m.ok) throw new Error('mint ' + m.reason);
  const fields = { actionId, argsHash: m.argsHash, nonce: m.nonce, exp: m.exp, approver: 'telegram:777' };
  signedTap = { ...fields, hmac: tap.computeTapHmac(key, fields) };
} else {
  // A live terminal grant for the retry-store case.
  if (!rc.grantRetry({ actionId }, { isInteractive: true }, { home }).ok) throw new Error('tty grant');
}

const approvals = join(home, '.shieldcortex', 'approvals');
const age = (lockName) => { const old = new Date(Date.now() - 20_000); fs.utimesSync(join(approvals, lockName), old, old); };
/** Run \`inner\` once, at the first temp write under \`storePath\`. */
function interpose(storePath, inner, outer) {
  const original = fs.writeFileSync;
  let fired = false;
  fs.writeFileSync = function (p, ...rest) {
    if (!fired && String(p).startsWith(storePath) && String(p).endsWith('.tmp')) { fired = true; inner(); }
    return original.call(fs, p, ...rest);
  };
  syncBuiltinESMExports();
  try { return { fired: () => fired, value: outer() }; }
  finally { fs.writeFileSync = original; syncBuiltinESMExports(); }
}

const out = { scenario };
const nonces = tap.approveTapNoncePath(home);
if (scenario === 'mint-verify') {
  // A mint paused past the stale threshold; meanwhile the tap is verified
  // and its grant spent. The mint resumes and writes its (old) snapshot.
  const r = interpose(nonces, () => {
    age('approve-tap-nonces.lock');
    out.innerApproved = tap.verifyApproveTap(signedTap, opts).ok;
    out.firstSpend = spend();
  }, () => tap.mintApproveTapNonce({ actionId }, { home, config, agentUid }));
  out.fired = r.fired();
  out.lateMint = r.value.ok ? 'ok' : r.value.reason;
  const replay = tap.verifyApproveTap(signedTap, opts);
  out.replay = replay.ok ? 'ok' : replay.reason;
  out.secondSpend = spend();
} else if (scenario === 'verify-verify') {
  // Two verifiers of one signed tap; the first is paused while spending.
  const r = interpose(nonces, () => {
    age('approve-tap-nonces.lock');
    out.innerApproved = tap.verifyApproveTap(signedTap, opts).ok;
    out.firstSpend = spend();
  }, () => tap.verifyApproveTap(signedTap, opts));
  out.fired = r.fired();
  out.outer = r.value.ok ? 'ok' : r.value.reason;
  out.secondSpend = spend();
  const replay = tap.verifyApproveTap(signedTap, opts);
  out.replay = replay.ok ? 'ok' : replay.reason;
} else if (scenario === 'remint-terminal-only') {
  // Between the preview (under the nonce lock) and the grant, a normal
  // remint adds a self-protection signal — same hash, identity and epoch.
  const r = interpose(nonces, () => {
    if (!rc.recordDenialFingerprint({ actionId, hash, tool: 'Bash', signals: ['touch-approval-store'], cwd, exactDigest }, { home }).ok) throw new Error('remint');
  }, () => tap.verifyApproveTap(signedTap, opts));
  out.fired = r.fired();
  out.outer = r.value.ok ? 'ok' : r.value.reason;
  out.grant = grantOnFile();
  out.spent = spend();
  const replay = tap.verifyApproveTap(signedTap, opts);
  out.replay = replay.ok ? 'ok' : replay.reason;
} else if (scenario === 'retry-consume') {
  // The retry store's own lock: a consumer paused past the stale threshold
  // while another consumer takes the lock over and spends the same grant.
  const r = interpose(rc.retryControlPath(home), () => {
    age('retry-control.lock');
    out.innerSpend = spend();
  }, () => spend());
  out.fired = r.fired();
  out.outerSpend = r.value;
  out.thirdSpend = spend();
}
process.stdout.write(JSON.stringify(out));
`;

function run(home: string, cwd: string, secretPath: string, scenario: string): Record<string, unknown> {
  const res = spawnSync(process.execPath, ['--input-type=module', '-e', CHILD, pathToFileURL(DIST).href, home, cwd, secretPath, scenario], {
    encoding: 'utf8', timeout: 60_000, env: { PATH: process.env.PATH ?? '/usr/bin:/bin' },
  });
  if (res.status !== 0) throw new Error(`child failed: ${String(res.stderr).slice(0, 800)}`);
  return JSON.parse(res.stdout) as Record<string, unknown>;
}

describe('#815 B — interleavings across processes', () => {
  let home: string;
  let cwd: string;
  let secretDir: string;
  let secretPath: string;

  beforeAll(() => {
    if (!existsSync(join(DIST, 'approve-tap.js'))) spawnSync('npm', ['run', 'build:ts'], { cwd: repoRoot, stdio: 'ignore' });
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-tap-il-'));
    cwd = mkdtempSync(join(tmpdir(), 'sc-tap-il-cwd-'));
    secretDir = mkdtempSync(join(tmpdir(), 'sc-tap-il-key-'));
    secretPath = join(secretDir, 'approve.key');
    writeFileSync(secretPath, `${'c3'.repeat(32)}\n`, { mode: 0o600 });
  });

  afterEach(() => {
    for (const d of [home, cwd, secretDir]) rmSync(d, { recursive: true, force: true });
  });

  it('a mint whose nonce lock was taken over as stale cannot write back: one spend, replay refused', () => {
    const out = run(home, cwd, secretPath, 'mint-verify');
    expect(out).toMatchObject({ fired: true, innerApproved: true, firstSpend: true, lateMint: 'unwritable', replay: 'nonce-used', secondSpend: false });
  }, 60_000);

  it('two verifiers, the first paused past takeover: exactly one grant and one spend', () => {
    const out = run(home, cwd, secretPath, 'verify-verify');
    expect(out).toMatchObject({ fired: true, innerApproved: true, firstSpend: true, outer: 'unwritable', secondSpend: false, replay: 'nonce-used' });
  }, 60_000);

  it('a self-protection remint between the preview and the grant is refused in the grant transaction', () => {
    const out = run(home, cwd, secretPath, 'remint-terminal-only');
    // Chosen semantics: the button is spent (fail closed) and no grant exists.
    expect(out).toMatchObject({ fired: true, outer: 'terminal-only', grant: null, spent: false, replay: 'nonce-used' });
  }, 60_000);

  it('the retry store: a consumer whose lock was taken over as stale cannot spend the grant a second time', () => {
    const out = run(home, cwd, secretPath, 'retry-consume');
    expect(out).toMatchObject({ fired: true, innerSpend: true, outerSpend: false, thirdSpend: false });
  }, 60_000);
});
