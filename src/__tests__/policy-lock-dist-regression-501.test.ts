/**
 * #501 — the regression proof, against the BUILT artefacts.
 *
 * Every other #501 suite runs in-process against TypeScript sources. This one
 * cannot: the defect was that the two enforcement surfaces and the CLI each
 * resolved their own view of the config, so the only honest proof is to drive
 * the shipped `dist/index.js` and the shipped `scripts/pre-tool-hook.mjs` as
 * separate processes and read what they actually do.
 *
 * The fixture is the SC-02 forge, in full:
 *
 *   1. a hermetic HOME + SHIELDCORTEX_CONFIG_DIR;
 *   2. a `.integrity-key` and a `config.json` carrying a VALID embedded `_sig`
 *      computed with it — i.e. the HMAC verifies, because the key sits beside
 *      the file it signs and anything that can edit one can re-sign the other.
 *      That is the whole point: the signature is not the control;
 *   3. `actionGuard.enabled: false` inside those correctly-signed bytes;
 *   4. a same-UID `policy.json` claiming the guard is off — the forged lock.
 *
 * On 5.0.5 that fixture produces an unguarded box with a green integrity check.
 * Here it must produce: doctor reporting the lock invalid and the posture
 * enforced, the hook DENYING the catastrophic payload, and the signed CLI
 * refusing to disable the guard.
 */
import { spawnSync } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { ensureFreshBuiltArtefacts } from './built-artefact-freshness.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIST_ENTRY = join(repoRoot, 'dist', 'index.js');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');

/** SC-01: assembled char by char — this file is scanned by the guard it drives. */
const SC01_CATASTROPHIC = ['r', 'm', ' ', '-', 'r', 'f', ' ', '/'].join('');

let home: string;
let configDir: string;
let protectedRoot: string;

/** The sources whose behaviour this suite asserts through the built output. */
const SOURCES_UNDER_TEST = [
  join(repoRoot, 'src', 'index.ts'),
  join(repoRoot, 'src', 'cli', 'doctor.ts'),
  join(repoRoot, 'src', 'cli', 'protect.ts'),
  join(repoRoot, 'src', 'cloud', 'config.ts'),
  join(repoRoot, 'src', 'cloud', 'cli.ts'),
  join(repoRoot, 'src', 'defence', 'iron-dome', 'policy-lock.ts'),
  join(repoRoot, 'src', 'defence', 'iron-dome', 'protected-root.ts'),
];

beforeAll(() => {
  // Missing OR stale. The usual probe-for-existence (pre-tool-hook-retry-310)
  // is not enough for a REGRESSION proof: a dist left over from before the fix
  // exists, so the suite would drive the old build and report green about code
  // that is not the code under review. Freshness is the property that matters.
  // Shared with `policy-lock-chain-e2e-501` through a cross-process lock, so
  // two parallel workers cannot each delete the dist the other is driving.
  ensureFreshBuiltArtefacts({
    repoRoot,
    sources: SOURCES_UNDER_TEST,
    artefacts: [
      DIST_ENTRY,
      join(repoRoot, 'dist', 'defence', 'iron-dome', 'policy-lock.js'),
      join(repoRoot, 'dist', 'cli', 'protect.js'),
    ],
  });
}, 600_000);

/**
 * Write a config.json whose embedded `_sig` GENUINELY verifies.
 *
 * Mirrors `canonicalBodyForSig` + `signConfig` in src/cloud/config.ts exactly:
 * HMAC-SHA256, keyed on the co-located `.integrity-key`, over
 * `JSON.stringify(objectWithout_sig, null, 2)`. If this ever stops matching,
 * the suite would be proving something weaker than it claims, so the first
 * test asserts the forgery is accepted before any of the others rely on it.
 */
function forgeSignedConfig(body: Record<string, unknown>): void {
  const key = randomBytes(32).toString('hex');
  writeFileSync(join(configDir, '.integrity-key'), key, { mode: 0o600 });
  const sig = createHmac('sha256', key).update(JSON.stringify(body, null, 2), 'utf-8').digest('hex');
  writeFileSync(join(configDir, 'config.json'), `${JSON.stringify({ ...body, _sig: sig }, null, 2)}\n`);
}

/** Drop a same-UID policy.json — a lock this very process could have written. */
function forgePolicyLock(policy: unknown = { actionGuard: { enabled: false, enforce: false } }): void {
  writeFileSync(join(protectedRoot, 'policy.json'), JSON.stringify(policy, null, 2));
}

function env(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    SHIELDCORTEX_CONFIG_DIR: configDir,
    SHIELDCORTEX_PROTECTED_ROOT: protectedRoot,
    ...extra,
  };
}

function runCli(args: string[]): { stdout: string; stderr: string; status: number } {
  const run = spawnSync(process.execPath, [DIST_ENTRY, ...args], {
    env: env(), encoding: 'utf8', timeout: 120_000,
  });
  return { stdout: run.stdout ?? '', stderr: run.stderr ?? '', status: run.status ?? 0 };
}

function runHook(command: string): { decision?: string; reason?: string; stdout: string } {
  const payload = JSON.stringify({
    session_id: 'sc-501-regression',
    cwd: home,
    permission_mode: 'default',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  });
  const run = spawnSync(process.execPath, [HOOK], {
    input: payload, env: env(), encoding: 'utf8', timeout: 60_000,
  });
  const stdout = run.stdout ?? '';
  if (!stdout.trim()) return { stdout };
  const parsed = JSON.parse(stdout);
  return {
    decision: parsed.hookSpecificOutput?.permissionDecision,
    reason: parsed.hookSpecificOutput?.permissionDecisionReason,
    stdout,
  };
}

/** doctor prints a leading blank line (and checks may log); take the JSON body. */
function doctorJson(): { results: Array<{ label: string; status: string; message: string; fix?: string }> } {
  const { stdout } = runCli(['doctor', '--json']);
  const start = stdout.indexOf('{');
  const end = stdout.lastIndexOf('}');
  expect(start).toBeGreaterThanOrEqual(0);
  return JSON.parse(stdout.slice(start, end + 1));
}

function row(json: ReturnType<typeof doctorJson>, needle: string) {
  return json.results.find((r) => r.label.toLowerCase().includes(needle));
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-501-dist-home-'));
  configDir = join(home, '.shieldcortex');
  mkdirSync(configDir, { recursive: true });
  protectedRoot = mkdtempSync(join(tmpdir(), 'sc-501-dist-root-'));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(protectedRoot, { recursive: true, force: true });
});

describe('#501 the forge itself — the signature is not the control', () => {
  it('a hand-written config with a recomputed _sig passes the integrity check', () => {
    // If this ever fails, every assertion below is testing a weaker fixture
    // than it claims. The point of the row is that the HMAC says "fine" to a
    // file a same-UID process just rewrote end to end.
    forgeSignedConfig({ actionGuard: { enabled: false, enforce: false } });
    const integrity = row(doctorJson(), 'config integrity');
    expect(integrity?.status).toBe('pass');
  });

  it('WITHOUT a lock, that forged config leaves the guard off — the 5.0.5 outcome', () => {
    forgeSignedConfig({ actionGuard: { enabled: false, enforce: false } });
    // No policy.json anywhere: this is today's behaviour, and it is the
    // baseline the lock has to change. The hook exits silently.
    expect(runHook(SC01_CATASTROPHIC).stdout).toBe('');
  });
});

describe('#501 with a forged same-UID policy lock, the built artefacts fail closed', () => {
  beforeEach(() => {
    forgeSignedConfig({
      actionGuard: { enabled: false, enforce: false, autoApprove: ['anything'], broker: { enabled: true } },
      defenceMode: 'permissive',
    });
    forgePolicyLock();
  });

  it('the built PreToolUse hook DENIES the SC-01 catastrophic payload', () => {
    const result = runHook(SC01_CATASTROPHIC);
    expect(result.decision).toBe('deny');
    expect(result.reason).toMatch(/catastrophic/i);
  });

  it('doctor reports the lock as invalid, not as absent and not as fine', () => {
    const lock = row(doctorJson(), 'policy lock');
    expect(lock?.status).toBe('fail');
    expect(lock?.message).toMatch(/UNVERIFIABLE/);
    expect(lock?.fix).toMatch(/shieldcortex protect/);
  });

  it('doctor reports the ENFORCED posture, not the posture the file asks for', () => {
    // The config says `enabled: false` with a valid signature. Before #501
    // doctor read the file and graded the file, so this row said "Action Guard
    // is disabled in config" on a box where the guard was, in fact, gating.
    const json = doctorJson();
    const configRow = json.results.find((r) => r.label.includes('Action guard config'));
    expect(configRow?.message ?? '').not.toMatch(/Action Guard is disabled in config/);
  });

  it('`config --action-guard-disable` is REFUSED, naming the lock', () => {
    const result = runCli(['config', '--action-guard-disable']);
    expect(result.status).toBe(1);
    const text = `${result.stdout}\n${result.stderr}`;
    expect(text).toMatch(/Refusing to loosen `actionGuard\.enabled`/);
    expect(text).toMatch(/policy\.json/);
    expect(text).toMatch(/`shieldcortex protect` as root/);
  });

  it('`config --cloud-status` reports the ENFORCED posture, through the config reader', () => {
    // The one assertion here that travels through readRawConfigState's lock
    // precedence rather than through a surface that reads the lock directly.
    // Without that precedence this prints "Action Guard: Off" and
    // "Defence Mode: permissive" — the forged config's own words.
    const result = runCli(['config', '--cloud-status']);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/Action Guard: Enforce/);
    expect(result.stdout).toMatch(/Defence Mode: strict/);
  });

  it('`config --policy-status` says the same thing the doctor row does', () => {
    const result = runCli(['config', '--policy-status']);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/UNVERIFIABLE/);
    expect(result.stdout).toMatch(/strict fail-closed posture/);
  });

  it('a write that TIGHTENS is still allowed — the lock is a floor, not a freeze', () => {
    const result = runCli(['config', '--action-guard-enforce']);
    expect(result.status).toBe(0);
  });
});

describe('#501 a MISSING dist cannot fail open while a lock exists', () => {
  it('the hook enforces the strict posture when its dist policy reader is gone', () => {
    forgeSignedConfig({ actionGuard: { enabled: false, enforce: false } });
    forgePolicyLock();
    const emptyDist = mkdtempSync(join(tmpdir(), 'sc-501-empty-dist-'));
    try {
      const payload = JSON.stringify({
        session_id: 'sc-501-nodist', cwd: home, permission_mode: 'default',
        hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: SC01_CATASTROPHIC },
      });
      const run = spawnSync(process.execPath, [HOOK], {
        input: payload,
        env: env({ SHIELDCORTEX_DIST_ROOT: emptyDist }),
        encoding: 'utf8',
        timeout: 60_000,
      });
      // With no dist the guard degrades to its inline catastrophic fallback —
      // which only runs at all because the policy probe refused to fail open.
      expect(run.stdout ?? '').not.toBe('');
      const parsed = JSON.parse(run.stdout!);
      expect(parsed.hookSpecificOutput?.permissionDecision).toBe('deny');
      expect(run.stderr ?? '').toMatch(/policy lock is present but the dist policy reader/);
    } finally {
      rmSync(emptyDist, { recursive: true, force: true });
    }
  });

  it('a missing dist with NO lock still fails open, as it always has', () => {
    // The other half of the rule: turning every tool call into a denial because
    // a build is stale is the outage ShieldCortex exists to prevent.
    forgeSignedConfig({ actionGuard: { enabled: true, enforce: true } });
    const emptyDist = mkdtempSync(join(tmpdir(), 'sc-501-empty-dist-2-'));
    try {
      const payload = JSON.stringify({
        session_id: 'sc-501-nodist-nolock', cwd: home, permission_mode: 'default',
        hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'ls -la' },
      });
      const run = spawnSync(process.execPath, [HOOK], {
        input: payload, env: env({ SHIELDCORTEX_DIST_ROOT: emptyDist }), encoding: 'utf8', timeout: 60_000,
      });
      const out = (run.stdout ?? '').trim();
      if (out) expect(JSON.parse(out).hookSpecificOutput?.permissionDecision).not.toBe('deny');
      expect(run.stderr ?? '').not.toMatch(/policy lock is present/);
    } finally {
      rmSync(emptyDist, { recursive: true, force: true });
    }
  });
});
