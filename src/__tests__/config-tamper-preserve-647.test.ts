/**
 * #647 — a write on a TAMPERED config.json must neither persist the forced
 * strict view nor sign the untrusted bytes.
 *
 * Before #647 `readRawConfigStateUnlocked` replaced a tampered file's data with
 * the strict fail-closed posture, and `mutateRawConfig` wrote from that read —
 * so the first incidental setter (or background writer) persisted
 * `reviewedScripts: []`, `autoApprove: []`, `defenceMode: 'strict'`, signed the
 * result and cleared the tamper flag. These cases pin the fix:
 *
 *   - explicit setters REFUSE (ConfigIntegrityRefusal), automatic writers SKIP;
 *   - the file's bytes, mode, mtime, pins and stale `_sig` survive untouched;
 *   - every reader still gets the strict posture (#501 unchanged), including
 *     through the mtime cache;
 *   - valid / self-heal / unsigned configs write exactly as before;
 *   - malformed / non-object / unreadable files are refused, never read as
 *     absent;
 *   - the only way past the gate is the previewed, hash-confirmed re-sign, which
 *     backs up first, audits, and will not loosen an Action Guard key that no
 *     verified lock covers.
 *
 * Isolation: a per-test SHIELDCORTEX_CONFIG_DIR, SHIELDCORTEX_PROTECTED_ROOT and
 * OPENCLAW_HOME under os.tmpdir(); the iron-dome audit logger and the re-sign's
 * audit sink (the only routes from config.ts to SQLite, both dynamic imports;
 * the real sink is driven end to end in config-resign-audit-dist-647) and the
 * OpenClaw plugin guard sync are mocked. Nothing here reads or writes the real
 * home directory, and nothing makes a network call.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash, createHmac } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { PROTECTED_ROOT_ENV, describeProtectedAudit, type ProtectedAuditEvent } from '../defence/iron-dome/protected-root.js';
import { POLICY_LOCK_FILENAME, clearPolicyLockReportState } from '../defence/iron-dome/policy-lock.js';

type AuditEntry = { action: string; allowed: boolean; reason: string };
const auditSpy = jest.fn<(entry: AuditEntry) => void>();
const guardSyncSpy = jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const }));

/** The re-sign's audit sink: records into the same spy, as the real one would into SQLite. */
const sinkRecord = jest.fn<(event: ProtectedAuditEvent) => number>();
const sinkClose = jest.fn<() => void>();
const openSinkSpy = jest.fn<() => Promise<{ location: string; record: typeof sinkRecord; close: typeof sinkClose }>>();
const SINK_LOCATION = '/test/memories.db';

jest.unstable_mockModule('../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: auditSpy }));
jest.unstable_mockModule('../cloud/recovery-audit.js', () => ({ openRecoveryAuditSink: openSinkSpy }));
jest.unstable_mockModule('../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: guardSyncSpy,
}));

type ConfigModule = typeof import('../cloud/config.js');

let configDir: string;
let protectedRoot: string;
let openclawHome: string;
let prevConfigDir: string | undefined;
let prevProtectedRoot: string | undefined;
let prevOpenclawHome: string | undefined;
let errorSpy: jest.SpiedFunction<typeof console.error>;

const SENTINEL = 'sc_live_SENTINEL_647';
const PINS = [{ path: '/opt/reviewed/deploy.sh', sha256: 'a'.repeat(64), addedAt: 1_700_000_000_000 }];
const FIXED_MTIME_S = 1_700_000_000;

const configFile = () => path.join(configDir, 'config.json');
const sigFile = () => path.join(configDir, '.config-sig');
const keyFile = () => path.join(configDir, '.integrity-key');

/** A fresh module instance: no cache, no process flags left by another case. */
async function freshConfig(): Promise<ConfigModule> {
  jest.resetModules();
  clearPolicyLockReportState();
  return import('../cloud/config.js');
}

function readOnDisk(): Record<string, any> {
  return JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
}

interface Snapshot { bytes: Buffer; mtimeMs: number; mode: number; entries: string[] }

function snapshot(): Snapshot {
  const st = fs.statSync(configFile());
  return {
    bytes: fs.readFileSync(configFile()),
    mtimeMs: st.mtimeMs,
    mode: st.mode & 0o777,
    entries: fs.readdirSync(configDir).sort(),
  };
}

function expectUnchanged(before: Snapshot): void {
  const after = snapshot();
  expect(after.bytes.equals(before.bytes)).toBe(true);
  expect(after.mtimeMs).toBe(before.mtimeMs);
  if (process.platform !== 'win32') expect(after.mode).toBe(before.mode);
  // No tmp file, no backup, no new or removed legacy sig.
  expect(after.entries).toEqual(before.entries);
}

/** Pin bytes + metadata to deterministic values a no-op must not move. */
function freeze(): Snapshot {
  if (process.platform !== 'win32') fs.chmodSync(configFile(), 0o640);
  fs.utimesSync(configFile(), FIXED_MTIME_S, FIXED_MTIME_S);
  return snapshot();
}

/**
 * The issue's acceptance fixture: a signed config carrying the operator's
 * pins, readiness gate, balanced mode and a credential — then a hand edit
 * (adding an auto-approve entry) that invalidates `_sig`.
 */
async function tamperedFixture(edit?: (cfg: Record<string, any>) => void): Promise<{ config: ConfigModule; before: Snapshot; staleSig: string }> {
  const seed = await freshConfig();
  seed.setCloudConfig({ cloudApiKey: SENTINEL, cloudEnabled: true });
  seed.setReviewedScripts(PINS);
  seed.setActionGuardCoreConfig({ enabled: true, enforce: true, readinessGate: true });
  seed.setDefenceMode('balanced');
  const onDisk = readOnDisk();
  const staleSig = onDisk._sig as string;
  onDisk.actionGuard.autoApprove = ['git_status'];
  if (edit) edit(onDisk);
  fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
  const before = freeze();
  guardSyncSpy.mockClear();
  auditSpy.mockClear();
  errorSpy.mockClear();
  return { config: await freshConfig(), before, staleSig };
}

async function flushAudit(): Promise<void> {
  for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r));
}

function auditRows(outcome: string): AuditEntry[] {
  return auditSpy.mock.calls.map((c) => c[0]).filter((e) => e.reason.startsWith(outcome));
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

beforeEach(() => {
  configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-647-cfg-'));
  protectedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-647-root-'));
  openclawHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-647-oc-'));
  prevConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
  prevProtectedRoot = process.env[PROTECTED_ROOT_ENV];
  prevOpenclawHome = process.env.OPENCLAW_HOME;
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env[PROTECTED_ROOT_ENV] = protectedRoot;
  process.env.OPENCLAW_HOME = openclawHome;
  auditSpy.mockClear();
  guardSyncSpy.mockClear();
  sinkRecord.mockReset();
  sinkRecord.mockImplementation((event) => { auditSpy(describeProtectedAudit(event)); return 7; });
  sinkClose.mockReset();
  openSinkSpy.mockReset();
  openSinkSpy.mockImplementation(async () => ({ location: SINK_LOCATION, record: sinkRecord, close: sinkClose }));
  errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
  if (prevConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfigDir;
  if (prevProtectedRoot === undefined) delete process.env[PROTECTED_ROOT_ENV];
  else process.env[PROTECTED_ROOT_ENV] = prevProtectedRoot;
  if (prevOpenclawHome === undefined) delete process.env.OPENCLAW_HOME;
  else process.env.OPENCLAW_HOME = prevOpenclawHome;
  for (const dir of [configDir, protectedRoot, openclawHome]) {
    try { fs.chmodSync(path.join(dir, 'config.json'), 0o600); } catch { /* absent or a dir */ }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('#647 explicit setters REFUSE on a tampered config and change nothing', () => {
  type Setter = [name: string, invoke: (c: ConfigModule) => unknown];
  const setters: Setter[] = [
    ['setCloudConfig', (c) => c.setCloudConfig({ cloudEnabled: false })],
    ['setDefenceMode (same value as the forced view)', (c) => c.setDefenceMode('strict')],
    ['setCloudSyncControls', (c) => c.setCloudSyncControls({ contentMode: 'metadata' })],
    ['addTrustedSkill', (c) => c.addTrustedSkill('/skills/x.md')],
    ['removeTrustedSkill', (c) => c.removeTrustedSkill('/skills/x.md')],
    ['setReviewedScripts (allowlist whole-list replacement)', (c) => c.setReviewedScripts([])],
    ['setActionGuardNotifyConfig', (c) => c.setActionGuardNotifyConfig({ enabled: true })],
    ['setActionGuardCoreConfig', (c) => c.setActionGuardCoreConfig({ enabled: true, enforce: true })],
    ['migrateInterceptorActionGuardAlias (doctor --fix-action-guard)', (c) => c.migrateInterceptorActionGuardAlias()],
    ['setCloudIronDomeCache (throw-policy; its one caller swallows the throw)', (c) => c.setCloudIronDomeCache({ patterns: [] })],
    ['setVerifyConfig', (c) => c.setVerifyConfig({ verifyEnabled: false })],
    ['setReviewCopilotConfig', (c) => c.setReviewCopilotConfig({ enabled: false })],
    ['setRankerConfig', (c) => c.setRankerConfig({ engine: 'rrf' })],
    ['setOpenClawMemoryConfig', (c) => c.setOpenClawMemoryConfig({ dedupe: true })],
    ['setOpenClawAutoMemory', (c) => c.setOpenClawAutoMemory(false)],
    ['setProactiveRecall', (c) => c.setProactiveRecall(false)],
    ['setSelfHeal', (c) => c.setSelfHeal(true)],
    ['restore410Defaults', (c) => c.restore410Defaults()],
    ['setAutoMemoryEnableConfig', (c) => c.setAutoMemoryEnableConfig({ enableStop: false })],
    ['setMemoryInjectContract', (c) => c.setMemoryInjectContract('sc_only')],
    ['setMemoryHostPosture', (c) => c.setMemoryHostPosture('bus_contract')],
    ['setMemoryHostRuntimes', (c) => c.setMemoryHostRuntimes(['hermes'])],
    ['setMemoryPlane', (c) => c.setMemoryPlane('sc_canonical')],
    ['setAutoMemorySamplingTurns', (c) => c.setAutoMemorySamplingTurns(3)],
    ['setToolResponseScanConfig', (c) => c.setToolResponseScanConfig({ scanToolResponses: true })],
    ['setRevokeBySourceEnabled', (c) => c.setRevokeBySourceEnabled(false)],
  ];

  it.each(setters)('%s throws ConfigIntegrityRefusal and leaves bytes, mode, mtime and directory untouched', async (_name, invoke) => {
    const { config, before } = await tamperedFixture();
    let thrown: unknown;
    try { invoke(config); } catch (err) { thrown = err; }
    expect(thrown).toBeInstanceOf(config.ConfigIntegrityRefusal);
    expect((thrown as Error).message).toMatch(/tampered/);
    expect((thrown as Error).message).toMatch(/config --resign/);
    // Never suggests the laundering path.
    expect((thrown as Error).message).not.toMatch(/re-run/i);
    expectUnchanged(before);
    expect(guardSyncSpy).not.toHaveBeenCalled();
    expect(config.isConfigTampered()).toBe(true);
    const again = await freshConfig();
    again.readRawConfig();
    expect(again.isConfigTampered()).toBe(true);
  });

  it('a refused setter does not touch openclaw.json either (the sync runs only after a write)', async () => {
    const { config } = await tamperedFixture();
    expect(() => config.setActionGuardCoreConfig({ enabled: false })).toThrow(config.ConfigIntegrityRefusal);
    expect(guardSyncSpy).not.toHaveBeenCalled();
    expect(fs.readdirSync(openclawHome)).toEqual([]);
  });
});

describe('#647 automatic writers SKIP on a tampered config, without a storm', () => {
  it('device id / name, last-sync stamp and the sync-defaults migration all skip, none throws, nothing is written', async () => {
    const { config, before } = await tamperedFixture();

    const id1 = config.getDeviceId();
    const id2 = config.getDeviceId();
    expect(id1).toMatch(/^[0-9a-f-]{36}$/);
    // One identity per process while persistence is refused — not one per call.
    expect(id2).toBe(id1);
    expect(typeof config.getDeviceName()).toBe('string');

    const nowSpy = jest.spyOn(Date, 'now');
    nowSpy.mockReturnValue(10_000_000_000_000);
    config.updateLastSyncAt();
    nowSpy.mockReturnValue(10_000_000_120_000); // past the 60s debounce: tries again
    config.updateLastSyncAt();
    config.flushLastSyncAt();
    nowSpy.mockRestore();

    // cloudEnabled is true with no excludeSensitive / migration stamp: the
    // v4.27 migration wants to write. It must answer from memory instead.
    expect(config.getCloudSyncControls().excludeSensitive).toBe(true);

    expectUnchanged(before);
    // Actionable, once — however many automatic writes were skipped.
    const refusals = errorSpy.mock.calls.filter((c) => String(c[0]).includes('refusing config writes'));
    expect(refusals).toHaveLength(1);
    expect(String(refusals[0][0])).toMatch(/shieldcortex doctor/);
    expect(guardSyncSpy).not.toHaveBeenCalled();
  });
});

describe('#647 the operator values and the tamper evidence survive', () => {
  it('after every setter and automatic writer has been refused, the file still holds the operator config and the stale _sig', async () => {
    const { config, staleSig } = await tamperedFixture();
    for (const attempt of [
      () => config.addTrustedSkill('/skills/x.md'),
      () => config.setReviewedScripts([]),
      () => config.setDefenceMode('strict'),
      () => config.setActionGuardCoreConfig({ enabled: true }),
    ]) {
      expect(attempt).toThrow(config.ConfigIntegrityRefusal);
    }
    config.getDeviceId();
    config.getCloudSyncControls();

    const onDisk = readOnDisk();
    expect(onDisk.actionGuard.reviewedScripts).toEqual(PINS);
    expect(onDisk.actionGuard.autoApprove).toEqual(['git_status']);
    expect(onDisk.actionGuard.readinessGate).toBe(true);
    expect(onDisk.defenceMode).toBe('balanced');
    expect(onDisk.cloudApiKey).toBe(SENTINEL);
    expect(onDisk._sig).toBe(staleSig);
    expect(onDisk.deviceId).toBeUndefined();
    expect(config.inspectConfigIntegrity().verdict).toBe('tampered');
  });
});

describe('#647 reads keep the #501 strict posture', () => {
  it('every reader still sees the fail-closed posture while the file keeps its own values', async () => {
    const { config } = await tamperedFixture();
    expect(config.getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: false });
    const raw = config.readRawConfig();
    expect(raw.defenceMode).toBe('strict');
    const guard = raw.actionGuard as Record<string, unknown>;
    expect(guard.autoApprove).toEqual([]);
    expect(guard.reviewedScripts).toEqual([]);
    expect(guard.broker).toEqual({ enabled: false });
    expect(config.getReviewedScriptsRaw()).toEqual([]);
    expect(config.getDefenceMode()).toBe('strict');
    expect(config.isConfigTampered()).toBe(true);
    // Non-posture keys are read from the file as before.
    expect(config.getCloudConfig().cloudApiKey).toBe(SENTINEL);
  });

  it('a CACHED read keeps the verdict: the second read is a cache hit and a setter still refuses', async () => {
    const { config, before } = await tamperedFixture();
    config.readRawConfig();
    config.readRawConfig();
    // The integrity warning is printed by an uncached classification only, so
    // one line across two reads proves the second came from the mtime cache.
    const warnings = errorSpy.mock.calls.filter((c) => String(c[0]).includes('config integrity check failed'));
    expect(warnings).toHaveLength(1);
    expect(config.isConfigTampered()).toBe(true);
    expect(config.getActionGuardCoreConfig().enforce).toBe(true);
    expect(() => config.addTrustedSkill('/skills/x.md')).toThrow(config.ConfigIntegrityRefusal);
    expectUnchanged(before);
  });
});

describe('#647 non-tampered configs write exactly as before', () => {
  it('valid: a setter writes and re-signs', async () => {
    const config = await freshConfig();
    config.setCloudConfig({ cloudApiKey: SENTINEL });
    config.setDefenceMode('permissive');
    const fresh = await freshConfig();
    expect(fresh.getDefenceMode()).toBe('permissive');
    expect(fresh.isConfigTampered()).toBe(false);
    expect(fresh.inspectConfigIntegrity().verdict).toBe('valid');
  });

  it('self-heal: a stale embedded _sig with a valid legacy sig is re-signed on read, then writable', async () => {
    const key = 'b'.repeat(64);
    fs.writeFileSync(keyFile(), key, { mode: 0o600 });
    const body = JSON.stringify({ cloudApiKey: SENTINEL, _sig: 'deadbeef'.repeat(8) }, null, 2) + '\n';
    fs.writeFileSync(configFile(), body);
    // Legacy whole-file sig over the exact bytes, keyed like the product.
    fs.writeFileSync(sigFile(), createHmac('sha256', key).update(body, 'utf-8').digest('hex'));

    const config = await freshConfig();
    expect(config.inspectConfigIntegrity().verdict).toBe('self-heal');
    expect(config.readRawConfig().cloudApiKey).toBe(SENTINEL);
    expect(config.isConfigTampered()).toBe(false);
    expect(() => config.setProactiveRecall(true)).not.toThrow();
    expect(readOnDisk().proactiveRecall).toBe(true);
    expect(config.inspectConfigIntegrity().verdict).toBe('valid');
  });

  it('unsigned legacy file: adopted on read, then writable and signed', async () => {
    fs.writeFileSync(configFile(), JSON.stringify({ cloudApiKey: SENTINEL }, null, 2));
    const config = await freshConfig();
    expect(config.inspectConfigIntegrity().verdict).toBe('unsigned');
    expect(() => config.setDefenceMode('balanced')).not.toThrow();
    expect(typeof readOnDisk()._sig).toBe('string');
    expect(readOnDisk().cloudApiKey).toBe(SENTINEL);
  });
});

describe('#647 malformed and unreadable are refused, never treated as absent', () => {
  it.each([
    ['torn JSON', `{ "cloudApiKey": "${SENTINEL}", NOT JSON`],
    ['JSON null', 'null'],
    ['a JSON array', '["x"]'],
    ['a JSON string', '"x"'],
  ])('%s: setters throw, automatic writers skip, bytes untouched, inspected as malformed', async (_label, bytes) => {
    fs.writeFileSync(configFile(), bytes);
    const before = freeze();
    const config = await freshConfig();
    expect(config.inspectConfigIntegrity().verdict).toBe('malformed');
    expect(() => config.setDefenceMode('strict')).toThrow(/corrupt|unparseable/);
    expect(() => config.getDeviceId()).not.toThrow();
    expectUnchanged(before);
  });

  it('a directory where config.json should be is unreadable, not absent', async () => {
    fs.mkdirSync(configFile());
    const config = await freshConfig();
    expect(config.inspectConfigIntegrity().verdict).toBe('unreadable');
    expect(() => config.setDefenceMode('strict')).toThrow(/corrupt|unparseable/);
    expect(fs.statSync(configFile()).isDirectory()).toBe(true);
  });

  const canChmod = process.platform !== 'win32' && !(typeof process.getuid === 'function' && process.getuid() === 0);
  (canChmod ? it : it.skip)('a file the process cannot read is refused, not overwritten', async () => {
    const seed = await freshConfig();
    seed.setCloudConfig({ cloudApiKey: SENTINEL });
    const bytes = fs.readFileSync(configFile());
    fs.chmodSync(configFile(), 0o000);
    const config = await freshConfig();
    expect(config.inspectConfigIntegrity().verdict).toBe('unreadable');
    expect(() => config.setDefenceMode('strict')).toThrow(/corrupt|unparseable/);
    fs.chmodSync(configFile(), 0o600);
    expect(fs.readFileSync(configFile()).equals(bytes)).toBe(true);
  });
});

describe('#647 inspectConfigIntegrity has no side effects', () => {
  function dirState(): { entries: string[] } {
    return { entries: fs.existsSync(configDir) ? fs.readdirSync(configDir).sort() : [] };
  }

  it('absent: nothing minted', async () => {
    const config = await freshConfig();
    const before = dirState();
    expect(config.inspectConfigIntegrity().verdict).toBe('absent');
    expect(dirState()).toEqual(before);
  });

  it('unsigned: reported, NOT adopted — no .config-sig and no .integrity-key minted', async () => {
    fs.writeFileSync(configFile(), JSON.stringify({ proactiveRecall: true }));
    const config = await freshConfig();
    const before = dirState();
    expect(config.inspectConfigIntegrity().verdict).toBe('unsigned');
    expect(dirState()).toEqual(before);
    expect(fs.existsSync(sigFile())).toBe(false);
    expect(fs.existsSync(keyFile())).toBe(false);
  });

  it('an embedded _sig with no integrity key reads tampered without minting a key', async () => {
    fs.writeFileSync(configFile(), JSON.stringify({ proactiveRecall: true, _sig: 'f'.repeat(64) }));
    const config = await freshConfig();
    expect(config.inspectConfigIntegrity().verdict).toBe('tampered');
    expect(fs.existsSync(keyFile())).toBe(false);
  });

  it('tampered: inspection does not change the process flag, the file or the directory', async () => {
    const { config, before } = await tamperedFixture();
    expect(config.inspectConfigIntegrity().verdict).toBe('tampered');
    expect(config.isConfigTampered()).toBe(false); // no ordinary read has run yet
    expectUnchanged(before);
  });
});

describe('#647 the policy lock still refuses first', () => {
  it('a loosening setter on a tampered config under an unverifiable lock is a PolicyLockRefusal, audited', async () => {
    const { before } = await tamperedFixture();
    fs.writeFileSync(path.join(protectedRoot, POLICY_LOCK_FILENAME), JSON.stringify({ actionGuard: { enabled: true } }));
    const config = await freshConfig();
    let thrown: unknown;
    try { config.setDefenceMode('permissive'); } catch (err) { thrown = err; }
    expect((thrown as Error).name).toBe('PolicyLockRefusal');
    expect(thrown).not.toBeInstanceOf(config.ConfigIntegrityRefusal);
    await flushAudit();
    expect(auditRows('policy_refused').length).toBeGreaterThan(0);
    expectUnchanged(before);
  });
});

describe('#647 deliberate re-sign: preview, exact-hash confirmation, backup, audit', () => {
  /** A tamper that only touches keys the Action Guard floor does not hold. */
  async function benignTamper(): Promise<{ config: ConfigModule; before: Snapshot }> {
    const seed = await freshConfig();
    seed.setCloudConfig({ cloudApiKey: SENTINEL });
    seed.setActionGuardCoreConfig({ enabled: true, enforce: true });
    seed.setDefenceMode('strict');
    const onDisk = readOnDisk();
    onDisk.proactiveRecall = true;
    onDisk.defenceMode = 'balanced';
    fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
    const before = freeze();
    auditSpy.mockClear();
    guardSyncSpy.mockClear();
    return { config: await freshConfig(), before };
  }

  it('the preview writes nothing, prints the FULL sha256 of the exact bytes, and names keys without values', async () => {
    const { config, before } = await tamperedFixture();
    const preview = config.previewConfigResign();
    expect(preview.verdict).toBe('tampered');
    expect(preview.sha256).toBe(sha256(before.bytes));
    expect(preview.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(preview.loosenedKeys).toEqual(expect.arrayContaining([
      'actionGuard.autoApprove', 'actionGuard.reviewedScripts', 'actionGuard.readinessGate', 'defenceMode',
    ]));
    expect(JSON.stringify(preview)).not.toContain(SENTINEL);
    expectUnchanged(before);
    await flushAudit();
    expect(auditSpy).not.toHaveBeenCalled();
  });

  it('without a verified lock, a re-sign that would make hand-edited Action Guard values effective is REFUSED', async () => {
    const { config, before } = await tamperedFixture();
    const preview = config.previewConfigResign();
    expect(preview.unauthorisedKeys).toEqual(expect.arrayContaining(['actionGuard.autoApprove', 'actionGuard.reviewedScripts']));
    expect(preview.unauthorisedKeys).not.toContain('defenceMode');
    await expect(config.resignTamperedConfig(preview.sha256!)).rejects.toThrow(/no verified policy lock covers/);
    expectUnchanged(before);
    await flushAudit();
    expect(auditRows('config_resigned')).toHaveLength(0);
    // A refused re-sign never opens the audit database.
    expect(openSinkSpy).not.toHaveBeenCalled();
  });

  it('a prefix, a mistyped hash, or bytes changed after the preview are refused and nothing is written', async () => {
    const { config, before } = await benignTamper();
    const preview = config.previewConfigResign();
    await expect(config.resignTamperedConfig(preview.sha256!.slice(0, 12))).rejects.toThrow(/full 64-character/);
    await expect(config.resignTamperedConfig('0'.repeat(64))).rejects.toThrow(/changed after the preview|mistyped/);
    expectUnchanged(before);

    const edited = readOnDisk();
    edited.proactiveRecall = false;
    fs.writeFileSync(configFile(), JSON.stringify(edited, null, 2) + '\n');
    const changed = snapshot();
    await expect(config.resignTamperedConfig(preview.sha256!)).rejects.toThrow(/changed after the preview/);
    expectUnchanged(changed);
    await flushAudit();
    expect(auditRows('config_resigned')).toHaveLength(0);
    expect(openSinkSpy).not.toHaveBeenCalled();
  });

  it('a config that is not tampered is not re-signed', async () => {
    const config = await freshConfig();
    config.setDefenceMode('balanced');
    const bytes = fs.readFileSync(configFile());
    await expect(config.resignTamperedConfig(sha256(bytes))).rejects.toThrow(/not tampered/);
    expect(fs.readFileSync(configFile()).equals(bytes)).toBe(true);
  });

  it('the confirmed re-sign backs up the reviewed bytes (0600), signs exactly them, reads valid, and audits config_resigned', async () => {
    const { config, before } = await benignTamper();
    const preview = config.previewConfigResign();
    expect(preview.unauthorisedKeys).toEqual([]);
    expect(preview.lockRefusal).toBeNull();
    expect(preview.loosenedKeys).toEqual(['defenceMode']);

    const result = await config.resignTamperedConfig(preview.sha256!, { now: new Date('2026-10-09T12:00:00.000Z') });
    expect(result.audit).toEqual({ recorded: true, rowId: 7, location: SINK_LOCATION });
    expect(openSinkSpy).toHaveBeenCalledTimes(1);
    expect(sinkClose).toHaveBeenCalledTimes(1);
    expect(result.previousVerdict).toBe('tampered');
    expect(result.previousSha256).toBe(sha256(before.bytes));
    expect(result.backupPath).toBe(`${configFile()}.bak-resign-2026-10-09T12-00-00-000Z`);
    expect(fs.readFileSync(result.backupPath).equals(before.bytes)).toBe(true);
    if (process.platform !== 'win32') expect(fs.statSync(result.backupPath).mode & 0o777).toBe(0o600);
    expect(result.newSha256).toBe(sha256(fs.readFileSync(configFile())));

    const fresh = await freshConfig();
    expect(fresh.inspectConfigIntegrity().verdict).toBe('valid');
    expect(fresh.getDefenceMode()).toBe('balanced'); // the file's value, no longer forced strict
    expect(fresh.isProactiveRecallEnabled()).toBe(true);
    expect(fresh.isConfigTampered()).toBe(false);
    expect(fresh.getCloudConfig().cloudApiKey).toBe(SENTINEL);

    await flushAudit();
    const rows = auditRows('config_resigned');
    expect(rows).toHaveLength(1);
    expect(rows[0].action).toBe('policy-lock');
    expect(rows[0].allowed).toBe(true);
    expect(rows[0].reason).toContain('previous verdict tampered');
    expect(rows[0].reason).toContain(result.previousSha256);
    expect(rows[0].reason).toContain(result.newSha256);
    expect(rows[0].reason).toContain(result.backupPath);
    expect(rows[0].reason).toContain('defenceMode');
    expect(rows[0].reason).not.toContain(SENTINEL);
    expect(guardSyncSpy).not.toHaveBeenCalled();
  });

  it('a second confirm of the same hash is refused (the file is valid now) and the backup is never overwritten', async () => {
    const { config } = await benignTamper();
    const preview = config.previewConfigResign();
    const when = new Date('2026-10-09T12:00:00.000Z');
    const first = await config.resignTamperedConfig(preview.sha256!, { now: when });
    const backup = fs.readFileSync(first.backupPath);
    await expect(config.resignTamperedConfig(preview.sha256!, { now: when })).rejects.toThrow(/not tampered/);
    expect(fs.readFileSync(first.backupPath).equals(backup)).toBe(true);
  });

  it('under an unverifiable lock, the re-sign is refused by the lock and audited as policy_refused', async () => {
    const { before } = await benignTamper();
    fs.writeFileSync(path.join(protectedRoot, POLICY_LOCK_FILENAME), JSON.stringify({ actionGuard: { enabled: true } }));
    const config = await freshConfig();
    const preview = config.previewConfigResign();
    // The preview already says so, without auditing anything itself.
    expect(preview.lockRefusal).toMatch(/Refusing to loosen `defenceMode`/);
    let thrown: unknown;
    try { await config.resignTamperedConfig(preview.sha256!); } catch (err) { thrown = err; }
    expect((thrown as Error).name).toBe('PolicyLockRefusal');
    expectUnchanged(before);
    await flushAudit();
    expect(auditRows('policy_refused').length).toBeGreaterThan(0);
    expect(auditRows('config_resigned')).toHaveLength(0);
  });

  it('an audit log that cannot be opened REFUSES the re-sign: no backup, no write, the file stays tampered', async () => {
    const { config, before } = await benignTamper();
    const preview = config.previewConfigResign();
    openSinkSpy.mockImplementationOnce(async () => { throw new Error('unable to open database file'); });
    await expect(config.resignTamperedConfig(preview.sha256!))
      .rejects.toThrow(/audit log that must record a re-sign could not be opened \(unable to open database file\).*Nothing was written/s);
    expectUnchanged(before);
    const fresh = await freshConfig();
    expect(fresh.inspectConfigIntegrity().verdict).toBe('tampered');
    expect(auditRows('config_resigned')).toHaveLength(0);
  });

  it('bytes that change WHILE the audit log opens are refused, and the sink is closed', async () => {
    const { config } = await benignTamper();
    const preview = config.previewConfigResign();
    let changed: Snapshot | undefined;
    openSinkSpy.mockImplementationOnce(async () => {
      const edited = readOnDisk();
      edited.proactiveRecall = false;
      fs.writeFileSync(configFile(), JSON.stringify(edited, null, 2) + '\n');
      changed = snapshot();
      return { location: SINK_LOCATION, record: sinkRecord, close: sinkClose };
    });
    await expect(config.resignTamperedConfig(preview.sha256!)).rejects.toThrow(/changed after the preview/);
    expectUnchanged(changed!);
    expect(sinkRecord).not.toHaveBeenCalled();
    expect(sinkClose).toHaveBeenCalledTimes(1);
  });

  it('a row that fails to write AFTER the re-sign landed is reported as NOT recorded, never as recorded', async () => {
    const { config, before } = await benignTamper();
    const preview = config.previewConfigResign();
    sinkRecord.mockImplementationOnce(() => { throw new Error(`the audit row could not be written to ${SINK_LOCATION}`); });
    const result = await config.resignTamperedConfig(preview.sha256!, { now: new Date('2026-10-09T13:00:00.000Z') });
    expect(result.audit).toEqual({
      recorded: false,
      location: SINK_LOCATION,
      error: `the audit row could not be written to ${SINK_LOCATION}`,
    });
    // The partial state is real and stated: the re-sign is in force, and the
    // reviewed bytes are kept as the evidence.
    const fresh = await freshConfig();
    expect(fresh.inspectConfigIntegrity().verdict).toBe('valid');
    expect(fs.readFileSync(result.backupPath).equals(before.bytes)).toBe(true);
    expect(sinkClose).toHaveBeenCalledTimes(1);
  });
});
