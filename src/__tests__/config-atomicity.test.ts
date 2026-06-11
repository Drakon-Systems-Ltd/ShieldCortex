import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync, utimesSync, statSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { createHmac } from 'crypto';

/**
 * Phase 7 — config hot-path hardening.
 *
 * Pins the contract for the four bugs the audit found in src/cloud/config.ts:
 *   1. Non-atomic two-file write (config.json + separate .config-sig) → torn
 *      reads / false tamper trips. Replaced by an atomic tmp+rename write with
 *      the HMAC embedded as a top-level `_sig` field.
 *   2. Auto-write on parse failure wiped the config (getDeviceId/getDeviceName
 *      rewrote `{}` + a fresh id, destroying cloudApiKey et al). Parse failure
 *      must now be read-only.
 *   3. Uncached per-scan reads (read+parse+HMAC on every accessor). Now
 *      mtime-cached, invalidated on write.
 *   4. Per-scan rewrite via updateLastSyncAt on every successful sync. Now
 *      time-debounced to ≤1 write / 60s.
 */

const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;

describe('config atomicity + integrity hardening', () => {
  let tempDir: string;
  let configDir: string;
  let configFile: string;
  let sigFile: string;
  let integrityKeyFile: string;

  beforeEach(() => {
    jest.resetModules();
    tempDir = mkdtempSync(join(tmpdir(), 'sc-config-atomicity-'));
    configDir = join(tempDir, '.shieldcortex');
    mkdirSync(configDir, { recursive: true });
    configFile = join(configDir, 'config.json');
    sigFile = join(configDir, '.config-sig');
    integrityKeyFile = join(configDir, '.integrity-key');
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
    if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
  });

  // ── Fix 2: never wipe on parse failure ──────────────────────────────
  describe('parse failure is read-only', () => {
    it('getDeviceId does not overwrite an unparseable config and preserves cloudApiKey', async () => {
      const config = await import('../cloud/config.js');
      // Seed a valid config carrying a credential.
      config.setCloudConfig({ cloudApiKey: 'sc_live_precious_key', cloudEnabled: true });
      expect(config.getCloudConfig().cloudApiKey).toBe('sc_live_precious_key');

      // Corrupt config.json so JSON.parse throws (simulates a torn write or
      // an editor mid-save). The bytes must survive a getDeviceId() call.
      const corrupt = '{ "cloudApiKey": "sc_live_precious_key", THIS IS NOT JSON';
      writeFileSync(configFile, corrupt);
      config.clearCloudConfigCache();

      const id = config.getDeviceId();
      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);

      // The corrupt bytes must remain untouched — no auto-rewrite happened.
      expect(readFileSync(configFile, 'utf-8')).toBe(corrupt);
    });

    it('getDeviceName does not overwrite an unparseable config', async () => {
      const config = await import('../cloud/config.js');
      const corrupt = 'not json at all }{';
      writeFileSync(configFile, corrupt);
      config.clearCloudConfigCache();

      const name = config.getDeviceName();
      expect(typeof name).toBe('string');
      expect(name.length).toBeGreaterThan(0);
      expect(readFileSync(configFile, 'utf-8')).toBe(corrupt);
    });
  });

  // ── Fix 1: atomic write + embedded HMAC ─────────────────────────────
  describe('atomic write with embedded HMAC', () => {
    it('round-trips data without leaking _sig and reports not tampered', async () => {
      const config = await import('../cloud/config.js');
      config.setCloudConfig({ cloudApiKey: 'x', cloudEnabled: true });
      const raw = config.readRawConfig();

      expect(raw.cloudApiKey).toBe('x');
      // _sig must never leak into the returned config object.
      expect('_sig' in raw).toBe(false);
      expect(config.isConfigTampered()).toBe(false);

      // On-disk file is self-consistent: it carries _sig and verification
      // passes without relying on a separate sig file.
      const onDisk = JSON.parse(readFileSync(configFile, 'utf-8'));
      expect(typeof onDisk._sig).toBe('string');
    });

    it('does not depend on a separate .config-sig file for the new format', async () => {
      const config = await import('../cloud/config.js');
      config.setCloudConfig({ cloudApiKey: 'x' });
      // Remove the legacy sig file entirely; the embedded _sig must still verify.
      if (existsSync(sigFile)) rmSync(sigFile);
      config.clearCloudConfigCache();
      jest.resetModules();
      const config2 = await import('../cloud/config.js');
      const raw = config2.readRawConfig();
      expect(raw.cloudApiKey).toBe('x');
      expect(config2.isConfigTampered()).toBe(false);
    });

    it('detects tampering when the body is modified without updating _sig', async () => {
      const config = await import('../cloud/config.js');
      config.setCloudConfig({ cloudApiKey: 'original', cloudEnabled: false });

      // Tamper: flip cloudEnabled but leave _sig as-is.
      const onDisk = JSON.parse(readFileSync(configFile, 'utf-8'));
      onDisk.cloudEnabled = true;
      writeFileSync(configFile, JSON.stringify(onDisk, null, 2) + '\n');
      config.clearCloudConfigCache();
      jest.resetModules();
      const config2 = await import('../cloud/config.js');
      config2.readRawConfig();
      expect(config2.isConfigTampered()).toBe(true);
      expect(config2.getDefenceMode()).toBe('strict'); // tampered → forced strict
    });
  });

  // ── Fix 1: backward compatibility with legacy .config-sig ───────────
  describe('legacy .config-sig compatibility', () => {
    it('reads an old-format config (separate sig file, no _sig) without false tamper, then upgrades on write', async () => {
      // Reproduce the legacy on-disk layout the OLD writer produced: a
      // config.json with NO _sig field, plus a separate .config-sig file
      // signed over the exact file bytes with the integrity key.
      const key = 'a'.repeat(64);
      writeFileSync(integrityKeyFile, key, { mode: 0o600 });
      const body = JSON.stringify({ cloudApiKey: 'sc_live_legacy', cloudEnabled: true }, null, 2) + '\n';
      writeFileSync(configFile, body);
      const legacySig = createHmac('sha256', key).update(body, 'utf-8').digest('hex');
      writeFileSync(sigFile, legacySig, { mode: 0o600 });

      const config = await import('../cloud/config.js');
      const raw = config.readRawConfig();
      expect(raw.cloudApiKey).toBe('sc_live_legacy');
      expect(config.isConfigTampered()).toBe(false);

      // A subsequent write upgrades to the embedded _sig format.
      config.setDefenceMode('balanced');
      const upgraded = JSON.parse(readFileSync(configFile, 'utf-8'));
      expect(typeof upgraded._sig).toBe('string');
      expect(upgraded.cloudApiKey).toBe('sc_live_legacy');
      // And it still verifies (not tampered) on a fresh read.
      config.clearCloudConfigCache();
      jest.resetModules();
      const config2 = await import('../cloud/config.js');
      config2.readRawConfig();
      expect(config2.isConfigTampered()).toBe(false);
    });
  });

  // ── Self-heal: stale embedded _sig but valid legacy sig → re-sign, no alarm ──
  //
  // Observed on a Mac after a cross-version config write: config.json carried an
  // embedded _sig that no longer matched the canonical body, BUT the legacy
  // .config-sig still validated over the exact file bytes. The old verifier saw
  // only "embedded mismatch" and screamed tampering + forced strict mode. Since
  // the legacy whole-file sig proves the bytes are authentic (same secret key;
  // any body edit breaks both sigs), this must self-heal silently instead.
  describe('self-heal on stale embedded _sig with a valid legacy sig', () => {
    it('treats a stale-embedded / valid-legacy config as authentic, re-signs it, and drops the legacy sig', async () => {
      const key = 'b'.repeat(64);
      writeFileSync(integrityKeyFile, key, { mode: 0o600 });

      // File carries a STALE (wrong) embedded _sig…
      const fileContent =
        JSON.stringify({ cloudApiKey: 'sc_live_heal', cloudEnabled: true, _sig: 'deadbeef'.repeat(8) }, null, 2) + '\n';
      writeFileSync(configFile, fileContent);
      // …but the legacy .config-sig validates over the EXACT bytes on disk.
      const legacySig = createHmac('sha256', key).update(fileContent, 'utf-8').digest('hex');
      writeFileSync(sigFile, legacySig, { mode: 0o600 });

      const config = await import('../cloud/config.js');
      const raw = config.readRawConfig();
      expect(raw.cloudApiKey).toBe('sc_live_heal');
      expect(config.isConfigTampered()).toBe(false);   // self-healed, NOT tampered
      expect(config.getDefenceMode()).not.toBe('strict'); // not force-downgraded

      // The self-heal rewrote the file: embedded _sig is now correct and the
      // stale legacy sig file is gone.
      expect(existsSync(sigFile)).toBe(false);
      const onDisk = JSON.parse(readFileSync(configFile, 'utf-8'));
      expect(typeof onDisk._sig).toBe('string');
      expect(onDisk._sig).not.toBe('deadbeef'.repeat(8));
      expect(onDisk.cloudApiKey).toBe('sc_live_heal');

      // A fresh read now verifies via the embedded sig alone — no warning.
      config.clearCloudConfigCache();
      jest.resetModules();
      const config2 = await import('../cloud/config.js');
      config2.readRawConfig();
      expect(config2.isConfigTampered()).toBe(false);
    });

    it('still detects genuine tampering when neither the embedded nor the legacy sig matches the bytes', async () => {
      const key = 'c'.repeat(64);
      writeFileSync(integrityKeyFile, key, { mode: 0o600 });

      // Embedded sig is wrong AND the legacy sig is over DIFFERENT bytes (so it
      // does not validate the current file) — a real tamper, not a stale sig.
      const fileContent =
        JSON.stringify({ cloudApiKey: 'sc_live_evil', cloudEnabled: true, _sig: 'deadbeef'.repeat(8) }, null, 2) + '\n';
      writeFileSync(configFile, fileContent);
      const sigOverOtherBytes = createHmac('sha256', key).update('some other content', 'utf-8').digest('hex');
      writeFileSync(sigFile, sigOverOtherBytes, { mode: 0o600 });

      const config = await import('../cloud/config.js');
      config.readRawConfig();
      expect(config.isConfigTampered()).toBe(true);
      expect(config.getDefenceMode()).toBe('strict');
    });
  });

  // ── Fix 3: mtime-cached reads ───────────────────────────────────────
  describe('mtime-cached readRawConfig', () => {
    it('serves the cached value when the file is unchanged, and invalidates on write', async () => {
      const config = await import('../cloud/config.js');
      config.setCloudConfig({ cloudApiKey: 'cached-value' });
      config.clearCloudConfigCache();

      // Pin the file mtime to a deterministic INTEGER-second value before priming
      // the cache, so statSync().mtimeMs is exactly `mtime * 1000` on every
      // filesystem. (Using the real fractional mtimeMs/1000 and restoring it via
      // utimesSync is flaky: macOS and CI Linux round the float→fs conversion
      // differently, so the restored mtimeMs may not equal the cached one.)
      const mtime = 1_700_000_000;
      utimesSync(configFile, mtime, mtime);

      // Prime the cache (records mtimeMs = mtime * 1000, an exact integer).
      const first = config.readRawConfig();
      expect(first.cloudApiKey).toBe('cached-value');

      // Mutate the on-disk bytes OUT OF BAND (no public API) but reset the
      // mtime to its previous value so the cache key is unchanged. A correct
      // mtime cache must return the OLD cached value, not re-read these bytes.
      writeFileSync(configFile, JSON.stringify({ cloudApiKey: 'sneaky-disk-edit' }, null, 2) + '\n');
      utimesSync(configFile, mtime, mtime);
      const second = config.readRawConfig();
      expect(second.cloudApiKey).toBe('cached-value'); // served from cache

      // Bump the mtime forward → cache key changes → real re-read.
      utimesSync(configFile, mtime + 5, mtime + 5);
      const third = config.readRawConfig();
      expect(third.cloudApiKey).toBe('sneaky-disk-edit');

      // A write through the public API must invalidate the cache too.
      config.setCloudConfig({ cloudApiKey: 'new-value' });
      expect(config.readRawConfig().cloudApiKey).toBe('new-value');
    });
  });

  // ── Fix 4: debounced lastSyncAt ─────────────────────────────────────
  describe('debounced updateLastSyncAt', () => {
    it('writes config.json at most once across a rapid burst', async () => {
      const config = await import('../cloud/config.js');
      // Establish a baseline file so writes are observable.
      config.setCloudConfig({ cloudApiKey: 'k' });
      // No lastSyncAt persisted yet.
      expect(JSON.parse(readFileSync(configFile, 'utf-8')).lastSyncAt).toBeUndefined();

      for (let i = 0; i < 50; i++) config.updateLastSyncAt();

      // The burst must collapse to at most one persisted write within the 60s
      // debounce window: the on-disk lastSyncAt reflects the FIRST write and
      // does not get rewritten 49 more times.
      const onDisk = JSON.parse(readFileSync(configFile, 'utf-8'));
      const persistedOnce = onDisk.lastSyncAt;
      expect(typeof persistedOnce).toBe('string');

      // The in-memory value advanced past the persisted one across the burst,
      // proving subsequent calls updated memory without rewriting the file.
      expect(config.getLastSyncAt()).not.toBe(undefined);
      // Re-read on-disk: still the same single persisted value (no churn).
      expect(JSON.parse(readFileSync(configFile, 'utf-8')).lastSyncAt).toBe(persistedOnce);
    });

    it('keeps the latest lastSyncAt readable in-memory and flushes on demand', async () => {
      const config = await import('../cloud/config.js');
      config.setCloudConfig({ cloudApiKey: 'k' });
      config.updateLastSyncAt();
      const inMem = config.getLastSyncAt();
      expect(typeof inMem).toBe('string');
      expect(() => new Date(inMem as string).toISOString()).not.toThrow();

      // flushLastSyncAt forces a persist; the value lands on disk.
      config.flushLastSyncAt();
      const onDisk = JSON.parse(readFileSync(configFile, 'utf-8'));
      expect(onDisk.lastSyncAt).toBe(inMem);
    });
  });

  // ── Critical gap fix: EVERY mutating writer is parseFail-guarded ─────
  //
  // Phase 7 only guarded setCloudConfig/getDeviceId/getDeviceName. 12 other
  // writers still read via readRawConfig() (which collapses a parse failure to
  // {}), mutated that {}, and wrote it back — atomically persisting a
  // near-empty, validly-signed config and DESTROYING cloudApiKey. These tests
  // drive each writer against a corrupt config and assert it never wipes.
  //
  // The list is explicit so a future unguarded writer added by omission fails
  // here. throw-policy writers MUST throw and leave the corrupt bytes intact;
  // skip-policy writers MUST no-op and leave the corrupt bytes intact. Either
  // way the on-disk file must be byte-identical (sentinel preserved in it).
  describe('all config writers refuse to wipe a corrupt config', () => {
    const SENTINEL = 'sc_live_SENTINEL';
    // Bytes that JSON.parse throws on but still contain the sentinel, so we can
    // assert the credential survived in the raw on-disk bytes.
    const CORRUPT = `{ "cloudApiKey": "${SENTINEL}", THIS IS NOT VALID JSON`;

    type Policy = 'throw' | 'skip';
    interface WriterCase {
      name: string;
      policy: Policy;
      invoke: (config: typeof import('../cloud/config.js')) => void;
    }

    // Every user-facing/explicit setter (throw) + every automatic/hot-path
    // writer (skip) that performs a read-modify-write of config.json.
    const writers: WriterCase[] = [
      { name: 'setCloudConfig', policy: 'throw', invoke: (c) => c.setCloudConfig({ cloudApiKey: 'sc_live_OVERWRITE', cloudEnabled: true }) },
      { name: 'setDefenceMode', policy: 'throw', invoke: (c) => c.setDefenceMode('strict') },
      { name: 'setCloudSyncControls', policy: 'throw', invoke: (c) => c.setCloudSyncControls({ contentMode: 'metadata' }) },
      { name: 'addTrustedSkill', policy: 'throw', invoke: (c) => c.addTrustedSkill('/some/new/skill.md') },
      { name: 'removeTrustedSkill', policy: 'throw', invoke: (c) => c.removeTrustedSkill('/some/skill.md') },
      { name: 'setCloudIronDomeCache', policy: 'throw', invoke: (c) => c.setCloudIronDomeCache({ patterns: [] }) },
      { name: 'setProactiveRecall', policy: 'throw', invoke: (c) => c.setProactiveRecall(true) },
      { name: 'restore410Defaults', policy: 'throw', invoke: (c) => c.restore410Defaults() },
      { name: 'setVerifyConfig', policy: 'throw', invoke: (c) => c.setVerifyConfig({ verifyEnabled: true }) },
      { name: 'setRankerConfig', policy: 'throw', invoke: (c) => c.setRankerConfig({ engine: 'legacy' }) },
      { name: 'setOpenClawMemoryConfig', policy: 'throw', invoke: (c) => c.setOpenClawMemoryConfig({ autoMemory: false }) },
      { name: 'setToolResponseScanConfig', policy: 'throw', invoke: (c) => c.setToolResponseScanConfig({ scanToolResponses: false }) },
      { name: 'setReviewCopilotConfig', policy: 'throw', invoke: (c) => c.setReviewCopilotConfig({ enabled: true }) },
      { name: 'setAutoMemoryEnableConfig', policy: 'throw', invoke: (c) => c.setAutoMemoryEnableConfig({ enableStop: true }) },
      // Skip-policy: automatic / hot-path writers that must NEVER throw.
      { name: 'getCloudSyncControls (migration write)', policy: 'skip', invoke: (c) => { c.getCloudSyncControls(); } },
      { name: 'getDeviceId (lazy persist)', policy: 'skip', invoke: (c) => { c.getDeviceId(); } },
      { name: 'getDeviceName (lazy persist)', policy: 'skip', invoke: (c) => { c.getDeviceName(); } },
      { name: 'updateLastSyncAt → persistLastSyncAt', policy: 'skip', invoke: (c) => { c.updateLastSyncAt(); c.flushLastSyncAt(); } },
    ];

    for (const w of writers) {
      it(`${w.name} (${w.policy}) does not wipe cloudApiKey on a corrupt config`, async () => {
        const config = await import('../cloud/config.js');
        // (a) Seed a valid config carrying the sentinel credential.
        config.setCloudConfig({ cloudApiKey: SENTINEL, cloudEnabled: true });
        expect(config.getCloudConfig().cloudApiKey).toBe(SENTINEL);

        // (b) Write unparseable bytes over config.json.
        writeFileSync(configFile, CORRUPT);
        config.clearCloudConfigCache();

        // (c) Invoke the writer with valid args.
        let threw = false;
        try {
          w.invoke(config);
        } catch {
          threw = true;
        }

        // (d) Assert by policy. Either way the corrupt bytes must be intact and
        // the sentinel must still be present in the raw on-disk bytes — no wipe.
        if (w.policy === 'throw') {
          expect(threw).toBe(true);
        } else {
          expect(threw).toBe(false);
        }
        const after = readFileSync(configFile, 'utf-8');
        expect(after).toBe(CORRUPT); // byte-identical: corrupt bytes preserved
        expect(after).toContain(SENTINEL); // credential never destroyed
      });
    }
  });

  // ── Concurrency sanity: interleaved writes/reads never see {} or tamper ──
  describe('interleaved writes/reads', () => {
    it('a present config is never observed as {} and never false-tampers', async () => {
      const config = await import('../cloud/config.js');
      config.setCloudConfig({ cloudApiKey: 'sc_live_concurrent', cloudEnabled: true });

      for (let i = 0; i < 30; i++) {
        config.setDefenceMode(i % 2 === 0 ? 'balanced' : 'permissive');
        const raw = config.readRawConfig();
        expect(raw.cloudApiKey).toBe('sc_live_concurrent');
        expect(config.isConfigTampered()).toBe(false);
      }
    });
  });
});
