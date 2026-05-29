import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

/**
 * Fix #3 — cloud sync defaults to shipping CONFIDENTIAL memory content.
 *
 * These tests pin the v4.27 safety contract:
 *   1. Fresh-default `CloudSyncControls` excludes CONFIDENTIAL+ memories
 *      from sync, so `shouldSyncRecord({ sensitivity_level: 'CONFIDENTIAL' })`
 *      returns false without any user action.
 *   2. Pre-upgrade configs that had `cloudEnabled: true` and never picked an
 *      explicit `cloudSyncExcludeSensitive` value get migrated once — the
 *      rewritten config file carries `cloudSyncExcludeSensitive: true` and
 *      a `cloudSyncDefaultsMigratedAt` timestamp so the migration doesn't
 *      re-run.
 *   3. Configs that already have an explicit `cloudSyncExcludeSensitive`
 *      (true OR false) are left alone — the user already chose.
 */

const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;

describe('cloud sync safety defaults', () => {
  let tempDir: string;
  let configDir: string;
  let configFile: string;

  beforeEach(() => {
    jest.resetModules();
    tempDir = mkdtempSync(join(tmpdir(), 'sc-sync-defaults-'));
    configDir = join(tempDir, '.shieldcortex');
    mkdirSync(configDir, { recursive: true });
    configFile = join(configDir, 'config.json');
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
    if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
  });

  describe('default CloudSyncControls', () => {
    it('excludeSensitive defaults to true on a fresh install', async () => {
      const { getCloudSyncControls } = await import('../config.js');
      const controls = getCloudSyncControls();
      expect(controls.excludeSensitive).toBe(true);
    });

    it('contentMode stays full so opt-in PUBLIC/INTERNAL sync still works', async () => {
      const { getCloudSyncControls } = await import('../config.js');
      const controls = getCloudSyncControls();
      expect(controls.contentMode).toBe('full');
    });
  });

  describe('shouldSyncRecord on fresh-default config', () => {
    it('returns false for a CONFIDENTIAL record', async () => {
      // memory-sync.ts pulls getDatabase at module load but shouldSyncRecord
      // itself does not touch the DB, so we can call it directly without
      // initialising SQLite.
      const { shouldSyncRecord } = await import('../memory-sync.js');
      const result = shouldSyncRecord({
        project: 'demo',
        sensitivity_level: 'CONFIDENTIAL',
        cloud_excluded: false,
      });
      expect(result).toBe(false);
    });

    it('returns false for RESTRICTED records as well', async () => {
      const { shouldSyncRecord } = await import('../memory-sync.js');
      expect(
        shouldSyncRecord({
          project: 'demo',
          sensitivity_level: 'RESTRICTED',
          cloud_excluded: false,
        }),
      ).toBe(false);
    });

    it('still allows PUBLIC and INTERNAL records through', async () => {
      const { shouldSyncRecord } = await import('../memory-sync.js');
      expect(
        shouldSyncRecord({
          project: 'demo',
          sensitivity_level: 'PUBLIC',
          cloud_excluded: false,
        }),
      ).toBe(true);
      expect(
        shouldSyncRecord({
          project: 'demo',
          sensitivity_level: 'INTERNAL',
          cloud_excluded: false,
        }),
      ).toBe(true);
    });

    it('honours an explicit opt-back-in via setCloudSyncControls', async () => {
      const { shouldSyncRecord } = await import('../memory-sync.js');
      const { setCloudSyncControls } = await import('../config.js');
      setCloudSyncControls({ excludeSensitive: false });
      expect(
        shouldSyncRecord({
          project: 'demo',
          sensitivity_level: 'CONFIDENTIAL',
          cloud_excluded: false,
        }),
      ).toBe(true);
    });
  });

  describe('one-shot migration in getCloudSyncControls', () => {
    it('rewrites legacy configs (cloudEnabled, no excludeSensitive field) to the safe default', async () => {
      // Seed a pre-v4.27 config: cloud is on but excludeSensitive was never
      // chosen, so it implicitly defaulted to false (the unsafe legacy).
      writeFileSync(
        configFile,
        JSON.stringify(
          {
            cloudEnabled: true,
            cloudApiKey: 'sc_test_legacy_user_key',
            cloudBaseUrl: 'https://api.shieldcortex.ai',
          },
          null,
          2,
        ),
      );

      const { getCloudSyncControls } = await import('../config.js');
      const controls = getCloudSyncControls();
      expect(controls.excludeSensitive).toBe(true);

      // The migration must have been persisted to disk so it doesn't re-run.
      const rewritten = JSON.parse(readFileSync(configFile, 'utf-8'));
      expect(rewritten.cloudSyncExcludeSensitive).toBe(true);
      expect(typeof rewritten.cloudSyncDefaultsMigratedAt).toBe('string');
      // ISO-8601 sanity check.
      expect(() => new Date(rewritten.cloudSyncDefaultsMigratedAt as string).toISOString()).not.toThrow();

      // Other config keys must survive the rewrite.
      expect(rewritten.cloudEnabled).toBe(true);
      expect(rewritten.cloudApiKey).toBe('sc_test_legacy_user_key');
    });

    it('leaves configs with an explicit excludeSensitive=false alone', async () => {
      writeFileSync(
        configFile,
        JSON.stringify(
          {
            cloudEnabled: true,
            cloudApiKey: 'sc_test_opted_in',
            cloudSyncExcludeSensitive: false,
          },
          null,
          2,
        ),
      );

      const { getCloudSyncControls } = await import('../config.js');
      const controls = getCloudSyncControls();
      expect(controls.excludeSensitive).toBe(false);

      const after = JSON.parse(readFileSync(configFile, 'utf-8'));
      expect(after.cloudSyncExcludeSensitive).toBe(false);
      // No migration stamp — the user already chose, nothing to migrate.
      expect(after.cloudSyncDefaultsMigratedAt).toBeUndefined();
    });

    it('leaves configs with cloud disabled alone (nothing to migrate)', async () => {
      writeFileSync(
        configFile,
        JSON.stringify({ cloudEnabled: false }, null, 2),
      );

      const { getCloudSyncControls } = await import('../config.js');
      const controls = getCloudSyncControls();
      expect(controls.excludeSensitive).toBe(true); // default-resolved

      const after = JSON.parse(readFileSync(configFile, 'utf-8'));
      // We did not touch the file because the user hadn't opted into cloud.
      expect(after.cloudSyncExcludeSensitive).toBeUndefined();
      expect(after.cloudSyncDefaultsMigratedAt).toBeUndefined();
    });

    it('does not re-run the migration if the stamp is already present', async () => {
      const firstStamp = '2026-01-01T00:00:00.000Z';
      writeFileSync(
        configFile,
        JSON.stringify(
          {
            cloudEnabled: true,
            cloudApiKey: 'sc_test_already_migrated',
            cloudSyncExcludeSensitive: true,
            cloudSyncDefaultsMigratedAt: firstStamp,
          },
          null,
          2,
        ),
      );

      const { getCloudSyncControls } = await import('../config.js');
      getCloudSyncControls();

      const after = JSON.parse(readFileSync(configFile, 'utf-8'));
      expect(after.cloudSyncDefaultsMigratedAt).toBe(firstStamp);
    });

    it('does not create a config file when none existed', async () => {
      // Fresh install path: no config file, nothing to migrate.
      expect(existsSync(configFile)).toBe(false);
      const { getCloudSyncControls } = await import('../config.js');
      const controls = getCloudSyncControls();
      expect(controls.excludeSensitive).toBe(true);
      expect(existsSync(configFile)).toBe(false);
    });
  });
});
