/**
 * #516 review: with the database singleton initialised (MCP/API server),
 * doctor's Iron Dome profile row must read the effective policy without
 * writing — the loader normalises trusted channels and writes them back.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { CloudIronDomeCache } from '../cloud/iron-dome-sync.js';
import type { IronDomeConfig } from '../defence/iron-dome/config.js';

const STAMP = '2020-01-01 00:00:00';

let cloudCache: CloudIronDomeCache | null = null;
let customPolicies = false;

const actualGate = await import('../license/gate.js');
const actualSync = await import('../cloud/iron-dome-sync.js');
jest.unstable_mockModule('../license/gate.js', () => ({
  ...actualGate,
  isFeatureEnabled: (feature: string) =>
    feature === 'custom_iron_dome_policies' ? customPolicies : actualGate.isFeatureEnabled(feature as never),
}));
jest.unstable_mockModule('../cloud/iron-dome-sync.js', () => ({
  ...actualSync,
  getCloudIronDomeCache: () => cloudCache,
  peekCloudIronDomeCache: () => cloudCache,
}));

const { initDatabase, closeDatabase, getDatabase } = await import('../database/init.js');
const { DEFAULT_IRON_DOME_CONFIG, IRON_DOME_PROFILES } = await import('../defence/iron-dome/config.js');
const ironDome = await import('../defence/iron-dome/index.js');
const { checkIronDomeProfile } = await import('../cli/doctor.js');

// Persisted shape that needs normalisation: `dashboard` missing from trusted channels.
const needsNormalising = (overrides: Partial<IronDomeConfig> = {}): IronDomeConfig => ({
  ...DEFAULT_IRON_DOME_CONFIG,
  enabled: true,
  trustedChannels: ['terminal', 'cli'],
  ...overrides,
});

describe('doctor Iron Dome profile on an initialised singleton (#516)', () => {
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-516-peek-'));
    dbPath = path.join(dir, 'memories.db');
    initDatabase(dbPath);
    cloudCache = null;
    customPolicies = false;
  });

  afterEach(() => {
    closeDatabase();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function store(config: IronDomeConfig): void {
    const db = getDatabase();
    db.exec(`CREATE TABLE IF NOT EXISTS iron_dome_config (
      key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT (datetime('now')))`);
    db.prepare('INSERT INTO iron_dome_config (key, value, updated_at) VALUES (?, ?, ?)')
      .run('config', JSON.stringify(config), STAMP);
  }

  function snapshot() {
    const db = getDatabase();
    const schema = db.prepare('SELECT type, name, sql FROM sqlite_master ORDER BY type, name').all() as Array<{ name: string }>;
    return {
      schema,
      row: schema.some((t) => t.name === 'iron_dome_config')
        ? db.prepare("SELECT value, updated_at FROM iron_dome_config WHERE key = 'config'").get()
        : null,
      changes: (db.prepare('SELECT total_changes() AS n').get() as { n: number }).n,
    };
  }

  it('leaves a row that needs normalisation untouched: value, timestamp and schema', async () => {
    store(needsNormalising());
    const before = snapshot();

    const result = await checkIronDomeProfile(dbPath);
    expect(result.status).toBe('warn');
    expect(result.message).toContain('default kill phrase');

    expect(snapshot()).toEqual(before);
    const row = before.row as { value: string; updated_at: string };
    expect(row.updated_at).toBe(STAMP);
    expect(JSON.parse(row.value).trustedChannels).toEqual(['terminal', 'cli']);

    // Still usable afterwards, and the regular loader still normalises.
    expect(ironDome.getEffectiveIronDomeConfig().trustedChannels).toContain('dashboard');
    const after = getDatabase().prepare("SELECT value, updated_at FROM iron_dome_config WHERE key = 'config'").get() as { value: string; updated_at: string };
    expect(JSON.parse(after.value).trustedChannels).toContain('dashboard');
  });

  it('does not create the config table when none exists', async () => {
    const before = snapshot();
    // Verdict follows the loader's in-memory fallback, which earlier tests set; only the store matters here.
    await checkIronDomeProfile(dbPath);
    expect(snapshot()).toEqual(before);
    expect(getDatabase().prepare("SELECT name FROM sqlite_master WHERE name = 'iron_dome_config'").get()).toBeUndefined();
  });

  it('peek and the loader agree on the effective policy', () => {
    store(needsNormalising({ killPhrase: 'my private stop trigger' }));
    const peeked = ironDome.peekEffectiveIronDomeConfig();
    expect(peeked.trustedChannels).toEqual(['terminal', 'cli', 'dashboard']);
    expect(ironDome.getEffectiveIronDomeConfig()).toEqual(peeked);
  });

  it('applies cloud policy over the local config', async () => {
    customPolicies = true;
    store(needsNormalising());
    cloudCache = {
      patterns: [],
      policy: { name: 'fleet', base_profile: 'school', config_overrides: { killPhrase: 'fleet stop trigger' } },
      patternsUpdatedAt: null,
      policyUpdatedAt: null,
      lastFetchedAt: STAMP,
    };
    const before = snapshot();

    const result = await checkIronDomeProfile(dbPath);
    expect(result).toMatchObject({ status: 'pass', message: 'school profile' });
    expect(snapshot()).toEqual(before);
  });

  it('keeps the local disabled flag above a cloud policy', async () => {
    customPolicies = true;
    store(needsNormalising({ enabled: false }));
    cloudCache = {
      patterns: [],
      policy: { name: 'fleet', base_profile: 'school', config_overrides: { killPhrase: 'fleet stop trigger' } },
      patternsUpdatedAt: null,
      policyUpdatedAt: null,
      lastFetchedAt: STAMP,
    };
    const result = await checkIronDomeProfile(dbPath);
    expect(result).toMatchObject({ status: 'info', message: 'Iron Dome not active — profile not checked' });
  });

  it('uses the persisted profile when neither custom nor cloud policy applies', async () => {
    store(needsNormalising({ ...IRON_DOME_PROFILES.school, killPhrase: 'private local stop' }));
    expect(await checkIronDomeProfile(dbPath)).toMatchObject({ status: 'pass', message: 'school profile' });
  });

  it('applies an active custom policy over cloud policy', async () => {
    customPolicies = true;
    store(needsNormalising());
    cloudCache = {
      patterns: [],
      policy: { name: 'fleet', base_profile: 'school', config_overrides: { killPhrase: 'fleet stop trigger' } },
      patternsUpdatedAt: null,
      policyUpdatedAt: null,
      lastFetchedAt: STAMP,
    };
    getDatabase().prepare('INSERT INTO iron_dome_policies (name, description, config, is_active) VALUES (?, ?, ?, 1)')
      .run('local', '', JSON.stringify({ baseProfile: 'paranoid' }));
    const before = snapshot();

    const result = await checkIronDomeProfile(dbPath);
    // Custom policy keeps the paranoid profile's stock phrase, so it warns where cloud would pass.
    expect(IRON_DOME_PROFILES.paranoid.killPhrase).toBe(DEFAULT_IRON_DOME_CONFIG.killPhrase);
    expect(result.status).toBe('warn');
    expect(result.message).toContain('default kill phrase');
    expect(snapshot()).toEqual(before);
  });
});
