/**
 * Ranker config resolver — env > file > default precedence.
 *
 * Covers Step A.4 of v4.15: SHIELDCORTEX_RANKER env var, ranker.engine
 * persisted in ~/.shieldcortex/config.json, and the fallback to 'rrf' when
 * neither is set. Also covers `setRankerConfig` round-tripping through the
 * raw config writer (HMAC-signed) without dropping unrelated keys.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const originalRankerEnv = process.env.SHIELDCORTEX_RANKER;

describe('ranker config resolver', () => {
  let tempDir: string;
  let configDir: string;

  beforeEach(() => {
    jest.resetModules();
    tempDir = mkdtempSync(join(tmpdir(), 'sc-ranker-cfg-'));
    configDir = join(tempDir, '.shieldcortex');
    mkdirSync(configDir, { recursive: true });
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
    delete process.env.SHIELDCORTEX_RANKER;
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
    if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
    if (originalRankerEnv === undefined) delete process.env.SHIELDCORTEX_RANKER;
    else process.env.SHIELDCORTEX_RANKER = originalRankerEnv;
  });

  it('defaults to rrf when no env var or config file is present', async () => {
    const { getRankerConfig } = await import('../cloud/config.js');
    const cfg = getRankerConfig();
    expect(cfg.engine).toBe('rrf');
    expect(cfg.rrfK).toBe(60);
    expect(cfg.weights).toEqual({ fts: 0.4, vector: 0.6, graph: 0.3 });
  });

  it('honours ranker.engine = legacy from config.json', async () => {
    // Write directly first; the integrity HMAC will be created on first read
    // and the first-run path treats the unsigned config as legitimate.
    writeFileSync(
      join(configDir, 'config.json'),
      JSON.stringify({ ranker: { engine: 'legacy' } }, null, 2),
    );
    const { getRankerConfig } = await import('../cloud/config.js');
    expect(getRankerConfig().engine).toBe('legacy');
  });

  it('SHIELDCORTEX_RANKER=legacy env overrides rrf in config.json', async () => {
    writeFileSync(
      join(configDir, 'config.json'),
      JSON.stringify({ ranker: { engine: 'rrf' } }, null, 2),
    );
    process.env.SHIELDCORTEX_RANKER = 'legacy';
    const { getRankerConfig } = await import('../cloud/config.js');
    expect(getRankerConfig().engine).toBe('legacy');
  });

  it('SHIELDCORTEX_RANKER=rrf env overrides legacy in config.json', async () => {
    writeFileSync(
      join(configDir, 'config.json'),
      JSON.stringify({ ranker: { engine: 'legacy' } }, null, 2),
    );
    process.env.SHIELDCORTEX_RANKER = 'rrf';
    const { getRankerConfig } = await import('../cloud/config.js');
    expect(getRankerConfig().engine).toBe('rrf');
  });

  it('invalid SHIELDCORTEX_RANKER value falls through to config.json', async () => {
    writeFileSync(
      join(configDir, 'config.json'),
      JSON.stringify({ ranker: { engine: 'legacy' } }, null, 2),
    );
    process.env.SHIELDCORTEX_RANKER = 'turbo'; // not a valid engine
    const { getRankerConfig } = await import('../cloud/config.js');
    expect(getRankerConfig().engine).toBe('legacy');
  });

  it('reads custom rrfK and weights from config.json', async () => {
    writeFileSync(
      join(configDir, 'config.json'),
      JSON.stringify({
        ranker: {
          engine: 'rrf',
          rrfK: 42,
          weights: { fts: 0.5, vector: 0.7, graph: 0.2 },
        },
      }, null, 2),
    );
    const { getRankerConfig } = await import('../cloud/config.js');
    const cfg = getRankerConfig();
    expect(cfg.rrfK).toBe(42);
    expect(cfg.weights).toEqual({ fts: 0.5, vector: 0.7, graph: 0.2 });
  });

  it('partial weights in config.json fall back to defaults (no half-applied)', async () => {
    writeFileSync(
      join(configDir, 'config.json'),
      JSON.stringify({ ranker: { engine: 'rrf', weights: { fts: 0.5 } } }, null, 2),
    );
    const { getRankerConfig } = await import('../cloud/config.js');
    const cfg = getRankerConfig();
    expect(cfg.weights).toEqual({ fts: 0.4, vector: 0.6, graph: 0.3 });
  });

  it('setRankerConfig persists engine without dropping unrelated keys', async () => {
    writeFileSync(
      join(configDir, 'config.json'),
      JSON.stringify({ cloudEnabled: true, defenceMode: 'strict' }, null, 2),
    );
    const { setRankerConfig, getRankerConfig } = await import('../cloud/config.js');
    setRankerConfig({ engine: 'legacy' });

    const persisted = JSON.parse(readFileSync(join(configDir, 'config.json'), 'utf-8'));
    expect(persisted.cloudEnabled).toBe(true);
    expect(persisted.defenceMode).toBe('strict');
    expect(persisted.ranker.engine).toBe('legacy');
    expect(getRankerConfig().engine).toBe('legacy');
  });

  it('setRankerConfig honours partial updates (engine only, weights only)', async () => {
    const { setRankerConfig, getRankerConfig } = await import('../cloud/config.js');
    setRankerConfig({ engine: 'legacy' });
    expect(getRankerConfig().engine).toBe('legacy');
    expect(getRankerConfig().weights).toEqual({ fts: 0.4, vector: 0.6, graph: 0.3 });

    setRankerConfig({ weights: { fts: 0.1, vector: 0.2, graph: 0.3 } });
    expect(getRankerConfig().engine).toBe('legacy'); // preserved
    expect(getRankerConfig().weights).toEqual({ fts: 0.1, vector: 0.2, graph: 0.3 });
  });
});
