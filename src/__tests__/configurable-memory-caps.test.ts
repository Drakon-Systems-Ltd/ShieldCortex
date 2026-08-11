import { createHmac } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { resolveMemoryConfig, validateCap, MIN_MEMORY_CAP, __resetCapWarningsForTest } from '../memory/config.js';
import { DEFAULT_CONFIG } from '../memory/types.js';

/**
 * Operator-configurable memory caps — follow-up to #236 (suggestion 4).
 *
 * `maxShortTermMemories`/`maxLongTermMemories` were hardcoded in
 * `DEFAULT_CONFIG` with no user-config path, so raising the ceiling meant
 * editing `dist/`. That ceiling is not cosmetic: once a store reaches it, every
 * surviving write permanently evicts an older memory, so it is the point at
 * which the product starts forgetting on the operator's behalf.
 *
 * The properties pinned here, in order of how much damage getting them wrong
 * would do:
 *   1. A cap of 0/negative is REFUSED, not honoured. Honouring it would make
 *      the next enforcement pass a store-wipe — an operator fat-fingering a
 *      zero must not lose their memory.
 *   2. Invalid values fall back to the default and are refused LOUDLY. A
 *      silently-ignored config key is the #225 defect class: the operator
 *      believes they configured something and nothing says otherwise.
 *   3. No config, unreadable config, or a malformed block ⇒ exactly today's
 *      defaults. This sits on the write path; it must never throw.
 *
 * Harness follows expiry-rules.test.ts: a fresh SHIELDCORTEX_CONFIG_DIR per
 * test (so readRawConfig's mtime cache cannot serve a stale read between
 * cases) with an integrity-signed body (so the reader does not fall back to
 * tamper mode instead of parsing what we wrote).
 */

const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
let tempDir: string;
let configDir: string;

/** Write an integrity-signed config.json the reader will actually trust. */
function writeConfig(obj: unknown): void {
  const key = 'a'.repeat(64);
  writeFileSync(join(configDir, '.integrity-key'), key, { mode: 0o600 });
  const body = JSON.stringify(obj, null, 2) + '\n';
  writeFileSync(join(configDir, 'config.json'), body);
  const sig = createHmac('sha256', key).update(body, 'utf-8').digest('hex');
  writeFileSync(join(configDir, '.config-sig'), sig, { mode: 0o600 });
}

/** Write a body that is not valid JSON at all (still signed, so the failure
 *  under test is the PARSE, not the integrity check). */
function writeRawConfigBody(body: string): void {
  const key = 'a'.repeat(64);
  writeFileSync(join(configDir, '.integrity-key'), key, { mode: 0o600 });
  writeFileSync(join(configDir, 'config.json'), body);
  const sig = createHmac('sha256', key).update(body, 'utf-8').digest('hex');
  writeFileSync(join(configDir, '.config-sig'), sig, { mode: 0o600 });
}

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), 'sc-mem-caps-'));
  configDir = join(tempDir, '.shieldcortex');
  mkdirSync(configDir, { recursive: true });
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  __resetCapWarningsForTest();
});

afterEach(() => {
  rmSync(tempDir, { recursive: true, force: true });
  if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
});

describe('configurable caps — the happy path', () => {
  it('honours a raised long-term cap from the memory block', () => {
    writeConfig({ memory: { maxLongTermMemories: 5000 } });
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(5000);
  });

  it('honours a raised short-term cap', () => {
    writeConfig({ memory: { maxShortTermMemories: 250 } });
    expect(resolveMemoryConfig().maxShortTermMemories).toBe(250);
  });

  it('leaves every other MemoryConfig field untouched', () => {
    writeConfig({ memory: { maxLongTermMemories: 5000 } });
    const resolved = resolveMemoryConfig();
    expect(resolved.decayRate).toBe(DEFAULT_CONFIG.decayRate);
    expect(resolved.consolidationThreshold).toBe(DEFAULT_CONFIG.consolidationThreshold);
    expect(resolved.ranker).toEqual(DEFAULT_CONFIG.ranker);
    expect(resolved.maxShortTermMemories).toBe(DEFAULT_CONFIG.maxShortTermMemories);
  });

  it('does not mutate DEFAULT_CONFIG', () => {
    // A shared module-level object edited in place would leak the override into
    // every other consumer in the process.
    writeConfig({ memory: { maxLongTermMemories: 9999 } });
    resolveMemoryConfig();
    expect(DEFAULT_CONFIG.maxLongTermMemories).toBe(1000);
  });
});

describe('configurable caps — a bad value must never wipe the store', () => {
  it('REFUSES a cap of 0 — honouring it would evict everything', () => {
    // The whole reason validation exists: enforceMemoryLimits with cap 0 would
    // delete every eligible row on the next pass.
    writeConfig({ memory: { maxLongTermMemories: 0 } });
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
  });

  it('REFUSES a negative cap', () => {
    writeConfig({ memory: { maxLongTermMemories: -50 } });
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
  });

  it('REFUSES anything below the documented minimum', () => {
    writeConfig({ memory: { maxLongTermMemories: MIN_MEMORY_CAP - 1 } });
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
  });

  it('accepts exactly the minimum', () => {
    writeConfig({ memory: { maxLongTermMemories: MIN_MEMORY_CAP } });
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(MIN_MEMORY_CAP);
  });

  it('refuses a numeric STRING rather than coercing it', () => {
    // Matches the `=== true` discipline used for config booleans: a value the
    // loader silently reinterprets is one the operator cannot reason about.
    writeConfig({ memory: { maxLongTermMemories: '5000' } });
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
  });

  it('refuses fractional, NaN and Infinity', () => {
    for (const bad of [10.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      __resetCapWarningsForTest();
      writeConfig({ memory: { maxLongTermMemories: bad } });
      expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
    }
  });

  it('rejects a bad value LOUDLY — a silently-ignored key is the #225 defect class', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      writeConfig({ memory: { maxLongTermMemories: 0 } });
      resolveMemoryConfig();
      const said = warn.mock.calls.map((c) => String(c[0])).join('\n');
      expect(said).toMatch(/maxLongTermMemories/);
      expect(said.toLowerCase()).toMatch(/ignoring|default/);
    } finally {
      warn.mockRestore();
    }
  });

  it('warns once per key, not once per write', () => {
    // This sits on the write path; a warning per insert would be a log flood.
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      writeConfig({ memory: { maxLongTermMemories: -1 } });
      resolveMemoryConfig();
      resolveMemoryConfig();
      resolveMemoryConfig();
      const hits = warn.mock.calls.filter((c) => String(c[0]).includes('maxLongTermMemories'));
      expect(hits).toHaveLength(1);
    } finally {
      warn.mockRestore();
    }
  });

  it('a bad value for one cap does not discard a good value for the other', () => {
    writeConfig({ memory: { maxLongTermMemories: 4000, maxShortTermMemories: -5 } });
    const resolved = resolveMemoryConfig();
    expect(resolved.maxLongTermMemories).toBe(4000);
    expect(resolved.maxShortTermMemories).toBe(DEFAULT_CONFIG.maxShortTermMemories);
  });
});

describe('configurable caps — absent or broken config yields today\'s behaviour', () => {
  it('no config file at all ⇒ defaults', () => {
    // Fresh temp config dir, nothing written.
    expect(resolveMemoryConfig()).toEqual(DEFAULT_CONFIG);
  });

  it('config without a memory block ⇒ defaults', () => {
    writeConfig({ cloudEnabled: false });
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
  });

  it('a memory block of the wrong shape ⇒ defaults, no throw', () => {
    for (const junk of ['nope', 42, [], null]) {
      expect(() => resolveMemoryConfig()).not.toThrow();
      writeConfig({ memory: junk });
      expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
    }
  });

  it('unparseable JSON ⇒ defaults, no throw (never block a write on config)', () => {
    writeRawConfigBody('{ this is not json');
    expect(() => resolveMemoryConfig()).not.toThrow();
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
  });
});

describe('validateCap — the unit contract', () => {
  it('passes through a valid whole number at or above the minimum', () => {
    expect(validateCap(5000)).toBe(5000);
    expect(validateCap(MIN_MEMORY_CAP)).toBe(MIN_MEMORY_CAP);
  });

  it('returns undefined (keep the default) for every invalid shape', () => {
    for (const bad of [0, -1, 1.5, '100', null, {}, [], true, Number.NaN, Number.POSITIVE_INFINITY]) {
      __resetCapWarningsForTest();
      expect(validateCap(bad)).toBeUndefined();
    }
  });

  it('treats undefined as "not configured", silently', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      expect(validateCap(undefined)).toBeUndefined();
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });
});
