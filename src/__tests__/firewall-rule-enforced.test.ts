import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { initDatabase, getDatabase, closeDatabase, isDatabaseInitialized } from '../database/init.js';
import { getEnabledFirewallRules } from '../defence/custom-rules/store.js';
import { runDefencePipeline } from '../defence/pipeline.js';

/**
 * Phase 1a regression guard for the firewall-rule application path.
 *
 * The defence pipeline applies enabled firewall rules from
 * ./custom-rules/store.js (a STATIC top-level import — see pipeline.ts). The
 * earlier createRequire(import.meta.url).require('./store.js') seam only worked
 * on Node >=22 (the require(esm) feature); on Node 20 it threw ERR_REQUIRE_ESM,
 * which the surrounding catch swallowed — silently no-opping the entire
 * firewall-rule layer so content that should be BLOCKED sailed through.
 *
 * Now that the seam is a static import, the ts-jest ESM environment can drive
 * the real block path (no require(esm) involved), so this asserts the genuine
 * verdict: a seeded enabled `block` rule on KEYWORD makes runDefencePipeline
 * return allowed === false. The compiled-dist harness (real Node ESM) and the
 * `npm run test:dist` guard remain the authoritative proof at the dist layer.
 */
describe('firewall rules are applied by the scan pipeline', () => {
  const KEYWORD = 'zebra-unicorn-sentinel';

  beforeAll(() => {
    closeDatabase();
    initDatabase(':memory:');
    // built_in=1 so the rule evaluates regardless of the Pro
    // `custom_firewall_rules` feature gate (the pipeline only skips
    // *user-added* rules when that feature is off).
    getDatabase()
      .prepare(
        `INSERT INTO firewall_rules (name, priority, condition_type, condition_value, action, enabled, built_in)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run('test:block-sentinel', 100, 'keyword', KEYWORD, 'block', 1, 1);
  });

  afterAll(() => {
    closeDatabase();
  });

  it('exposes the seeded enabled block rule via the store the pipeline imports', () => {
    expect(isDatabaseInitialized()).toBe(true);

    const rules = getEnabledFirewallRules();
    const seeded = rules.find((r) => r.name === 'test:block-sentinel');

    expect(seeded).toBeDefined();
    expect(seeded!.enabled).toBe(1);
    expect(seeded!.action).toBe('block');
    expect(seeded!.condition_value).toBe(KEYWORD);
  });

  it('runDefencePipeline BLOCKS content matching an enabled block rule', () => {
    const result = runDefencePipeline(
      `a harmless note about ${KEYWORD}`,
      'note',
      { type: 'user', identifier: 't' },
    );

    expect(result.allowed).toBe(false);
    expect(result.firewall.result).toBe('BLOCK');
    expect(result.firewall.reason).toContain('test:block-sentinel');
  });

  it('runDefencePipeline ALLOWS content that does not match any rule', () => {
    const result = runDefencePipeline(
      'an entirely unremarkable note',
      'note',
      { type: 'user', identifier: 't' },
    );

    expect(result.allowed).toBe(true);
  });
});
