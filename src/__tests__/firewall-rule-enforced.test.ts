import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { initDatabase, getDatabase, closeDatabase, isDatabaseInitialized } from '../database/init.js';
import { getEnabledFirewallRules } from '../defence/custom-rules/store.js';
import { runDefencePipeline } from '../defence/pipeline.js';

/**
 * Phase 1a regression guard for the firewall-rule application path.
 *
 * The defence pipeline loads ./custom-rules/store.js lazily via require()
 * inside a try/catch (kept lazy on purpose: avoids eager-loading the DB layer
 * and dodges an import cycle). Under real Node ESM a bare require() throws
 * ReferenceError, the surrounding catch swallows it, and the entire
 * firewall-rule layer silently no-ops — content that should be blocked sails
 * through. The fix is a createRequire() shim at the top of pipeline.ts.
 *
 * IMPORTANT — why this asserts via the store, not only the pipeline:
 * ts-jest runs under `"type": "module"`, so Node refuses require() of an ESM
 * module *regardless* of createRequire — `Must use import to load ES Module`.
 * That means the pipeline's lazy-require path CANNOT be exercised under jest at
 * all (with or without the bug). The genuine proof that createRequire fixes the
 * runtime is the compiled-dist harness running under real Node ESM, plus the
 * `npm run test:dist` bare-require guard. This test guards the data + query +
 * regex contract those rely on: the exact store function the pipeline requires
 * returns the seeded enabled block rule, and that rule's condition matches the
 * content. If this contract breaks, the dist path has nothing to act on.
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
      .run('test:block-sentinel', 1, 'keyword', KEYWORD, 'block', 1, 1);
  });

  afterAll(() => {
    closeDatabase();
  });

  it('exposes the seeded enabled block rule via the store the pipeline requires', () => {
    expect(isDatabaseInitialized()).toBe(true);

    const rules = getEnabledFirewallRules();
    const seeded = rules.find((r) => r.name === 'test:block-sentinel');

    expect(seeded).toBeDefined();
    expect(seeded!.enabled).toBe(1);
    expect(seeded!.action).toBe('block');
    expect(seeded!.condition_value).toBe(KEYWORD);

    // The pipeline blocks when `new RegExp(rule.condition_value, 'gi')` matches
    // the content — assert that predicate here so the rule is genuinely
    // actionable, not just present.
    const regex = new RegExp(seeded!.condition_value, 'gi');
    expect(regex.test(`a harmless note about ${KEYWORD}`)).toBe(true);
  });

  it('runDefencePipeline returns a verdict for matching content (smoke)', () => {
    // Smoke-level: confirms the pipeline runs end-to-end with rules seeded and
    // never fails-open by throwing. The authoritative block assertion lives in
    // the dist harness (real Node ESM) — see the file header.
    const result = runDefencePipeline(
      `a harmless note about ${KEYWORD}`,
      'note',
      { type: 'user', identifier: 't' },
    );
    expect(result).toHaveProperty('allowed');
    expect(result).toHaveProperty('firewall');
  });
});
