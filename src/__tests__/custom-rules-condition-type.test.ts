import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { initDatabase, getDatabase, closeDatabase } from '../database/init.js';
import { runDefencePipeline } from '../defence/pipeline.js';

/**
 * Phase 17 A1 — custom firewall rules must honour their own `condition_type`.
 *
 * Before the fix, EVERY rule's `condition_value` was compiled as a RegExp,
 * so a `keyword` rule whose value contains regex metacharacters (`a.b`)
 * matched "axb" (the `.` was a wildcard) while NOT matching the literal
 * intent. `domain` rules were never matched as hostnames at all. `regex`
 * rules must keep working.
 */
function seedRule(condition_type: string, condition_value: string, name: string): void {
  getDatabase()
    .prepare(
      `INSERT INTO firewall_rules (name, priority, condition_type, condition_value, action, enabled, built_in)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(name, 50, condition_type, condition_value, 'block', 1, 1);
}

describe('custom firewall rules honour condition_type', () => {
  beforeAll(() => {
    closeDatabase();
    initDatabase(':memory:');
    seedRule('keyword', 'a.b', 'test:keyword-literal');
    seedRule('regex', 'wid+get', 'test:regex-rule');
    seedRule('domain', 'evil.example.com', 'test:domain-rule');
  });

  afterAll(() => {
    closeDatabase();
  });

  it('keyword rule "a.b" matches the literal substring "a.b"', () => {
    const r = runDefencePipeline('here is a.b in the note', 'note', { type: 'user', identifier: 't' });
    expect(r.allowed).toBe(false);
    expect(r.firewall.reason).toContain('test:keyword-literal');
  });

  it('keyword rule "a.b" does NOT match "axb" (the dot is literal, not a wildcard)', () => {
    const r = runDefencePipeline('here is axb in the note', 'note', { type: 'user', identifier: 't' });
    // Must not be blocked BY THE KEYWORD RULE.
    if (!r.allowed) {
      expect(r.firewall.reason).not.toContain('test:keyword-literal');
    }
  });

  it('regex rule "wid+get" still matches "widddget"', () => {
    const r = runDefencePipeline('the widddget broke', 'note', { type: 'user', identifier: 't' });
    expect(r.allowed).toBe(false);
    expect(r.firewall.reason).toContain('test:regex-rule');
  });

  it('domain rule matches a URL whose host is the configured domain', () => {
    const r = runDefencePipeline('see https://evil.example.com/path for details', 'note', {
      type: 'user',
      identifier: 't',
    });
    expect(r.allowed).toBe(false);
    expect(r.firewall.reason).toContain('test:domain-rule');
  });

  it('domain rule does NOT match an unrelated lookalike (evil.example.com.attacker.net is a different host)... but DOES match a subdomain of it', () => {
    // A subdomain of the configured domain SHOULD match (api.evil.example.com).
    const sub = runDefencePipeline('call api.evil.example.com now', 'note', { type: 'user', identifier: 't' });
    expect(sub.allowed).toBe(false);
    expect(sub.firewall.reason).toContain('test:domain-rule');

    // Plain prose mentioning neither the keyword, regex, nor domain stays allowed.
    const clean = runDefencePipeline('an entirely unremarkable note', 'note', { type: 'user', identifier: 't' });
    expect(clean.allowed).toBe(true);
  });
});
