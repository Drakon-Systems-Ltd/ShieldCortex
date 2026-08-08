import { describe, it, expect } from '@jest/globals';
import plugin from '../index.js';

/**
 * Issue #209 — single source of truth for Action Guard config, plugin side.
 *
 * Before this fix the plugin read ONLY `interceptor.actionGuard`, while the
 * Claude Code hook read ONLY top-level `actionGuard` — two keys, one guard,
 * silently divergent postures. The resolution: top-level `actionGuard` governs
 * every surface; `interceptor.actionGuard` stays as a deprecated alias that
 * fills per-key gaps. An explicit top-level value always wins.
 *
 * normaliseConfig folds the merged result into `interceptor.actionGuard`
 * internally so initInterceptor and everything downstream is untouched — the
 * alias dies at the parse boundary, not in the enforcement path.
 *
 * Hook-side contract: src/__tests__/pre-tool-hook-209-alias.test.ts.
 * Doctor surfacing: src/cli/__tests__/doctor-action-guard.test.ts.
 */

const parse = (value: unknown) => plugin.configSchema.parse(value) as any;

describe('plugin config — #209 top-level actionGuard single source of truth', () => {
  it('accepts a top-level actionGuard block and folds it into the interceptor config', () => {
    const parsed = parse({ actionGuard: { enforce: false } });
    expect(parsed.interceptor?.actionGuard?.enforce).toBe(false);
  });

  it('top-level values win over conflicting alias values', () => {
    const parsed = parse({
      actionGuard: { enforce: false },
      interceptor: { actionGuard: { enforce: true } },
    });
    expect(parsed.interceptor?.actionGuard?.enforce).toBe(false);
  });

  it('alias keys survive as gap-fill when the top-level block does not set them', () => {
    const parsed = parse({
      actionGuard: { enforce: false },
      interceptor: { actionGuard: { enabled: true, autoApprove: ['git_force_push'] } },
    });
    expect(parsed.interceptor?.actionGuard).toEqual({
      enforce: false,
      enabled: true,
      autoApprove: ['git_force_push'],
    });
  });

  it('alias-only config still works unchanged (back-compat)', () => {
    const parsed = parse({ interceptor: { actionGuard: { enforce: false } } });
    expect(parsed.interceptor?.actionGuard?.enforce).toBe(false);
  });

  it('invalid top-level values are dropped individually, valid siblings survive', () => {
    const parsed = parse({ actionGuard: { enabled: 'false', enforce: false } });
    expect(parsed.interceptor?.actionGuard?.enforce).toBe(false);
    expect(parsed.interceptor?.actionGuard?.enabled).toBeUndefined();
  });

  it('other interceptor keys are untouched by the fold', () => {
    const parsed = parse({
      actionGuard: { enforce: false },
      interceptor: { enabled: true, severityActions: { high: 'warn' } },
    });
    expect(parsed.interceptor?.enabled).toBe(true);
    expect(parsed.interceptor?.severityActions?.high).toBe('warn');
    expect(parsed.interceptor?.actionGuard?.enforce).toBe(false);
  });
});
