import path from 'path';
import { pathToFileURL } from 'url';
import { beforeAll, describe, expect, it } from '@jest/globals';
import type * as Toolsets from '../claude-toolsets.js';

/**
 * #679 review 2 — the reviewer's probes, run against the BUILT module
 * (`dist/integrations/claude-toolsets.js`) the way the review ran them.
 * `npm test` rebuilds a stale dist before Jest starts (scripts/run-jest.mjs).
 */

let mod: typeof Toolsets;

beforeAll(async () => {
  const built = path.resolve(process.cwd(), 'dist', 'integrations', 'claude-toolsets.js');
  mod = (await import(pathToFileURL(built).href)) as typeof Toolsets;
});

function makeGuard(overrides: Partial<Toolsets.ToolsetGuardOptions> = {}) {
  const events: Toolsets.ToolsetAuditEvent[] = [];
  const guard = new mod.ToolsetGuard({
    toolset: 'browser',
    urlAllowlist: ['docs.example.com'],
    audit: (e) => events.push(e),
    ...overrides,
  });
  return { guard, events };
}

describe('dist probe B1 — urlPolicy in observe mode checks and records (#679 review 2)', () => {
  it('observe urlPolicy on a script URL emits one values-free call event and does not throw', () => {
    const { guard, events } = makeGuard();
    expect(() => guard.urlPolicy()({ tabId: 't1' }, 'javascript:alert(1)')).not.toThrow();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ kind: 'call', member: 'navigate', mode: 'observe', decision: 'block', outcome: 'observed' });
    expect(events[0].signals).toEqual(expect.arrayContaining(['url-policy', 'url-scheme-script:javascript']));
    expect(JSON.stringify(events)).not.toContain('alert(1)');
  });

  it('observe urlPolicy records the host only, never path or query', () => {
    const { guard, events } = makeGuard();
    guard.urlPolicy()({}, 'https://evil.example/collect?d=SECRET-QUERY');
    expect(events).toHaveLength(1);
    expect(events[0].host).toBe('evil.example');
    expect(events[0].decision).toBe('require_approval');
    const s = JSON.stringify(events);
    expect(s).not.toContain('SECRET-QUERY');
    expect(s).not.toContain('/collect');
  });

  it('enforce urlPolicy also records, and throws only on block / ask', () => {
    const { guard, events } = makeGuard({ mode: 'enforce' });
    const policy = guard.urlPolicy();
    expect(() => policy({}, 'javascript:alert(1)')).toThrow(/not allowed/);
    expect(() => policy({}, 'https://docs.example.com/x')).not.toThrow();
    expect(events.map((e) => e.outcome)).toEqual(['refused', 'allowed']);
  });
});
