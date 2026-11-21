/**
 * SCN-010 review (Sol P3) — recall enrichment (`src/memory/lifecycle.ts`
 * `enrichMemory`) must not fail SILENTLY when the memory-directive screen
 * throws.
 *
 * Fail-open stays exactly as it was: the appended text goes on to the defence
 * pipeline scan as before SCN-010. What changes: each throw is counted
 * (`getEnrichmentDirectiveUnavailableCount`, apart from the refusal count) and
 * said once per process in fixed words — never the exception message, the
 * appended text or the title.
 *
 * The S module is replaced by one whose detector throws, so the REAL
 * lifecycle, store and pipeline run against it.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';

const SENTINEL = 'QZXV-SENTINEL-4419';

jest.unstable_mockModule('../defence/firewall/memory-directive-policy.js', () => ({
  MEMORY_DIRECTIVE_INDICATOR: 'memory_directive',
  MEMORY_DIRECTIVE_PATTERN: {
    CONTROL_RELAXATION: 'memory_directive:control_relaxation',
    CLAIMED_AUTHORITY: 'memory_directive:claimed_authority',
    CONCEALMENT: 'memory_directive:concealment',
    SECRET_ROUTING: 'memory_directive:secret_routing',
    IDENTITY_OVERRIDE: 'memory_directive:identity_override',
    PERMISSIVE_DEFAULT: 'memory_directive:permissive_default',
    BULK_EGRESS: 'memory_directive:bulk_egress',
  },
  MEMORY_DIRECTIVE_CLAUSE_MAX: 240,
  detectMemoryDirective: () => {
    throw new Error(`injected screen fault ${SENTINEL}`);
  },
  memoryCandidateText: (title: string | null | undefined, content: string | null | undefined) =>
    [title, content].filter((part) => typeof part === 'string' && part.length > 0).join('\n'),
}));

const { initDatabase, closeDatabase } = await import('../database/init.js');
const { addMemory, getMemoryById } = await import('../memory/store.js');
const {
  clearEnrichmentCooldown,
  enrichMemory,
  getEnrichmentDirectiveRefusalCount,
  getEnrichmentDirectiveUnavailableCount,
} = await import('../memory/lifecycle.js');

const BASE = 'staging bucket release scripts notes for the deploy runbook';
const APPENDED = `staging bucket release scripts notes now cover the rollback order ${SENTINEL}`;
const TITLE = `deploy ${SENTINEL}`;

const output: string[] = [];
const spies: Array<{ mockRestore: () => void }> = [];

beforeAll(() => {
  for (const method of ['log', 'warn', 'error', 'info', 'debug'] as const) {
    spies.push(jest.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      output.push(args.map(String).join(' '));
    }));
  }
  spies.push(jest.spyOn(process.stderr, 'write').mockImplementation(((chunk: unknown) => {
    output.push(String(chunk));
    return true;
  }) as never));
});

afterAll(() => {
  for (const spy of spies) spy.mockRestore();
});

describe('enrichMemory: a throwing memory-directive screen is reported, not silent', () => {
  beforeEach(() => { initDatabase(':memory:'); });
  afterEach(() => { closeDatabase(); });

  it('fails open (enrichment still appended), counts each throw apart from refusals, says it once', () => {
    const unavailable = getEnrichmentDirectiveUnavailableCount();
    const refusals = getEnrichmentDirectiveRefusalCount();

    for (let i = 0; i < 2; i += 1) {
      const mem = addMemory({ title: TITLE, content: BASE }, undefined, { type: 'user', identifier: 'direct' });
      clearEnrichmentCooldown(mem.id);
      const result = enrichMemory(mem.id, APPENDED, 'search');
      expect(result.enriched).toBe(true);
      expect(getMemoryById(mem.id)!.content).toContain('rollback order');
    }

    expect(getEnrichmentDirectiveUnavailableCount()).toBe(unavailable + 2);
    expect(getEnrichmentDirectiveRefusalCount()).toBe(refusals);
    const notices = output.filter((l) => l.includes('[shieldcortex] memory_directive_screen_unavailable'));
    expect(notices).toHaveLength(1);
    expect(notices[0]).toContain('the memory-directive screen threw');
  });

  it('no captured output carries the appended text, the title or the exception message', () => {
    expect(output.length).toBeGreaterThan(0);
    for (const line of output) {
      expect(line).not.toContain(SENTINEL);
      expect(line).not.toContain('injected');
    }
  });
});
