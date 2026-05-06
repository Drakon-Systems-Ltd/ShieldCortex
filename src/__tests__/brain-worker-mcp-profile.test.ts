import { describe, it, expect } from '@jest/globals';
import { BrainWorker } from '../worker/brain-worker.js';
import { MCP_LIGHT_TICK_INTERVAL_MS, DEFAULT_WORKER_CONFIG } from '../worker/types.js';

/**
 * Verify the MCP-lite profile shape:
 *   - light tick cadence is the lite 15 min default (not full's 5 min)
 *   - explicit lightTickIntervalMs overrides win
 *   - profile defaults to 'full'
 *
 * Behavioural assertions about which paths run inside lightTick/mediumTick
 * are covered by the doctor + brain-worker integration tests; those need
 * a populated DB and are heavier than this config-shape sanity check.
 */
describe('BrainWorker — MCP profile (#45)', () => {
  it('defaults to the full profile', () => {
    const worker = new BrainWorker();
    expect(worker.getConfig().profile).toBe('full');
    expect(worker.getConfig().lightTickIntervalMs).toBe(DEFAULT_WORKER_CONFIG.lightTickIntervalMs);
  });

  it('applies the lite 15-minute cadence when profile is mcp', () => {
    const worker = new BrainWorker({ profile: 'mcp' });
    expect(worker.getConfig().profile).toBe('mcp');
    expect(worker.getConfig().lightTickIntervalMs).toBe(MCP_LIGHT_TICK_INTERVAL_MS);
  });

  it('honours an explicit lightTickIntervalMs override under mcp profile', () => {
    const worker = new BrainWorker({ profile: 'mcp', lightTickIntervalMs: 60_000 });
    expect(worker.getConfig().lightTickIntervalMs).toBe(60_000);
  });
});
