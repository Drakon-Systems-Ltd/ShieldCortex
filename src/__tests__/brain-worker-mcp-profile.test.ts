import { afterEach, describe, it, expect, jest } from '@jest/globals';
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

  // The worker runs IN-PROCESS inside the MCP stdio server (index.ts), where
  // stdout is the JSON-RPC channel. console.log goes to stdout and corrupts that
  // stream → the client reports "Connection closed"; console.error goes to
  // stderr and is safe. So the worker must log exclusively via console.error.
  // (The end-to-end stdout-purity guarantee is pinned separately by
  // mcp-stdout-purity.test.ts, which spawns the real server.)
  describe('logs via console.error, never console.log (MCP protocol safety)', () => {
    let logSpy: jest.SpiedFunction<typeof console.log>;
    let errSpy: jest.SpiedFunction<typeof console.error>;

    afterEach(() => {
      logSpy?.mockRestore();
      errSpy?.mockRestore();
    });

    const joined = (spy: jest.SpiedFunction<typeof console.log>) =>
      spy.mock.calls.map((c) => c.map(String).join(' ')).join('\n');

    it('start() and stop() use console.error (stderr), not console.log (stdout)', () => {
      const worker = new BrainWorker({ profile: 'mcp' });
      // Spy AFTER construction so we only capture start()/stop() output.
      logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
      errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      worker.start();
      worker.stop();

      // The smoking gun: nothing the worker logs may go to stdout (console.log).
      expect(joined(logSpy)).not.toContain('[BrainWorker]');
      // …and the diagnostics still happen — on stderr (console.error).
      expect(joined(errSpy)).toContain('[BrainWorker] Starting background worker');
      expect(joined(errSpy)).toContain('[BrainWorker] Stopped');
    });
  });
});
