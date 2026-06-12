import { describe, expect, it } from '@jest/globals';
import { activateMacosService, activateLinuxService } from '../install.js';

/**
 * The legacy `launchctl load -w` lies on an already-loaded service: it prints
 * "Load failed: 5: Input/output error" to stderr yet exits 0, so install
 * claimed success while the old process kept running with the old service
 * definition (launchd caches the plist at load time). These tests pin the
 * honest bootout/drain/bootstrap replacement.
 *
 * launchd facts the mock encodes (verified empirically on macOS 26.5):
 *  - `launchctl print <target>` exits 0 while a booted-out job is still
 *    draining, non-zero (113) once it is gone.
 *  - `launchctl bootstrap` fails with EIO for ~5s after bootout while the
 *    old instance tears down (SIGTERM→SIGKILL escalation).
 *  - `launchctl bootout` on an absent job exits 3 ("No such process").
 */

type Step = 'ok' | 'throw';

/** Per-pattern scripted exec: results consumed per call, last one repeats. */
function mockExec(plan: Array<{ pattern: RegExp; results: Step[] }> = []) {
  const calls: string[] = [];
  const state = plan.map((p) => ({ ...p, next: 0 }));
  const exec = (command: string) => {
    calls.push(command);
    for (const p of state) {
      if (p.pattern.test(command)) {
        const step = p.results[Math.min(p.next, p.results.length - 1)];
        p.next++;
        if (step === 'throw') throw new Error(`mock failure: ${command}`);
        return '';
      }
    }
    return '';
  };
  return { calls, exec };
}

const PLIST = '/tmp/com.shieldcortex.dashboard.plist';

describe('activateMacosService — fresh install', () => {
  it('enables + bootstraps without bootout or drain polling', async () => {
    // First (and only) print probe fails = not loaded.
    const { calls, exec } = mockExec([{ pattern: /launchctl print /, results: ['throw'] }]);
    const result = await activateMacosService(PLIST, { exec, retryDelayMs: 0 });
    expect(result.reloaded).toBe(false);
    expect(calls.filter((c) => c.includes('launchctl print')).length).toBe(1);
    expect(calls.some((c) => c.includes('launchctl bootout'))).toBe(false);
    expect(calls.some((c) => c.includes('launchctl enable'))).toBe(true);
    expect(calls.some((c) => c.includes('launchctl bootstrap') && c.includes(PLIST))).toBe(true);
  });

  it('does NOT retry bootstrap (no EIO window when nothing is draining) and propagates the failure', async () => {
    const { calls, exec } = mockExec([
      { pattern: /launchctl print /, results: ['throw'] },
      { pattern: /launchctl bootstrap/, results: ['throw'] },
    ]);
    await expect(activateMacosService(PLIST, { exec, retryDelayMs: 0 })).rejects.toThrow(/bootstrap/);
    expect(calls.filter((c) => c.includes('launchctl bootstrap')).length).toBe(1);
  });
});

describe('activateMacosService — reload of a running service', () => {
  it('boots out, waits for the drain, enables, then bootstraps — in that order', async () => {
    // print: probe ok → first drain poll says gone.
    const { calls, exec } = mockExec([{ pattern: /launchctl print /, results: ['ok', 'throw'] }]);
    const result = await activateMacosService(PLIST, { exec, retryDelayMs: 0 });
    expect(result.reloaded).toBe(true);
    const bootout = calls.findIndex((c) => c.includes('launchctl bootout'));
    const enable = calls.findIndex((c) => c.includes('launchctl enable'));
    const bootstrap = calls.findIndex((c) => c.includes('launchctl bootstrap'));
    expect(bootout).toBeGreaterThan(-1);
    expect(enable).toBeGreaterThan(bootout);
    expect(bootstrap).toBeGreaterThan(enable);
  });

  it('polls `launchctl print` until the old instance has drained before bootstrapping', async () => {
    // probe ok, then two drain polls still loaded, then gone.
    const { calls, exec } = mockExec([
      { pattern: /launchctl print /, results: ['ok', 'ok', 'ok', 'throw'] },
    ]);
    await activateMacosService(PLIST, { exec, retryDelayMs: 0 });
    expect(calls.filter((c) => c.includes('launchctl print')).length).toBe(4);
    const lastPrint = calls.map((c) => c.includes('launchctl print')).lastIndexOf(true);
    const bootstrap = calls.findIndex((c) => c.includes('launchctl bootstrap'));
    expect(bootstrap).toBeGreaterThan(lastPrint);
    expect(calls.filter((c) => c.includes('launchctl bootstrap')).length).toBe(1);
  });

  it('gives up the drain poll at the deadline and still attempts bootstrap', async () => {
    // print never reports the job gone — drain must time out, not hang.
    const { calls, exec } = mockExec([{ pattern: /launchctl print /, results: ['ok'] }]);
    const result = await activateMacosService(PLIST, { exec, retryDelayMs: 0, drainTimeoutMs: 5 });
    expect(result.reloaded).toBe(true);
    expect(calls.filter((c) => c.includes('launchctl bootstrap')).length).toBe(1);
  });

  it('tolerates a bootout failure (job vanished between probe and bootout) and continues', async () => {
    const { calls, exec } = mockExec([
      { pattern: /launchctl print /, results: ['ok', 'throw'] },
      { pattern: /launchctl bootout/, results: ['throw'] },
    ]);
    const result = await activateMacosService(PLIST, { exec, retryDelayMs: 0 });
    expect(result.reloaded).toBe(true);
    expect(calls.some((c) => c.includes('launchctl enable'))).toBe(true);
    expect(calls.filter((c) => c.includes('launchctl bootstrap')).length).toBe(1);
  });

  it('retries a transient bootstrap EIO as a safety net behind the drain poll', async () => {
    const { calls, exec } = mockExec([
      { pattern: /launchctl print /, results: ['ok', 'throw'] },
      { pattern: /launchctl bootstrap/, results: ['throw', 'ok'] },
    ]);
    const result = await activateMacosService(PLIST, { exec, retryDelayMs: 0 });
    expect(result.reloaded).toBe(true);
    expect(calls.filter((c) => c.includes('launchctl bootstrap')).length).toBe(2);
  });

  it('propagates a persistent bootstrap failure instead of claiming success', async () => {
    const { exec } = mockExec([
      { pattern: /launchctl print /, results: ['ok', 'throw'] },
      { pattern: /launchctl bootstrap/, results: ['throw'] },
    ]);
    await expect(activateMacosService(PLIST, { exec, retryDelayMs: 0 })).rejects.toThrow(/bootstrap/);
  });
});

describe('activateLinuxService', () => {
  it('daemon-reloads, enables, then restarts the unit (enable --now is a no-op start on a running unit)', () => {
    const { calls, exec } = mockExec();
    activateLinuxService(exec);
    expect(calls[0]).toContain('daemon-reload');
    expect(calls.some((c) => /systemctl --user enable shieldcortex-dashboard/.test(c))).toBe(true);
    expect(calls.some((c) => /systemctl --user restart shieldcortex-dashboard/.test(c))).toBe(true);
  });
});
