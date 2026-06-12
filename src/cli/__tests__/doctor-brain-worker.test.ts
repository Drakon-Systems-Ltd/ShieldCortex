import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * worker.json is last-writer-wins: when an MCP-hosted worker dies with its
 * Claude Code session, its dead pid sits in the file until a surviving
 * worker's next tick overwrites it (up to 15 min for mcp-profile survivors).
 * Doctor used to warn "process gone" inside that window — a false positive
 * users hit every time they ran doctor right after closing a session.
 *
 * The grace window (15 min + 5 min slack = 20 min) applies ONLY to
 * mcp-profile hosts: a dead full-profile host (dashboard/api/worker —
 * typically supervised) is a real failure and must warn immediately.
 */
describe('doctor brain-worker check — dead-pid takeover grace window', () => {
  let tmpHome: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doc-bw-'));
    originalEnv = { ...process.env };
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.SHIELDCORTEX_DISABLE_WORKER;
    jest.resetModules();
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function writeWorkerState(pid: number, tickAgeMs: number, profile = 'mcp'): void {
    const stateDir = path.join(tmpHome, '.shieldcortex', 'state');
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(
      path.join(stateDir, 'worker.json'),
      JSON.stringify({
        pid,
        profile,
        lastLightTick: new Date(Date.now() - tickAgeMs).toISOString(),
      }),
    );
  }

  /** Spawn a child that exits immediately — its pid is guaranteed dead. */
  function deadPid(): number {
    for (let i = 0; i < 5; i++) {
      const child = spawnSync(process.execPath, ['-e', '']);
      if (!child.pid) continue;
      try {
        process.kill(child.pid, 0); // pid was reused by a live process — retry
      } catch {
        return child.pid; // ESRCH — definitely dead
      }
    }
    throw new Error('could not obtain a dead pid');
  }

  async function check() {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    return mod.checkBrainWorker();
  }

  it('dead mcp pid with a fresh tick → info (awaiting takeover), not warn', async () => {
    writeWorkerState(deadPid(), 4 * 60 * 1000); // 4 min — inside the grace window
    const result = await check();
    expect(result.status).toBe('info');
    expect(result.message).toMatch(/takes over/i);
  });

  it('grace boundary: 19 min → info, 21 min → warn (window is 15 min tick + 5 min slack)', async () => {
    writeWorkerState(deadPid(), 19 * 60 * 1000);
    expect((await check()).status).toBe('info');

    writeWorkerState(deadPid(), 21 * 60 * 1000);
    jest.resetModules();
    expect((await check()).status).toBe('warn');
  });

  it('dead pid with a stale tick (past the grace window) → warn', async () => {
    writeWorkerState(deadPid(), 25 * 60 * 1000);
    const result = await check();
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/process gone/i);
  });

  it('dead FULL-profile pid gets no grace — supervised host death is a real failure', async () => {
    writeWorkerState(deadPid(), 4 * 60 * 1000, 'full');
    const result = await check();
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/process gone/i);
  });

  it('future-dated tick (clock skew) gets no grace — dead pid still warns', async () => {
    writeWorkerState(deadPid(), -5 * 60 * 1000); // tick 5 min in the future
    const result = await check();
    expect(result.status).toBe('warn');
  });

  it('live pid with a fresh tick → pass (regression guard)', async () => {
    writeWorkerState(process.pid, 60 * 1000);
    const result = await check();
    expect(result.status).toBe('pass');
  });

  it('live pid with a stale tick (>30 min) → warn (regression guard)', async () => {
    writeWorkerState(process.pid, 45 * 60 * 1000);
    const result = await check();
    expect(result.status).toBe('warn');
  });
});
