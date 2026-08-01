/**
 * Issue #114.1 — `readPersistedPurgeDate` must clamp future-dated purge
 * timestamps to null (never-purged) rather than trust them.
 *
 * A corrupt worker.json (clock skew, manual edit, or a bad write) with a
 * future `lastAuditPurge`/`lastSessionPurge` would otherwise suppress the
 * daily age purge until that future date + 24h. The size-pressure valve
 * still runs every tick (anti-brick property holds), but the age purge
 * should not be wedgeable by bad persisted state — for BOTH keys, since
 * they share this one read path.
 *
 * Mirrors the doctor brain-worker test's harness (src/cli/__tests__/
 * doctor-brain-worker.test.ts): mock os.homedir() to a scratch dir, write
 * worker.json directly, jest.resetModules() + dynamic import so the module
 * re-reads WORKER_STATE_FILE against the mocked homedir.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

describe('readPersistedPurgeDate — future-dated timestamps clamp to null (#114)', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-purge-date-'));
    jest.resetModules();
  });

  afterEach(() => {
    jest.restoreAllMocks();
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function writeWorkerState(state: Record<string, unknown>): void {
    const stateDir = path.join(tmpHome, '.shieldcortex', 'state');
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(path.join(stateDir, 'worker.json'), JSON.stringify(state));
  }

  async function readPurgeDate(key: 'lastAuditPurge' | 'lastSessionPurge') {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../worker/brain-worker.js');
    return mod.readPersistedPurgeDate(key);
  }

  it('a future lastAuditPurge clamps to null instead of wedging the age purge', async () => {
    const future = new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(); // +6h
    writeWorkerState({ lastAuditPurge: future });
    const result = await readPurgeDate('lastAuditPurge');
    expect(result).toBeNull();
  });

  it('a future lastSessionPurge clamps to null too — same read path, both keys', async () => {
    const future = new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString();
    writeWorkerState({ lastSessionPurge: future });
    const result = await readPurgeDate('lastSessionPurge');
    expect(result).toBeNull();
  });

  it('a far-future timestamp (corrupt-write style) also clamps to null', async () => {
    writeWorkerState({ lastAuditPurge: '2099-01-01T00:00:00.000Z' });
    const result = await readPurgeDate('lastAuditPurge');
    expect(result).toBeNull();
  });

  it('control: a past timestamp is honoured normally (regression guard)', async () => {
    const past = new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(); // -6h
    writeWorkerState({ lastAuditPurge: past });
    const result = await readPurgeDate('lastAuditPurge');
    expect(result?.toISOString()).toBe(past);
  });

  it('missing key still returns null (never-purged, unrelated to the clamp)', async () => {
    writeWorkerState({});
    const result = await readPurgeDate('lastAuditPurge');
    expect(result).toBeNull();
  });
});
