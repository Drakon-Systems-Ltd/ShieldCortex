import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  findFreshEnforcementEntry,
  runCanaryProbe,
  evaluateSelfCheck,
  runPluginSelfCheck,
  type CanaryResult,
  type CanaryProbeDeps,
} from '../setup/openclaw-selfcheck.js';
import type { PluginIndexRow } from '../integrations/openclaw-plugin-index.js';

/**
 * Finding #1 (BLOCKER): the enforcement canary must be a LIVE probe, not a
 * 10-minute audit-log grep. It must synthesise a nonce-tagged operation, then
 * require a FRESH audit entry (timestamp strictly at/after probe start) whose
 * content carries that unique nonce. A stale pre-break deny — the exact aiquant
 * #74 timeline — must NOT satisfy it.
 *
 * Finding #3 (MEDIUM): the self-check must additionally prove
 * onDiskVersion >= expectedVersion, so an unpinned `plugins update` that lands a
 * downgrade (the 4.25.4 class) HARD-FAILS instead of silently passing.
 */
const PLUGIN = 'shieldcortex-realtime';

function writeAuditLine(home: string, entry: Record<string, unknown>): void {
  const dir = path.join(home, '.shieldcortex', 'audit');
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(path.join(dir, 'realtime-2026-07-11.jsonl'), JSON.stringify(entry) + '\n');
}

describe('findFreshEnforcementEntry — fresh + nonce-matched deny only', () => {
  let home: string;
  beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-canary-')); });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  it('finds a deny that is newer than probe start AND carries the nonce', () => {
    const start = Date.parse('2026-07-11T10:50:00.000Z');
    writeAuditLine(home, { ts: '2026-07-11T10:50:05.000Z', decision: 'deny', marker: 'sc-canary-NONCE1' });
    const r = findFreshEnforcementEntry(home, { nonce: 'sc-canary-NONCE1', sinceMs: start });
    expect(r.found).toBe(true);
  });

  it('STALE false-positive: a pre-break deny BEFORE probe start does NOT satisfy the canary', () => {
    // aiquant timeline: last real deny at 10:40, interceptor dropped, probe runs later.
    const preBreakDeny = '2026-07-11T10:40:00.000Z';
    const probeStart = Date.parse('2026-07-11T10:50:00.000Z');
    writeAuditLine(home, { ts: preBreakDeny, decision: 'deny', marker: 'sc-canary-NONCE1' });
    const r = findFreshEnforcementEntry(home, { nonce: 'sc-canary-NONCE1', sinceMs: probeStart });
    expect(r.found).toBe(false);
  });

  it('a FRESH deny without the probe nonce does NOT satisfy the canary (unrelated live traffic)', () => {
    const start = Date.parse('2026-07-11T10:50:00.000Z');
    writeAuditLine(home, { ts: '2026-07-11T10:50:05.000Z', decision: 'deny', reason: 'some other block' });
    const r = findFreshEnforcementEntry(home, { nonce: 'sc-canary-NONCE1', sinceMs: start });
    expect(r.found).toBe(false);
  });

  it('a fresh nonce-tagged entry that was ALLOWED (not denied) does NOT satisfy the canary', () => {
    const start = Date.parse('2026-07-11T10:50:00.000Z');
    writeAuditLine(home, { ts: '2026-07-11T10:50:05.000Z', decision: 'allow', marker: 'sc-canary-NONCE1' });
    const r = findFreshEnforcementEntry(home, { nonce: 'sc-canary-NONCE1', sinceMs: start });
    expect(r.found).toBe(false);
  });
});

describe('runCanaryProbe — active synthetic op + fresh nonce gate', () => {
  let home: string;
  beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-canary-')); });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  const baseDeps = (over: Partial<CanaryProbeDeps>): CanaryProbeDeps => ({
    now: () => 1_000_000,
    makeNonce: () => 'sc-canary-FIXED',
    triggerSyntheticOp: async () => ({ dispatched: true }),
    findFresh: () => ({ found: true, at: 'x' }),
    ...over,
  });

  it('denied+audited when the synthetic op is dispatched AND a fresh nonce-matched deny appears', async () => {
    let sawNonce: string | undefined;
    let sawSince: number | undefined;
    const c: CanaryResult = await runCanaryProbe(home, PLUGIN, baseDeps({
      triggerSyntheticOp: async (_h, _p, nonce) => { sawNonce = nonce; return { dispatched: true }; },
      findFresh: (_h, q) => { sawSince = q.sinceMs; return { found: q.nonce === 'sc-canary-FIXED', at: 'now' }; },
    }));
    expect(c.ran).toBe(true);
    expect(c.denied).toBe(true);
    expect(c.auditEntryFound).toBe(true);
    expect(sawNonce).toBe('sc-canary-FIXED');
    expect(sawSince).toBe(1_000_000);
  });

  it('ran:false when the synthetic op could not be dispatched (guarded / no live gateway)', async () => {
    const c = await runCanaryProbe(home, PLUGIN, baseDeps({
      triggerSyntheticOp: async () => ({ dispatched: false, detail: 'skipped under test runner' }),
    }));
    expect(c.ran).toBe(false);
    expect(c.denied).toBe(false);
  });

  it('dispatched but NO fresh matching deny → not enforcing (interceptor dead)', async () => {
    const c = await runCanaryProbe(home, PLUGIN, baseDeps({
      triggerSyntheticOp: async () => ({ dispatched: true }),
      findFresh: () => ({ found: false }),
    }));
    expect(c.ran).toBe(true);
    expect(c.denied).toBe(false);
    expect(c.auditEntryFound).toBe(false);
  });

  it('end-to-end: a dispatched op whose interceptor writes the FRESH nonce entry passes; a stale log does not', async () => {
    // Interceptor is alive: dispatching writes a fresh nonce-tagged deny.
    const alive = await runCanaryProbe(home, PLUGIN, {
      now: () => Date.parse('2026-07-11T10:50:00.000Z'),
      makeNonce: () => 'sc-canary-LIVE',
      triggerSyntheticOp: async (h, _p, nonce) => {
        writeAuditLine(h, { ts: '2026-07-11T10:50:01.000Z', decision: 'deny', marker: nonce });
        return { dispatched: true };
      },
      findFresh: findFreshEnforcementEntry,
    });
    expect(alive.denied).toBe(true);

    // Interceptor is DEAD: dispatching writes nothing; only a stale pre-break deny exists.
    const home2 = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-canary-'));
    writeAuditLine(home2, { ts: '2026-07-11T10:40:00.000Z', decision: 'deny', marker: 'sc-canary-DEAD' });
    const dead = await runCanaryProbe(home2, PLUGIN, {
      now: () => Date.parse('2026-07-11T10:50:00.000Z'),
      makeNonce: () => 'sc-canary-DEAD',
      triggerSyntheticOp: async () => ({ dispatched: true }), // interceptor unloaded → no new entry
      findFresh: findFreshEnforcementEntry,
    });
    expect(dead.denied).toBe(false);
    fs.rmSync(home2, { recursive: true, force: true });
  });
});

describe('evaluateSelfCheck — version proof (onDiskVersion >= expectedVersion)', () => {
  const loadedRoster: PluginIndexRow = {
    installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2' } },
    plugins: [{ pluginId: PLUGIN, enabled: true, origin: 'npm' }],
    warning: null,
  };
  const passingCanary: CanaryResult = { ran: true, denied: true, auditEntryFound: true };

  it('HARD FAILS when the on-disk version regressed below expected (silent-downgrade guard)', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN, index: loadedRoster, canary: passingCanary,
      expectedVersion: '4.47.2', onDiskVersion: '4.25.4',
    });
    expect(v.ok).toBe(false);
    expect(v.versionProof).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/version|downgrade|regress|4\.25\.4/i);
  });

  it('passes the version proof when on-disk == expected', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN, index: loadedRoster, canary: passingCanary,
      expectedVersion: '4.47.2', onDiskVersion: '4.47.2',
    });
    expect(v.versionProof).toBe(true);
    expect(v.ok).toBe(true);
  });

  it('passes the version proof when on-disk is newer than expected', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN, index: loadedRoster, canary: passingCanary,
      expectedVersion: '4.47.2', onDiskVersion: '4.47.3',
    });
    expect(v.versionProof).toBe(true);
    expect(v.ok).toBe(true);
  });

  it('version proof is inert (true) when no expectedVersion is supplied', () => {
    const v = evaluateSelfCheck({ pluginId: PLUGIN, index: loadedRoster, canary: passingCanary });
    expect(v.versionProof).toBe(true);
    expect(v.ok).toBe(true);
  });
});

describe('runPluginSelfCheck — reads the on-disk version and enforces the version proof', () => {
  let home: string;
  const PKG_SUBPATH = path.join('node_modules', '@drakon-systems', 'shieldcortex-realtime');
  beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-selfcheck-ver-')); });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  function installOnDisk(version: string): void {
    const oc = path.join(home, '.openclaw');
    const pkgDir = path.join(oc, 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-abc', PKG_SUBPATH);
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ version }));
    fs.mkdirSync(path.join(oc, 'plugins'), { recursive: true });
    fs.writeFileSync(
      path.join(oc, 'plugins', 'installs.json'),
      JSON.stringify({ installRecords: { [PLUGIN]: { version, installPath: pkgDir } } }),
    );
  }

  const loadedRoster: PluginIndexRow = {
    installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2' } },
    plugins: [{ pluginId: PLUGIN, enabled: true, origin: 'npm' }],
    warning: null,
  };
  const passingCanary: CanaryResult = { ran: true, denied: true, auditEntryFound: true };

  it('FAILS a roster-loaded + canary-passing host when the on-disk build regressed', async () => {
    installOnDisk('4.25.4');
    const v = await runPluginSelfCheck(home, {
      pluginId: PLUGIN,
      expectedVersion: '4.47.2',
      readIndex: () => loadedRoster,
      canaryProbe: async () => passingCanary,
    });
    expect(v.ok).toBe(false);
    expect(v.versionProof).toBe(false);
  });

  it('passes when roster, canary, AND on-disk version all agree', async () => {
    installOnDisk('4.47.2');
    const v = await runPluginSelfCheck(home, {
      pluginId: PLUGIN,
      expectedVersion: '4.47.2',
      readIndex: () => loadedRoster,
      canaryProbe: async () => passingCanary,
    });
    expect(v.ok).toBe(true);
    expect(v.versionProof).toBe(true);
  });
});
