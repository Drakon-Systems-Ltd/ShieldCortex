import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import {
  assertOperationAllowed,
  deactivateKillSwitch,
  isKillSwitchActive,
  KillSwitchError,
  __refreshControlStateForTest,
} from '../api/control.js';

/**
 * Phase 2 cross-process kill-switch proof.
 *
 * The bug: kill-switch / pause state lived only in module memory, so a
 * dashboard (API process) activation never reached the separate MCP server
 * process — the MCP process kept serving remember/forget/recall.
 *
 * The fix: control_state (single row id=1) is the source of truth. Mutators
 * persist to it; gated reads refresh from it through a 1s TTL cache.
 *
 * This suite simulates "another process" (the dashboard API) by writing the
 * control_state row directly via raw SQL — THIS process never calls
 * activateKillSwitch. We then bypass the TTL with __refreshControlStateForTest()
 * (cheaper than a real >1s sleep) and assert the lockdown is honoured here.
 */

function writeControlRow(mode: 'active' | 'paused' | 'kill_switch', meta: unknown): void {
  getDatabase()
    .prepare(
      `INSERT OR REPLACE INTO control_state (id, mode, meta_json, updated_at)
       VALUES (1, ?, ?, ?)`,
    )
    .run(mode, meta ? JSON.stringify(meta) : null, new Date().toISOString());
}

describe('kill switch is honoured cross-process via control_state', () => {
  beforeEach(() => {
    // A prior test in this worker may have left module state active/inactive.
    deactivateKillSwitch('test-cleanup');
    closeDatabase();
    initDatabase(':memory:');
  });

  afterEach(() => {
    // CRITICAL: leave global control state clean (active) and the row cleared so
    // downstream suites in this worker are not locked down.
    deactivateKillSwitch('test-cleanup');
    try {
      getDatabase().prepare('DELETE FROM control_state').run();
    } catch {
      // DB may already be closed in a failing test — best-effort.
    }
    __refreshControlStateForTest();
    closeDatabase();
  });

  it('locks down THIS process when ANOTHER process sets mode=kill_switch in the row', () => {
    // Sanity: this process never activated the switch.
    expect(isKillSwitchActive()).toBe(false);
    expect(() => assertOperationAllowed('memory_write')).not.toThrow();

    // Simulate the dashboard API process activating the kill switch.
    writeControlRow('kill_switch', {
      triggeredAt: new Date().toISOString(),
      source: 'manual',
      reason: 'dashboard emergency stop',
    });

    // Without a refresh, our TTL cache still says 'active' — prove the bypass
    // hook makes us pick up the other process's change.
    __refreshControlStateForTest();

    // Core proof: a gated op throws even though THIS process never activated it.
    expect(() => assertOperationAllowed('memory_write')).toThrow(KillSwitchError);
    expect(isKillSwitchActive()).toBe(true);
  });

  it('still allows forensic ops (status) during a cross-process lockdown', () => {
    writeControlRow('kill_switch', { triggeredAt: new Date().toISOString(), source: 'manual' });
    __refreshControlStateForTest();

    expect(() => assertOperationAllowed('memory_write')).toThrow(KillSwitchError);
    // status is in ALLOWED_DURING_LOCKDOWN — must not throw.
    expect(() => assertOperationAllowed('status')).not.toThrow();
    expect(() => assertOperationAllowed('audit')).not.toThrow();
    expect(() => assertOperationAllowed('resume')).not.toThrow();
  });

  it('honours deactivation performed by another process', () => {
    // Locked down first.
    writeControlRow('kill_switch', { triggeredAt: new Date().toISOString(), source: 'manual' });
    __refreshControlStateForTest();
    expect(() => assertOperationAllowed('memory_write')).toThrow(KillSwitchError);

    // Another process deactivates by writing mode=active.
    writeControlRow('active', null);
    __refreshControlStateForTest();

    expect(() => assertOperationAllowed('memory_write')).not.toThrow();
    expect(isKillSwitchActive()).toBe(false);
  });

  it('falls back to in-memory state when no DB is initialised', () => {
    // Tear down the DB this test does not need it.
    deactivateKillSwitch('test-cleanup');
    closeDatabase();

    // With no DB, loadControlState() no-ops and we keep the fresh in-memory
    // 'active' state — uninitialised-DB callers must not be broken or throw.
    expect(() => assertOperationAllowed('memory_write')).not.toThrow();
    expect(isKillSwitchActive()).toBe(false);

    // Re-init so afterEach cleanup has a live DB to clear.
    initDatabase(':memory:');
  });
});
