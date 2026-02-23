/**
 * Iron Dome — Confirmation Gate Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import type { IronDomeConfig } from '../config.js';
import { DEFAULT_IRON_DOME_CONFIG } from '../config.js';

describe('Confirmation Gate', () => {
  let activeConfig: IronDomeConfig;

  beforeEach(() => {
    activeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
    };
  });

  it('should classify destructive actions as RED', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    const result = classifyAction('rm', activeConfig);
    expect(result.tier).toBe('red');
    expect(result.reversible).toBe(false);
  });

  it('should classify all default RED actions correctly', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    const redActions = ['delete', 'drop', 'truncate', 'purge', 'wipe', 'shred', 'destroy',
      'force_push', 'delete_branch', 'modify_firewall', 'chmod_recursive'];
    for (const action of redActions) {
      const result = classifyAction(action, activeConfig);
      expect(result.tier).toBe('red');
    }
  });

  it('should classify safe actions as GREEN', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    const result = classifyAction('read_file', activeConfig);
    expect(result.tier).toBe('green');
    expect(result.reversible).toBe(true);
  });

  it('should classify all default GREEN actions correctly', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    const greenActions = ['read_file', 'write_new_file', 'git_commit', 'git_push',
      'run_report', 'web_search', 'web_fetch', 'create_directory', 'list_files'];
    for (const action of greenActions) {
      const result = classifyAction(action, activeConfig);
      expect(result.tier).toBe('green');
    }
  });

  it('should classify announcement actions as AMBER', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    const result = classifyAction('edit_file', activeConfig);
    expect(result.tier).toBe('amber');
    expect(result.reversible).toBe(true);
  });

  it('should classify all default AMBER actions correctly', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    const amberActions = ['install_package', 'update_package', 'create_cron',
      'restart_service', 'modify_config', 'database_migrate'];
    for (const action of amberActions) {
      const result = classifyAction(action, activeConfig);
      expect(result.tier).toBe('amber');
    }
  });

  it('should default unknown actions to AMBER', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    const result = classifyAction('some_unknown_action', activeConfig);
    expect(result.tier).toBe('amber');
    expect(result.description).toContain('not classified');
  });

  it('should return GREEN for everything when Iron Dome is disabled', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    const disabledConfig = { ...activeConfig, enabled: false };
    const result = classifyAction('rm', disabledConfig);
    expect(result.tier).toBe('green');
    expect(result.description).toContain('not active');
  });

  it('should be case-insensitive for action matching', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    const result = classifyAction('DELETE', activeConfig);
    expect(result.tier).toBe('red');
  });

  it('should match partial command names (contains match)', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    // "rm" is in the RED list, so "rm -rf /tmp" should match
    const result = classifyAction('rm -rf /tmp', activeConfig);
    expect(result.tier).toBe('red');
  });

  it('should normalise action to lowercase in result', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    const result = classifyAction('DELETE_BRANCH', activeConfig);
    expect(result.action).toBe('delete_branch');
  });

  it('should prioritise RED over GREEN when both match', async () => {
    const { classifyAction } = await import('../confirmation-gate.js');
    // Custom config where an action appears in both red and green
    const conflictConfig: IronDomeConfig = {
      ...activeConfig,
      confirmationProtocol: {
        red: ['dangerous_action'],
        amber: [],
        green: ['dangerous_action'],
      },
    };
    const result = classifyAction('dangerous_action', conflictConfig);
    expect(result.tier).toBe('red');
  });

  // ── requiresConfirmation ──

  it('requiresConfirmation should return true for RED actions', async () => {
    const { requiresConfirmation } = await import('../confirmation-gate.js');
    expect(requiresConfirmation('rm', activeConfig)).toBe(true);
    expect(requiresConfirmation('delete', activeConfig)).toBe(true);
  });

  it('requiresConfirmation should return false for AMBER actions', async () => {
    const { requiresConfirmation } = await import('../confirmation-gate.js');
    expect(requiresConfirmation('edit_file', activeConfig)).toBe(false);
  });

  it('requiresConfirmation should return false for GREEN actions', async () => {
    const { requiresConfirmation } = await import('../confirmation-gate.js');
    expect(requiresConfirmation('read_file', activeConfig)).toBe(false);
  });

  it('requiresConfirmation should return false when disabled', async () => {
    const { requiresConfirmation } = await import('../confirmation-gate.js');
    const disabledConfig = { ...activeConfig, enabled: false };
    expect(requiresConfirmation('rm', disabledConfig)).toBe(false);
  });

  // ── requiresAnnouncement ──

  it('requiresAnnouncement should return true for RED actions', async () => {
    const { requiresAnnouncement } = await import('../confirmation-gate.js');
    expect(requiresAnnouncement('rm', activeConfig)).toBe(true);
  });

  it('requiresAnnouncement should return true for AMBER actions', async () => {
    const { requiresAnnouncement } = await import('../confirmation-gate.js');
    expect(requiresAnnouncement('edit_file', activeConfig)).toBe(true);
  });

  it('requiresAnnouncement should return true for unknown actions', async () => {
    const { requiresAnnouncement } = await import('../confirmation-gate.js');
    expect(requiresAnnouncement('mystery_action', activeConfig)).toBe(true);
  });

  it('requiresAnnouncement should return false for GREEN actions', async () => {
    const { requiresAnnouncement } = await import('../confirmation-gate.js');
    expect(requiresAnnouncement('read_file', activeConfig)).toBe(false);
  });

  it('requiresAnnouncement should return false when disabled', async () => {
    const { requiresAnnouncement } = await import('../confirmation-gate.js');
    const disabledConfig = { ...activeConfig, enabled: false };
    expect(requiresAnnouncement('delete', disabledConfig)).toBe(false);
  });
});
