/**
 * Iron Dome — Action Gate Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import type { IronDomeConfig } from '../config.js';
import { DEFAULT_IRON_DOME_CONFIG } from '../config.js';

describe('Action Gate', () => {
  let activeConfig: IronDomeConfig;

  beforeEach(() => {
    activeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
      requireApproval: ['send_email', 'delete_file', 'api_call', 'purchase'],
      autoApprove: ['read_file', 'search', 'calculate'],
      subAgentRestrictions: {
        blockedOperations: ['export_data', 'bulk_email'],
        sanitiseContext: true,
      },
    };
  });

  it('should auto-approve whitelisted actions', async () => {
    const { isActionAllowed } = await import('../action-gate.js');
    const result = isActionAllowed('read_file', activeConfig);
    expect(result.decision).toBe('approved');
  });

  it('should require approval for restricted actions', async () => {
    const { isActionAllowed } = await import('../action-gate.js');
    const result = isActionAllowed('send_email', activeConfig);
    expect(result.decision).toBe('requires_approval');
  });

  it('should approve unknown actions not in either list', async () => {
    const { isActionAllowed } = await import('../action-gate.js');
    const result = isActionAllowed('custom_action', activeConfig);
    expect(result.decision).toBe('approved');
  });

  it('should block sub-agent restricted operations', async () => {
    const { isActionAllowed } = await import('../action-gate.js');
    const agentSource = { type: 'agent' as const, identifier: 'sub-agent-1' };
    const result = isActionAllowed('export_data', activeConfig, agentSource);
    expect(result.decision).toBe('blocked');
  });

  it('should not block non-agent sources for sub-agent restrictions', async () => {
    const { isActionAllowed } = await import('../action-gate.js');
    const userSource = { type: 'user' as const, identifier: 'direct' };
    const result = isActionAllowed('export_data', activeConfig, userSource);
    // Not in requireApproval or autoApprove, so should be approved
    expect(result.decision).toBe('approved');
  });

  it('should be case-insensitive for action names', async () => {
    const { isActionAllowed } = await import('../action-gate.js');
    const result = isActionAllowed('Send_Email', activeConfig);
    expect(result.decision).toBe('requires_approval');
  });

  it('should approve all actions when Iron Dome is disabled', async () => {
    const { isActionAllowed } = await import('../action-gate.js');
    const disabledConfig = { ...activeConfig, enabled: false };
    const result = isActionAllowed('send_email', disabledConfig);
    expect(result.decision).toBe('approved');
    expect(result.reason).toContain('not active');
  });

  it('should include action name in result', async () => {
    const { isActionAllowed } = await import('../action-gate.js');
    const result = isActionAllowed('Delete_File', activeConfig);
    expect(result.action).toBe('delete_file');
  });

  it('should match partial action names', async () => {
    const { isActionAllowed } = await import('../action-gate.js');
    const result = isActionAllowed('make_api_call', activeConfig);
    expect(result.decision).toBe('requires_approval');
  });
});
