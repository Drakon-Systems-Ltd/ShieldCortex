/**
 * Iron Dome — Gateway Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import type { IronDomeConfig } from '../config.js';
import { DEFAULT_IRON_DOME_CONFIG } from '../config.js';

describe('Gateway', () => {
  let activeConfig: IronDomeConfig;

  beforeEach(() => {
    activeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
      trustedChannels: ['terminal', 'cli', 'telegram'],
    };
  });

  it('should allow trusted channels', async () => {
    const { isChannelTrusted } = await import('../gateway.js');
    expect(isChannelTrusted('terminal', activeConfig)).toBe(true);
    expect(isChannelTrusted('cli', activeConfig)).toBe(true);
    expect(isChannelTrusted('telegram', activeConfig)).toBe(true);
  });

  it('should block untrusted channels', async () => {
    const { isChannelTrusted } = await import('../gateway.js');
    expect(isChannelTrusted('email', activeConfig)).toBe(false);
    expect(isChannelTrusted('web', activeConfig)).toBe(false);
    expect(isChannelTrusted('unknown', activeConfig)).toBe(false);
  });

  it('should be case-insensitive for channel names', async () => {
    const { isChannelTrusted } = await import('../gateway.js');
    expect(isChannelTrusted('Terminal', activeConfig)).toBe(true);
    expect(isChannelTrusted('CLI', activeConfig)).toBe(true);
  });

  it('should allow all channels when Iron Dome is disabled', async () => {
    const { isChannelTrusted } = await import('../gateway.js');
    const disabledConfig = { ...activeConfig, enabled: false };
    expect(isChannelTrusted('email', disabledConfig)).toBe(true);
    expect(isChannelTrusted('unknown', disabledConfig)).toBe(true);
  });

  it('should return gateway result with correct trust level', async () => {
    const { validateGateway } = await import('../gateway.js');
    const trusted = validateGateway('terminal', 'test instruction', activeConfig);
    expect(trusted.allowed).toBe(true);
    expect(trusted.trustLevel).toBe('trusted');

    const untrusted = validateGateway('email', 'test instruction', activeConfig);
    expect(untrusted.allowed).toBe(false);
    expect(untrusted.trustLevel).toBe('untrusted');
  });

  it('should include channel name in result', async () => {
    const { validateGateway } = await import('../gateway.js');
    const result = validateGateway('Terminal', 'test', activeConfig);
    expect(result.channel).toBe('terminal');
  });

  it('should pass through when disabled', async () => {
    const { validateGateway } = await import('../gateway.js');
    const disabledConfig = { ...activeConfig, enabled: false };
    const result = validateGateway('email', 'anything', disabledConfig);
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain('not active');
  });
});
