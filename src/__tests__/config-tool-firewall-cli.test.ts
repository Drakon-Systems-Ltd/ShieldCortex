/**
 * Tests the `shieldcortex config --tool-firewall-*` flags — the user-facing
 * switch that turns the tool-output firewall from observe-only (advisory) to
 * acting (enforce). Without these the enforce path is unreachable except by
 * hand-editing config.json.
 */

import { describe, it, expect, beforeEach, afterAll, jest } from '@jest/globals';
import { handleCloudConfig } from '../cloud/cli.js';
import { getToolResponseScanConfig, setToolResponseScanConfig } from '../cloud/config.js';

beforeEach(() => {
  setToolResponseScanConfig({ scanToolResponses: true, toolResponseMode: 'advisory' });
  jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterAll(() => {
  // The config sandbox is per-WORKER; restore defaults so a left-over enforce/off
  // state cannot bleed into later suites that read the tool-firewall default.
  setToolResponseScanConfig({ scanToolResponses: true, toolResponseMode: 'advisory' });
});

describe('config --tool-firewall-* flags', () => {
  it('--tool-firewall-enforce switches to enforce mode', () => {
    handleCloudConfig(['--tool-firewall-enforce']);
    expect(getToolResponseScanConfig().toolResponseMode).toBe('enforce');
  });

  it('--tool-firewall-advisory switches back to advisory mode', () => {
    setToolResponseScanConfig({ toolResponseMode: 'enforce' });
    handleCloudConfig(['--tool-firewall-advisory']);
    expect(getToolResponseScanConfig().toolResponseMode).toBe('advisory');
  });

  it('--tool-firewall-off disables tool-response scanning', () => {
    handleCloudConfig(['--tool-firewall-off']);
    expect(getToolResponseScanConfig().scanToolResponses).toBe(false);
  });

  it('--tool-firewall-on re-enables tool-response scanning', () => {
    setToolResponseScanConfig({ scanToolResponses: false });
    handleCloudConfig(['--tool-firewall-on']);
    expect(getToolResponseScanConfig().scanToolResponses).toBe(true);
  });
});
