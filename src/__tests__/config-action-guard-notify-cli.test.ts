/**
 * #275 — `shieldcortex config --action-guard-notify-*` flags: the signed CLI
 * path for setting the Action Guard notify channel. Before this, doctor's
 * suggested fix was a bare key path ("set actionGuard.notify.enabled: true"),
 * so operators hand-edited ~/.shieldcortex/config.json — which invalidated the
 * embedded `_sig` HMAC and forced defenceMode strict. These flags write
 * through mutateRawConfig/writeRawConfig, so the config is re-signed and the
 * integrity check stays green.
 */

import fs from 'fs';
import path from 'path';
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { handleCloudConfig } from '../cloud/cli.js';
import {
  getActionGuardNotifyConfig,
  setActionGuardNotifyConfig,
  setReviewedScripts,
  getConfigDir,
  clearCloudConfigCache,
  readRawConfig,
  isConfigTampered,
} from '../cloud/config.js';

const configFile = () => path.join(getConfigDir(), 'config.json');
const legacySigFile = () => path.join(getConfigDir(), '.config-sig');

function resetConfigDir(): void {
  fs.rmSync(configFile(), { force: true });
  fs.rmSync(legacySigFile(), { force: true });
  clearCloudConfigCache();
}

beforeEach(() => {
  resetConfigDir();
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  resetConfigDir();
});

describe('config --action-guard-notify-* flags (#275)', () => {
  it('--action-guard-notify-openclaw enables notify via the OpenClaw approval channel', () => {
    handleCloudConfig(['--action-guard-notify-openclaw']);
    const cfg = getActionGuardNotifyConfig();
    expect(cfg.enabled).toBe(true);
    expect(cfg.openclaw).toBe(true);
  });

  it('--action-guard-notify-webhook enables notify with the given https URL', () => {
    handleCloudConfig(['--action-guard-notify-webhook', 'https://hooks.example.invalid/sc']);
    const cfg = getActionGuardNotifyConfig();
    expect(cfg.enabled).toBe(true);
    expect(cfg.webhookUrl).toBe('https://hooks.example.invalid/sc');
  });

  it('--action-guard-notify-disable turns notify off but keeps the channel config for re-enable', () => {
    handleCloudConfig(['--action-guard-notify-webhook', 'https://hooks.example.invalid/sc']);
    handleCloudConfig(['--action-guard-notify-disable']);
    const cfg = getActionGuardNotifyConfig();
    expect(cfg.enabled).toBe(false);
    expect(cfg.webhookUrl).toBe('https://hooks.example.invalid/sc');
  });

  it('rejects an http:// webhook URL and leaves the config untouched', () => {
    const exitSpy = jest
      .spyOn(process, 'exit')
      .mockImplementation(((): never => { throw new Error('exit'); }) as never);
    expect(() =>
      handleCloudConfig(['--action-guard-notify-webhook', 'http://hooks.example.invalid/sc']),
    ).toThrow('exit');
    expect(exitSpy).toHaveBeenCalledWith(1);
    const cfg = getActionGuardNotifyConfig();
    expect(cfg.enabled).toBe(false);
    expect(cfg.webhookUrl).toBeUndefined();
  });

  it('rejects a non-URL webhook value', () => {
    jest
      .spyOn(process, 'exit')
      .mockImplementation(((): never => { throw new Error('exit'); }) as never);
    expect(() =>
      handleCloudConfig(['--action-guard-notify-webhook', 'not a url']),
    ).toThrow('exit');
    expect(getActionGuardNotifyConfig().enabled).toBe(false);
  });

  it('rejects a missing webhook value', () => {
    jest
      .spyOn(process, 'exit')
      .mockImplementation(((): never => { throw new Error('exit'); }) as never);
    expect(() => handleCloudConfig(['--action-guard-notify-webhook'])).toThrow('exit');
    expect(getActionGuardNotifyConfig().enabled).toBe(false);
  });

  it('writes a SIGNED config: `_sig` is present and a fresh read does not trip the tamper flag', () => {
    handleCloudConfig(['--action-guard-notify-openclaw']);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(typeof onDisk._sig).toBe('string');
    expect(onDisk._sig).toMatch(/^[0-9a-f]{64}$/);
    clearCloudConfigCache();
    const raw = readRawConfig();
    expect(isConfigTampered()).toBe(false);
    expect(raw.defenceMode).not.toBe('strict');
  });

  it('preserves sibling actionGuard keys and unrelated top-level keys on write', () => {
    handleCloudConfig(['--mode', 'balanced']);
    setReviewedScripts([{ hash: 'abc123' }]);
    handleCloudConfig(['--action-guard-notify-webhook', 'https://hooks.example.invalid/sc']);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.defenceMode).toBe('balanced');
    expect(onDisk.actionGuard.reviewedScripts).toEqual([{ hash: 'abc123' }]);
    expect(onDisk.actionGuard.notify.enabled).toBe(true);
    expect(onDisk.actionGuard.notify.webhookUrl).toBe('https://hooks.example.invalid/sc');
  });

  it('setActionGuardNotifyConfig rejects non-https URLs at the API layer too', () => {
    expect(() => setActionGuardNotifyConfig({ webhookUrl: 'http://x.example/hook' })).toThrow(/https/);
    expect(() => setActionGuardNotifyConfig({ webhookUrl: 'ftp://x.example/hook' })).toThrow(/https/);
    expect(() => setActionGuardNotifyConfig({ webhookUrl: 'nonsense' })).toThrow(/https|URL/i);
    expect(getActionGuardNotifyConfig().webhookUrl).toBeUndefined();
  });

  it('the same hand-edit the CLI replaces DOES trip the integrity check (why doctor must not recommend it)', () => {
    handleCloudConfig(['--action-guard-notify-openclaw']);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    onDisk.actionGuard.notify.webhookUrl = 'https://hooks.example.invalid/hand-edited';
    fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
    clearCloudConfigCache();
    const raw = readRawConfig();
    expect(isConfigTampered()).toBe(true);
    expect(raw.defenceMode).toBe('strict');
  });
});
