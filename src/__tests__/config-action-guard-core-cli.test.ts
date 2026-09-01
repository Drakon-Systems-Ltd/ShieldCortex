/**
 * `shieldcortex config --action-guard-enable|disable|enforce|advisory` — the
 * signed CLI path for the Action Guard core switches. Before this, doctor's
 * suggested fix for `actionGuard.enabled: false` was to hand-edit
 * ~/.shieldcortex/config.json — which invalidated the embedded `_sig` HMAC and
 * forced defenceMode strict. These flags write through
 * mutateRawConfig/writeRawConfig, so the config is re-signed and the integrity
 * check stays green. Guard is OFF unless `enabled` is explicitly true.
 * `enforce` still defaults ON when absent, so advisory writes an explicit
 * false.
 */

import fs from 'fs';
import path from 'path';
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { handleCloudConfig } from '../cloud/cli.js';
import {
  getActionGuardCoreConfig,
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

let logSpy: ReturnType<typeof jest.spyOn>;

beforeEach(() => {
  resetConfigDir();
  logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  resetConfigDir();
});

describe('config --action-guard-* core flags', () => {
  it('defaults OFF for enabled when the config has no actionGuard block', () => {
    const cfg = getActionGuardCoreConfig();
    expect(cfg.enabled).toBe(false);
    expect(cfg.enforce).toBe(true);
  });

  it('--action-guard-enable writes enabled:true and a SIGNED config that does not trip the tamper flag', () => {
    handleCloudConfig(['--action-guard-enable']);
    expect(getActionGuardCoreConfig().enabled).toBe(true);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.actionGuard.enabled).toBe(true);
    expect(typeof onDisk._sig).toBe('string');
    expect(onDisk._sig).toMatch(/^[0-9a-f]{64}$/);
    clearCloudConfigCache();
    const raw = readRawConfig();
    expect(isConfigTampered()).toBe(false);
    expect(raw.defenceMode).not.toBe('strict');
  });

  it('--action-guard-disable writes an explicit enabled:false and status shows Off', () => {
    handleCloudConfig(['--action-guard-disable']);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.actionGuard.enabled).toBe(false);
    expect(getActionGuardCoreConfig().enabled).toBe(false);
    logSpy.mockClear();
    handleCloudConfig(['--cloud-status']);
    const lines = logSpy.mock.calls.map((c) => String(c[0]));
    expect(lines.some((l) => l.includes('Action Guard: Off'))).toBe(true);
  });

  it('--action-guard-enforce writes enabled:true AND enforce:true, and status shows Enforce', () => {
    handleCloudConfig(['--action-guard-enforce']);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.actionGuard.enabled).toBe(true);
    expect(onDisk.actionGuard.enforce).toBe(true);
    logSpy.mockClear();
    handleCloudConfig(['--cloud-status']);
    const lines = logSpy.mock.calls.map((c) => String(c[0]));
    expect(lines.some((l) => l.includes('Action Guard: Enforce'))).toBe(true);
  });

  it('--action-guard-advisory writes enforce:false and leaves enabled as-is, status shows Advisory', () => {
    handleCloudConfig(['--action-guard-enable']);
    handleCloudConfig(['--action-guard-advisory']);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.actionGuard.enabled).toBe(true);
    expect(onDisk.actionGuard.enforce).toBe(false);
    const cfg = getActionGuardCoreConfig();
    expect(cfg.enabled).toBe(true);
    expect(cfg.enforce).toBe(false);
    logSpy.mockClear();
    handleCloudConfig(['--cloud-status']);
    const lines = logSpy.mock.calls.map((c) => String(c[0]));
    expect(lines.some((l) => l.includes('Action Guard: Advisory (warn-mode)'))).toBe(true);
  });

  it('--action-guard-advisory on a disabled guard still writes enforce:false without re-enabling', () => {
    handleCloudConfig(['--action-guard-disable']);
    handleCloudConfig(['--action-guard-advisory']);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.actionGuard.enabled).toBe(false);
    expect(onDisk.actionGuard.enforce).toBe(false);
  });

  it('disable then enforce re-enables: enforce implies enabled', () => {
    handleCloudConfig(['--action-guard-disable']);
    handleCloudConfig(['--action-guard-enforce']);
    const cfg = getActionGuardCoreConfig();
    expect(cfg.enabled).toBe(true);
    expect(cfg.enforce).toBe(true);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.actionGuard.enabled).toBe(true);
    expect(onDisk.actionGuard.enforce).toBe(true);
  });

  it('preserves sibling actionGuard keys (notify, reviewedScripts) on write', () => {
    handleCloudConfig(['--action-guard-notify-webhook', 'https://hooks.example.invalid/sc']);
    setReviewedScripts([{ hash: 'abc123' }]);
    handleCloudConfig(['--action-guard-enforce']);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.actionGuard.notify.enabled).toBe(true);
    expect(onDisk.actionGuard.notify.webhookUrl).toBe('https://hooks.example.invalid/sc');
    expect(onDisk.actionGuard.reviewedScripts).toEqual([{ hash: 'abc123' }]);
    expect(onDisk.actionGuard.enabled).toBe(true);
    expect(onDisk.actionGuard.enforce).toBe(true);
  });

  it('preserves unrelated top-level keys (defenceMode) on write', () => {
    handleCloudConfig(['--mode', 'balanced']);
    handleCloudConfig(['--action-guard-enable']);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.defenceMode).toBe('balanced');
    expect(onDisk.actionGuard.enabled).toBe(true);
  });

  it('the same hand-edit the CLI replaces DOES trip the integrity check (why doctor must not recommend it)', () => {
    handleCloudConfig(['--action-guard-enable']);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    onDisk.actionGuard.enabled = false;
    fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
    clearCloudConfigCache();
    const raw = readRawConfig();
    expect(isConfigTampered()).toBe(true);
    expect(raw.defenceMode).toBe('strict');
  });
});
