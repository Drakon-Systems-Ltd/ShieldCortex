/**
 * Signed Guard CLI syncs OpenClaw plugin actionGuard.enabled/enforce onto an
 * EXISTING object entry. Missing/malformed config does not invent an agent or
 * entry. Guard stays off by default.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { handleCloudConfig } from '../../cloud/cli.js';
import {
  clearCloudConfigCache,
  getActionGuardCoreConfig,
  getConfigDir,
  setActionGuardCoreConfig,
} from '../../cloud/config.js';
import { syncOpenClawPluginActionGuard } from '../openclaw-plugin-guard-sync.js';

function writeOpenClaw(home: string, doc: unknown): string {
  const dir = join(home, '.openclaw');
  mkdirSync(dir, { recursive: true });
  const path = join(dir, 'openclaw.json');
  writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`);
  return path;
}

describe('syncOpenClawPluginActionGuard', () => {
  let prevHome: string | undefined;
  let tmp: string;

  beforeEach(() => {
    prevHome = process.env.OPENCLAW_HOME;
    tmp = mkdtempSync(join(tmpdir(), 'sc-guard-sync-'));
    process.env.OPENCLAW_HOME = tmp;
    clearCloudConfigCache();
  });

  afterEach(() => {
    if (prevHome === undefined) delete process.env.OPENCLAW_HOME;
    else process.env.OPENCLAW_HOME = prevHome;
    rmSync(tmp, { recursive: true, force: true });
    clearCloudConfigCache();
  });

  it('writes enabled/enforce onto an existing object entry and preserves hooks + siblings', () => {
    writeOpenClaw(tmp, {
      plugins: {
        entries: {
          'shieldcortex-realtime': {
            enabled: true,
            hooks: { allowConversationAccess: false },
            config: { actionGuard: { enforce: false }, keepMe: 1 },
          },
          codex: { enabled: true, config: { appServer: { networkProxy: true } } },
        },
      },
    });

    const out = syncOpenClawPluginActionGuard({ enabled: true, enforce: true });
    expect(out.status).toBe('applied');

    const onDisk = JSON.parse(readFileSync(join(tmp, '.openclaw', 'openclaw.json'), 'utf8'));
    const sc = onDisk.plugins.entries['shieldcortex-realtime'];
    expect(sc.enabled).toBe(true);
    expect(sc.hooks.allowConversationAccess).toBe(false);
    expect(sc.config.keepMe).toBe(1);
    expect(sc.config.actionGuard.enabled).toBe(true);
    expect(sc.config.actionGuard.enforce).toBe(true);
    expect(onDisk.plugins.entries.codex.config.appServer.networkProxy).toBe(true);
  });

  it('does not invent an entry when none exists', () => {
    writeOpenClaw(tmp, { plugins: { entries: { codex: { enabled: true } } } });
    expect(syncOpenClawPluginActionGuard({ enabled: true })).toEqual({ status: 'skipped', reason: 'no-entry' });
    const onDisk = JSON.parse(readFileSync(join(tmp, '.openclaw', 'openclaw.json'), 'utf8'));
    expect(onDisk.plugins.entries['shieldcortex-realtime']).toBeUndefined();
  });

  it('skips missing config', () => {
    expect(syncOpenClawPluginActionGuard({ enabled: false })).toEqual({
      status: 'skipped',
      reason: 'missing-config',
    });
  });

  it('skips malformed JSON without rewriting', () => {
    const dir = join(tmp, '.openclaw');
    mkdirSync(dir, { recursive: true });
    const path = join(dir, 'openclaw.json');
    writeFileSync(path, '{ this is not json');
    expect(syncOpenClawPluginActionGuard({ enabled: true })).toEqual({
      status: 'skipped',
      reason: 'malformed',
    });
    expect(readFileSync(path, 'utf8')).toBe('{ this is not json');
  });

  it('ignores null/false entry values — not an object record', () => {
    writeOpenClaw(tmp, {
      plugins: { entries: { 'shieldcortex-realtime': null, 'mc-watchdog': false } },
    });
    expect(syncOpenClawPluginActionGuard({ enabled: true })).toEqual({
      status: 'skipped',
      reason: 'no-entry',
    });
  });

  it('advisory writes enforce:false without flipping a disabled guard on', () => {
    writeOpenClaw(tmp, {
      plugins: {
        entries: {
          'shieldcortex-realtime': {
            enabled: true,
            config: { actionGuard: { enabled: false, enforce: true } },
          },
        },
      },
    });
    expect(syncOpenClawPluginActionGuard({ enforce: false }).status).toBe('applied');
    const sc = JSON.parse(readFileSync(join(tmp, '.openclaw', 'openclaw.json'), 'utf8'))
      .plugins.entries['shieldcortex-realtime'];
    expect(sc.config.actionGuard.enabled).toBe(false);
    expect(sc.config.actionGuard.enforce).toBe(false);
  });
});

describe('setActionGuardCoreConfig plane sync', () => {
  let prevHome: string | undefined;
  let tmp: string;

  beforeEach(() => {
    prevHome = process.env.OPENCLAW_HOME;
    tmp = mkdtempSync(join(tmpdir(), 'sc-guard-signed-'));
    process.env.OPENCLAW_HOME = tmp;
    clearCloudConfigCache();
    rmSync(join(getConfigDir(), 'config.json'), { force: true });
  });

  afterEach(() => {
    if (prevHome === undefined) delete process.env.OPENCLAW_HOME;
    else process.env.OPENCLAW_HOME = prevHome;
    rmSync(tmp, { recursive: true, force: true });
    rmSync(join(getConfigDir(), 'config.json'), { force: true });
    clearCloudConfigCache();
    jest.restoreAllMocks();
  });

  it('enable writes signed enabled:true AND plugin enabled:true', () => {
    writeOpenClaw(tmp, {
      plugins: {
        entries: {
          'shieldcortex-realtime': { enabled: true, config: { actionGuard: { enforce: false } } },
        },
      },
    });
    const sync = setActionGuardCoreConfig({ enabled: true });
    expect(sync.status).toBe('applied');
    expect(getActionGuardCoreConfig().enabled).toBe(true);
    const sc = JSON.parse(readFileSync(join(tmp, '.openclaw', 'openclaw.json'), 'utf8'))
      .plugins.entries['shieldcortex-realtime'];
    expect(sc.config.actionGuard.enabled).toBe(true);
    expect(sc.config.actionGuard.enforce).toBe(false);
  });

  it('CLI enable prints restart advice when the plugin entry exists', () => {
    writeOpenClaw(tmp, {
      plugins: {
        entries: { 'shieldcortex-realtime': { enabled: true, config: {} } },
      },
    });
    const lines: string[] = [];
    jest.spyOn(console, 'log').mockImplementation((m?: unknown) => { lines.push(String(m ?? '')); });
    handleCloudConfig(['--action-guard-enable']);
    expect(lines.some((l) => /Restart the gateway/i.test(l))).toBe(true);
    expect(getActionGuardCoreConfig().enabled).toBe(true);
  });

  it('CLI enable still signs when OpenClaw config is absent — no invented entry', () => {
    const lines: string[] = [];
    jest.spyOn(console, 'log').mockImplementation((m?: unknown) => { lines.push(String(m ?? '')); });
    handleCloudConfig(['--action-guard-enable']);
    expect(getActionGuardCoreConfig().enabled).toBe(true);
    expect(lines.some((l) => /plugin entry not present/i.test(l))).toBe(true);
  });
});
