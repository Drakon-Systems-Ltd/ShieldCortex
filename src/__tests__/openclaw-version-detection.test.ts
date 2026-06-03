import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { isRealtimePluginRegistered } from '../cli/update.js';
import { checkOpenClawPluginVersion } from '../cli/doctor.js';

/**
 * Regression (2026-06-03): `shieldcortex update` reported "OpenClaw plugin: not
 * installed" and silently skipped the plugin, leaving it stale (4.29.0) while
 * the npm package reached 4.30.1 — and `doctor` said "plugin installed" without
 * ever reading the version, so the staleness was invisible.
 *
 * Root cause: detection only checked `~/.openclaw/extensions/` and a
 * non-existent `~/.openclaw/npm/node_modules/...` path. OpenClaw's modern
 * `openclaw plugins install` stores the package under
 * `~/.openclaw/npm/projects/<name>-<hash>/node_modules/` and records it in
 * `~/.openclaw/plugins/installs.json`. These tests pin: (a) update detects the
 * registry-managed install, and (b) doctor surfaces the version + flags
 * staleness.
 */

const REALTIME_RECORD = {
  source: 'npm',
  spec: '@drakon-systems/shieldcortex-realtime@latest',
  installPath: '/home/u/.openclaw/npm/projects/drakon-systems-shieldcortex-realtime-abc/node_modules/@drakon-systems/shieldcortex-realtime',
  version: '4.29.0',
  resolvedVersion: '4.29.0',
};

function writeInstalls(dir: string, json: unknown): string {
  const pluginsDir = path.join(dir, '.openclaw', 'plugins');
  fs.mkdirSync(pluginsDir, { recursive: true });
  const file = path.join(pluginsDir, 'installs.json');
  fs.writeFileSync(file, JSON.stringify(json, null, 2));
  return file;
}

describe('update — isRealtimePluginRegistered (registry detection)', () => {
  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ocreg-'));
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('detects a registry-managed install via installRecords (the missed case — no extensions/ dir)', () => {
    writeInstalls(home, { installRecords: { 'shieldcortex-realtime': REALTIME_RECORD } });
    // No ~/.openclaw/extensions/shieldcortex-realtime exists — the old detection
    // returned false here, so `update` skipped the plugin. It must now be seen.
    expect(isRealtimePluginRegistered(home)).toBe(true);
  });

  it('detects via the plugins[] array entry as a fallback', () => {
    writeInstalls(home, { plugins: [{ pluginId: 'shieldcortex-realtime' }, { pluginId: 'brave' }] });
    expect(isRealtimePluginRegistered(home)).toBe(true);
  });

  it('returns false when the registry has no shieldcortex-realtime entry', () => {
    writeInstalls(home, { installRecords: { brave: {}, codex: {} }, plugins: [{ pluginId: 'brave' }] });
    expect(isRealtimePluginRegistered(home)).toBe(false);
  });

  it('returns false when there is no installs.json at all', () => {
    expect(isRealtimePluginRegistered(home)).toBe(false);
  });

  it('returns false (not throw) on an unreadable / malformed registry', () => {
    const pluginsDir = path.join(home, '.openclaw', 'plugins');
    fs.mkdirSync(pluginsDir, { recursive: true });
    fs.writeFileSync(path.join(pluginsDir, 'installs.json'), '{ not valid json');
    expect(isRealtimePluginRegistered(home)).toBe(false);
  });
});

describe('doctor — checkOpenClawPluginVersion (staleness)', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ocver-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('WARNs when the installed plugin lags the running package (the reported case: 4.29.0 vs 4.30.1)', async () => {
    const file = writeInstalls(dir, { installRecords: { 'shieldcortex-realtime': { version: '4.29.0' } } });
    const r = await checkOpenClawPluginVersion(file, '4.30.1');
    expect(r.status).toBe('warn');
    expect(r.message).toContain('4.29.0');
    expect(r.message).toContain('4.30.1');
    expect(r.fix).toContain('openclaw plugins update shieldcortex-realtime');
  });

  it('PASSes when the installed plugin matches the running package', async () => {
    const file = writeInstalls(dir, { installRecords: { 'shieldcortex-realtime': { version: '4.30.1' } } });
    const r = await checkOpenClawPluginVersion(file, '4.30.1');
    expect(r.status).toBe('pass');
    expect(r.message).toContain('4.30.1');
    expect(r.message).toContain('current');
  });

  it('reports INFO (not a warning) when the installed plugin is ahead of the local package', async () => {
    const file = writeInstalls(dir, { installRecords: { 'shieldcortex-realtime': { version: '4.31.0' } } });
    const r = await checkOpenClawPluginVersion(file, '4.30.1');
    expect(r.status).toBe('info');
    expect(r.message).toContain('ahead');
  });

  it('falls back to resolvedVersion when version is absent', async () => {
    const file = writeInstalls(dir, { installRecords: { 'shieldcortex-realtime': { resolvedVersion: '4.29.0' } } });
    const r = await checkOpenClawPluginVersion(file, '4.30.1');
    expect(r.status).toBe('warn');
    expect(r.message).toContain('4.29.0');
  });

  it('skips (info) when the registry is absent', async () => {
    const r = await checkOpenClawPluginVersion(path.join(dir, 'nope', 'installs.json'), '4.30.1');
    expect(r.status).toBe('info');
    expect(r.message).toContain('skipped');
  });

  it('skips (info) when the realtime plugin is not registered', async () => {
    const file = writeInstalls(dir, { installRecords: { brave: { version: '1.0.0' } } });
    const r = await checkOpenClawPluginVersion(file, '4.30.1');
    expect(r.status).toBe('info');
    expect(r.message).toContain('not registered');
  });
});
