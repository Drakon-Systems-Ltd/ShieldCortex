import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

import {
  installOpenClawHook,
  openClawConfigPath,
  snapshotOpenClawConfig,
  __setNativePluginInstallForTest,
} from '../openclaw.js';

/**
 * #214 leftovers — #213 restores a wiped stanza after install, but the
 * installer still had no on-disk snapshot of the config it was about to let
 * `openclaw plugins install` rewrite, and it deleted the extensions copy
 * BEFORE that native install was known to succeed.
 *
 * Field shape (Case, aiquant, 8 Aug): native install exited 0, stanza gone,
 * CLI said installed. The 13:57 `.bak` is why the box was recoverable at all.
 */

const PLUGIN = 'shieldcortex-realtime';

let tempHome: string;
let previousDocker: string | undefined;
let previousExitCode: string | number | undefined;

function configPath(): string {
  return path.join(tempHome, '.openclaw', 'openclaw.json');
}

function writeConfig(cfg: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2) + '\n');
}

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-214-bak-'));
  previousDocker = process.env.DOCKER;
  process.env.DOCKER = 'false';
  fs.mkdirSync(path.join(tempHome, '.openclaw'), { recursive: true });
  previousExitCode = process.exitCode;
  process.exitCode = undefined;
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
  const resolved = openClawConfigPath();
  if (!resolved.startsWith(tempHome + path.sep)) {
    throw new Error(`REFUSING TO RUN: home redirect failed (${resolved})`);
  }
});

afterEach(() => {
  __setNativePluginInstallForTest(null);
  if (previousDocker === undefined) delete process.env.DOCKER;
  else process.env.DOCKER = previousDocker;
  process.exitCode = previousExitCode;
  jest.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
});

describe('#214 pre-install snapshot of openclaw.json', () => {
  it('writes a dated .sc-preinstall.bak that still holds the pre-wipe stanza', async () => {
    writeConfig({
      plugins: {
        allow: ['codex', PLUGIN],
        entries: {
          codex: { enabled: true },
          [PLUGIN]: { enabled: true, hooks: { allowConversationAccess: true } },
        },
      },
    });
    const before = fs.readFileSync(configPath(), 'utf-8');

    __setNativePluginInstallForTest(() => {
      // The field wipe: native install exits 0 and the stanza is gone.
      writeConfig({ plugins: { allow: ['codex'], entries: { codex: { enabled: true } } } });
      return 'native-package';
    });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    const backups = fs.readdirSync(path.join(tempHome, '.openclaw'))
      .filter((n) => n.startsWith('openclaw.json.sc-preinstall.bak'));
    expect(backups.length).toBe(1);
    const snap = fs.readFileSync(path.join(tempHome, '.openclaw', backups[0]), 'utf-8');
    expect(snap).toBe(before);
    expect(JSON.parse(snap).plugins.allow).toContain(PLUGIN);
  });

  it('snapshotOpenClawConfig is a no-op when openclaw.json does not exist yet', () => {
    const result = snapshotOpenClawConfig(tempHome);
    expect(result).toBeNull();
    const leftovers = fs.readdirSync(path.join(tempHome, '.openclaw'))
      .filter((n) => n.includes('sc-preinstall'));
    expect(leftovers).toEqual([]);
  });

  it('a native wipe is still restored (#213) and the backup is not the live file', async () => {
    writeConfig({
      plugins: {
        allow: ['codex', PLUGIN],
        entries: { codex: { enabled: true }, [PLUGIN]: { enabled: true } },
      },
    });
    __setNativePluginInstallForTest(() => {
      writeConfig({ plugins: { allow: ['codex'], entries: { codex: { enabled: true } } } });
      return 'native-package';
    });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    const live = JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
    expect(live.plugins.allow).toContain(PLUGIN);
    expect(live.plugins.entries[PLUGIN].enabled).toBe(true);
    // Isolate from other suites that leave exitCode=1 on the worker
    // (macos-test failed this assertion while the stanza was restored).
    expect(process.exitCode).not.toBe(1);
  });
});

describe('#214 native install must not destroy the extensions copy first', () => {
  it('tryNativeOpenClawPluginInstall source does not rmSync the extensions copy before spawn', () => {
    const src = fs.readFileSync(
      path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'openclaw.ts'),
      'utf-8',
    );
    const fn = src.slice(src.indexOf('function tryNativeOpenClawPluginInstall'), src.indexOf('function findExtensionsDir'));
    const rmAt = fn.indexOf('rmSync');
    const spawnAt = fn.indexOf('spawnSync');
    expect(spawnAt).toBeGreaterThan(0);
    // Deleting the working copy before we know native install succeeded is
    // defect 3 in #214. A later rmSync (cleanup after success) is fine.
    if (rmAt >= 0) expect(rmAt).toBeGreaterThan(spawnAt);
  });
});
