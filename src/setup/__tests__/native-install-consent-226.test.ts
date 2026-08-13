import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

import {
  installOpenClawHook,
  isDockerEnvironment,
  openClawConfigPath,
  readConversationAccessGrantOnDisk,
  __setNativePluginInstallForTest,
} from '../openclaw.js';

/**
 * #226 — `--allow-conversation-access` was a no-op on the common install path.
 *
 * `installPlugin` tries the NATIVE route first: `openclaw plugins install
 * @drakon-systems/shieldcortex-realtime@latest`. On any box with the `openclaw`
 * binary on PATH that succeeds, and `installPlugin` RETURNS THERE — several
 * branches before `trustLocalPlugin`, which is the only thing that writes
 * `plugins.entries[id].hooks.allowConversationAccess`. So the flag was parsed,
 * documented in `--help`, threaded through three call signatures, and then
 * silently dropped for the majority of installs. The operator gave consent,
 * saw no error, and got a gateway that still refused every conversation hook.
 *
 * The fix routes the consent through the one call every non-skipped install
 * mode converges on — the #213 post-install `verifyPluginRegistration`, which
 * writes merge-preservingly and re-reads the file to prove the write landed —
 * and hoists the granted/NOT-granted operator notice out of the local-copy
 * branch so every mode reports it.
 *
 * HOST SAFETY — read this before editing the setup below.
 *
 * `installOpenClawHook` WRITES openclaw.json, and it resolves its path through
 * `resolveUserHome()` → `os.homedir()`. Setting `process.env.HOME` does NOT
 * redirect that under Jest: jest's `process.env` is a copy that never reaches
 * the native binding, so a suite written that way runs the installer against
 * the developer's REAL `~/.openclaw/openclaw.json` and grants a live box
 * conversation access. (Asked how I know.) The redirect here is a spy on
 * `os.homedir`, and `beforeEach` PROVES it landed — by asking the module under
 * test which config path it resolves — and throws before any test body runs if
 * it did not. A missing redirect must be a loud failure, never a live edit.
 *
 * The gateway restart and the live self-check are both switched off
 * (`restartGateway: false`), and the native installer is a stub, so no process
 * is spawned either.
 */

const PLUGIN = 'shieldcortex-realtime';

let tempHome: string;
let previousDocker: string | undefined;
let logSpy: ReturnType<typeof jest.spyOn>;
let warnSpy: ReturnType<typeof jest.spyOn>;
let errorSpy: ReturnType<typeof jest.spyOn>;
let previousExitCode: number | string | undefined;

function configPath(): string {
  return path.join(tempHome, '.openclaw', 'openclaw.json');
}

function readConfig(): any {
  return JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
}

function writeConfig(cfg: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2) + '\n');
}

/** Everything the installer printed, on any stream. */
function output(): string {
  return [...logSpy.mock.calls, ...warnSpy.mock.calls, ...errorSpy.mock.calls]
    .map((args) => args.map(String).join(' '))
    .join('\n');
}

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-native-consent-226-'));
  // Neutralise container detection: `installPlugin` skips entirely inside a
  // container, which would make this test assert nothing on a CI runner that
  // happens to be one. `DOCKER=false` is the escape the installer's own advice
  // already tells operators to use.
  previousDocker = process.env.DOCKER;
  process.env.DOCKER = 'false';
  // ~/.openclaw must exist or installOpenClawHook exits before it gets here.
  fs.mkdirSync(path.join(tempHome, '.openclaw'), { recursive: true });
  previousExitCode = process.exitCode;
  logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

  // THE REDIRECT…
  jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
  // …AND THE PROOF IT LANDED. Ask the module under test where it will write.
  // If anything about home resolution (a spy that did not take, SUDO_USER, a
  // root uid) puts that outside the temp dir, fail HERE — before a single test
  // body runs — rather than let the installer loose on a real box.
  const resolved = openClawConfigPath();
  if (!resolved.startsWith(tempHome + path.sep)) {
    throw new Error(
      `REFUSING TO RUN: home redirect failed. installOpenClawHook would write ${resolved}, ` +
      `not a path under ${tempHome}.`,
    );
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

/** The install, with hooks and the gateway restart out of the way — this suite
 *  is about what lands in openclaw.json, not about copying hook files. */
async function runInstall(opts: { grantConversationAccess?: boolean } = {}): Promise<void> {
  await installOpenClawHook({
    noHooks: true,
    restartGateway: false,
    grantConversationAccess: opts.grantConversationAccess,
  });
}

describe('#226 the container escape hatch the installer already documents actually works', () => {
  it('DOCKER=false overrides the markers, as the skip message tells operators to do', () => {
    expect(isDockerEnvironment()).toBe(false);
    process.env.DOCKER = 'true';
    expect(isDockerEnvironment()).toBe(true);
    process.env.DOCKER = 'false';
    expect(isDockerEnvironment()).toBe(false);
  });
});

describe('#226 native install honours --allow-conversation-access', () => {
  it('writes the grant even though the native path never reaches trustLocalPlugin', async () => {
    __setNativePluginInstallForTest(() => 'native-package');
    // The native installer registers the plugin itself; the grant is a
    // separate key it knows nothing about.
    writeConfig({ plugins: { allow: [PLUGIN], entries: { [PLUGIN]: { enabled: true } } } });

    await runInstall({ grantConversationAccess: true });

    const after = readConfig();
    expect(after.plugins.entries[PLUGIN]).toEqual({
      enabled: true,
      hooks: { allowConversationAccess: true },
    });
    expect(readConversationAccessGrantOnDisk(tempHome)).toBe(true);
  });

  it('reports the grant out loud on the native path, which used to print nothing at all', async () => {
    __setNativePluginInstallForTest(() => 'native-package');
    writeConfig({ plugins: { allow: [PLUGIN], entries: { [PLUGIN]: { enabled: true } } } });

    await runInstall({ grantConversationAccess: true });

    expect(output()).toMatch(/Granted conversation-hook access at your request/);
    expect(output()).toMatch(/read prompts and model output on this box/);
  });

  it('the linked-install mode gets the same treatment', async () => {
    __setNativePluginInstallForTest(() => 'native-link');
    writeConfig({ plugins: { allow: [PLUGIN], entries: { [PLUGIN]: { enabled: true } } } });

    await runInstall({ grantConversationAccess: true });

    expect(readConversationAccessGrantOnDisk(tempHome)).toBe(true);
  });

  it('other hook policies on the same stanza survive the write', async () => {
    __setNativePluginInstallForTest(() => 'native-package');
    writeConfig({
      plugins: {
        allow: ['codex', PLUGIN],
        entries: {
          codex: { enabled: true, config: { appServer: {} } },
          [PLUGIN]: { enabled: true, hooks: { somethingElse: true } },
        },
      },
    });

    await runInstall({ grantConversationAccess: true });

    const after = readConfig();
    expect(after.plugins.entries[PLUGIN].hooks).toEqual({
      somethingElse: true,
      allowConversationAccess: true,
    });
    // Never a whole-file clobber: the neighbour plugin is untouched.
    expect(after.plugins.entries.codex).toEqual({ enabled: true, config: { appServer: {} } });
    expect(after.plugins.allow).toContain('codex');
  });

  it('a native install that also wiped the stanza (#213) is restored WITH the grant', async () => {
    __setNativePluginInstallForTest(() => 'native-package');
    // The field shape from #213: `openclaw plugins install` exits 0 and the
    // stanza is gone.
    writeConfig({ plugins: { allow: ['codex'], entries: { codex: { enabled: true } } } });

    await runInstall({ grantConversationAccess: true });

    const after = readConfig();
    expect(after.plugins.allow).toContain(PLUGIN);
    expect(after.plugins.entries[PLUGIN]).toEqual({
      enabled: true,
      hooks: { allowConversationAccess: true },
    });
    expect(output()).toMatch(/stanza restored/);
  });
});

describe('#226 without consent the installer still never grants it', () => {
  it('leaves the gate untouched and says what that costs', async () => {
    __setNativePluginInstallForTest(() => 'native-package');
    writeConfig({ plugins: { allow: [PLUGIN], entries: { [PLUGIN]: { enabled: true } } } });

    await runInstall();

    expect(readConfig().plugins.entries[PLUGIN]).toEqual({ enabled: true });
    expect(readConversationAccessGrantOnDisk(tempHome)).toBe(false);
    // The notice is the point: an operator must not have to discover an inert
    // conversation firewall from a config diff.
    expect(output()).toMatch(/conversation-hook access is NOT granted/);
    expect(output()).toMatch(/--allow-conversation-access/);
  });

  it('an existing grant is preserved, not stripped, by an install without the flag', async () => {
    __setNativePluginInstallForTest(() => 'native-package');
    writeConfig({
      plugins: {
        allow: [PLUGIN],
        entries: { [PLUGIN]: { enabled: true, hooks: { allowConversationAccess: true } } },
      },
    });

    await runInstall();

    expect(readConversationAccessGrantOnDisk(tempHome)).toBe(true);
    // And it is reported as the pre-existing state rather than as a new grant.
    expect(output()).toMatch(/already granted on this box/);
  });

  it('the notice is skipped entirely when no plugin was installed', async () => {
    __setNativePluginInstallForTest(() => null);
    writeConfig({ plugins: { allow: [], entries: {} } });

    await installOpenClawHook({ noHooks: true, noPlugins: true, restartGateway: false });

    expect(output()).not.toMatch(/conversation-hook access/);
  });
});

describe('#226 the local-copy path keeps reporting the same thing', () => {
  it('reports NOT granted once, from the hoisted call, not twice from two places', async () => {
    // The notice used to live inside installPlugin's local-copy branch. It now
    // lives in installOpenClawHook — so exactly one copy of it must appear.
    __setNativePluginInstallForTest(() => 'native-package');
    writeConfig({ plugins: { allow: [PLUGIN], entries: { [PLUGIN]: { enabled: true } } } });

    await runInstall();

    const occurrences = output().split('conversation-hook access is NOT granted').length - 1;
    expect(occurrences).toBe(1);
  });
});
