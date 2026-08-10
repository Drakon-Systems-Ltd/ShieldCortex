import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import {
  resolveLocalExtensionInstall,
  readLocalExtensionPluginVersion,
  readInstalledRealtimePluginVersion,
} from '../openclaw-plugin-state.js';
import { gatherReconcileInput, reconcilePluginState } from '../openclaw-plugin-index.js';
import { checkOpenClawPluginLoadState } from '../../cli/doctor.js';

/**
 * #226 — the trusted-local-copy install read as "not installed".
 *
 * `installPlugin` has two routes. The native one (`openclaw plugins install`)
 * writes an installs.json record, an npm project dir and a SQLite index row.
 * The FALLBACK one — used whenever there is no `openclaw` binary on PATH, or
 * the package install fails, or the box is air-gapped — copies the plugin into
 * `~/.openclaw/extensions/shieldcortex-realtime/` and registers it in
 * openclaw.json. OpenClaw loads it from there perfectly well.
 *
 * None of the three layers the reconciler consulted records that copy. So on a
 * correctly installed, gateway-loaded, protected box, `installed` computed
 * false — and because the same installer had written `enabled: true`, the
 * verdict was `enabled-not-installed`: a red doctor FAIL announcing that "the
 * gateway boots with NO memory firewall and NO action guard".
 *
 * The fix has to be narrow in the other direction too. A DIRECTORY is not an
 * install: an interrupted copy, or an uninstall that removed the files but not
 * the folder, leaves one behind, and counting it would trade this false FAIL
 * for a false PASS — the #222 shape, which is the worse of the two. So both
 * `index.js` and `openclaw.plugin.json` must be present.
 */

const PLUGIN = 'shieldcortex-realtime';
const VERSION = '4.47.35';

let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-localcopy-226-'));
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function extDir(): string {
  return path.join(home, '.openclaw', 'extensions', PLUGIN);
}

/** Exactly what `installPlugin`'s local-copy branch leaves on disk. */
function writeValidLocalCopy(manifestVersion: string | null = VERSION): void {
  fs.mkdirSync(extDir(), { recursive: true });
  fs.writeFileSync(path.join(extDir(), 'index.js'), 'export default {};\n');
  fs.writeFileSync(path.join(extDir(), 'interceptor.js'), 'export {};\n');
  const manifest: Record<string, unknown> = { id: PLUGIN, name: 'ShieldCortex Real-time Scanner' };
  if (manifestVersion) manifest.version = manifestVersion;
  fs.writeFileSync(path.join(extDir(), 'openclaw.plugin.json'), JSON.stringify(manifest, null, 2) + '\n');
  // The installer writes this three-key ESM marker. Note: NO version field —
  // reading the version from here alone reports a valid install as unknown.
  fs.writeFileSync(
    path.join(extDir(), 'package.json'),
    JSON.stringify({ name: 'shieldcortex-realtime-local', type: 'module', private: true }, null, 2) + '\n',
  );
}

function writeOpenClawConfig(enabled: boolean): void {
  const dir = path.join(home, '.openclaw');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'openclaw.json'),
    JSON.stringify(
      { plugins: { allow: [PLUGIN], entries: { [PLUGIN]: { enabled } } } },
      null,
      2,
    ) + '\n',
  );
}

/** gatherReconcileInput with the two live-host readers stubbed out, so the
 *  test never touches this box's SQLite index or gateway log. */
function gather(over: { index?: unknown } = {}) {
  return gatherReconcileInput(home, {
    expectedVersion: VERSION,
    readIndex: () => (over.index as never) ?? null,
    readLiveRoster: () => null,
  });
}

describe('#226 a valid extensions copy IS an install', () => {
  it('resolveLocalExtensionInstall finds it, and the version comes off the manifest', () => {
    writeValidLocalCopy();
    expect(resolveLocalExtensionInstall(home)).toBe(extDir());
    expect(readLocalExtensionPluginVersion(home)).toBe(VERSION);
    // The shared reader agrees, so doctor/update/self-check all see the build.
    expect(readInstalledRealtimePluginVersion(home)).toBe(VERSION);
  });

  it('gatherReconcileInput reports it as on-disk, and the reconciler stops calling it uninstalled', () => {
    writeValidLocalCopy();
    writeOpenClawConfig(true);

    const gathered = gather();
    expect(gathered.onDiskInstallPath).toBe(extDir());
    expect(gathered.onDiskVersion).toBe(VERSION);

    const verdict = reconcilePluginState(gathered);
    // The bug: enabled + a real on-disk build classified as "no package is
    // installed on this host".
    expect(verdict.state).not.toBe('enabled-not-installed');
    expect(verdict.state).not.toBe('not-installed');
  });

  it('with the index confirming it loaded, the verdict is healthy', () => {
    writeValidLocalCopy();
    writeOpenClawConfig(true);

    const verdict = reconcilePluginState({
      ...gather({
        index: {
          installRecords: {},
          plugins: [{ pluginId: PLUGIN, enabled: true }],
          warning: null,
        },
      }),
      liveRoster: [PLUGIN],
    });

    expect(verdict.state).toBe('healthy');
    expect(verdict.severity).toBe('ok');
  });

  it('doctor no longer FAILs a correctly installed local-copy box', async () => {
    writeValidLocalCopy();
    writeOpenClawConfig(true);

    const result = await checkOpenClawPluginLoadState(home, VERSION);

    // Whatever else it says (the SQLite index is genuinely unreadable in a
    // temp home, which is its own honest warn), it must not claim the box has
    // no interceptor installed.
    expect(result.status).not.toBe('fail');
    expect(result.message).not.toMatch(/no package is installed on this host/);
  });

  it('a valid copy whose manifest version is unreadable still counts as installed', () => {
    // The version is a nice-to-have; the INSTALL is the fact. A manifest that
    // predates the version sync, or one an operator hand-edited, must not turn
    // a working install back into "nothing here".
    writeValidLocalCopy(null);
    writeOpenClawConfig(true);

    const gathered = gather();
    expect(gathered.onDiskVersion).toBeNull();
    expect(gathered.onDiskInstallPath).toBe(extDir());
    expect(reconcilePluginState(gathered).state).not.toBe('enabled-not-installed');
  });
});

describe('#226 a stale or partial extensions directory is NOT an install', () => {
  it('an empty directory does not count — and the enabled-but-absent FAIL still fires', () => {
    fs.mkdirSync(extDir(), { recursive: true });
    writeOpenClawConfig(true);

    expect(resolveLocalExtensionInstall(home)).toBeNull();
    expect(readLocalExtensionPluginVersion(home)).toBeNull();
    expect(readInstalledRealtimePluginVersion(home)).toBeNull();

    const verdict = reconcilePluginState(gather());
    // This is the state the check exists for: config claims protection, no
    // package on the box. Widening "installed" must not have silenced it.
    expect(verdict.state).toBe('enabled-not-installed');
    expect(verdict.severity).toBe('fail');
  });

  it('an index.js with no manifest does not count — OpenClaw will not load it', () => {
    fs.mkdirSync(extDir(), { recursive: true });
    fs.writeFileSync(path.join(extDir(), 'index.js'), 'export default {};\n');
    writeOpenClawConfig(true);

    expect(resolveLocalExtensionInstall(home)).toBeNull();
    expect(reconcilePluginState(gather()).state).toBe('enabled-not-installed');
  });

  it('a manifest with no index.js does not count either', () => {
    fs.mkdirSync(extDir(), { recursive: true });
    fs.writeFileSync(path.join(extDir(), 'openclaw.plugin.json'), JSON.stringify({ version: VERSION }));
    writeOpenClawConfig(true);

    expect(resolveLocalExtensionInstall(home)).toBeNull();
    expect(reconcilePluginState(gather()).state).toBe('enabled-not-installed');
  });

  it('no extensions directory at all is still plainly not-installed', () => {
    writeOpenClawConfig(false);
    expect(resolveLocalExtensionInstall(home)).toBeNull();
    expect(reconcilePluginState(gather()).state).toBe('not-installed');
  });

  it('a stale empty directory on a host with NO config claim stays a benign not-installed', () => {
    // No openclaw.json entry: nothing claims protection, so nothing is wrong.
    fs.mkdirSync(extDir(), { recursive: true });
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({ plugins: { allow: [], entries: {} } }));

    const verdict = reconcilePluginState(gather());
    expect(verdict.state).toBe('not-installed');
    expect(verdict.severity).toBe('ok');
  });
});
