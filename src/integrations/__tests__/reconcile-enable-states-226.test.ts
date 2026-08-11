import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  reconcilePluginState,
  planReconcileActions,
  readConfigEnable,
  type ReconcileInput,
} from '../openclaw-plugin-index.js';

/**
 * #226 — the reconciler's config-side blind spots.
 *
 * Three states it could not tell apart, each of which resolved to a confident
 * answer it had no evidence for:
 *
 *  1. installed-not-enabled routed its remediation to a REINSTALL. The package
 *     was already on disk and byte-correct; `plugins install --force` does not
 *     write an enable flag, so the plan ran, reported success, and left the
 *     host exactly as unprotected as it found it.
 *  2. `enabled: true` in config with NO package installed fell into
 *     `not-installed` / severity ok — "nothing is claimed" reasoning applied to
 *     a config that claims protection out loud.
 *  3. A truncated or permission-denied openclaw.json was caught by the same
 *     `catch` as a file with no entry, so cannot-read became "config says
 *     nothing" and the #222 rule convicted it as an unprotected wipe.
 *
 * And two false reds: an operator who deliberately sets `enabled: false` was
 * told they had a security failure, and so was one whose uninstall left an
 * empty npm project directory behind.
 */

const PLUGIN = 'shieldcortex-realtime';

function input(over: Partial<ReconcileInput> = {}): ReconcileInput {
  return {
    pluginId: PLUGIN,
    expectedVersion: '4.47.35',
    config: { enabled: true, inAllow: true },
    installsJson: { version: '4.47.35', installPath: '/x' },
    index: {
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.35', installPath: '/x' } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
      warning: null,
    },
    onDiskVersion: '4.47.35',
    projectDirs: [],
    liveRoster: [PLUGIN],
    ...over,
  };
}

describe('#226 (1) installed-not-enabled repairs by ENABLING, never reinstalling', () => {
  it('is a fail, and the recommended action is re-register', () => {
    const v = reconcilePluginState(
      input({ config: { enabled: null, inAllow: false }, liveRoster: [] }),
    );
    expect(v.state).toBe('installed-not-enabled');
    expect(v.severity).toBe('fail');
    expect(v.recommendedAction).toBe('re-register');
  });

  it('the plan writes the config and reloads — it never runs an install command', () => {
    const v = reconcilePluginState(
      input({ config: { enabled: null, inAllow: false }, liveRoster: [] }),
    );
    const steps = planReconcileActions(v, {
      pluginId: PLUGIN,
      packageName: '@drakon-systems/shieldcortex-realtime',
      expectedVersion: '4.47.35',
    });
    expect(steps.map((s) => s.kind)).toEqual([
      'restore-registration',
      'gateway-reload',
      'self-check',
    ]);
    // The precise regression: no step shells out to the installer.
    expect(steps.some((s) => s.kind.startsWith('openclaw'))).toBe(false);
    expect(steps.some((s) => (s.command ?? []).includes('install'))).toBe(false);
  });

  it('stays re-register for an OpenClaw-tracked install too', () => {
    // openClawTracked used to switch the routing to `plugins update`, which is
    // just as irrelevant to a config flag as `plugins install`.
    const v = reconcilePluginState(
      input({ config: { enabled: null, inAllow: false }, liveRoster: [] }),
    );
    expect(v.openClawTracked).toBe(true);
    expect(v.recommendedAction).toBe('re-register');
  });
});

describe('#226 (2) config enabled + package absent is a FAIL, not "not installed"', () => {
  const absent = {
    installsJson: null,
    index: { installRecords: {}, plugins: [], warning: null },
    onDiskVersion: null,
    projectDirs: [],
    liveRoster: [],
  } as const;

  it('fails and names the disagreement between config and disk', () => {
    const v = reconcilePluginState(input({ ...absent, config: { enabled: true, inAllow: true } }));
    expect(v.state).toBe('enabled-not-installed');
    expect(v.severity).toBe('fail');
    expect(v.recommendedAction).toBe('install');
    expect(v.reasons.join(' ')).toMatch(/ENABLES .* but no package is installed/i);
  });

  it('an allow-list-only enable (entries stanza absent) counts as enabled', () => {
    const v = reconcilePluginState(input({ ...absent, config: { enabled: null, inAllow: true } }));
    expect(v.state).toBe('enabled-not-installed');
    expect(v.severity).toBe('fail');
  });

  it('but a genuinely unconfigured host is still ok/not-installed', () => {
    const v = reconcilePluginState(input({ ...absent, config: { enabled: null, inAllow: false } }));
    expect(v.state).toBe('not-installed');
    expect(v.severity).toBe('ok');
  });

  it('remediation for the enabled-but-absent case is an install', () => {
    const v = reconcilePluginState(input({ ...absent, config: { enabled: true, inAllow: true } }));
    const steps = planReconcileActions(v, {
      pluginId: PLUGIN,
      packageName: '@drakon-systems/shieldcortex-realtime',
      expectedVersion: '4.47.35',
    });
    expect(steps.map((s) => s.kind)).toContain('openclaw-install');
  });
});

describe('#226 (11) an unreadable openclaw.json is INDETERMINATE, not absent', () => {
  it('warns rather than convicting the host as wiped', () => {
    const v = reconcilePluginState(
      input({
        config: { enabled: null, inAllow: false, readable: false, present: true },
        liveRoster: [],
      }),
    );
    expect(v.state).toBe('config-unreadable');
    expect(v.severity).toBe('warn');
    expect(v.configReadable).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/INDETERMINATE/);
    // The false red this replaces.
    expect(v.state).not.toBe('installed-not-enabled');
  });

  it('outranks every other rule — a regressed version cannot be judged either', () => {
    const v = reconcilePluginState(
      input({
        config: { enabled: null, inAllow: false, readable: false, present: true },
        onDiskVersion: '4.25.4',
      }),
    );
    expect(v.state).toBe('config-unreadable');
  });

  it('a caller that says nothing about readability still means "read it"', () => {
    // Every pre-#226 fixture omits the flag; none of them may change meaning.
    const v = reconcilePluginState(input());
    expect(v.configReadable).toBe(true);
    expect(v.state).toBe('healthy');
  });
});

describe('#226 (12) explicit enabled:false is ALWAYS an intentional disable', () => {
  /**
   * The rule, and why it has no evidence test in front of it.
   *
   * `enabled: false` is a sentence somebody typed. A wiped stanza (no entry at
   * all) is not — that stays the #222 fail. An earlier cut of this branch tried
   * to split the explicit case on "was this plugin ever running here", reading
   * the install index and the live roster as prior-presence evidence. Neither
   * is evidence of that: the index lags config by design and still lists a
   * plugin disabled minutes ago, and the RUNNING gateway is expected to still
   * have it loaded from the pre-disable config until it restarts. So the most
   * ordinary sequence there is — edit openclaw.json, run doctor before
   * restarting — hit both branches and reported a correct, deliberate operator
   * action as a red security FAIL. That is how the alarm that catches the real
   * wipe gets ignored.
   */
  it('no stale index row, nothing loaded → WARN, reported as an intentional disable', () => {
    const v = reconcilePluginState(
      input({
        config: { enabled: false, inAllow: false },
        index: {
          installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.35', installPath: '/x' } },
          plugins: [],
          warning: null,
        },
        liveRoster: [],
      }),
    );
    expect(v.state).toBe('disabled-by-operator');
    expect(v.severity).toBe('warn');
    expect(v.recommendedAction).toBe('none');
    // Remediation must never propose reinstalling a package that is present.
    expect(v.reasons.join(' ')).toMatch(/nothing needs reinstalling/i);
    // And it still says out loud what the host is running without.
    expect(v.reasons.join(' ')).toMatch(/WITHOUT the memory firewall/i);
  });

  it('a STALE index row saying enabled does not turn the operator\'s decision into a fault', () => {
    const v = reconcilePluginState(
      input({ config: { enabled: false, inAllow: false }, liveRoster: [] }),
    );
    expect(v.loadedInIndex).toBe(true);
    expect(v.state).toBe('disabled-by-operator');
    expect(v.severity).toBe('warn');
  });

  it('a still-loaded RUNNING gateway does not either — but the restart is named', () => {
    const v = reconcilePluginState(
      input({ config: { enabled: false, inAllow: false }, liveRoster: [PLUGIN] }),
    );
    expect(v.state).toBe('disabled-by-operator');
    expect(v.severity).toBe('warn');
    expect(v.reasons.join(' ')).toMatch(/protection ends at the next restart/i);
  });

  it('`inAllow: true` alongside enabled:false is still the operator\'s call', () => {
    // Leaving plugins.allow alone while flipping `enabled` is the ordinary way
    // to disable a plugin; the explicit false wins.
    const v = reconcilePluginState(
      input({ config: { enabled: false, inAllow: true }, liveRoster: [] }),
    );
    expect(v.state).toBe('disabled-by-operator');
    expect(v.severity).toBe('warn');
  });

  it('a WIPED stanza (no entry at all) is still a FAIL — nobody typed that', () => {
    const v = reconcilePluginState(
      input({
        config: { enabled: null, inAllow: false },
        index: {
          installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.35', installPath: '/x' } },
          plugins: [],
          warning: null,
        },
        liveRoster: [],
      }),
    );
    expect(v.state).toBe('installed-not-enabled');
    expect(v.severity).toBe('fail');
    expect(v.recommendedAction).toBe('re-register');
  });
});

describe('#226 (4) a stale project directory is not an installation', () => {
  /**
   * `openclaw plugins uninstall` drops the install record and the config stanza
   * and does not always reap the npm project directory under
   * `~/.openclaw/npm/projects`. Counting that leftover as installation evidence
   * made a cleanly uninstalled host classify installed-not-enabled and report a
   * red FAIL — "the gateway will boot WITHOUT the interceptor" — about a plugin
   * the operator deliberately removed.
   */
  const uninstalled = {
    installsJson: null,
    index: { installRecords: {}, plugins: [], warning: null },
    onDiskVersion: null,
    liveRoster: [],
  } as const;

  it('an empty leftover project dir after uninstall is NOT-INSTALLED, not a fail', () => {
    const v = reconcilePluginState(
      input({
        ...uninstalled,
        config: { enabled: null, inAllow: false },
        projectDirs: ['shieldcortex-realtime-abc123'],
      }),
    );
    expect(v.state).toBe('not-installed');
    expect(v.severity).toBe('ok');
  });

  it('each real install record on its own still counts as installed', () => {
    const withInstallsJson = reconcilePluginState(
      input({
        ...uninstalled,
        installsJson: { version: '4.47.35', installPath: '/x' },
        config: { enabled: null, inAllow: false },
      }),
    );
    expect(withInstallsJson.state).toBe('installed-not-enabled');

    const withOnDisk = reconcilePluginState(
      input({ ...uninstalled, onDiskVersion: '4.47.35', config: { enabled: null, inAllow: false } }),
    );
    expect(withOnDisk.state).toBe('installed-not-enabled');

    const withIndexRecord = reconcilePluginState(
      input({
        ...uninstalled,
        index: {
          installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.35', installPath: '/x' } },
          plugins: [],
          warning: null,
        },
        config: { enabled: null, inAllow: false },
      }),
    );
    expect(withIndexRecord.state).toBe('installed-not-enabled');
  });

  it('config enabling a plugin whose only trace is a stale dir is still the enabled-not-installed FAIL', () => {
    const v = reconcilePluginState(
      input({
        ...uninstalled,
        config: { enabled: true, inAllow: true },
        projectDirs: ['shieldcortex-realtime-abc123'],
      }),
    );
    expect(v.state).toBe('enabled-not-installed');
    expect(v.severity).toBe('fail');
  });

  it('duplicate dirs are still reported when the plugin IS installed', () => {
    const v = reconcilePluginState(
      input({ projectDirs: ['shieldcortex-realtime-a', 'shieldcortex-realtime-b'] }),
    );
    expect(v.state).toBe('duplicate-install');
  });
});

describe('#226 readConfigEnable — three outcomes off a real disk', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-cfgread-'));
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
  });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  const write = (body: string) =>
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), body, 'utf-8');

  it('parsed: reports the enable flag and marks the file readable', () => {
    write(JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: true } }, allow: [PLUGIN] } }));
    expect(readConfigEnable(home, PLUGIN)).toEqual({
      enabled: true,
      inAllow: true,
      readable: true,
      present: true,
    });
  });

  it('absent file: readable + not present, never "unreadable"', () => {
    const r = readConfigEnable(home, PLUGIN);
    expect(r.readable).toBe(true);
    expect(r.present).toBe(false);
    expect(r.enabled).toBeNull();
  });

  it('TRUNCATED file: unreadable — the state that used to masquerade as "no entry"', () => {
    write('{ "plugins": { "entries": { "shieldcortex-realtime": { "enabl');
    const r = readConfigEnable(home, PLUGIN);
    expect(r.readable).toBe(false);
    expect(r.present).toBe(true);
  });

  it('valid JSON that is not an object is also unreadable, not empty', () => {
    write('"just a string"');
    expect(readConfigEnable(home, PLUGIN).readable).toBe(false);
  });

  it('an unreadable read feeds straight through to the indeterminate verdict', () => {
    write('{ truncated');
    const v = reconcilePluginState(input({ config: readConfigEnable(home, PLUGIN) }));
    expect(v.state).toBe('config-unreadable');
  });
});
