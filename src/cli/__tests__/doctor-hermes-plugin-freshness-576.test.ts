import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { checkHermesPluginFreshness, doctorExitCode } from '../doctor.js';
import { hermesPluginSourceDir } from '../../setup/hermes-refresh.js';
import { probeHermesDiscovery } from '../../setup/hermes-plugins.js';

/**
 * #576 — doctor already warns when the file-copied OpenClaw hook falls behind
 * the packaged version (#574's row). The Hermes plugin is installed the same
 * way and had no such row, so a gateway running the previous `pre_tool_call`
 * gate looked perfectly healthy.
 *
 * The row is WARN at most — never a FAIL — and it only speaks about the copy
 * Hermes ITSELF says it loads: where that question has no answer, the
 * `Hermes plugin copies` row (#569) is the one with the remedy, and this one
 * stays quiet rather than restating it in yellow. WARN carries doctor's
 * ordinary exit contract and no exception to it: exit 0, and exit 1 under
 * `--strict`, which is documented as "every ⚠️ becomes exit 1".
 */
let home: string;
let hermes: string;
let plugins: string;
let installed: string;
const savedHermesHome = process.env.HERMES_HOME;
const savedProjectPlugins = process.env.HERMES_ENABLE_PROJECT_PLUGINS;
const SOURCE = hermesPluginSourceDir();

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-fresh-'));
  hermes = path.join(home, '.hermes');
  plugins = path.join(hermes, 'plugins');
  installed = path.join(plugins, 'shieldcortex');
  fs.mkdirSync(plugins, { recursive: true });
  delete process.env.HERMES_HOME;
  delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
  if (savedProjectPlugins === undefined) delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
  else process.env.HERMES_ENABLE_PROJECT_PLUGINS = savedProjectPlugins;
});

function installCopy(dest: string = installed): void {
  fs.cpSync(SOURCE, dest, {
    recursive: true,
    filter: (src) => !['tests', '__pycache__', '.pytest_cache'].includes(path.basename(src)),
  });
}

const HAS_HERMES = (() => {
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-probe-'));
  try {
    fs.mkdirSync(path.join(probeDir, '.hermes', 'plugins'), { recursive: true });
    return 'roots' in probeHermesDiscovery({ home: probeDir, hermesHome: null });
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
})();
const describeWithHermes = HAS_HERMES ? describe : describe.skip;

/** Doctor prints paths tildified, and a CI temp dir can live under $HOME. */
function shown(target: string): string {
  const real = os.homedir();
  return target.startsWith(real) ? target.replace(real, '~') : target;
}

describeWithHermes('checkHermesPluginFreshness (#576)', () => {
  it('passes on an install that matches the packaged source', async () => {
    installCopy();
    const result = await checkHermesPluginFreshness(home);
    expect(result.status).toBe('pass');
    expect(result.message).toMatch(/up to date/);
  });

  it('is not troubled by the packaged `tests/` the installer never copies', async () => {
    installCopy();
    expect(fs.existsSync(path.join(SOURCE, 'tests'))).toBe(true);
    expect(fs.existsSync(path.join(installed, 'tests'))).toBe(false);
    expect((await checkHermesPluginFreshness(home)).status).toBe('pass');
  });

  it('WARNS — never fails — on the exact drift #576 reported', async () => {
    installCopy();
    fs.writeFileSync(path.join(installed, '__init__.py'), '# shieldcortex 5.1.0\n');
    fs.rmSync(path.join(installed, 'shadow.py'));
    const exitBefore = process.exitCode;

    const result = await checkHermesPluginFreshness(home);

    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/out of date/);
    expect(result.message).toContain(shown(installed));
    expect(result.message).toMatch(/2 file\(s\) differ/);
    expect(result.fix).toMatch(/shieldcortex hermes install/);
    expect(result.fix).toMatch(/restart the Hermes gateway/);
    // A stale gate is old code running, not a broken host: the row never
    // FAILS, the same rule the #569 row follows, and running the check does
    // not set an exit code by itself.
    expect(process.exitCode).toBe(exitBefore);
  });

  it('is exit 0 normally and exit 1 under --strict, like every other WARN', async () => {
    installCopy();
    fs.writeFileSync(path.join(installed, '__init__.py'), '# shieldcortex 5.1.0\n');

    const row = await checkHermesPluginFreshness(home);

    // Pinned through the AGGREGATION, not through `process.exitCode` right
    // after the check: the row joins doctor's ordinary results array, and it
    // is `doctorExitCode` over that array that decides (r2 review point 5).
    expect(row.status).toBe('warn');
    expect(doctorExitCode([row])).toBe(0);
    expect(doctorExitCode([row], { strict: true })).toBe(1);
    // And a clean host is 0 under --strict too, so the escalation is the
    // warning's and not the row's mere presence.
    installCopy();
    const clean = await checkHermesPluginFreshness(home);
    expect(doctorExitCode([clean], { strict: true })).toBe(0);
  });

  it('says nothing about freshness while a shadowing copy is in play', async () => {
    installCopy();
    fs.rmSync(path.join(installed, 'shadow.py'));
    const shadow = path.join(plugins, 'shieldcortex.bak-x');
    fs.mkdirSync(shadow, { recursive: true });
    fs.writeFileSync(path.join(shadow, 'plugin.yaml'), 'name: shieldcortex\nkind: standalone\n');

    const result = await checkHermesPluginFreshness(home);

    // The installed copy IS stale, but it is not necessarily the copy Hermes
    // loads — and the row that explains that has the remedy attached.
    expect(result.status).toBe('info');
    expect(result.message).toMatch(/Hermes plugin copies/);
  });

  it('skips when Hermes is there but nothing is installed', async () => {
    const result = await checkHermesPluginFreshness(home);
    expect(result.status).toBe('info');
    expect(result.message).toMatch(/not installed/);
  });
});

describe('an interrupted refresh is reported, never repaired (#576 r2/r3 blocker 1)', () => {
  const NO_HERMES = { interpreter: null } as const;

  /**
   * The state a crash between the two renames leaves, and the ONLY two facts
   * doctor reads to recognise it: the standard target has no `plugin.yaml`,
   * and one of our own swaps left a `shieldcortex-preupdate-*` under this
   * root. Neither of them names a path for anything to act on — doctor does
   * not act at all, and `update`'s remedy is an install from the package.
   */
  function crashState(): void {
    fs.mkdirSync(path.join(hermes, 'backups', 'shieldcortex-preupdate-2026-09-24T12-00-00-000Z', 'shieldcortex'), {
      recursive: true,
    });
  }

  it('does not report a host whose plugin the crash removed as "not installed"', async () => {
    // Without this row it reads as a quiet skip, which is how an operator
    // never learns there is a one-command fix waiting.
    crashState();

    const result = await checkHermesPluginFreshness(home, NO_HERMES);

    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/interrupted refresh left/);
    expect(result.message).not.toMatch(/not installed/);
    expect(result.fix).toMatch(/shieldcortex update/);
    expect(result.fix).toMatch(/shieldcortex hermes install/);
  });

  it('writes nothing — doctor reports, and repairs only behind an explicit --fix', async () => {
    crashState();
    const before = fs.readdirSync(hermes).sort();

    await checkHermesPluginFreshness(home, NO_HERMES);

    expect(fs.readdirSync(hermes).sort()).toEqual(before);
    expect(fs.existsSync(installed)).toBe(false);
  });

  it('does not claim an interrupted refresh on a host that never installed it', async () => {
    // No backup means no evidence this host ever had the plugin, and
    // inventing one would nag every Hermes user who does not use ShieldCortex.
    const result = await checkHermesPluginFreshness(home, NO_HERMES);
    expect(result.status).toBe('info');
    expect(result.message).not.toMatch(/interrupted refresh/);
  });

  it('is silent once the plugin is back, backup or no backup', async () => {
    crashState();
    installCopy();
    const result = await checkHermesPluginFreshness(home, NO_HERMES);
    expect(result.status).not.toBe('warn');
  });

  it('escalates under --strict like any other warning', async () => {
    crashState();
    const row = await checkHermesPluginFreshness(home, NO_HERMES);
    expect(doctorExitCode([row])).toBe(0);
    expect(doctorExitCode([row], { strict: true })).toBe(1);
  });
});

describe('checkHermesPluginFreshness — without Hermes to ask (#569 r4)', () => {
  const NO_HERMES = { interpreter: null } as const;

  it('skips rather than guessing which copy is loaded', async () => {
    installCopy();
    fs.rmSync(path.join(installed, 'shadow.py'));
    const result = await checkHermesPluginFreshness(home, NO_HERMES);
    expect(result.status).toBe('info');
    expect(result.message).toMatch(/could not determine which copy Hermes loads/);
  });

  it('skips a host with no Hermes at all', async () => {
    const bare = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-bare-'));
    try {
      const result = await checkHermesPluginFreshness(bare, NO_HERMES);
      expect(result.status).toBe('info');
      expect(result.message).toMatch(/Hermes not detected/);
    } finally {
      fs.rmSync(bare, { recursive: true, force: true });
    }
  });
});
