import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { checkHermesPluginFreshness } from '../doctor.js';
import { hermesPluginSourceDir } from '../../setup/hermes-refresh.js';
import { probeHermesDiscovery } from '../../setup/hermes-plugins.js';

/**
 * #576 — doctor already warns when the file-copied OpenClaw hook falls behind
 * the packaged version (#574's row). The Hermes plugin is installed the same
 * way and had no such row, so a gateway running the previous `pre_tool_call`
 * gate looked perfectly healthy.
 *
 * The row is WARN at most and never touches the exit code, and it only speaks
 * about the copy Hermes ITSELF says it loads — where that question has no
 * answer, the `Hermes plugin copies` row (#569) is the one with the remedy, and
 * this one stays quiet rather than restating it in yellow.
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
    // A stale gate is old code running, not a broken host: the row must not
    // move doctor's exit code, the same rule the #569 row follows.
    expect(process.exitCode).toBe(exitBefore);
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
