/**
 * #708 — one onboarding command, named the same everywhere.
 *
 * On 5.6.0 the README said `shieldcortex setup`, `status` printed
 * `Run: shieldcortex install` when Claude Code hooks were missing, doctor's
 * Hooks / Hook timeouts / Schema fixes said `shieldcortex install`, and the
 * top-level `--help` called `install` an "Alias for setup" and led its examples
 * with `quickstart`. They are not aliases:
 *
 *   - `setup` (no arguments) is the host-table wizard — the onboarding command.
 *   - `install` is the Claude Code install (`setupClaudeMd`), the same call
 *     `setup claude` makes. It is kept for scripts and the --without-* opt-outs.
 *   - `quickstart [target]` is the wizard's handler under an older name: the
 *     same targets, no hook flags, no `uninstall`.
 *
 * A targeted Claude Code repair therefore names `setup claude`, not bare
 * `setup`, which skips a host it already counts as wired.
 *
 * Nothing here runs an installer: the doctor check takes an injected settings
 * path and environment, the dispatcher takes recorder handlers, and the rest
 * reads the shipped text.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runHooksCheck } from '../doctor.js';
import { SETUP_HELP, dispatchSetupCommand } from '../setup-dispatch.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const read = (...p: string[]) => fs.readFileSync(path.join(repoRoot, ...p), 'utf-8');

const claudeEnv = { hasClaude: true, hasOpenClaw: false, hasVSCode: false, hasCodex: false, isHeadless: false };

describe('#708 — doctor names `setup claude` for a Claude Code hook repair', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-708-')); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  it('no settings.json yet on a Claude Code host', () => {
    const result = runHooksCheck(path.join(tmpDir, 'settings.json'), claudeEnv);
    expect(result.status).toBe('info');
    expect(result.fix).toMatch(/`shieldcortex setup claude`/);
    expect(result.fix).not.toMatch(/shieldcortex install/);
  });

  it('settings.json with none of the hooks wired', () => {
    const settingsPath = path.join(tmpDir, 'settings.json');
    fs.writeFileSync(settingsPath, JSON.stringify({ hooks: {} }));
    const result = runHooksCheck(settingsPath, claudeEnv);
    expect(result.status).toBe('warn');
    expect(result.fix).toMatch(/`shieldcortex setup claude`/);
    expect(result.fix).not.toMatch(/shieldcortex install/);
  });

  it('no doctor fix or message in the source recommends `shieldcortex install` any more', () => {
    expect(read('src', 'cli', 'doctor.ts')).not.toMatch(/shieldcortex install\b/);
    expect(read('src', 'setup', 'doctor.ts')).not.toMatch(/shieldcortex install\b/);
  });
});

describe('#708 — `setup claude` is the same install `install` runs', () => {
  it('install reaches setupClaudeMd({}) and setup claude reaches the quickstart handler with "claude"', async () => {
    const calls: Array<[string, unknown]> = [];
    const deps = {
      log: () => {},
      uninstallSetup: async () => { calls.push(['uninstallSetup', undefined]); },
      setupClaudeMd: async (opts: unknown) => { calls.push(['setupClaudeMd', opts]); },
      handleQuickstartCommand: async (t?: string) => { calls.push(['handleQuickstartCommand', t]); },
    };
    await dispatchSetupCommand('install', [], deps);
    await dispatchSetupCommand('setup', ['claude'], deps);
    expect(calls).toEqual([
      ['setupClaudeMd', {}],
      ['handleQuickstartCommand', 'claude'],
    ]);
  });

  it("the quickstart handler's claude target is setupClaudeMd({}) — the same call", () => {
    const src = read('src', 'setup', 'quickstart.ts');
    expect(src).toMatch(/case 'claude':[\s\S]{0,400}?await setupClaudeMd\(\{\}\);/);
  });

  it('main() sends quickstart to that same handler, with only one target word', () => {
    const src = read('src', 'index.ts');
    expect(src).toMatch(
      /process\.argv\[2\] === 'quickstart'\)[\s\S]{0,200}?handleQuickstartCommand\(process\.argv\[3\]\)/,
    );
  });
});

describe('#708 — status recommends setup, never install', () => {
  const src = read('src', 'setup', 'status.ts');

  it('the no-database hint and the missing-hooks hint both name setup', () => {
    expect(src).toContain("Run 'shieldcortex setup' to get started.");
    expect(src).toContain('Run: shieldcortex setup claude');
    expect(src).not.toMatch(/shieldcortex install\b/);
  });
});

describe('#708 — help text describes install and quickstart accurately', () => {
  it('setup --help names setup as onboarding and neither older name as an alias', () => {
    expect(SETUP_HELP).toContain('setup is the onboarding command');
    expect(SETUP_HELP).toMatch(/setup claude runs the same install as a bare install/);
    expect(SETUP_HELP).toMatch(/it is not the setup wizard/);
    expect(SETUP_HELP).toMatch(/quickstart \[target\] is an older name for setup's guided path/);
    expect(SETUP_HELP).not.toMatch(/alias/i);
  });

  describe('top-level --help', () => {
    const src = read('src', 'index.ts');
    const start = src.indexOf('${bold}COMMANDS${reset}');
    const end = src.indexOf('${bold}DOCS${reset}', start);
    const help = src.slice(start, end);
    const examples = help.slice(help.indexOf('${bold}EXAMPLES${reset}'));

    it('the help block was found', () => {
      expect(start).toBeGreaterThan(0);
      expect(end).toBeGreaterThan(start);
      expect(examples.length).toBeGreaterThan(0);
    });

    it('setup is the command that says start here; install and quickstart are described, not aliased', () => {
      expect(help).toMatch(/\$\{cyan\}setup\$\{reset\} \[target\]\s+Start here/);
      expect(help).toMatch(/\$\{cyan\}install\$\{reset\} \[flags\]\s+The Claude Code install, kept for scripts\. Not the\n\s+setup wizard/);
      expect(help).toMatch(/\$\{cyan\}quickstart\$\{reset\} \[target\]\s+Older name for setup's guided path/);
      expect(src).not.toMatch(/Alias for setup/);
    });

    it('setup is not listed as taking --without-* (setup rejects them; install takes them)', () => {
      const setupEntry = help.slice(help.indexOf('${cyan}setup${reset}'), help.indexOf('${cyan}install${reset}'));
      expect(setupEntry).not.toMatch(/--without-/);
    });

    it('the examples onboard with setup, not install or quickstart', () => {
      expect(examples).toMatch(/^\s+shieldcortex setup$/m);
      expect(examples).not.toMatch(/shieldcortex (install|quickstart)\b/);
    });
  });
});

describe('#708 — README agrees with the code', () => {
  const readme = read('README.md');
  const install = readme.slice(readme.indexOf('## Install'), readme.indexOf('## Where it can block'));

  it('the install steps onboard with setup', () => {
    expect(install).toMatch(/```bash\nnpm install -g shieldcortex\nshieldcortex setup\nshieldcortex doctor\n```/);
  });

  it('install and quickstart are described as the older names they are', () => {
    expect(install).not.toMatch(/also `quickstart`/);
    expect(install).toMatch(/`install` is not the wizard/);
    expect(install).toMatch(/same Claude Code install as `setup claude`/);
    expect(install).toMatch(/`quickstart` takes the same targets as `setup`'s guided path, without hook flags or `uninstall`/);
  });

  it('the suppressed-lifecycle-scripts note points back at setup and does not prescribe a bypass', () => {
    expect(install).toMatch(/--ignore-scripts/);
    expect(install).toMatch(/wires no host/);
    expect(install).toMatch(/run `shieldcortex setup`, then `shieldcortex doctor`/);
    expect(install).not.toMatch(/--foreground-scripts|ignore-scripts=false|npm rebuild/);
  });

  it('the postinstall facts the note cites are still true of scripts/postinstall.mjs', () => {
    const pkg = JSON.parse(read('package.json')) as { scripts?: Record<string, string> };
    expect(pkg.scripts?.postinstall).toBe('node scripts/postinstall.mjs');
    const post = read('scripts', 'postinstall.mjs');
    expect(post).toContain('verifyNativeModule();');
    expect(post).toContain('writeFreshInstallDefaults()');
    expect(post).toContain('shieldcortex setup');
    // The only installer postinstall spawns is the refresh of an OpenClaw
    // integration already on the box — never setup / install / quickstart.
    expect(post).not.toMatch(/\[cliPath, '(setup|install|quickstart)'/);
  });
});
