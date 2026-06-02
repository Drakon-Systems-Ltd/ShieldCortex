import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { hookFilesStale } from '../setup/openclaw';

/**
 * Task 6b — staleness detection for the file-copy-installed cortex-memory hook.
 *
 * The hook lives at ~/.openclaw/hooks/cortex-memory/ as a COPY of the package's
 * hooks/openclaw/cortex-memory/ source. A package update does not auto-recopy it
 * on every install shape, so the installed handler.ts/runtime.mjs can drift
 * behind the packaged version and keep running old extraction logic.
 *
 * `hookFilesStale(destDir)` is the single source of truth for "out of date":
 * byte-for-byte comparison of every HOOK_FILE against the packaged source.
 *
 * These tests use temp dirs only — they NEVER touch the live ~/.openclaw.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Mirror src/setup/openclaw.ts: HOOK_SOURCE = <repoRoot>/hooks/openclaw/cortex-memory
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const HOOK_SOURCE = path.join(REPO_ROOT, 'hooks', 'openclaw', 'cortex-memory');
const HOOK_FILES = ['HOOK.md', 'handler.ts', 'runtime.mjs'] as const;

function copySourceInto(destDir: string): void {
  fs.mkdirSync(destDir, { recursive: true });
  for (const file of HOOK_FILES) {
    fs.copyFileSync(path.join(HOOK_SOURCE, file), path.join(destDir, file));
  }
}

describe('hookFilesStale — installed cortex-memory hook freshness', () => {
  let dest: string;

  beforeEach(() => {
    dest = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hookstale-'));
  });

  afterEach(() => {
    fs.rmSync(dest, { recursive: true, force: true });
  });

  it('is false for a faithful copy of the packaged hook files', () => {
    const installDir = path.join(dest, 'cortex-memory');
    copySourceInto(installDir);
    expect(hookFilesStale(installDir)).toBe(false);
  });

  it('is true when an installed file differs (appended byte)', () => {
    const installDir = path.join(dest, 'cortex-memory');
    copySourceInto(installDir);
    // Drift one file by a single byte — exactly the "stale handler" scenario.
    fs.appendFileSync(path.join(installDir, 'handler.ts'), '\n// drift\n');
    expect(hookFilesStale(installDir)).toBe(true);
  });

  it('is true when an installed file is missing', () => {
    const installDir = path.join(dest, 'cortex-memory');
    copySourceInto(installDir);
    fs.rmSync(path.join(installDir, 'runtime.mjs'));
    expect(hookFilesStale(installDir)).toBe(true);
  });

  it('is true when the destination directory does not exist', () => {
    const installDir = path.join(dest, 'does-not-exist');
    expect(hookFilesStale(installDir)).toBe(true);
  });

  it('does not mutate the destination (pure read-only check)', () => {
    const installDir = path.join(dest, 'cortex-memory');
    copySourceInto(installDir);
    const before = HOOK_FILES.map((f) => fs.readFileSync(path.join(installDir, f)));
    hookFilesStale(installDir);
    const after = HOOK_FILES.map((f) => fs.readFileSync(path.join(installDir, f)));
    for (let i = 0; i < HOOK_FILES.length; i++) {
      expect(after[i].equals(before[i])).toBe(true);
    }
    // No extra files were written.
    expect(fs.readdirSync(installDir).sort()).toEqual([...HOOK_FILES].sort());
  });
});

describe('postinstall — plugin-present branch refreshes the hook (Task 6b)', () => {
  // postinstall.mjs spawns the CLI, so it's not cheaply unit-testable. Guard the
  // branch logic at the source level: when a plugin is detected AND a hook is
  // installed, the plugin-present path must ALSO run the full hook refresh
  // (refreshOpenClawInstall) — not just copy plugin files and stop.
  const postinstallSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'scripts', 'postinstall.mjs'),
    'utf-8',
  );

  // Isolate the `else if (state.pluginInstalled)` block so the assertion can't
  // false-pass on the separate `else if (state.hookInstalled)` (plugin-absent) branch.
  const pluginBranch = (() => {
    const start = postinstallSrc.indexOf('else if (state.pluginInstalled)');
    expect(start).toBeGreaterThan(-1);
    const after = postinstallSrc.slice(start);
    // Up to the start of the next top-level `else if (state.hookInstalled)`.
    const end = after.indexOf('} else if (state.hookInstalled)');
    expect(end).toBeGreaterThan(-1);
    return after.slice(0, end);
  })();

  it('runs refreshOpenClawInstall inside the plugin-present branch', () => {
    expect(pluginBranch).toMatch(/refreshOpenClawInstall\(cliPath\)/);
  });

  it('gates the hook refresh on state.hookInstalled', () => {
    expect(pluginBranch).toMatch(/if\s*\(\s*state\.hookInstalled\s*\)/);
  });

  it('no longer prints the old "run full refresh for hook updates" dead-end', () => {
    expect(pluginBranch).not.toMatch(/Run full refresh for hook updates/i);
  });
});

describe('doctor — OpenClaw hook freshness check', () => {
  let dest: string;

  beforeEach(() => {
    dest = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hookdoctor-'));
  });

  afterEach(() => {
    fs.rmSync(dest, { recursive: true, force: true });
  });

  it('reports info (skipped) when no hook is installed', async () => {
    const { checkOpenClawHookFreshness } = await import('../cli/doctor.js');
    const r = await checkOpenClawHookFreshness(path.join(dest, 'absent'));
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/not installed/i);
  });

  it('passes on a fresh installed copy', async () => {
    const { checkOpenClawHookFreshness } = await import('../cli/doctor.js');
    const installDir = path.join(dest, 'cortex-memory');
    copySourceInto(installDir);
    const r = await checkOpenClawHookFreshness(installDir);
    expect(r.status).toBe('pass');
  });

  it('warns with an actionable fix when the installed hook is stale', async () => {
    const { checkOpenClawHookFreshness } = await import('../cli/doctor.js');
    const installDir = path.join(dest, 'cortex-memory');
    copySourceInto(installDir);
    fs.appendFileSync(path.join(installDir, 'handler.ts'), '\n// drift\n');
    const r = await checkOpenClawHookFreshness(installDir);
    expect(r.status).toBe('warn');
    expect(r.fix).toMatch(/shieldcortex openclaw install/);
  });
});
