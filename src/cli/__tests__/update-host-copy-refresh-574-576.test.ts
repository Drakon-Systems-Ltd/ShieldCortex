import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { stepHermesPlugin, stepOpenClawHook } from '../update.js';
import {
  HOOK_FILES,
  hookFilesStale,
  installedHookDirs,
  refreshInstalledHookFiles,
} from '../../setup/openclaw.js';
import type { HermesRefreshResult } from '../../setup/hermes-refresh.js';

/**
 * #574 / #576 — `shieldcortex update` advanced the npm package, the
 * registry-managed OpenClaw plugin and the ClawHub skill, and walked straight
 * past the two integrations installed by FILE COPY: the cortex-memory hook and
 * the Hermes plugin. Both stayed on the previous release until an operator
 * noticed a doctor warning and re-ran an installer by hand; hosts that upgrade
 * unattended never did.
 *
 * Everything here runs against a fake home under a temp dir. No `$HOME`, no
 * `openclaw`, no `hermes`, no network.
 */
let home: string;
let openclawHook: string;
let claudeHook: string;
const HOOK_SOURCE = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  '..', '..', '..', 'hooks', 'openclaw', 'cortex-memory',
);

/** Swallow the step renderer's own output; return what it printed. */
function captureStdout(): { lines: () => string; restore: () => void } {
  const written: string[] = [];
  const spy = jest
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: unknown) => { written.push(String(chunk)); return true; });
  return { lines: () => written.join(''), restore: () => spy.mockRestore() };
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-update-refresh-'));
  openclawHook = path.join(home, '.openclaw', 'hooks', 'cortex-memory');
  claudeHook = path.join(home, '.claude', 'hooks', 'cortex-memory');
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
});

/** An installed hook copy that is BEHIND the packaged source. */
function installStaleHook(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
  for (const file of HOOK_FILES) {
    fs.writeFileSync(path.join(dir, file), `// shieldcortex 5.1.0 ${file}\n`);
  }
}

/** An installed hook copy byte-identical to the packaged source. */
function installCurrentHook(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
  for (const file of HOOK_FILES) {
    fs.copyFileSync(path.join(HOOK_SOURCE, file), path.join(dir, file));
  }
}

describe('installedHookDirs — what is there, never what should be (#574)', () => {
  it('creates nothing on a host with no hook installed', () => {
    expect(installedHookDirs(home)).toEqual([]);
    // `findAllHooksDirs` (the INSTALL path) would have made `hooks/` here. The
    // refresh path must not: an update that conjures a hooks directory has
    // installed an integration nobody asked for.
    expect(fs.existsSync(path.join(home, '.openclaw'))).toBe(false);
    expect(fs.existsSync(path.join(home, '.claude'))).toBe(false);
  });

  it('finds both host layouts when they exist', () => {
    installStaleHook(openclawHook);
    installStaleHook(claudeHook);
    expect(installedHookDirs(home).sort()).toEqual([openclawHook, claudeHook].sort());
  });
});

describe('refreshInstalledHookFiles — the copy half of `openclaw install` (#574)', () => {
  it('re-copies a stale hook and leaves a current one alone', () => {
    installStaleHook(openclawHook);
    installCurrentHook(claudeHook);
    expect(hookFilesStale(openclawHook)).toBe(true);

    const result = refreshInstalledHookFiles(home);

    expect(result.refreshed).toEqual([openclawHook]);
    expect(result.current).toEqual([claudeHook]);
    expect(result.failed).toEqual([]);
    expect(hookFilesStale(openclawHook)).toBe(false);
    for (const file of HOOK_FILES) {
      expect(fs.readFileSync(path.join(openclawHook, file))).toEqual(
        fs.readFileSync(path.join(HOOK_SOURCE, file)),
      );
    }
  });

  it('reports the directory it could not write, and keeps going', () => {
    installStaleHook(openclawHook);
    installStaleHook(claudeHook);
    // A FILE where `backups/` belongs: `mkdir -p` raises EEXIST/ENOTDIR
    // whoever is running, which a mode-based fixture cannot promise under
    // root. Since the refresh publishes a staged directory rather than
    // overwriting files in place, the fault has to land on the publication
    // path — corrupting a file inside the live hook no longer stops anything,
    // because the whole directory is replaced.
    fs.writeFileSync(path.join(home, '.claude', 'backups'), 'not a directory\n');

    const result = refreshInstalledHookFiles(home);

    expect(result.refreshed).toEqual([openclawHook]);
    expect(result.failed.map((f) => f.dir)).toEqual([claudeHook]);
    // The set that could not be republished is byte-for-byte what it was.
    for (const file of HOOK_FILES) {
      expect(fs.readFileSync(path.join(claudeHook, file), 'utf-8')).toBe(`// shieldcortex 5.1.0 ${file}\n`);
    }
  });
});

describe('stepOpenClawHook — what `update` reports (#574)', () => {
  it('skips a host with no installed hook, and names the command that adds it', async () => {
    const out = captureStdout();
    try {
      const result = await stepOpenClawHook({ home });
      expect(result.status).toBe('skip');
      expect(result.summary).toMatch(/not installed/);
      expect(out.lines()).toMatch(/shieldcortex openclaw install/);
    } finally {
      out.restore();
    }
    expect(fs.existsSync(path.join(home, '.openclaw'))).toBe(false);
  });

  it('refreshes a stale hook and says a gateway restart is what loads it', async () => {
    installStaleHook(openclawHook);
    const out = captureStdout();
    let result;
    try {
      result = await stepOpenClawHook({ home });
    } finally {
      out.restore();
    }
    expect(result.status).toBe('ok');
    expect(result.summary).toMatch(/refreshed 1 copy/);
    expect(result.summary).toMatch(/restart the gateway/);
    // The hook module is imported ONCE into the long-lived gateway process, so
    // new bytes change nothing until it restarts — and `update` must say that
    // rather than restart it, which would kill every in-flight turn.
    expect(result.detail?.join('\n')).toMatch(/take effect on the next restart/);
    expect(hookFilesStale(openclawHook)).toBe(false);
    // Paths are printed home-scrubbed, like every other captured line.
    expect(result.detail?.join('\n')).toContain('~/.openclaw/hooks/cortex-memory');
  });

  it('says "current" without copying when the installed hook matches', async () => {
    installCurrentHook(openclawHook);
    const before = HOOK_FILES.map((f) => fs.statSync(path.join(openclawHook, f)).mtimeMs);
    const out = captureStdout();
    let result;
    try {
      result = await stepOpenClawHook({ home });
    } finally {
      out.restore();
    }
    expect(result.status).toBe('ok');
    expect(result.summary).toMatch(/current \(1 copy\)/);
    expect(HOOK_FILES.map((f) => fs.statSync(path.join(openclawHook, f)).mtimeMs)).toEqual(before);
  });

  it('warns — never fails the flow — when a copy could not be written', async () => {
    installStaleHook(openclawHook);
    fs.writeFileSync(path.join(home, '.openclaw', 'backups'), 'not a directory\n');
    const out = captureStdout();
    let result;
    try {
      result = await stepOpenClawHook({ home });
    } finally {
      out.restore();
    }
    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/could not be refreshed/);
    expect(result.detail?.join('\n')).toMatch(/could not refresh ~\/\.openclaw/);
  });

  it('warns rather than claiming currency when the packaged source is missing', async () => {
    const result = await runQuietly(() => stepOpenClawHook({
      home,
      refresh: () => ({
        installed: [openclawHook],
        refreshed: [],
        current: [],
        failed: [],
        backups: [],
        warnings: [],
        sourceAvailable: false,
      }),
    }));
    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/packaged hook source not found/);
  });
});

/** Run a step with its rendering swallowed. */
async function runQuietly<T>(fn: () => Promise<T>): Promise<T> {
  const out = captureStdout();
  try {
    return await fn();
  } finally {
    out.restore();
  }
}

describe('stepHermesPlugin — what `update` reports (#576)', () => {
  const base: HermesRefreshResult = { status: 'current', summary: '', detail: [], refreshed: [] };

  it('skips quietly when there is no installed copy', async () => {
    const result = await runQuietly(() => stepHermesPlugin({
      home,
      refresh: () => ({ ...base, status: 'not-installed', summary: 'Hermes plugin not installed' }),
    }));
    expect(result.status).toBe('skip');
    expect(result.summary).toBe('Hermes plugin not installed');
  });

  it('reports a refresh with the restart the gateway needs', async () => {
    const result = await runQuietly(() => stepHermesPlugin({
      home,
      refresh: () => ({
        ...base,
        status: 'refreshed',
        summary: 'refreshed 1 copy — restart the Hermes gateway to load it',
        detail: [`${home}/.hermes/plugins/shieldcortex refreshed; previous copy kept at ${home}/.hermes/backups/x`],
        refreshed: [{ dir: `${home}/.hermes/plugins/shieldcortex`, backup: `${home}/.hermes/backups/x` }],
      }),
    }));
    expect(result.status).toBe('ok');
    expect(result.summary).toMatch(/restart the Hermes gateway/);
    // Backup paths are printed, home-scrubbed: an operator must be able to find
    // the copy that was moved aside.
    expect(result.detail?.join('\n')).toContain('~/.hermes/backups/x');
  });

  it('prints the stamped backup directory verbatim, not as a redacted fragment', async () => {
    // `shieldcortex-preupdate-<iso stamp>` is a 40-plus character run of
    // [A-Za-z0-9-], which the CHILD-OUTPUT sanitiser redacts as a possible
    // credential. That reads `previous copy kept at ~[REDACTED-high_entropy]`
    // and loses the only fact the line carries.
    const backup = `${home}/.hermes/backups/shieldcortex-preupdate-2026-09-24T23-10-23-474Z/shieldcortex`;
    const result = await runQuietly(() => stepHermesPlugin({
      home,
      refresh: () => ({
        ...base,
        status: 'refreshed',
        summary: 'refreshed 1 copy — restart the Hermes gateway to load it',
        detail: [`${home}/.hermes/plugins/shieldcortex refreshed; previous copy kept at ${backup}`],
        refreshed: [{ dir: `${home}/.hermes/plugins/shieldcortex`, backup }],
      }),
    }));
    expect(result.detail?.join('\n')).toContain(
      '~/.hermes/backups/shieldcortex-preupdate-2026-09-24T23-10-23-474Z/shieldcortex',
    );
    expect(result.detail?.join('\n')).not.toMatch(/REDACTED/);
  });

  it('reports "current" as a pass with no detail', async () => {
    const result = await runQuietly(() => stepHermesPlugin({
      home,
      refresh: () => ({ ...base, status: 'current', summary: 'current (1 copy)' }),
    }));
    expect(result.status).toBe('ok');
    expect(result.summary).toBe('current (1 copy)');
  });

  it('surfaces a refusal as a warn that carries the reason and the remedy', async () => {
    const result = await runQuietly(() => stepHermesPlugin({
      home,
      refresh: () => ({
        ...base,
        status: 'warn',
        summary: 'could not determine which copy Hermes loads — nothing written ' +
          '(run `shieldcortex doctor --fix-hermes-plugin-copies`, then `shieldcortex hermes install`)',
        detail: ['no Hermes interpreter found'],
      }),
    }));
    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/--fix-hermes-plugin-copies/);
    expect(result.detail).toEqual(['no Hermes interpreter found']);
  });
});
