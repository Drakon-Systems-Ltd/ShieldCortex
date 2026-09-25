import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { HOOK_FILES, hookFilesStale, refreshInstalledHookFiles } from '../openclaw.js';
import { journalPath, readJournal, writeJournal } from '../swap-journal.js';

/**
 * #574 round 2, blocker 2 — the hook refresh overwrote `HOOK.md`,
 * `handler.ts` and `runtime.mjs` one at a time, IN PLACE. A failure on the
 * third left the new handler beside the old runtime: a mismatched pair the
 * gateway would import on its next restart, which no amount of error reporting
 * undoes. The reviewer's fault-injection probe confirmed it.
 *
 * The refresh now stages the complete set outside every hook discovery
 * directory, verifies it byte-for-byte, and publishes it through the same
 * journalled swap the Hermes plugin uses (blocker 1). These cases are the
 * proof, on fake homes under a temp dir — no `$HOME`, no gateway.
 */
let home: string;
let configRoot: string;
let hooksRoot: string;
let hookDir: string;
const HOOK_SOURCE = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  '..', '..', '..', 'hooks', 'openclaw', 'cortex-memory',
);
const FROZEN = new Date('2026-09-24T12:34:56.789Z');
const OLD = (file: string): string => `// shieldcortex 5.1.0 ${file}\n`;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hook-refresh-'));
  configRoot = path.join(home, '.openclaw');
  hooksRoot = path.join(configRoot, 'hooks');
  hookDir = path.join(hooksRoot, 'cortex-memory');
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
});

function installStale(dir: string = hookDir): void {
  fs.mkdirSync(dir, { recursive: true });
  for (const file of HOOK_FILES) fs.writeFileSync(path.join(dir, file), OLD(file));
}

/** The old set, exactly as it was — the thing a failed refresh must preserve. */
function expectOldSetIntact(dir: string = hookDir): void {
  for (const file of HOOK_FILES) {
    expect(fs.readFileSync(path.join(dir, file), 'utf-8')).toBe(OLD(file));
  }
}

/** Directories OpenClaw's `loadHooksFromDir` would enumerate under `hooks/`. */
function hookDirsIn(root: string): string[] {
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory() && fs.existsSync(path.join(root, e.name, 'HOOK.md')))
    .map((e) => e.name)
    .sort();
}

describe('a failed hook refresh leaves the previously working set intact (#574 r2)', () => {
  it('fault on the THIRD file of the staged copy writes nothing into the live hook', () => {
    installStale();
    let copies = 0;
    const real = fs.copyFileSync;
    jest.spyOn(fs, 'copyFileSync').mockImplementation((from, to) => {
      copies += 1;
      if (copies === 3) throw Object.assign(new Error('ENOSPC: simulated'), { code: 'ENOSPC' });
      return real(from, to);
    });

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(result.refreshed).toEqual([]);
    expect(result.failed.map((f) => f.dir)).toEqual([hookDir]);
    // The whole point: the old HOOK.md and handler.ts are NOT half-replaced.
    expectOldSetIntact();
    // And the two failed copies went into staging, which was cleaned up.
    expect(fs.readdirSync(configRoot).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
    expect(fs.existsSync(path.join(configRoot, 'backups'))).toBe(false);
  });

  it('a staged set that does not verify is never published', () => {
    installStale();
    const real = fs.copyFileSync;
    jest.spyOn(fs, 'copyFileSync').mockImplementation((from, to) => {
      const out = real(from, to);
      // A silent short write: the copy "succeeded" but the bytes are wrong.
      if (String(to).endsWith('runtime.mjs')) fs.writeFileSync(to as string, 'truncated');
      return out;
    });

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(result.refreshed).toEqual([]);
    expect(result.failed[0].error).toMatch(/did not verify/);
    expectOldSetIntact();
  });

  it('refuses a symlinked hook directory, `hooks/` or `backups/` without writing', () => {
    for (const link of ['hooks', 'backups'] as const) {
      const fresh = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hook-link-'));
      const target = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hook-target-'));
      try {
        const root = path.join(fresh, '.openclaw');
        const dir = path.join(root, 'hooks', 'cortex-memory');
        if (link === 'hooks') {
          fs.mkdirSync(path.join(target, 'cortex-memory'), { recursive: true });
          for (const file of HOOK_FILES) {
            fs.writeFileSync(path.join(target, 'cortex-memory', file), OLD(file));
          }
          fs.mkdirSync(root, { recursive: true });
          fs.symlinkSync(target, path.join(root, 'hooks'));
        } else {
          installStale(dir);
          fs.symlinkSync(target, path.join(root, 'backups'));
        }

        const result = refreshInstalledHookFiles(fresh, { now: FROZEN });

        expect(result.refreshed).toEqual([]);
        expect(result.failed[0].error).toMatch(/is a symlink/);
        // Nothing was written through the link.
        expect(fs.readdirSync(target).filter((n) => n !== 'cortex-memory')).toEqual([]);
        expectOldSetIntact(link === 'hooks' ? path.join(target, 'cortex-memory') : dir);
      } finally {
        fs.rmSync(fresh, { recursive: true, force: true });
        fs.rmSync(target, { recursive: true, force: true });
      }
    }
  });
});

describe('the staged set never becomes a second hook (#574 r2)', () => {
  it('stages outside `hooks/` and keeps the old set out of it too', () => {
    installStale();
    const seen: string[][] = [];
    const real = fs.renameSync;
    const renames: Array<{ from: string; to: string }> = [];
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      renames.push({ from: String(from), to: String(to) });
      seen.push(hookDirsIn(hooksRoot));
      const out = real(from, to);
      seen.push(hookDirsIn(hooksRoot));
      return out;
    });

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(result.refreshed).toEqual([hookDir]);
    expect(hookFilesStale(hookDir)).toBe(false);
    // OpenClaw's `loadHooksFromDir` enumerates the SUBDIRECTORIES of
    // `hooks/` and loads any that holds a HOOK.md, keying them by name with
    // later sources winning. So a staging directory in there IS a second
    // cortex-memory hook while it exists.
    // At every observed moment, `hooks/` holds either nothing loadable or the
    // one cortex-memory hook — never a second copy of it.
    for (const state of seen) expect(['', 'cortex-memory']).toContain(state.join(','));
    const publish = renames.find((r) => r.to === hookDir);
    expect(publish).toBeDefined();
    expect(publish!.from.startsWith(`${hooksRoot}${path.sep}`)).toBe(false);
    expect(publish!.from.startsWith(`${configRoot}${path.sep}.shieldcortex-hook-staging-`)).toBe(true);
    // The displaced set went to `<configRoot>/backups`, which nothing scans.
    expect(result.backups).toHaveLength(1);
    expect(result.backups[0].backup.startsWith(path.join(configRoot, 'backups'))).toBe(true);
    expectOldSetIntact(result.backups[0].backup);
    expect(hookDirsIn(hooksRoot)).toEqual(['cortex-memory']);
    expect(fs.readdirSync(configRoot).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
  });
});

describe('a crash between the hook renames is recovered (#574 r2)', () => {
  function crashAfterFirstRename(): ReturnType<typeof refreshInstalledHookFiles> {
    const real = fs.renameSync;
    const spy = jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      if (String(to) === hookDir) throw Object.assign(new Error('EIO: simulated'), { code: 'EIO' });
      return real(from, to);
    });
    try {
      return refreshInstalledHookFiles(home, { now: FROZEN });
    } finally {
      spy.mockRestore();
    }
  }

  it('leaves the journal and staging for recovery, and names the command', () => {
    installStale();

    const result = crashAfterFirstRename();

    expect(fs.existsSync(hookDir)).toBe(false);
    expect(result.failed[0].error).toMatch(/shieldcortex update/);
    const journal = readJournal(configRoot);
    expect('journal' in journal && journal.journal.kind).toBe('openclaw-hook');
    expect(fs.existsSync(String('journal' in journal ? journal.journal.staged : ''))).toBe(true);
  });

  it('is put back by the next refresh, which then republishes cleanly', () => {
    installStale();
    crashAfterFirstRename();
    expect(fs.existsSync(hookDir)).toBe(false);

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(result.recovered.join('\n')).toMatch(/interrupted refresh was found/);
    expect(result.refreshed).toEqual([hookDir]);
    expect(hookFilesStale(hookDir)).toBe(false);
    expect(fs.existsSync(journalPath(configRoot))).toBe(false);
    expect(hookDirsIn(hooksRoot)).toEqual(['cortex-memory']);
  });

  it('reports rather than guesses when the journal cannot be parsed', () => {
    installStale();
    fs.writeFileSync(journalPath(configRoot), '{ truncated');

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(result.failed.map((f) => f.dir)).toContain(configRoot);
    expect(fs.existsSync(journalPath(configRoot))).toBe(true);
  });

  it('clears a journal whose swap had already completed, keeping the backup', () => {
    installStale();
    const backupRoot = path.join(configRoot, 'backups', 'cortex-memory-preupdate-x');
    fs.mkdirSync(path.join(backupRoot, 'cortex-memory'), { recursive: true });
    fs.writeFileSync(path.join(backupRoot, 'cortex-memory', 'HOOK.md'), 'previous\n');
    const stagingRoot = path.join(configRoot, '.shieldcortex-hook-staging-x');
    fs.mkdirSync(stagingRoot);
    writeJournal({
      version: 1,
      kind: 'openclaw-hook',
      root: configRoot,
      target: hookDir,
      backup: path.join(backupRoot, 'cortex-memory'),
      staged: path.join(stagingRoot, 'cortex-memory'),
      stagingRoot,
      packagedVersion: '5.2.0',
      phase: 'publishing',
      startedAt: FROZEN.toISOString(),
      pid: 1,
    });

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(result.recovered.join('\n')).toMatch(/is in place, so it was cleared/);
    expect(fs.existsSync(journalPath(configRoot))).toBe(false);
    expect(fs.readFileSync(path.join(backupRoot, 'cortex-memory', 'HOOK.md'), 'utf-8')).toBe('previous\n');
    expect(fs.existsSync(stagingRoot)).toBe(false);
  });
});

describe('the packaged set is what gets published (#574)', () => {
  it('a refreshed hook is byte-identical to the package', () => {
    installStale();
    refreshInstalledHookFiles(home, { now: FROZEN });
    for (const file of HOOK_FILES) {
      expect(fs.readFileSync(path.join(hookDir, file))).toEqual(
        fs.readFileSync(path.join(HOOK_SOURCE, file)),
      );
    }
  });
});
