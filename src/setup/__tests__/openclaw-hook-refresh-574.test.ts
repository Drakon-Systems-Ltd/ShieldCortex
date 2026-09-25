import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { HOOK_FILES, hookFilesStale, refreshInstalledHookFiles } from '../openclaw.js';
import { updateLockPath } from '../host-swap.js';

/**
 * #574 round 2 blocker 2 — the hook refresh overwrote `HOOK.md`,
 * `handler.ts` and `runtime.mjs` one at a time, IN PLACE. A failure on the
 * third left the new handler beside the old runtime: a mismatched pair the
 * gateway would import on its next restart, which no amount of error reporting
 * undoes. The reviewer's fault-injection probe confirmed it.
 *
 * Round 2 replaced it with a JOURNALLED swap; round 3 removed the journal,
 * because a recovery that reads its destination from a file can be told where
 * to write; round 4 removed the healing too, because a `backups/` entry is
 * also what a SUCCESSFUL refresh leaves, so healing from one reinstalls a hook
 * the operator has just uninstalled. The set is still staged outside every
 * hook discovery directory, flushed, verified byte-for-byte and swapped in —
 * but a missing hook is reported, never written.
 *
 * These cases are the proof, on fake homes under a temp dir — no `$HOME`, no
 * gateway.
 */
let home: string;
let configRoot: string;
let hooksRoot: string;
let hookDir: string;
let elsewhere: string;
const HOOK_SOURCE = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  '..', '..', '..', 'hooks', 'openclaw', 'cortex-memory',
);
const FROZEN = new Date('2026-09-24T12:34:56.789Z');
const STAMP = '2026-09-24T12-34-56-789Z';
const JOURNAL = '.shieldcortex-refresh-journal.json';
const OLD = (file: string): string => `// shieldcortex 5.1.0 ${file}\n`;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hook-refresh-'));
  elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hook-elsewhere-'));
  configRoot = path.join(home, '.openclaw');
  hooksRoot = path.join(configRoot, 'hooks');
  hookDir = path.join(hooksRoot, 'cortex-memory');
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(elsewhere, { recursive: true, force: true });
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

/** Every path under `root`, relative and sorted — a whole-tree fingerprint. */
function treeOf(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string, prefix: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isSymbolicLink()) out.push(`${rel} -> ${fs.readlinkSync(path.join(dir, entry.name))}`);
      else if (entry.isDirectory()) { out.push(`${rel}/`); walk(path.join(dir, entry.name), rel); }
      else out.push(`${rel} ${fs.readFileSync(path.join(dir, entry.name), 'utf-8')}`);
    }
  };
  walk(root, '');
  return out;
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
    // The reservation the failed publication made was given back, so the
    // refusal leaves no empty directory under `backups/`.
    expect(fs.readdirSync(path.join(configRoot, 'backups'))).toEqual([]);
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

describe('a crash between the hook renames is reported, never repaired (#574 r4)', () => {
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

  it('leaves the backup and nothing else, and names the command that puts it back', () => {
    installStale();

    const result = crashAfterFirstRename();

    expect(fs.existsSync(hookDir)).toBe(false);
    expect(result.failed[0].error).toMatch(/shieldcortex openclaw install/);
    expect(fs.readdirSync(path.join(configRoot, 'backups'))).toEqual([`cortex-memory-preupdate-${STAMP}`]);
    // No journal and no staging tree survive: nothing for a later run to read
    // a destination out of.
    expect(fs.readdirSync(configRoot).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
  });

  it('is not put back by the next refresh — absence is reported, not repaired (r3 blocker 1)', () => {
    installStale();
    const crashed = crashAfterFirstRename();
    expect(fs.existsSync(hookDir)).toBe(false);
    // Said at the moment it is known, with the backup path in the sentence.
    const backup = fs.readdirSync(path.join(configRoot, 'backups'))[0];
    expect(crashed.failed[0].error).toContain(path.join(configRoot, 'backups', backup));

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(fs.existsSync(hookDir)).toBe(false);
    expect(result.refreshed).toEqual([]);
    expect(result.installed).toEqual([]);
    expect(fs.readdirSync(path.join(configRoot, 'backups'))).toHaveLength(1);
  });

  it('leaves a config root that never had the hook alone, backup or no backup (r3 blocker 1)', () => {
    fs.mkdirSync(configRoot, { recursive: true });

    expect(refreshInstalledHookFiles(home, { now: FROZEN }).installed).toEqual([]);
    expect(fs.existsSync(hooksRoot)).toBe(false);

    // The reviewer's planted layout: an EMPTY entry in exactly the shape one
    // of our own swaps writes. Round 3 installed the package on the strength
    // of it; a backup-shaped directory is not installation intent.
    fs.mkdirSync(path.join(configRoot, 'backups', 'cortex-memory-preupdate-planted'), { recursive: true });

    expect(refreshInstalledHookFiles(home, { now: FROZEN }).installed).toEqual([]);
    expect(fs.existsSync(hooksRoot)).toBe(false);
  });

  it('leaves a PARTIAL hook directory alone rather than adopting it', () => {
    // The reviewer's ENOSPC probe left a target with one file and no HOOK.md.
    // "The directory exists" is not "the hook is installed" — and "the hook is
    // missing" is not permission to write one.
    fs.mkdirSync(hookDir, { recursive: true });
    fs.writeFileSync(path.join(hookDir, 'handler.ts'), 'half a hook\n');
    fs.mkdirSync(path.join(configRoot, 'backups', 'cortex-memory-preupdate-old'), { recursive: true });

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(result.installed).toEqual([]);
    expect(result.refreshed).toEqual([]);
    expect(fs.readdirSync(hookDir)).toEqual(['handler.ts']);
    expect(fs.readdirSync(path.join(configRoot, 'backups'))).toEqual(['cortex-memory-preupdate-old']);
  });
});

describe('planted files name no destination (#574 r3)', () => {
  it('a planted journal and a planted staging directory are inert', () => {
    fs.mkdirSync(path.join(elsewhere, 'treasure'), { recursive: true });
    fs.writeFileSync(path.join(elsewhere, 'treasure', 'payroll.csv'), 'do not move me\n');
    installStale();
    fs.writeFileSync(path.join(configRoot, JOURNAL), `${JSON.stringify({
      version: 1,
      kind: 'openclaw-hook',
      root: configRoot,
      target: path.join(elsewhere, 'victim'),
      backup: path.join(elsewhere, 'treasure'),
      staged: path.join(elsewhere, 'staged'),
      stagingRoot: path.join(elsewhere, 'treasure'),
      packagedVersion: '5.2.0',
      phase: 'publishing',
      startedAt: FROZEN.toISOString(),
      pid: 1,
    })}\n`);
    fs.mkdirSync(path.join(configRoot, '.shieldcortex-hook-staging-planted'), { recursive: true });
    fs.writeFileSync(path.join(configRoot, '.shieldcortex-hook-staging-planted', 'keep.txt'), 'keep\n');
    const before = treeOf(elsewhere);

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(result.refreshed).toEqual([hookDir]);
    expect(treeOf(elsewhere)).toEqual(before);
    expect(fs.existsSync(path.join(elsewhere, 'victim'))).toBe(false);
    expect(fs.readFileSync(path.join(configRoot, '.shieldcortex-hook-staging-planted', 'keep.txt'), 'utf-8')).toBe('keep\n');
    expect(fs.existsSync(path.join(configRoot, JOURNAL))).toBe(true);
  });

  it('writes through no predictable temp name — the `.next` link victim survives', () => {
    // Round 2's `advanceJournalPhase` wrote `<journal>.next` with `openSync(…,
    // 'w')`, which FOLLOWS a symlink planted at that name and truncates the
    // referent. The reviewer confirmed both the overwrite and the symlink
    // being installed as the journal.
    const victim = path.join(elsewhere, 'victim.txt');
    fs.writeFileSync(victim, 'important\n');
    installStale();
    const trap = path.join(configRoot, `${JOURNAL}.next`);
    fs.symlinkSync(victim, trap);
    const opened: string[] = [];
    const realOpen = fs.openSync;
    jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
      opened.push(String(p));
      return (realOpen as (...a: unknown[]) => number)(p, ...rest);
    }) as typeof fs.openSync);

    expect(refreshInstalledHookFiles(home, { now: FROZEN }).refreshed).toEqual([hookDir]);

    expect(fs.readFileSync(victim, 'utf-8')).toBe('important\n');
    expect(fs.lstatSync(trap).isSymbolicLink()).toBe(true);
    expect(opened.filter((p) => p.includes(JOURNAL))).toEqual([]);
  });
});

describe('one writer per config root (#574 r2 blocker 3)', () => {
  it('a second refresh that starts mid-swap refuses and writes nothing', () => {
    installStale();
    let inner: ReturnType<typeof refreshInstalledHookFiles> | null = null;
    const real = fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      // BEFORE the displacing rename, not after: the target is still there and
      // still stale, so the re-entrant run has real work to do and the only
      // thing that can stop it is the lock.
      if (inner === null && String(to).includes('-preupdate-')) {
        inner = refreshInstalledHookFiles(home, { now: FROZEN });
      }
      return real(from, to);
    });

    const outer = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(outer.refreshed).toEqual([hookDir]);
    expect(inner).not.toBeNull();
    expect(inner!.refreshed).toEqual([]);
    expect(inner!.failed[0].error).toMatch(/another ShieldCortex update\/install is running/);
    // Exactly ONE writer: one backup, no staging left, a hook that verifies.
    expect(fs.readdirSync(path.join(configRoot, 'backups'))).toHaveLength(1);
    expect(fs.readdirSync(configRoot).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
    expect(hookFilesStale(hookDir)).toBe(false);
  });

  it('a held lock stops the refresh before it writes anything', () => {
    installStale();
    fs.writeFileSync(updateLockPath(configRoot), `shieldcortex-update ${process.pid} ${FROZEN.toISOString()}\n`);

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(result.refreshed).toEqual([]);
    expect(result.failed[0].error).toMatch(/another ShieldCortex update\/install is running/);
    expectOldSetIntact();
    expect(fs.existsSync(path.join(configRoot, 'backups'))).toBe(false);
  });
});

describe('the staged set is durable before it is reachable (#574 r2 blocker 4)', () => {
  it('every staged file is fsynced before the first rename', () => {
    installStale();
    const staged = path.join(configRoot, `.shieldcortex-hook-staging-${STAMP}`, 'cortex-memory');
    const byFd = new Map<number, string>();
    const synced: string[] = [];
    let syncedAtFirstRename: string[] | null = null;

    const realOpen = fs.openSync;
    jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
      const fd = (realOpen as (...a: unknown[]) => number)(p, ...rest);
      byFd.set(fd, String(p));
      return fd;
    }) as typeof fs.openSync);
    const realFsync = fs.fsyncSync;
    jest.spyOn(fs, 'fsyncSync').mockImplementation((fd: number) => {
      synced.push(byFd.get(fd) ?? `fd:${fd}`);
      return realFsync(fd);
    });
    const realRename = fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      syncedAtFirstRename ??= [...synced];
      return realRename(from, to);
    });

    expect(refreshInstalledHookFiles(home, { now: FROZEN }).refreshed).toEqual([hookDir]);

    expect(syncedAtFirstRename).not.toBeNull();
    const before = new Set(syncedAtFirstRename!);
    for (const file of HOOK_FILES) expect(before.has(path.join(staged, file))).toBe(true);
    expect(before.has(staged)).toBe(true);
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
