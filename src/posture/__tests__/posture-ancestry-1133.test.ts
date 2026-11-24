import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { collectPostureRecords } from '../collect.js';
import { summarisePosture, type PostureRecord } from '../posture-record.js';
import { LIVE, NOW, hermesHome, reportBody, writeReport } from './self-report-fixture.js';

/**
 * #1133 — a self-report is trusted only when the directories above the
 * posture root are private too: the config directory itself, and each
 * directory above it up to and including the home directory (or up to the
 * filesystem root for a config directory outside the home).
 *
 * A symbolic link on that path is judged where it is named (the directory
 * holding it, and its owner) and then along the path it names, so a private
 * link to a private directory is trusted, inside the home or outside it.
 *
 * Every fixture is a fresh temp tree with modes set explicitly, so nothing
 * depends on the process umask and nothing touches the real home or config.
 * No ownership is changed: another owner is only ever a uid the collector is
 * told it runs as, or a link's owner as the collector's lstat reports it.
 */

const itPosix = process.platform === 'win32' ? it.skip : it;
const noOpenClawBinary = { openclawBinaryPresent: () => false };
const DAY = 24 * 3_600_000;

let root: string;
let home: string;
let configDir: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-posture-ancestry-1133-'));
  home = path.join(root, 'home');
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  fs.chmodSync(configDir, 0o700);
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(root, { recursive: true, force: true });
});

/** `base/...parts`, each level created owner-only whatever the umask. */
function privateDir(base: string, ...parts: string[]): string {
  let dir = base;
  for (const part of parts) {
    dir = path.join(dir, part);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
  }
  return dir;
}

/** The collector's lstat reports `link` as owned by `owner`; nothing on disk changes. */
function linkOwnedBy(link: string, owner: number): void {
  const realLstat = fs.lstatSync.bind(fs) as typeof fs.lstatSync;
  jest.spyOn(fs, 'lstatSync').mockImplementation(((p: fs.PathLike, o?: unknown) => {
    const st = realLstat(p, o as never) as fs.Stats;
    if (String(p) === link && st.isSymbolicLink()) st.uid = owner;
    return st;
  }) as typeof fs.lstatSync);
}

function collect(dir: string = configDir, over: { home?: string; uid?: number } = {}): PostureRecord[] {
  const deps = over.uid === undefined ? LIVE : { ...LIVE, uid: () => over.uid };
  return collectPostureRecords({ home: over.home ?? home, configDir: dir, nowMs: NOW, hostDeps: noOpenClawBinary, deps });
}

const hermes = (recs: PostureRecord[]) => recs.filter((r) => r.runtime === 'hermes');

/** A fresh enforcing report from a live process: trusted, it is loaded. */
function expectTrusted(recs: PostureRecord[]): void {
  const h = hermes(recs);
  expect(h).toHaveLength(1);
  expect(h[0].runtime_loaded.value).toBe('yes');
  expect(h[0].notes.join(' ')).not.toMatch(/insecure self-report directory/);
}

/** The same report as one non-stale trust rejection naming `reason`. */
function expectRejected(recs: PostureRecord[], reason: RegExp): void {
  const h = hermes(recs);
  expect(h).toHaveLength(1);
  expect([h[0].key.instance, h[0].stale, h[0].stale_reason, h[0].runtime_loaded.value]).toEqual(['p4242-s100', false, null, 'unknown']);
  expect(h[0].notes.join(' ')).toMatch(/self-report rejected: insecure self-report directory: /);
  expect(h[0].notes.join(' ')).toMatch(reason);
  expect(summarisePosture(recs).green).toBe(false);
}

describe('#1133 control: a private path from home to the report is trusted', () => {
  it('home and config dir owner-only: the report is loaded', () => {
    writeReport(configDir, reportBody());
    expectTrusted(collect());
  });

  itPosix('a sticky other-writable directory above the config dir is accepted', () => {
    const shared = path.join(home, 'shared');
    const dir = path.join(shared, 'sc');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
    fs.chmodSync(shared, 0o1777);
    expect(fs.lstatSync(shared).mode & 0o1777).toBe(0o1777);
    writeReport(dir, reportBody());
    expectTrusted(collect(dir));
  });

  itPosix('a home reached through a symlink is judged as the directory it names', () => {
    const realHome = path.join(root, 'real-home');
    fs.mkdirSync(realHome, { mode: 0o700 });
    fs.chmodSync(realHome, 0o700);
    const linkHome = path.join(root, 'link-home');
    fs.symlinkSync(realHome, linkHome);
    const dir = path.join(linkHome, '.shieldcortex');
    fs.mkdirSync(dir, { mode: 0o700 });
    fs.chmodSync(dir, 0o700);
    writeReport(dir, reportBody());
    expectTrusted(collect(dir, { home: linkHome }));
  });

  itPosix('a home behind a link whose target has `..` is the directory the system resolves', () => {
    const far = privateDir(root, 'far');
    privateDir(far, 'inner');
    const realHome = privateDir(far, 'real-home');
    fs.symlinkSync(path.join(far, 'inner'), path.join(root, 'hop'));
    const linkHome = path.join(root, 'link-home');
    fs.symlinkSync('hop/../real-home', linkHome);
    const dir = privateDir(linkHome, '.shieldcortex');
    writeReport(dir, reportBody());
    expectTrusted(collect(dir, { home: linkHome }));
    fs.chmodSync(realHome, 0o770);
    expectRejected(collect(dir, { home: linkHome }), /directory writable by group or others \(above the config directory\)/);
  });
});

describe('#1133 the config directory itself', () => {
  itPosix('a group-writable config dir: every report under it is a trust rejection', () => {
    writeReport(configDir, reportBody());
    fs.chmodSync(configDir, 0o770);
    expectRejected(collect(), /directory writable by group or others \(config directory\)/);
  });

  itPosix('a symlinked config dir is not a real directory, with or without a trailing slash', () => {
    const real = path.join(home, 'sc-real');
    fs.mkdirSync(real, { mode: 0o700 });
    fs.chmodSync(real, 0o700);
    writeReport(real, reportBody());
    const link = path.join(home, 'sc-link');
    fs.symlinkSync(real, link);
    expectRejected(collect(link), /not a real directory \(config directory\)/);
    expectRejected(collect(`${link}${path.sep}`), /not a real directory \(config directory\)/);
    // Named by its real path, the same tree is trusted.
    expectTrusted(collect(real));
  });

  itPosix('a config dir owned by another uid is a trust rejection', () => {
    writeReport(configDir, reportBody());
    const uid = process.getuid!();
    expectRejected(collect(configDir, { uid: uid + 1 }), /directory owned by another user \(config directory\)/);
  });

  itPosix('an old report under an insecure config dir is never aged out', () => {
    const file = writeReport(configDir, reportBody());
    fs.utimesSync(file, new Date(NOW - 8 * DAY), new Date(NOW - 8 * DAY));
    fs.chmodSync(configDir, 0o770);
    expectRejected(collect(), /\(config directory\)/);
  });
});

describe('#1133 directories above the config directory', () => {
  itPosix('a group-writable home is a trust rejection', () => {
    writeReport(configDir, reportBody());
    fs.chmodSync(home, 0o770);
    expectRejected(collect(), /directory writable by group or others \(above the config directory\)/);
  });

  itPosix('a writable intermediate parent under home is a trust rejection', () => {
    const parent = path.join(home, '.config');
    const dir = path.join(parent, 'shieldcortex');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
    writeReport(dir, reportBody());
    expectTrusted(collect(dir));
    fs.chmodSync(parent, 0o777);
    expectRejected(collect(dir), /directory writable by group or others \(above the config directory\)/);
  });


  itPosix('a listed, empty runtime directory under an insecure parent is one trust rejection, not an omission', () => {
    fs.mkdirSync(path.join(configDir, 'posture', 'hermes'), { recursive: true, mode: 0o700 });
    fs.chmodSync(path.join(configDir, 'posture'), 0o700);
    fs.chmodSync(path.join(configDir, 'posture', 'hermes'), 0o700);
    expect(hermes(collect())).toEqual([]);
    fs.chmodSync(home, 0o770);
    const h = hermes(collect());
    expect(h).toHaveLength(1);
    expect([h[0].key.instance, h[0].stale, h[0].runtime_loaded.value]).toEqual([null, false, 'unknown']);
    expect(h[0].notes.join(' ')).toMatch(/\(above the config directory\)/);
    expect(h[0].notes.join(' ')).not.toMatch(/no self-report/);
  });
});

describe('#1133 ordinary missing reports keep their meaning under an insecure path', () => {
  const shape = (recs: PostureRecord[]) => recs.map((r) => [r.runtime, r.profile, r.key.instance, r.runtime_loaded.value, r.stale, r.notes]);

  itPosix('no posture directory: the same records as on a private path', () => {
    hermesHome(home);
    const secure = shape(collect());
    expect(hermes(collect()).map((r) => [r.key.instance, r.runtime_loaded.value])).toEqual([[null, 'unobserved']]);
    fs.chmodSync(configDir, 0o770);
    fs.chmodSync(home, 0o770);
    expect(shape(collect())).toEqual(secure);
  });

  itPosix('a posture root with no runtime directory: the same records as on a private path', () => {
    hermesHome(home);
    fs.mkdirSync(path.join(configDir, 'posture'), { mode: 0o700 });
    fs.chmodSync(path.join(configDir, 'posture'), 0o700);
    const secure = shape(collect());
    fs.chmodSync(configDir, 0o770);
    expect(shape(collect())).toEqual(secure);
  });

  it('a config dir that does not exist: nothing is invented', () => {
    hermesHome(home);
    const missing = path.join(home, 'no-such-config');
    expect(hermes(collect(missing)).map((r) => [r.key.instance, r.runtime_loaded.value])).toEqual([[null, 'unobserved']]);
    expect(hermes(collect(missing))[0].notes.join(' ')).not.toMatch(/insecure/);
  });
});

describe('#1133 a config directory outside the home (SHIELDCORTEX_CONFIG_DIR)', () => {
  // Above a config dir outside the home, every directory up to the filesystem
  // root is judged; root-owned and sticky system directories are accepted.
  // `/tmp` is used, not os.tmpdir(), so the control does not depend on the
  // modes of a per-user temp directory's parents.
  let ext: string;
  const tmpRoot = process.platform === 'win32' ? os.tmpdir() : '/tmp';

  beforeEach(() => {
    ext = fs.mkdtempSync(path.join(tmpRoot, 'sc-posture-ancestry-1133-ext-'));
    fs.chmodSync(ext, 0o700);
  });

  afterEach(() => {
    fs.rmSync(ext, { recursive: true, force: true });
  });

  itPosix('a private config dir outside the home is trusted', () => {
    const tmpStat = fs.statSync(fs.realpathSync(tmpRoot));
    // Precondition for the control, not part of the rule under test.
    expect(tmpStat.uid === 0 || tmpStat.uid === process.getuid!()).toBe(true);
    const dir = path.join(ext, 'sc');
    fs.mkdirSync(dir, { mode: 0o700 });
    fs.chmodSync(dir, 0o700);
    writeReport(dir, reportBody());
    expectTrusted(collect(dir));
  });

  itPosix('outside the home, a parent reached through a symlink (as macOS /tmp) is judged by its real path', () => {
    const real = path.join(ext, 'real');
    const dir = path.join(real, 'sc');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(real, 0o700);
    fs.chmodSync(dir, 0o700);
    writeReport(dir, reportBody());
    const link = path.join(ext, 'link');
    fs.symlinkSync(real, link);
    expectTrusted(collect(path.join(link, 'sc')));
    fs.chmodSync(real, 0o770);
    expectRejected(collect(path.join(link, 'sc')), /directory writable by group or others \(above the config directory\)/);
  });

  itPosix('a group-writable parent of a config dir outside the home is a trust rejection', () => {
    const dir = path.join(ext, 'sc');
    fs.mkdirSync(dir, { mode: 0o700 });
    fs.chmodSync(dir, 0o700);
    writeReport(dir, reportBody());
    fs.chmodSync(ext, 0o770);
    expectRejected(collect(dir), /directory writable by group or others \(above the config directory\)/);
  });
});

describe('#1133 a symbolic link above the config directory, inside the home', () => {
  /** `~/dotfiles/config/shieldcortex` with a report, named as `~/.config/shieldcortex`. */
  function linkedConfig(target: (real: string) => string = (real) => real): { real: string; link: string; dir: string } {
    const real = privateDir(home, 'dotfiles', 'config');
    privateDir(real, 'shieldcortex');
    writeReport(path.join(real, 'shieldcortex'), reportBody());
    const link = path.join(home, '.config');
    fs.symlinkSync(target(real), link);
    return { real, link, dir: path.join(link, 'shieldcortex') };
  }

  itPosix('a private link to a private directory in the home is trusted (absolute target)', () => {
    const { real, dir } = linkedConfig();
    expectTrusted(collect(dir));
    // The same tree by its real path: the same judgment.
    expectTrusted(collect(path.join(real, 'shieldcortex')));
  });

  itPosix('a private link to a private directory in the home is trusted (relative target)', () => {
    const { dir } = linkedConfig(() => path.join('dotfiles', 'config'));
    expectTrusted(collect(dir));
  });

  itPosix('a chain of private links is trusted', () => {
    const real = privateDir(home, 'real');
    privateDir(real, 'sc');
    writeReport(path.join(real, 'sc'), reportBody());
    fs.symlinkSync('real', path.join(home, 'l2'));
    fs.symlinkSync('l2', path.join(home, 'l1'));
    fs.symlinkSync(path.join(home, 'l1'), path.join(home, 'l0'));
    expectTrusted(collect(path.join(home, 'l0', 'sc')));
  });

  itPosix('the directory a link names is judged: a group-writable target is a trust rejection', () => {
    const { real, dir } = linkedConfig();
    fs.chmodSync(real, 0o770);
    expectRejected(collect(dir), /directory writable by group or others \(above the config directory\)/);
  });

  itPosix('a directory above the link target is judged too', () => {
    const { dir } = linkedConfig();
    fs.chmodSync(path.join(home, 'dotfiles'), 0o777);
    expectRejected(collect(dir), /directory writable by group or others \(above the config directory\)/);
  });

  itPosix('the directory holding the link is judged: a private target behind a group-writable directory is a trust rejection', () => {
    const real = privateDir(home, 'real');
    privateDir(real, 'sc');
    writeReport(path.join(real, 'sc'), reportBody());
    const shared = privateDir(home, 'shared');
    fs.symlinkSync(real, path.join(shared, 'link'));
    const dir = path.join(shared, 'link', 'sc');
    expectTrusted(collect(dir));
    fs.chmodSync(shared, 0o770);
    expectRejected(collect(dir), /directory writable by group or others \(above the config directory\)/);
  });

  itPosix('a link owned by another user is a trust rejection; one owned by root is trusted', () => {
    const { link, dir } = linkedConfig();
    linkOwnedBy(link, process.getuid!() + 1);
    expectRejected(collect(dir), /symbolic link owned by another user \(above the config directory\)/);
    jest.restoreAllMocks();
    linkOwnedBy(link, 0);
    expectTrusted(collect(dir));
  });

  itPosix('a name the judgment cannot stat or read is reported as missing or unreadable, and is never trusted', () => {
    const { link, dir } = linkedConfig();
    const middle = path.join(home, 'dotfiles');
    const fail = (code: string) => Object.assign(new Error(code), { code });
    const realLstat = fs.lstatSync.bind(fs) as typeof fs.lstatSync;
    // The listing and the report reads are untouched; only the judgment's
    // lstat of `middle` (or readlink of `link`) fails, as in a race.
    const lstatFails = (code: string) => jest.spyOn(fs, 'lstatSync').mockImplementation(((p: fs.PathLike, o?: unknown) => {
      if (String(p) === middle) throw fail(code);
      return realLstat(p, o as never);
    }) as typeof fs.lstatSync);
    lstatFails('ENOENT');
    expectRejected(collect(dir), /missing directory \(above the config directory\)/);
    jest.restoreAllMocks();
    lstatFails('EACCES');
    expectRejected(collect(dir), /unreadable directory \(above the config directory\)/);
    jest.restoreAllMocks();
    jest.spyOn(fs, 'readlinkSync').mockImplementation(((p: fs.PathLike) => {
      throw fail(String(p) === link ? 'EIO' : 'EINVAL');
    }) as typeof fs.readlinkSync);
    expectRejected(collect(dir), /unreadable symbolic link \(above the config directory\)/);
    jest.restoreAllMocks();
    expectTrusted(collect(dir));
  });

  itPosix('the config directory itself is still never a link, however private', () => {
    const { link } = linkedConfig((real) => path.join(real, 'shieldcortex'));
    expectRejected(collect(link), /not a real directory \(config directory\)/);
  });

  itPosix('a link to a missing directory is the ordinary missing report: nothing is invented', () => {
    hermesHome(home);
    fs.symlinkSync(path.join(home, 'no-such-dir'), path.join(home, '.config'));
    const h = hermes(collect(path.join(home, '.config', 'shieldcortex')));
    expect(h.map((r) => [r.key.instance, r.runtime_loaded.value])).toEqual([[null, 'unobserved']]);
    expect(h[0].notes.join(' ')).not.toMatch(/insecure/);
  });

  // 33 links: Linux resolves them (its limit is 40), the judgment stops at 32.
  (process.platform === 'linux' ? it : it.skip)('more links than the judgment follows is a trust rejection, not a trusted path', () => {
    const real = privateDir(home, 'real');
    privateDir(real, 'sc');
    writeReport(path.join(real, 'sc'), reportBody());
    const n = 33;
    fs.symlinkSync('real', path.join(home, `l${n - 1}`));
    for (let i = n - 2; i >= 0; i--) fs.symlinkSync(`l${i + 1}`, path.join(home, `l${i}`));
    expectRejected(collect(path.join(home, 'l0', 'sc')), /too many symbolic links \(above the config directory\)/);
  });
});

describe('#1133 a symbolic link above the config directory, leaving the home', () => {
  // The target lies under /tmp, so the walk goes to the filesystem root.
  let ext: string;
  const tmpRoot = process.platform === 'win32' ? os.tmpdir() : '/tmp';

  beforeEach(() => {
    ext = fs.mkdtempSync(path.join(tmpRoot, 'sc-posture-ancestry-1133-out-'));
    fs.chmodSync(ext, 0o700);
  });

  afterEach(() => {
    fs.rmSync(ext, { recursive: true, force: true });
  });

  itPosix('a private link in the home to a private directory outside it is trusted; a writable target parent is not', () => {
    const real = privateDir(ext, 'data', 'config');
    privateDir(real, 'sc');
    writeReport(path.join(real, 'sc'), reportBody());
    fs.symlinkSync(real, path.join(home, '.config'));
    const dir = path.join(home, '.config', 'sc');
    expectTrusted(collect(dir));
    fs.chmodSync(path.join(ext, 'data'), 0o770);
    expectRejected(collect(dir), /directory writable by group or others \(above the config directory\)/);
  });

  itPosix('a relative link that climbs out of the home is judged from the root', () => {
    const fixtureHome = privateDir(ext, 'home');
    const real = privateDir(ext, 'outside', 'config');
    privateDir(real, 'sc');
    writeReport(path.join(real, 'sc'), reportBody());
    fs.symlinkSync(path.join('..', 'outside', 'config'), path.join(fixtureHome, '.config'));
    const dir = path.join(fixtureHome, '.config', 'sc');
    expectTrusted(collect(dir, { home: fixtureHome }));
    fs.chmodSync(path.join(ext, 'outside'), 0o770);
    expectRejected(collect(dir, { home: fixtureHome }), /directory writable by group or others \(above the config directory\)/);
  });

  itPosix('`..` after a link is the parent of where the link leads, as the system resolves it', () => {
    const somewhere = privateDir(ext, 'somewhere');
    privateDir(somewhere, 'inner');
    const real = privateDir(somewhere, 'config');
    privateDir(real, 'sc');
    writeReport(path.join(real, 'sc'), reportBody());
    fs.symlinkSync(path.join(somewhere, 'inner'), path.join(home, 'jump'));
    // Spelled inside the home; the system resolves it to <ext>/somewhere/config.
    // A literal target: path.join would fold `jump/..` away by its spelling.
    fs.symlinkSync('jump/../config', path.join(home, '.config'));
    const dir = path.join(home, '.config', 'sc');
    // The system's realpath; Node's JS realpath resolves `..` in a link's target by its spelling.
    expect(fs.realpathSync.native(dir)).toBe(fs.realpathSync.native(path.join(real, 'sc')));
    expectTrusted(collect(dir));
    fs.chmodSync(somewhere, 0o770);
    expectRejected(collect(dir), /directory writable by group or others \(above the config directory\)/);
  });
});

describe('#1133 a config directory outside the home named through a link', () => {
  let ext: string;
  const tmpRoot = process.platform === 'win32' ? os.tmpdir() : '/tmp';

  beforeEach(() => {
    ext = fs.mkdtempSync(path.join(tmpRoot, 'sc-posture-ancestry-1133-named-'));
    fs.chmodSync(ext, 0o700);
  });

  afterEach(() => {
    fs.rmSync(ext, { recursive: true, force: true });
  });

  itPosix('the directory that holds the link is judged, not only the real path', () => {
    const real = privateDir(ext, 'real');
    privateDir(real, 'sc');
    writeReport(path.join(real, 'sc'), reportBody());
    const shared = privateDir(ext, 'shared');
    fs.symlinkSync(real, path.join(shared, 'link'));
    const dir = path.join(shared, 'link', 'sc');
    expectTrusted(collect(dir));
    fs.chmodSync(shared, 0o770);
    expectRejected(collect(dir), /directory writable by group or others \(above the config directory\)/);
    // The real path of the same tree does not pass through it.
    expectTrusted(collect(path.join(real, 'sc')));
  });

  itPosix('a link into the home is judged from the home once it reaches it', () => {
    privateDir(home, 'sc');
    writeReport(path.join(home, 'sc'), reportBody());
    fs.symlinkSync(home, path.join(ext, 'to-home'));
    const dir = path.join(ext, 'to-home', 'sc');
    expectTrusted(collect(dir));
    fs.chmodSync(home, 0o770);
    expectRejected(collect(dir), /directory writable by group or others \(above the config directory\)/);
  });
});
