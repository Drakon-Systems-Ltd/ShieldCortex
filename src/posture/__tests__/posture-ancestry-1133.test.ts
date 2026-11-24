import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { collectPostureRecords } from '../collect.js';
import { summarisePosture, type PostureRecord } from '../posture-record.js';
import { LIVE, NOW, hermesHome, reportBody, writeReport } from './self-report-fixture.js';

/**
 * #1133 — a self-report is trusted only when the directories above the
 * posture root are private too: the config directory itself, and each
 * directory above it up to and including the home directory (or up to the
 * filesystem root for a config directory outside the home).
 *
 * Every fixture is a fresh temp tree with modes set explicitly, so nothing
 * depends on the process umask and nothing touches the real home or config.
 * No ownership is changed: another owner is only ever a uid the collector is
 * told it runs as.
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
  fs.rmSync(root, { recursive: true, force: true });
});

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

  itPosix('inside the home, a symlinked parent is not a real directory; the real path of the same tree is trusted', () => {
    const real = path.join(home, 'dotfiles', 'config');
    const dir = path.join(real, 'shieldcortex');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(path.join(home, 'dotfiles'), 0o700);
    fs.chmodSync(real, 0o700);
    fs.chmodSync(dir, 0o700);
    writeReport(dir, reportBody());
    const link = path.join(home, '.config');
    fs.symlinkSync(real, link);
    expectRejected(collect(path.join(link, 'shieldcortex')), /not a real directory \(above the config directory\)/);
    expectTrusted(collect(dir));
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
