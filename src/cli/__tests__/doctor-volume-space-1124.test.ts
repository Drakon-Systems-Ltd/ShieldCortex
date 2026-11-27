import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import { extractFixCommands } from '../doctor-report.js';
import {
  VOLUME_LOW_BYTES,
  VOLUME_LOW_SHARE,
  VOLUME_NEAR_FULL_BYTES,
  VOLUME_NEAR_FULL_SHARE,
  VOLUME_SPACE_LABEL,
  checkVolumeFreeSpace,
  classifyVolumeSpace,
  readVolumeSpace,
  volumeSpaceRow,
  type VolumeSpaceEvidence,
  type VolumeStatfs,
} from '../doctor-volume-space.js';

/**
 * #1124 part 3 — doctor's `Free space` row.
 *
 * The `Disk` row judges ShieldCortex's own footprint against its budget and
 * says in its own text that it measures nothing about the filesystem. This row
 * is the filesystem half: free space on the volume that actually holds the
 * ShieldCortex home. Its one hard rule is that "the volume is nearly full" and
 * "the volume could not be measured" never share a status or a wording.
 */

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
const BLOCK = 4096;
const HOME = '/home/op';
const SC_DIR = '/home/op/.shieldcortex';

/** A statfs answer for a volume of `totalBytes` with `availableBytes` free to this user. */
function sample(totalBytes: number, availableBytes: number, extra: Record<string, number> = {}): VolumeStatfs {
  return { bsize: BLOCK, blocks: totalBytes / BLOCK, bavail: availableBytes / BLOCK, ...extra };
}

function errno(code: string): NodeJS.ErrnoException {
  const err = new Error(`${code}: simulated`) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

function measured(totalBytes: number, availableBytes: number): VolumeSpaceEvidence {
  return readVolumeSpace(SC_DIR, { statfsSync: () => sample(totalBytes, availableBytes), home: HOME });
}

function rowFor(totalBytes: number, availableBytes: number) {
  return checkVolumeFreeSpace(SC_DIR, { statfsSync: () => sample(totalBytes, availableBytes), home: HOME });
}

describe('thresholds', () => {
  it('are the documented values', () => {
    expect(VOLUME_NEAR_FULL_BYTES).toBe(100 * MiB);
    expect(VOLUME_NEAR_FULL_SHARE).toBe(0.05);
    expect(VOLUME_LOW_BYTES).toBe(1 * GiB);
    expect(VOLUME_LOW_SHARE).toBe(0.20);
  });
});

describe('readVolumeSpace', () => {
  it('turns block counts into bytes and a share', () => {
    expect(measured(100 * GiB, 40 * GiB)).toEqual({
      kind: 'measured',
      homePath: SC_DIR,
      measuredPath: SC_DIR,
      homeExists: true,
      totalBytes: 100 * GiB,
      availableBytes: 40 * GiB,
      availableShare: 0.4,
    });
  });

  it('reads the blocks available to this user, not the root-reserved free count', () => {
    const evidence = readVolumeSpace(SC_DIR, {
      // ext4 keeps 5% for root: bfree says 5 GiB, an unprivileged write has 50 MiB.
      statfsSync: () => sample(100 * GiB, 50 * MiB, { bfree: (5 * GiB) / BLOCK }),
    });
    expect(evidence).toMatchObject({ kind: 'measured', availableBytes: 50 * MiB });
    expect(classifyVolumeSpace(evidence)).toBe('near-full');
  });

  it('asks about the home path itself, so a home that is a link to another volume reports that volume', () => {
    const asked: string[] = [];
    const evidence = readVolumeSpace(SC_DIR, {
      statfsSync: (target) => {
        asked.push(target);
        // statfs follows links: the answer for the home is the linked volume's.
        return target === SC_DIR ? sample(2 * GiB, 30 * MiB) : sample(500 * GiB, 400 * GiB);
      },
    });
    expect(asked).toEqual([SC_DIR]);
    expect(evidence).toMatchObject({ kind: 'measured', measuredPath: SC_DIR, totalBytes: 2 * GiB });
  });

  it('measures the nearest existing parent when the home has not been created yet', () => {
    const asked: string[] = [];
    const evidence = readVolumeSpace('/home/op/new/.shieldcortex', {
      statfsSync: (target) => {
        asked.push(target);
        if (target !== HOME) throw errno('ENOENT');
        return sample(100 * GiB, 40 * GiB);
      },
      lstatSync: () => { throw errno('ENOENT'); },
    });
    expect(asked).toEqual(['/home/op/new/.shieldcortex', '/home/op/new', HOME]);
    expect(evidence).toMatchObject({ kind: 'measured', measuredPath: HOME, homeExists: false, availableBytes: 40 * GiB });
  });

  it('does not fall back to the parent volume for a home that exists but does not resolve', () => {
    // A dangling link: the home will live wherever the link points, which is
    // not necessarily the parent's volume.
    const asked: string[] = [];
    const evidence = readVolumeSpace(SC_DIR, {
      statfsSync: (target) => { asked.push(target); throw errno('ENOENT'); },
      lstatSync: () => ({}),
    });
    expect(asked).toEqual([SC_DIR]);
    expect(evidence.kind).toBe('unavailable');
  });

  it.each([
    ['EACCES'],
    ['EPERM'],
    ['ENOSYS'],
    ['EIO'],
  ])('reports %s from statfs as unavailable evidence carrying the code', (code) => {
    const asked: string[] = [];
    const evidence = readVolumeSpace(SC_DIR, {
      statfsSync: (target) => { asked.push(target); throw errno(code); },
      // Would send the read to the parent if anything but ENOENT were walked past.
      lstatSync: () => { throw errno('ENOENT'); },
      home: HOME,
    });
    expect(evidence).toEqual({
      kind: 'unavailable',
      reason: `reading the volume at ~/.shieldcortex failed (${code})`,
      code,
    });
    expect(asked).toEqual([SC_DIR]);
  });

  it('reports a parent that cannot be inspected as unavailable, not as absent', () => {
    const evidence = readVolumeSpace(SC_DIR, {
      statfsSync: () => { throw errno('ENOENT'); },
      lstatSync: () => { throw errno('EACCES'); },
    });
    expect(evidence).toMatchObject({ kind: 'unavailable', code: 'EACCES' });
  });

  it('reports a runtime with no statfs as unavailable', () => {
    expect(readVolumeSpace(SC_DIR, { statfsSync: null }).kind).toBe('unavailable');
  });

  it.each([
    ['a volume reporting zero blocks', { bsize: BLOCK, blocks: 0, bavail: 0 }],
    ['a zero block size', { bsize: 0, blocks: 1000, bavail: 10 }],
    ['a negative available count', { bsize: BLOCK, blocks: 1000, bavail: -1 }],
    ['more available blocks than the volume has', { bsize: BLOCK, blocks: 1000, bavail: 1001 }],
    ['a non-finite count', { bsize: BLOCK, blocks: Number.NaN, bavail: 10 }],
    ['a missing field', { bsize: BLOCK, blocks: 1000 } as unknown as VolumeStatfs],
  ])('reports %s as unavailable rather than computing a figure from it', (_name, stat) => {
    const evidence = readVolumeSpace(SC_DIR, { statfsSync: () => stat });
    expect(evidence.kind).toBe('unavailable');
    expect(classifyVolumeSpace(evidence)).toBe('unavailable');
  });
});

describe('classifyVolumeSpace', () => {
  it.each([
    ['plenty of room', 'healthy', 100 * GiB, 40 * GiB],
    // 0.5% free, but 20 GiB of it: a large volume is not judged on its share alone.
    ['a large volume with a small share free', 'healthy', 4096 * GiB, 20 * GiB],
    // 78% free, though under 1 GiB: a small volume is not judged on bytes alone.
    ['a small volume that is mostly empty', 'healthy', 256 * MiB, 200 * MiB],
    ['under 1 GiB and under 20% free', 'low', 100 * GiB, 500 * MiB],
    ['a small volume under 20% free', 'low', 256 * MiB, 40 * MiB],
    ['under 100 MiB and under 5% free', 'near-full', 100 * GiB, 50 * MiB],
    ['a small volume under 5% free', 'near-full', 256 * MiB, 8 * MiB],
    ['nothing available', 'near-full', 100 * GiB, 0],
    // Both lines are strict: exactly on a line is the better verdict.
    ['exactly 100 MiB available', 'low', 100 * GiB, 100 * MiB],
    ['exactly 1 GiB available', 'healthy', 100 * GiB, 1 * GiB],
    ['exactly 5% free on a small volume', 'low', 1000 * MiB, 50 * MiB],
    ['exactly 20% free on a small volume', 'healthy', 1000 * MiB, 200 * MiB],
  ])('%s is %s', (_name, verdict, total, available) => {
    expect(classifyVolumeSpace(measured(total, available))).toBe(verdict);
  });
});

describe('the Free space row', () => {
  it('passes a healthy volume and states the figures', () => {
    const row = rowFor(100 * GiB, 40 * GiB);
    expect(row).toEqual({
      label: VOLUME_SPACE_LABEL,
      status: 'pass',
      message: '40.0 GB available of 100.0 GB (40%) on the volume holding ~/.shieldcortex',
    });
  });

  it('fails a nearly full volume, with a remedy that deletes nothing', () => {
    const row = rowFor(100 * GiB, 50 * MiB);
    expect(row.label).toBe(VOLUME_SPACE_LABEL);
    expect(row.status).toBe('fail');
    expect(row.message).toContain('50.0 MB available of 100.0 GB');
    expect(row.message).toContain('nearly full');
    expect(row.fix).toBeDefined();
    expect(row.fix).toContain('df -h');
    // Read-only row: it names no ShieldCortex command, so nothing it prints
    // can be copied into a delete.
    expect(row.fix).not.toMatch(/shieldcortex [a-z]/);
    expect(row.fix).not.toMatch(/\brm\b|prune|vacuum|--execute/);
  });

  it('warns on a volume that is running low', () => {
    const row = rowFor(100 * GiB, 500 * MiB);
    expect(row.status).toBe('warn');
    expect(row.message).toContain('500.0 MB available of 100.0 GB');
    expect(row.message).toContain('running low');
    expect(row.message).not.toContain('nearly full');
    expect(row.fix).toBeDefined();
  });

  it('shows a share under 1% as such, never as 0%', () => {
    expect(rowFor(100 * GiB, 50 * MiB).message).toContain('(<1%)');
    expect(rowFor(100 * GiB, 0).message).toContain('(0%)');
  });

  it('warns when the volume could not be measured, and says nothing about fullness', () => {
    const row = checkVolumeFreeSpace(SC_DIR, { statfsSync: () => { throw errno('EACCES'); }, home: HOME });
    expect(row.label).toBe(VOLUME_SPACE_LABEL);
    // Not a pass (nothing was verified) and not a fail (nothing was found).
    expect(row.status).toBe('warn');
    expect(row.message).toMatch(/^not measured — /);
    expect(row.message).toContain('EACCES');
    expect(row.message).not.toMatch(/nearly full|running low|available of/);
    expect(row.fix).toContain('df -h');
  });

  it('prints its advice as prose: no fix text yields a command for the report to offer', () => {
    const unmeasured = checkVolumeFreeSpace(SC_DIR, { statfsSync: null, home: HOME });
    for (const row of [rowFor(100 * GiB, 50 * MiB), rowFor(100 * GiB, 500 * MiB), unmeasured]) {
      expect(row.fix).toBeDefined();
      expect(extractFixCommands(row.fix)).toEqual([]);
    }
  });

  it('keeps the unmeasured wording apart from every measured one', () => {
    const unavailable = volumeSpaceRow({ kind: 'unavailable', reason: 'the volume reports no size' });
    for (const [total, available] of [[100 * GiB, 40 * GiB], [100 * GiB, 500 * MiB], [100 * GiB, 50 * MiB]]) {
      const row = rowFor(total, available);
      expect(row.message).not.toMatch(/not measured/);
      expect(row.message).not.toBe(unavailable.message);
    }
    expect(unavailable.status).toBe('warn');
    expect(unavailable.message).toBe('not measured — the volume reports no size');
  });

  it('says so when the home does not exist yet and names where it measured', () => {
    const row = checkVolumeFreeSpace(SC_DIR, {
      statfsSync: (target) => {
        if (target === SC_DIR) throw errno('ENOENT');
        return sample(100 * GiB, 40 * GiB);
      },
      lstatSync: () => { throw errno('ENOENT'); },
      home: HOME,
    });
    expect(row.status).toBe('pass');
    expect(row.message).toBe(
      '40.0 GB available of 100.0 GB (40%) on the volume holding ~ '
      + '(~/.shieldcortex is not created yet; measured at its nearest existing parent)',
    );
  });
});

describe('against the real filesystem', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-volume-space-'));
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('reads figures from the real statfs fields', () => {
    const evidence = readVolumeSpace(tmpDir);
    expect(evidence.kind).toBe('measured');
    if (evidence.kind !== 'measured') return;
    expect(evidence.measuredPath).toBe(tmpDir);
    expect(evidence.totalBytes).toBeGreaterThan(0);
    expect(evidence.availableBytes).toBeGreaterThanOrEqual(0);
    expect(evidence.availableBytes).toBeLessThanOrEqual(evidence.totalBytes);
  });

  it('creates nothing: a home that does not exist is still absent afterwards', () => {
    const scDir = path.join(tmpDir, 'not-yet', '.shieldcortex');
    const evidence = readVolumeSpace(scDir);
    expect(evidence).toMatchObject({ kind: 'measured', measuredPath: tmpDir, homeExists: false });
    expect(fs.readdirSync(tmpDir)).toEqual([]);
  });

  it('refuses a dangling link instead of measuring its parent', () => {
    const scDir = path.join(tmpDir, '.shieldcortex');
    fs.symlinkSync(path.join(tmpDir, 'gone'), scDir);
    expect(readVolumeSpace(scDir).kind).toBe('unavailable');
  });
});

describe('registration', () => {
  it('runs once in doctor, directly after the Disk row, against the configured home', () => {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const source = fs.readFileSync(path.join(here, '..', 'doctor.ts'), 'utf8');
    const list = source.slice(source.indexOf('const checks: Array<'));
    const entries = list.slice(0, list.indexOf('];')).split('\n').map((line) => line.trim());
    const disk = entries.indexOf('checkDiskUsage,');
    expect(disk).toBeGreaterThan(-1);
    expect(entries[disk + 1]).toBe('async () => checkVolumeFreeSpace(getConfigDir()), // #1124: the filesystem, not the budget');
    expect(source.match(/checkVolumeFreeSpace\(/g)).toHaveLength(1);
  });
});
