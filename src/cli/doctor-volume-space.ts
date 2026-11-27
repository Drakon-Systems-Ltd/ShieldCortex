/**
 * Doctor's `Free space` row (#1124 part 3): free space on the volume that
 * actually holds the ShieldCortex home.
 *
 * The `Disk` row judges ShieldCortex's own footprint against its budget and
 * says in its own text that it measures nothing about the filesystem. Since
 * #1043 took audit evidence out of that budget, a volume filled by audit
 * evidence — or by anything else on the machine — could reach zero bytes free
 * with doctor still green. This row is the filesystem half.
 *
 * Read-only by construction: one `statfs` per path tried and, only for a path
 * `statfs` calls missing, one `lstat`. It creates, deletes and repairs
 * nothing, reads no config, and names no command that would.
 *
 * Two states must never share a status or a wording:
 *
 *   - near-full / low: the volume WAS measured and has little room left;
 *   - unavailable: the volume could NOT be measured, so nothing is known.
 *
 * An unmeasured volume is a `warn` reading "not measured — …": it is not a
 * pass, because nothing was verified, and not a fail, because nothing was
 * found. A figure is only ever printed from a `statfs` answer that adds up.
 *
 * ── Thresholds ──────────────────────────────────────────────────────────────
 *
 * Each verdict needs BOTH an absolute and a relative condition, with strict
 * `<` on each:
 *
 *   near-full (fail)  available < 100 MiB  AND  available < 5% of the volume
 *   low       (warn)  available <   1 GiB  AND  available < 20% of the volume
 *
 * Bytes alone would fail a deliberately small volume (a 256 MiB tmpfs home
 * that is three-quarters empty) for being small. A share alone would fail a
 * 4 TB disk with 20 GB free, which is nowhere near a write failure for a
 * store whose default budget is 100 MiB. Requiring both means a large volume
 * is judged by its bytes and a small one by its share; the two meet at
 * 2000 MiB (fail: 100 MiB / 5%, a little under 2 GiB) and 5 GiB (warn) of
 * volume size.
 *
 *   - 100 MiB is ShieldCortex's default disk budget. Below it the volume can
 *     no longer hold one more copy of a store at that budget, which is what
 *     a vacuum and the safety backup before a repair can each need.
 *   - 5% and 20% free are chosen to echo the `Disk` row's 95% and 80% lines.
 *     That is an analogy and not the same test: `Disk` compares
 *     ShieldCortex's footprint with its budget and trips ON its line (`>=`);
 *     this row reads the filesystem, trips strictly below, and also needs
 *     the byte condition.
 *   - 1 GiB is ten default budgets: room to act before the fail line. What
 *     the budget exempts (backups, the model cache, audit evidence with no
 *     retention yet, #579) usually lands on the same volume.
 *
 * "Available" is `bavail`, the blocks an unprivileged process may use, not
 * `bfree`: on a filesystem that reserves blocks for root, `bfree` keeps
 * reporting room after ordinary writes have started to fail.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { homeToTilde } from './term-ui.js';

export const VOLUME_SPACE_LABEL = 'Free space';

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

export const VOLUME_NEAR_FULL_BYTES = 100 * MiB;
export const VOLUME_NEAR_FULL_SHARE = 0.05;
export const VOLUME_LOW_BYTES = 1 * GiB;
export const VOLUME_LOW_SHARE = 0.20;

/** The three `fs.statfsSync` fields this row reads. */
export interface VolumeStatfs {
  /** Block size in bytes. */
  bsize: number;
  /** Total blocks on the volume. */
  blocks: number;
  /** Blocks available to an unprivileged process. */
  bavail: number;
}

/** Injectable for tests; production passes nothing. */
export interface VolumeSpaceDeps {
  /** `null` stands for a runtime with no `fs.statfsSync` (Node before 18.15). */
  statfsSync?: ((target: string) => VolumeStatfs) | null;
  lstatSync?: (target: string) => unknown;
  /** Home directory used to shorten paths for display. */
  home?: string;
}

export type VolumeSpaceEvidence =
  | {
    kind: 'measured';
    /** The ShieldCortex home that was asked about. */
    homePath: string;
    /** The path the figures were read at: the home, or its nearest existing parent. */
    measuredPath: string;
    homeExists: boolean;
    totalBytes: number;
    availableBytes: number;
    /** availableBytes / totalBytes, 0 to 1. */
    availableShare: number;
  }
  | { kind: 'unavailable'; reason: string; code?: string };

export type VolumeSpaceVerdict = 'healthy' | 'low' | 'near-full' | 'unavailable';

/** Structurally a doctor `CheckResult`; declared here so this module imports nothing from doctor. */
export interface VolumeSpaceRow {
  label: string;
  status: 'pass' | 'warn' | 'fail';
  message: string;
  fix?: string;
}

function errnoCode(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return typeof code === 'string' && code ? code : 'UNKNOWN';
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

/**
 * The paths to ask about, deepest first: the configured home, then each
 * shorter prefix of it down to the root.
 *
 * The home is kept as configured: nothing in it is folded, dropped or tidied,
 * because each of those changes what the filesystem is asked.
 *
 * `..` first. `/srv/link/../sc` is
 * `/srv/sc` only if `/srv/link` is a real directory; if it is a link to
 * `/mnt/data/sub`, the filesystem resolves the same string to `/mnt/data/sc`,
 * on another volume. `path.resolve`, `path.normalize` and `path.join` all fold
 * the `..` in the string without looking, so none of them may touch it: every
 * path handed to `statfs` is a prefix of what was configured, and the
 * filesystem does the resolving. The same goes for the walk up from a home
 * that does not exist yet: the parent of `/srv/link/../sc` is `/srv/link/..`,
 * which is `/mnt/data`, and `path.dirname` of a folded path would say `/srv`.
 *
 * Empty and `.` segments are kept too, wherever they sit. They are not noise:
 * `name/`, `name/.` and `name/./child` each require `name` to be a directory,
 * and `statfs` on the bare `name` does not — it answers for a regular file.
 * Dropping them would turn a home path that does not resolve (ENOTDIR) into a
 * healthy reading of whatever volume the file is on. So the first probe is the
 * configured string, character for character, and each later one is that
 * string cut at a separator: `/srv/sc/.`, then `/srv/sc`, then `/srv`.
 *
 * Cutting at every separator is also what finds a dangling link spelled
 * `link/` or `link/.`. `lstat` follows a final link written that way and
 * reports it absent, exactly as `statfs` does; the next probe down is the bare
 * `link`, where `lstat` sees the link itself.
 *
 * Windows folds `..` in the string itself before it follows any link, so
 * there `path.resolve` IS the operating system's reading.
 */
function pathsToProbe(scDir: string): string[] {
  let absolute: string;
  if (path.sep === '\\') absolute = path.resolve(scDir);
  else if (path.isAbsolute(scDir)) absolute = scDir;
  else {
    const cwd = process.cwd();
    absolute = `${cwd}${cwd.endsWith(path.sep) ? '' : path.sep}${scDir}`;
  }
  const root = path.parse(absolute).root;
  const segments = absolute.slice(root.length).split(path.sep);
  const probes: string[] = [];
  for (let depth = segments.length; depth > 0; depth--) {
    probes.push(root + segments.slice(0, depth).join(path.sep));
  }
  // The last cut is the root itself when the path is the root or starts `//`.
  if (probes[probes.length - 1] !== root) probes.push(root);
  return probes;
}

/**
 * Read free space for the volume holding `scDir`.
 *
 * `statfs` follows links, so a home that is a link to another volume reports
 * that volume, and so does a home reached through a link and then `..` (see
 * `pathsToProbe`). A home that does not exist yet is measured at its nearest
 * existing parent, which is where it will be created. A path that exists but
 * does not resolve (a link whose target is missing) is NOT walked past: the
 * home would live wherever the link points, and that is not known to be the
 * parent's volume.
 */
export function readVolumeSpace(scDir: string, deps: VolumeSpaceDeps = {}): VolumeSpaceEvidence {
  const statfs = deps.statfsSync === undefined
    ? (fs.statfsSync as ((target: string) => VolumeStatfs) | undefined)
    : deps.statfsSync;
  if (typeof statfs !== 'function') {
    return { kind: 'unavailable', reason: 'this Node runtime cannot read filesystem free space (no fs.statfsSync)' };
  }
  const lstat = deps.lstatSync ?? fs.lstatSync;
  const show = (target: string): string => homeToTilde(target, deps.home ?? os.homedir());

  const probes = pathsToProbe(scDir);
  const homePath = probes[0];
  for (let index = 0; ; index++) {
    const target = probes[index];
    let stat: VolumeStatfs;
    try {
      stat = statfs(target);
    } catch (err: unknown) {
      const code = errnoCode(err);
      if (code !== 'ENOENT') {
        return { kind: 'unavailable', reason: `reading the volume at ${show(target)} failed (${code})`, code };
      }
      // ENOENT from statfs is either "not there" or "there, but a link to
      // nothing". Only the first may be answered from the parent.
      let lstatCode: string | null = null;
      try {
        lstat(target);
      } catch (lerr: unknown) {
        lstatCode = errnoCode(lerr);
      }
      if (lstatCode === null) {
        return {
          kind: 'unavailable',
          reason: `${show(target)} exists but does not resolve (a link whose target is missing), so its volume is not known`,
          code,
        };
      }
      if (lstatCode !== 'ENOENT') {
        return { kind: 'unavailable', reason: `inspecting ${show(target)} failed (${lstatCode})`, code: lstatCode };
      }
      if (index === probes.length - 1) {
        return { kind: 'unavailable', reason: `no existing directory was found above ${show(homePath)}`, code };
      }
      continue;
    }

    const { bsize, blocks, bavail } = (stat ?? {}) as Partial<VolumeStatfs>;
    if (isCount(blocks) && blocks === 0) {
      return {
        kind: 'unavailable',
        reason: `the filesystem at ${show(target)} reports no size (0 blocks), as some virtual and network filesystems do`,
      };
    }
    if (!isCount(bsize) || bsize === 0 || !isCount(blocks) || !isCount(bavail) || bavail > blocks) {
      return {
        kind: 'unavailable',
        reason: `the filesystem at ${show(target)} returned free-space figures that do not add up`,
      };
    }
    const totalBytes = blocks * bsize;
    const availableBytes = bavail * bsize;
    return {
      kind: 'measured',
      homePath,
      measuredPath: target,
      homeExists: index === 0,
      totalBytes,
      availableBytes,
      availableShare: availableBytes / totalBytes,
    };
  }
}

/** Pure: the verdict for a piece of evidence. See the threshold table at the top of this file. */
export function classifyVolumeSpace(evidence: VolumeSpaceEvidence): VolumeSpaceVerdict {
  if (evidence.kind !== 'measured') return 'unavailable';
  const { availableBytes, availableShare } = evidence;
  if (availableBytes < VOLUME_NEAR_FULL_BYTES && availableShare < VOLUME_NEAR_FULL_SHARE) return 'near-full';
  if (availableBytes < VOLUME_LOW_BYTES && availableShare < VOLUME_LOW_SHARE) return 'low';
  return 'healthy';
}

/** Same units and rounding as the `Disk` row, so the two rows read alike. */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < MiB) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < GiB) return `${(bytes / MiB).toFixed(1)} MB`;
  return `${(bytes / GiB).toFixed(1)} GB`;
}

function formatShare(share: number): string {
  const pct = Math.round(share * 100);
  // A sliver must not print as "0%": only a volume with nothing left does.
  return pct === 0 && share > 0 ? '<1%' : `${pct}%`;
}

const READ_ONLY_NOTE = 'This row only reads the filesystem and deletes nothing; the Disk row is the separate check of '
  + 'ShieldCortex\'s own footprint against its budget.';

/** Pure: the doctor row for a piece of evidence. */
export function volumeSpaceRow(evidence: VolumeSpaceEvidence, home: string = os.homedir()): VolumeSpaceRow {
  if (evidence.kind !== 'measured') {
    return {
      label: VOLUME_SPACE_LABEL,
      status: 'warn',
      message: `not measured — ${evidence.reason}`,
      fix: 'Doctor could not read free space for the volume holding the ShieldCortex home, so this row says '
        + 'nothing about how full it is. Check it by hand: `df -h` on that directory shows the volume.',
    };
  }

  const where = homeToTilde(evidence.measuredPath, home);
  const notCreated = evidence.homeExists
    ? ''
    : ` (${homeToTilde(evidence.homePath, home)} is not created yet; measured at its nearest existing parent)`;
  const figures = `${formatBytes(evidence.availableBytes)} available of ${formatBytes(evidence.totalBytes)} `
    + `(${formatShare(evidence.availableShare)}) on the volume holding ${where}${notCreated}`;
  const line = (bytes: number, share: number): string =>
    `under ${bytes >= GiB ? `${bytes / GiB} GB` : `${bytes / MiB} MB`} is available and under `
    + `${Math.round(share * 100)}% of the volume is free`;

  const verdict = classifyVolumeSpace(evidence);
  if (verdict === 'near-full') {
    return {
      label: VOLUME_SPACE_LABEL,
      status: 'fail',
      message: `${figures} — nearly full`,
      // Figures, the risk, and where to look. No instruction: what to do about
      // a full volume is the operator's call, and this row is report-only.
      fix: `The volume is nearly full: ${line(VOLUME_NEAR_FULL_BYTES, VOLUME_NEAR_FULL_SHARE)}. Writes to the `
        + 'ShieldCortex home (memory saves, audit evidence, backups) fail when the volume has no space left. '
        + '`df -h` on that directory shows the volume and what else shares it. '
        + READ_ONLY_NOTE,
    };
  }
  if (verdict === 'low') {
    return {
      label: VOLUME_SPACE_LABEL,
      status: 'warn',
      message: `${figures} — running low`,
      // Free-space counters do not show whether writes are succeeding, so
      // this says only what was measured.
      fix: `The volume is running low: ${line(VOLUME_LOW_BYTES, VOLUME_LOW_SHARE)}. `
        + '`df -h` on that directory shows the volume and what else shares it. '
        + READ_ONLY_NOTE,
    };
  }
  return { label: VOLUME_SPACE_LABEL, status: 'pass', message: figures };
}

/** The doctor check: read the volume holding `scDir`, then report it. */
export function checkVolumeFreeSpace(scDir: string, deps: VolumeSpaceDeps = {}): VolumeSpaceRow {
  return volumeSpaceRow(readVolumeSpace(scDir, deps), deps.home);
}
