/**
 * Read-only posture collector (#613).
 *
 * Reads, never writes: no directory is created, no config or consent file is
 * touched, Guard is never armed, no host binary is executed. The only probe
 * that looks outside the home is host-table's OpenClaw binary lookup, which
 * callers (and tests) can inject, the Linux `/proc/<pid>/stat` read that
 * checks a reporting process's start identity, and (#1133) the lstat or
 * readlink of each name on the path to the config directory, which reaches
 * the filesystem root for a config directory outside the home or behind a
 * link that leads out of it.
 *
 * Self-reports live at
 *
 *     <configDir>/posture/<runtime>/<profile>/<instance>.json
 *
 * one file per reporting process, written by the runtime processes
 * themselves (Claude Code hook, OpenClaw plugin, Hermes plugin). Each file is
 * untrusted: the directories and the file must be owned by this user and not
 * writable by anyone else, and so must the config directory, which is never a
 * symlink. Every directory on the path that names it, up to the home (or the
 * filesystem root, outside the home), must be owned by this user or root and
 * not writable by anyone else unless sticky; a symlink on that path must be
 * owned by this user or root and is judged again along the path it names
 * (#1133, `insecureNamedPath`). The file must be a regular file (symlinks
 * are not followed) under the size cap, those file checks are repeated on the opened
 * descriptor using its exact device and inode, and its content must name the
 * same runtime, profile and instance as its path. Then `parseSelfReport`
 * validates it.
 *
 * A file is bounded host-local evidence, never liveness on its own: for a
 * resident process the host's process-start check decides whether the
 * reporter is still the process that wrote it. That check only proves an
 * exit inside the reporter's own PID namespace (#970): a report that recorded
 * another namespace, or none, is never `ended` by a pid lookup here.
 *
 * #970: the namespace travels in a SIDECAR beside the report,
 *
 *     <configDir>/posture/<runtime>/<profile>/<instance>.pidns
 *
 * holding only its digits (or `null`), never in the report: the report stays
 * the closed v1 schema every earlier CLI reads, and an earlier CLI lists only
 * `*.json` names, so it never sees the sidecar. See `readPidNsSidecar`.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  GATE_RUNTIMES,
  MAX_INSTANCES_PER_PROFILE,
  SELF_REPORT_MAX_BYTES,
  deriveMemoryOnlyRecord,
  deriveToolGateRecord,
  isGateRuntime,
  isValidInstanceKey,
  isValidProfileId,
  markStaleRecords,
  noCurrentReportRecord,
  parseSelfReport,
  rejectionMayAge,
  type GateRuntimeId,
  type Installed,
  type LivenessCheck,
  type MemoryOnlyRuntimeId,
  type PostureRecord,
  type SelfReportRead,
} from './posture-record.js';
import { hostArtefactWired, scanHostTable, type HostId, type HostTableDeps } from '../setup/host-table.js';

export interface CollectDeps {
  /**
   * The host's start token for `pid`: a string when the process exists, null
   * when it does not, undefined when this host cannot tell.
   */
  processStart?: (pid: number) => string | null | undefined;
  /**
   * #970: the collector's own PID namespace id (Linux: inode of
   * /proc/self/ns/pid), or null where it cannot be read. A pid lookup proves
   * a reporter exited only when its report recorded this same id.
   */
  pidNamespace?: () => string | null;
  /** This user's uid, or undefined where the platform has none. */
  uid?: () => number | undefined;
}

export interface CollectOptions {
  home?: string;
  /** ShieldCortex config dir; defaults to SHIELDCORTEX_CONFIG_DIR or ~/.shieldcortex. */
  configDir?: string;
  nowMs?: number;
  maxAgeMs?: number;
  hostDeps?: HostTableDeps;
  deps?: CollectDeps;
}

export function defaultConfigDir(home: string = os.homedir()): string {
  const override = process.env.SHIELDCORTEX_CONFIG_DIR?.trim();
  return override ? override : path.join(home, '.shieldcortex');
}

export function postureSelfReportDir(configDir: string = defaultConfigDir()): string {
  return path.join(configDir, 'posture');
}

/** #970: the PID-namespace sidecar's suffix; `<instance>.pidns` sits beside `<instance>.json`. */
export const PID_NS_SIDECAR_SUFFIX = '.pidns';
/** Largest sidecar read: 20 digits, or `null`. */
const PID_NS_SIDECAR_MAX_BYTES = 32;
const PID_NS_RE = /^[0-9]{1,20}$/;

/** Where one process's self-report lives. */
export function selfReportPath(configDir: string, runtime: GateRuntimeId, profile: string, instance: string): string {
  return path.join(postureSelfReportDir(configDir), runtime, profile, `${instance}.json`);
}

/**
 * Linux: field 22 of /proc/<pid>/stat (start time in clock ticks since boot).
 * The comm field can contain spaces and parentheses, so split after the LAST
 * `)`. Exported for the writers' tests.
 */
export function linuxProcessStart(pid: number): string | null | undefined {
  if (process.platform !== 'linux') return undefined;
  let text: string;
  try {
    text = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code === 'ENOENT' || code === 'ESRCH' ? null : undefined;
  }
  const rest = text.slice(text.lastIndexOf(')') + 2).split(' ');
  const start = rest[19];
  return start && /^[0-9]+$/.test(start) ? start : undefined;
}

/**
 * Linux: this process's PID namespace id — the inode of /proc/self/ns/pid,
 * the same number `readlink` shows as `pid:[<inode>]`. Null elsewhere or when
 * unreadable. The writers record the same value in each report (#970).
 */
export function linuxPidNamespace(): string | null {
  if (process.platform !== 'linux') return null;
  try {
    const ino = fs.statSync('/proc/self/ns/pid', { bigint: true }).ino;
    return ino > 0n ? ino.toString() : null;
  } catch {
    return null;
  }
}

const defaultDeps: Required<CollectDeps> = {
  processStart: linuxProcessStart,
  pidNamespace: linuxPidNamespace,
  uid: () => (typeof process.getuid === 'function' ? process.getuid() : undefined),
};

const HOST_ID_FOR: Record<GateRuntimeId | MemoryOnlyRuntimeId, HostId> = {
  claude_code: 'claude',
  openclaw: 'openclaw',
  hermes: 'hermes',
  codex: 'codex',
  copilot: 'copilot',
};

/** Why a directory on the self-report path is not trustworthy, or null. */
function insecureDir(dir: string, uid: number | undefined): string | null {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(dir);
  } catch {
    return 'unreadable directory';
  }
  if (st.isSymbolicLink() || !st.isDirectory()) return 'not a real directory';
  if (process.platform === 'win32') return null;
  if (uid !== undefined && st.uid !== uid) return 'directory owned by another user';
  if ((st.mode & 0o022) !== 0) return 'directory writable by group or others';
  return null;
}

/**
 * #1133: the most symbolic links one ancestry judgment follows. macOS's own
 * limit (MAXSYMLINKS), below Linux's 40. A path that needs more is not judged
 * and is not trusted.
 */
const MAX_ANCESTRY_LINKS = 32;
/** #1133: the most names one ancestry judgment visits, including the names links add. */
const MAX_ANCESTRY_STEPS = 4096;

/** The names in `p`. Empty and `.` names are dropped; `..` is kept for the walk. */
function pathNames(p: string): string[] {
  return p.split(path.sep).filter((n) => n !== '' && n !== '.');
}

function startsWithNames(names: readonly string[], prefix: readonly string[]): boolean {
  return prefix.length <= names.length && prefix.every((n, i) => names[i] === n);
}

/** A failed stat, as a finding: gone is not the same as unreadable. */
function statFailure(err: unknown): string {
  return (err as NodeJS.ErrnoException | null)?.code === 'ENOENT' ? 'missing directory' : 'unreadable directory';
}

/**
 * #1133: `raw`, a name as the filesystem returned it, as a string only when
 * that string is exactly those bytes again; otherwise null.
 *
 * A POSIX name is bytes. Decoding bytes that are not valid UTF-8 replaces
 * them, and the replaced spelling can name a different file from the one the
 * system resolves by the original bytes. The ancestry walk judges names by
 * their spelling, so a name that does not survive the decode is not judged:
 * the caller refuses it. Valid UTF-8, including non-ASCII names, is kept.
 */
export function losslessUtf8Name(raw: Uint8Array): string | null {
  const bytes = Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
  const name = bytes.toString('utf8');
  return Buffer.from(name, 'utf8').equals(bytes) ? name : null;
}

/** The home's real path as the system resolves it, or the finding when it cannot be had. */
type HomeReal = { real: string } | { lost: string };

function realHome(homeNamed: string): HomeReal {
  let raw: Buffer;
  try {
    // The system's realpath: the JS one resolves `..` in a link's target by
    // its spelling, not as the system does. As bytes, so a lossy decode is
    // refused rather than walked.
    raw = fs.realpathSync.native(homeNamed, { encoding: 'buffer' });
  } catch (err) {
    return { lost: statFailure(err) };
  }
  const real = losslessUtf8Name(raw);
  return real === null ? { lost: 'home real path not valid UTF-8' } : { real };
}

/**
 * Why a directory on the path above the config directory is not trustworthy,
 * or null. Owned by this user or by root (root can write anywhere already).
 * Writable by group or others only when sticky (as /tmp): then no one else can
 * rename or remove an entry in it that this user or root owns, and the walk
 * requires that of the next entry. A symlink is not a real directory here:
 * the walk follows links itself, so `st` is never one it meant to follow.
 */
function untrustedAncestor(st: fs.Stats, uid: number | undefined): string | null {
  if (st.isSymbolicLink() || !st.isDirectory()) return 'not a real directory';
  if (uid !== undefined && st.uid !== uid && st.uid !== 0) return 'directory owned by another user';
  if ((st.mode & 0o022) !== 0 && (st.mode & 0o1000) === 0) return 'directory writable by group or others';
  return null;
}

/**
 * #1133: why the path that names `start` (an absolute, resolved directory:
 * the config directory's parent) is not trustworthy, or null.
 *
 * The path is resolved here one name at a time, as the system resolves it,
 * and every step is judged before it is taken:
 *
 * - a directory: `untrustedAncestor`;
 * - a symbolic link: the directory holding it has already been judged; the
 *   link must be owned by this user or root; then the path it names is walked
 *   the same way, from the directory holding it (relative) or afresh
 *   (absolute). So a link is judged both where it is named and where it leads;
 * - `..`: the parent of a directory already judged on this walk, or, above
 *   where the walk began, the walk begins again there.
 *
 * A walk begins at the home when the path starts with the home, as named or
 * as its real path. The home is judged as the directory it names (the system
 * may link it); nothing above it, nor a link naming it, is judged. Any other
 * walk begins at the filesystem root, so root-owned system directories and
 * links (macOS `/tmp`, `/var`) are judged and accepted.
 *
 * A link target and the home's real path are read as bytes and walked only
 * when they decode to UTF-8 losslessly (`losslessUtf8Name`); otherwise the
 * path is not trusted.
 *
 * Bounded: at most MAX_ANCESTRY_LINKS links and MAX_ANCESTRY_STEPS names, past
 * which the path is not trusted. A point-in-time judgment by path (lstat,
 * readlink, stat): it is not atomic with the later reads, so a change between
 * the two is not seen here. The report file and its PID-namespace sidecar are
 * each checked again on their own opened descriptors (#1160); no directory on
 * this path is. Owner and mode bits only: ACLs, extended attributes, mount
 * options and bind mounts are not consulted.
 */
function insecureNamedPath(start: string, homeNamed: string, home: HomeReal, uid: number | undefined): string | null {
  const homeNames = pathNames(homeNamed);
  const homeReal = 'real' in home ? home.real : null;
  const homeRealNames = homeReal !== null ? pathNames(homeReal) : [];
  const fsRoot = path.parse(homeNamed).root;
  let anchor = fsRoot;
  let cur = fsRoot;
  let todo: string[] = [];

  // Begin (again) at the absolute path `names`. Null, or why it is untrusted.
  const begin = (names: string[]): string | null => {
    const inHome = startsWithNames(names, homeNames)
      ? homeNames.length
      : homeReal !== null && startsWithNames(names, homeRealNames) ? homeRealNames.length : -1;
    let st: fs.Stats;
    if (inHome >= 0) {
      if (!('real' in home)) return home.lost;
      try {
        st = fs.statSync(homeNamed);
      } catch (err) {
        return statFailure(err);
      }
      anchor = home.real;
      todo = names.slice(inHome);
    } else {
      try {
        st = fs.lstatSync(fsRoot);
      } catch (err) {
        return statFailure(err);
      }
      anchor = fsRoot;
      todo = names;
    }
    cur = anchor;
    return untrustedAncestor(st, uid);
  };

  let why = begin(pathNames(start));
  if (why) return why;
  let links = 0;
  for (let steps = 0; todo.length > 0; steps++) {
    if (steps >= MAX_ANCESTRY_STEPS) return 'path too long to judge';
    const name = todo.shift() as string;
    if (name === '..') {
      if (cur !== anchor) {
        cur = path.dirname(cur);
      } else if (path.dirname(cur) !== cur) {
        why = begin([...pathNames(path.dirname(cur)), ...todo]);
        if (why) return why;
      }
      continue;
    }
    const next = path.join(cur, name);
    let st: fs.Stats;
    try {
      st = fs.lstatSync(next);
    } catch (err) {
      return statFailure(err);
    }
    if (!st.isSymbolicLink()) {
      why = untrustedAncestor(st, uid);
      if (why) return why;
      cur = next;
      continue;
    }
    if (uid !== undefined && st.uid !== uid && st.uid !== 0) return 'symbolic link owned by another user';
    if (++links > MAX_ANCESTRY_LINKS) return 'too many symbolic links';
    let raw: Buffer;
    try {
      raw = fs.readlinkSync(next, { encoding: 'buffer' });
    } catch {
      return 'unreadable symbolic link';
    }
    const target = losslessUtf8Name(raw);
    if (target === null) return 'symbolic link target not valid UTF-8';
    if (path.isAbsolute(target)) {
      why = begin([...pathNames(target), ...todo]);
      if (why) return why;
    } else {
      todo = [...pathNames(target), ...todo];
    }
  }
  return null;
}

/**
 * #1133: why the config directory, or the path that names it, makes every
 * self-report under it untrusted; null when the path is private.
 *
 * The config directory gets the posture directories' own rule (a real
 * directory, not a symlink; this user's; not writable by group or others).
 * Its parent path, as named, is then judged by `insecureNamedPath`: up to the
 * home for a path inside it, else to the filesystem root, following and
 * judging each link on the way.
 *
 * The home is where the walk stops. A config directory that IS the home, as
 * named or as its real path, has passed the check above and nothing over it
 * is judged. Any other spelling that reaches the home's directory (through a
 * link in a parent) is not the home's name, and its parent path is walked.
 *
 * Windows has no owner/mode check here, as for the posture directories, so
 * nothing above the config directory is walked there.
 */
function insecureConfigAncestry(configDir: string, home: string, uid: number | undefined): string | null {
  // Resolved, as the collector's own joined paths are, so a trailing separator
  // cannot make lstat follow a symlinked config dir.
  const cfg = path.resolve(configDir);
  const own = insecureDir(cfg, uid);
  if (own) return `${own} (config directory)`;
  if (process.platform === 'win32') return null;
  const homeNamed = path.resolve(home);
  if (cfg === homeNamed) return null;
  const homeReal = realHome(homeNamed);
  if ('real' in homeReal && cfg === homeReal.real) return null;
  const why = insecureNamedPath(path.dirname(cfg), homeNamed, homeReal, uid);
  return why ? `${why} (above the config directory)` : null;
}

/**
 * Names in `dir`, or null when it cannot be listed. A successful listing of
 * nothing is `[]`, never null: an empty secure directory is not unreadable.
 */
function listNames(dir: string): string[] | null {
  try {
    return fs.readdirSync(dir).sort();
  } catch {
    return null;
  }
}

/**
 * Exact stat, same request as `linuxPidNamespace`. Device and inode stay
 * bigint. A number stat has already rounded those identifiers; converting the
 * rounded number back to bigint does not recover them.
 */
const EXACT_STAT = { bigint: true } as const;

const NS_PER_MS = 1_000_000n;
const MAX_SAFE_MS = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_SAFE_MS = BigInt(Number.MIN_SAFE_INTEGER);

/** Fractional milliseconds from an exact nanosecond timestamp. Not `BigIntStats.mtimeMs`. */
function mtimeMsFromNs(ns: bigint): number {
  const ms = ns / NS_PER_MS;
  const frac = ns % NS_PER_MS;
  if (ms > MAX_SAFE_MS || ms < MIN_SAFE_MS) return Number.NaN;
  return Number(ms) + Number(frac) / 1e6;
}

/**
 * Comparable mtime. A number `mtimeMs` already carries a fraction, or is not
 * finite. An exact stat's fraction lives in `mtimeNs`; its `mtimeMs` is whole
 * milliseconds and is not a substitute. No precise value is not a timestamp.
 */
function preciseMtimeMs(st: { mtimeMs?: unknown; mtimeNs?: unknown }): number {
  if (typeof st.mtimeMs === 'number') return st.mtimeMs;
  if (typeof st.mtimeNs === 'bigint') return mtimeMsFromNs(st.mtimeNs);
  return Number.NaN;
}

type DescriptorMtime = { kind: 'ns'; ns: bigint } | { kind: 'ms'; ms: number };

/**
 * Time used to order a sidecar against its report. A number `mtimeMs` is
 * already the fraction the caller supplied, same rule as `preciseMtimeMs`.
 * Otherwise the exact nanoseconds. A whole-millisecond bigint is not a
 * substitute for a missing `mtimeNs`.
 */
function descriptorMtime(st: { mtimeMs?: unknown; mtimeNs?: unknown }): DescriptorMtime | null {
  if (typeof st.mtimeMs === 'number') return { kind: 'ms', ms: st.mtimeMs };
  if (typeof st.mtimeNs === 'bigint') return { kind: 'ns', ns: st.mtimeNs };
  return null;
}

function nsWithinSafeMs(ns: bigint): boolean {
  const ms = ns / NS_PER_MS;
  return ms <= MAX_SAFE_MS && ms >= MIN_SAFE_MS;
}

/**
 * True when the sidecar is not older than the report. Exact nanoseconds
 * compare as bigint, so adjacent values that become one Number still order.
 * Number milliseconds compare only when neither side has exact nanoseconds.
 * Missing, mixed, non-finite and out-of-range times are not fresh. Equality
 * is accepted. This is not the millisecond content-aging value.
 */
function sidecarNotOlder(report: DescriptorMtime | null, sidecar: DescriptorMtime | null): boolean {
  if (report?.kind === 'ns' && sidecar?.kind === 'ns') {
    return nsWithinSafeMs(report.ns) && nsWithinSafeMs(sidecar.ns) && sidecar.ns >= report.ns;
  }
  if (report?.kind === 'ms' && sidecar?.kind === 'ms') {
    return Number.isFinite(report.ms) && Number.isFinite(sidecar.ms) && sidecar.ms >= report.ms;
  }
  return false;
}

function sameDeviceInode(a: { dev: unknown; ino: unknown }, b: { dev: unknown; ino: unknown }): boolean {
  return typeof a.dev === 'bigint' && typeof a.ino === 'bigint'
    && typeof b.dev === 'bigint' && typeof b.ino === 'bigint'
    && a.dev === b.dev && a.ino === b.ino;
}

function exceedsByteCap(size: unknown, cap: number): boolean {
  if (typeof size === 'bigint') return size > BigInt(cap);
  return typeof size === 'number' && size > cap;
}

function byteCountAbove(n: number, size: unknown): boolean {
  if (typeof size === 'bigint') return BigInt(n) > size;
  if (typeof size === 'number') return n > size;
  return true;
}

function ownedByOther(stUid: unknown, uid: number): boolean {
  if (typeof stUid === 'bigint') return stUid !== BigInt(uid);
  return typeof stUid !== 'number' || stUid !== uid;
}

function groupOrOtherBits(mode: unknown): boolean {
  if (typeof mode === 'bigint') return (mode & 0o077n) !== 0n;
  return typeof mode !== 'number' || (mode & 0o077) !== 0;
}

/** The PID-namespace sidecar for a self-report file (same basename, `.pidns`). */
export function pidNsSidecarPath(reportFile: string): string {
  return reportFile.endsWith('.json') ? `${reportFile.slice(0, -'.json'.length)}${PID_NS_SIDECAR_SUFFIX}` : `${reportFile}${PID_NS_SIDECAR_SUFFIX}`;
}

/**
 * #970: the reporter's PID namespace from its report's sidecar, or null
 * ("namespace unknown": the record then falls back to the 7-day age rule, like
 * any report from an earlier writer). Untrusted like the report: a regular
 * file (never a symlink), owned by this user, owner-only, tiny, and exactly
 * digits or `null`. Missing, unreadable or malformed is null.
 *
 * It is trusted only when the sidecar's opened mtime is not older than the
 * report's opened mtime: the writers rewrite it after every report write, so
 * an older one is from before the report's last write and vouches for nothing.
 * Exact nanoseconds compare as bigint. A missing, mixed, non-finite or
 * out-of-range timestamp is not evidence the sidecar is fresh. Equality is
 * accepted. (The basename is the process's start identity — pid + start ticks,
 * or pid + a random token — so a different process does not share it; the
 * mtime rule also covers a sidecar whose rewrite failed.)
 */
export function readPidNsSidecar(
  reportFile: string,
  reportOpened: { mtimeMs?: unknown; mtimeNs?: unknown },
  uid: number | undefined,
): string | null {
  const file = pidNsSidecarPath(reportFile);
  let fd: number | null = null;
  try {
    const st = fs.lstatSync(file, EXACT_STAT);
    if (!st.isFile() || exceedsByteCap(st.size, PID_NS_SIDECAR_MAX_BYTES)) return null;
    if (process.platform !== 'win32') {
      if (uid !== undefined && ownedByOther(st.uid, uid)) return null;
      if (groupOrOtherBits(st.mode)) return null;
    }
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(fd, EXACT_STAT);
    // Type, size, owner, mode, and exact dev+ino are decided on this descriptor.
    // A failure stays null and does not change the report's rejection. Freshness
    // is this descriptor's nanoseconds against the report's, not a Number
    // rounding of either. A timestamp that is not fresh is not namespace evidence.
    if (!opened.isFile() || exceedsByteCap(opened.size, PID_NS_SIDECAR_MAX_BYTES)) return null;
    if (process.platform !== 'win32') {
      if (uid !== undefined && ownedByOther(opened.uid, uid)) return null;
      if (groupOrOtherBits(opened.mode)) return null;
    }
    if (!sameDeviceInode(opened, st)) return null;
    if (!sidecarNotOlder(descriptorMtime(reportOpened), descriptorMtime(opened))) return null;
    const buf = Buffer.alloc(PID_NS_SIDECAR_MAX_BYTES + 1);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    const text = buf.subarray(0, n).toString('utf8');
    return PID_NS_RE.test(text) ? text : null;
  } catch {
    return null;
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch { /* read-only handle */ }
    }
  }
}

/** Read one self-report as untrusted input. Never follows a symlink. */
export function readSelfReportFile(
  file: string,
  expect: { runtime: GateRuntimeId; profile: string; instance: string },
  uid: number | undefined,
): SelfReportRead {
  // #970: every rejection here is a TRUST rejection (its mtime is no evidence)
  // except a content rejection of a file that passed every trust check.
  const invalid = (reason: string): SelfReportRead => ({ kind: 'invalid', reason, instance: expect.instance, rejection: 'trust' });
  const contentInvalid = (reason: string, observedMtimeMs: number): SelfReportRead => ({
    kind: 'invalid', reason, instance: expect.instance, rejection: 'content', observedMtimeMs,
  });
  const oversize = (size: number | bigint): SelfReportRead => invalid(`size ${size} bytes exceeds the ${SELF_REPORT_MAX_BYTES}-byte cap`);
  let st: fs.BigIntStats;
  try {
    st = fs.lstatSync(file, EXACT_STAT);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code === 'ENOENT' || code === 'ENOTDIR' ? { kind: 'absent' } : invalid('unreadable');
  }
  if (!st.isFile()) return invalid('not a regular file');
  if (process.platform !== 'win32') {
    if (uid !== undefined && ownedByOther(st.uid, uid)) return invalid('owned by another user');
    if (groupOrOtherBits(st.mode)) return invalid('readable or writable by group or others (must be owner-only)');
  }
  if (exceedsByteCap(st.size, SELF_REPORT_MAX_BYTES)) {
    return typeof st.size === 'bigint' || typeof st.size === 'number'
      ? oversize(st.size)
      : invalid('unreadable');
  }
  let fd: number | null = null;
  try {
    // O_NOFOLLOW applies only to a final-component symlink. Type, owner, mode,
    // size, exact device and inode, and content-rejection mtime come from the
    // opened descriptor. Fractional mtime is kept; a whole-millisecond bigint
    // is not used in its place.
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(fd, EXACT_STAT);
    if (!opened.isFile()) return invalid('not a regular file');
    if (exceedsByteCap(opened.size, SELF_REPORT_MAX_BYTES)) {
      return typeof opened.size === 'bigint' || typeof opened.size === 'number' ? oversize(opened.size) : invalid('unreadable');
    }
    if (process.platform !== 'win32') {
      if (uid !== undefined && ownedByOther(opened.uid, uid)) return invalid('owned by another user');
      if (groupOrOtherBits(opened.mode)) return invalid('readable or writable by group or others (must be owner-only)');
    }
    if (!sameDeviceInode(opened, st)) return invalid('unreadable');
    const observedMtimeMs = preciseMtimeMs(opened);
    const buf = Buffer.alloc(SELF_REPORT_MAX_BYTES + 1);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    if (n > SELF_REPORT_MAX_BYTES) return oversize(n);
    if (byteCountAbove(n, opened.size)) return invalid('unreadable');
    const read = parseSelfReport(buf.subarray(0, n).toString('utf8'), n);
    const again = fs.fstatSync(fd, EXACT_STAT);
    if (!again.isFile() || !sameDeviceInode(again, opened) || again.size !== opened.size) {
      return invalid('unreadable');
    }
    // parseSelfReport classifies its own rejections (oversize is trust); an
    // unclassified one stays trust. Only a content rejection carries the
    // opened descriptor's mtime.
    if (read.kind === 'invalid') return read.rejection === 'content' ? contentInvalid(read.reason, observedMtimeMs) : invalid(read.reason);
    if (read.kind === 'valid') {
      const r = read.report;
      if (r.runtime !== expect.runtime) return contentInvalid('report names a different runtime than its path', observedMtimeMs);
      if (r.profile !== expect.profile) return contentInvalid('report names a different profile than its path (wrong profile)', observedMtimeMs);
      if (r.instance.key !== expect.instance) return contentInvalid('report names a different instance than its file', observedMtimeMs);
      // #970: join the namespace sidecar on this descriptor's exact nanoseconds.
      // observedMtimeMs stays the separate millisecond value for content-rejection age.
      r.instance.pid_ns = readPidNsSidecar(file, opened, uid);
    }
    return read;
  } catch {
    return invalid('unreadable');
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch { /* read-only handle */ }
    }
  }
}

function checkLiveness(read: SelfReportRead, deps: Required<CollectDeps>, collectorNs: string | null): LivenessCheck {
  if (read.kind !== 'valid') return 'unsupported';
  const { pid, process_start: start, liveness, pid_ns: reportNs } = read.report.instance;
  if (liveness !== 'process' || pid === null) return 'unsupported';
  // #970: a pid number means something only inside its own PID namespace. A
  // report from another namespace cannot be looked up here at all; one that
  // recorded none (an earlier writer) can still be shown ALIVE by an exact
  // pid + start match, but a miss is not proof it exited.
  if (reportNs !== null && collectorNs !== null && reportNs !== collectorNs) return 'unscoped';
  const sameNs = reportNs !== null && reportNs === collectorNs;
  let seen: string | null | undefined;
  try {
    seen = deps.processStart(pid);
  } catch {
    seen = undefined;
  }
  if (seen === undefined) return 'unsupported';
  if (seen === null) return sameNs ? 'ended' : 'unscoped';
  // Pid exists. Without a reported start token a reused pid is indistinguishable.
  if (start === null) return 'unsupported';
  if (seen === start) return 'alive';
  return sameNs ? 'ended' : 'unscoped';
}

interface ProfileFiles {
  profile: string;
  insecure: string | null;
  instances: string[];
  skipped: number;
}

/** One profile carrying an insecure-directory finding and no instance id. */
function zeroInstanceProfile(profile: string, insecure: string | null): ProfileFiles {
  return { profile, insecure: insecure ?? 'unreadable directory', instances: [], skipped: 0 };
}

/**
 * Profiles and instance files a gate runtime has reported from (names only).
 * `ancestry` is the #1133 finding for the config directory and above it.
 */
function reportingProfiles(dir: string, runtime: GateRuntimeId, uid: number | undefined, ancestry: () => string | null): ProfileFiles[] {
  const rtDir = path.join(dir, runtime);
  const rootNames = listNames(dir);
  // Unlistable posture root: the runtime name was never seen; do not invent a
  // runtime here. No posture root, or no directory for this runtime, is the
  // ordinary missing report: nothing above it is judged for that (#1133).
  if (rootNames === null || rootNames.indexOf(runtime) < 0) return [];
  // #1133: a listed runtime directory is only as private as the path above it.
  const rootInsecure = ancestry() ?? insecureDir(dir, uid) ?? insecureDir(rtDir, uid);
  const profileNames = listNames(rtDir);
  // Listed runtime directory that cannot be listed: keep the finding. A
  // successful empty listing is not this case.
  if (profileNames === null) return [zeroInstanceProfile('default', rootInsecure)];
  const out: ProfileFiles[] = [];
  for (const profile of profileNames) {
    if (!isValidProfileId(profile)) continue;
    const pDir = path.join(rtDir, profile);
    const insecure = rootInsecure ?? insecureDir(pDir, uid);
    const names = listNames(pDir);
    if (names === null) {
      // Listed profile directory that cannot be listed: keep the entry.
      out.push(zeroInstanceProfile(profile, insecure));
      continue;
    }
    // Newest first, so the cap drops the oldest leftovers, never a live report.
    const mtime = (n: string) => {
      try {
        return fs.lstatSync(path.join(pDir, `${n}.json`)).mtimeMs;
      } catch {
        return 0;
      }
    };
    const all = names
      .filter((n) => n.endsWith('.json'))
      .map((n) => n.slice(0, -'.json'.length))
      .filter(isValidInstanceKey)
      .map((n) => ({ n, m: mtime(n) }))
      .sort((a, b) => b.m - a.m || a.n.localeCompare(b.n))
      .map((x) => x.n);
    out.push({
      profile,
      insecure,
      instances: all.slice(0, MAX_INSTANCES_PER_PROFILE),
      skipped: Math.max(0, all.length - MAX_INSTANCES_PER_PROFILE),
    });
  }
  // Insecure, and nothing under it produced a profile entry (empty, or only
  // names outside the profile grammar). A secure empty listing stays [].
  if (out.length === 0 && rootInsecure) return [zeroInstanceProfile('default', rootInsecure)];
  return out;
}

function isRegularFile(p: string): boolean {
  try {
    return fs.lstatSync(p).isFile();
  } catch {
    return false;
  }
}

function isRealDir(p: string): boolean {
  try {
    const st = fs.lstatSync(p);
    return st.isDirectory() && !st.isSymbolicLink();
  } catch {
    return false;
  }
}

/**
 * Hermes artefacts for one profile. A Hermes home, or a plugin directory, is
 * not proof the plugin is there: `yes` needs both `plugin.yaml` and
 * `__init__.py` as regular files. A plugin directory without them is
 * `unknown`; no plugin directory is `no`.
 */
export function hermesArtefacts(home: string, profile: string): { installed: Installed; note: string | null } {
  const root = path.join(home, '.hermes');
  const bases = profile === 'default' ? [root] : [path.join(root, 'profiles', profile), root];
  let sawDir = false;
  for (const base of bases) {
    const dir = path.join(base, 'plugins', 'shieldcortex');
    if (isRegularFile(path.join(dir, 'plugin.yaml')) && isRegularFile(path.join(dir, '__init__.py'))) {
      return { installed: 'yes', note: null };
    }
    if (isRealDir(dir)) sawDir = true;
  }
  return sawDir
    ? { installed: 'unknown', note: 'a shieldcortex plugin directory exists but plugin.yaml / __init__.py are missing' }
    : { installed: 'no', note: 'no ShieldCortex plugin artefacts for this Hermes profile' };
}

function probeInstalled(runtime: GateRuntimeId | MemoryOnlyRuntimeId, home: string, profile: string): { installed: Installed; note: string | null } {
  try {
    if (runtime === 'hermes') return hermesArtefacts(home, profile);
    return { installed: hostArtefactWired(HOST_ID_FOR[runtime], home) ? 'yes' : 'no', note: null };
  } catch {
    return { installed: 'unknown', note: 'the ShieldCortex artefacts could not be read' };
  }
}

/**
 * One record per (runtime, profile, plane, instance) for every runtime this
 * box shows any trace of. A runtime with artefacts but no report gets one
 * `unobserved` record for its default profile. Runtimes with no host, no
 * artefact and no self-report are omitted rather than reported as a record of
 * nothing. The list is what was FOUND: it never claims there are no others.
 */
export function collectPostureRecords(opts: CollectOptions = {}): PostureRecord[] {
  const home = opts.home ?? os.homedir();
  const configDir = opts.configDir ?? defaultConfigDir(home);
  const nowMs = opts.nowMs ?? Date.now();
  const deps: Required<CollectDeps> = { ...defaultDeps, ...(opts.deps ?? {}) };
  let uid: number | undefined;
  try {
    uid = deps.uid();
  } catch {
    uid = undefined;
  }
  let collectorNs: string | null;
  try {
    collectorNs = deps.pidNamespace();
  } catch {
    collectorNs = null;
  }
  const dir = postureSelfReportDir(configDir);
  const table = scanHostTable(home, opts.hostDeps ?? {});
  const present = new Map(table.rows.map((r) => [r.id, r.present]));
  const records: PostureRecord[] = [];
  // #1133: judged once, and only when some runtime directory was listed.
  let ancestryFinding: string | null | undefined;
  const ancestry = () => (ancestryFinding === undefined ? (ancestryFinding = insecureConfigAncestry(configDir, home, uid)) : ancestryFinding);

  for (const runtime of GATE_RUNTIMES) {
    const hostId = HOST_ID_FOR[runtime];
    const profiles = reportingProfiles(dir, runtime, uid, ancestry);
    const base = probeInstalled(runtime, home, 'default');
    if (!present.get(hostId) && base.installed === 'no' && profiles.length === 0) continue;
    const list: ProfileFiles[] = profiles.length > 0 ? profiles : [{ profile: 'default', insecure: null, instances: [], skipped: 0 }];
    for (const pf of list) {
      const inst = probeInstalled(runtime, home, pf.profile);
      const derive = (read: SelfReportRead, liveness: LivenessCheck = 'unsupported', lastSeenMs: number | null = null) => deriveToolGateRecord({
        runtime,
        profile: pf.profile,
        installed: inst.installed,
        installedNote: inst.note,
        read,
        liveness,
        nowMs,
        maxAgeMs: opts.maxAgeMs,
        lastSeenMs,
      });
      const recs: PostureRecord[] = [];
      if (pf.instances.length === 0) {
        // #1153: insecure with no instance file is a trust rejection, not an
        // omission and not an absent read. No instance id is invented, and
        // absent is not also recorded.
        if (pf.insecure) {
          recs.push(derive({
            kind: 'invalid',
            reason: `insecure self-report directory: ${pf.insecure}`,
            rejection: 'trust',
          }));
        } else {
          recs.push(derive({ kind: 'absent' }));
        }
      }
      for (const instance of pf.instances) {
        let read: SelfReportRead;
        const file = path.join(dir, runtime, pf.profile, `${instance}.json`);
        if (pf.insecure) {
          read = { kind: 'invalid', reason: `insecure self-report directory: ${pf.insecure}`, instance, rejection: 'trust' };
        } else if (!isGateRuntime(runtime)) {
          // Trust: no reader vouches for a path under a runtime it cannot validate.
          read = { kind: 'invalid', reason: 'unknown runtime', instance, rejection: 'trust' };
        } else {
          read = readSelfReportFile(file, { runtime, profile: pf.profile, instance }, uid);
        }
        // Content-rejection age uses the opened descriptor mtime carried on that
        // read, and only when rejectionMayAge is true. A missing or non-finite
        // mtime is null. Trust, absent, and validated reads do not pass one.
        const carried = read.kind === 'invalid' && typeof read.observedMtimeMs === 'number' && Number.isFinite(read.observedMtimeMs)
          ? read.observedMtimeMs
          : null;
        recs.push(derive(read, checkLiveness(read, deps, collectorNs), rejectionMayAge(read) ? carried : null));
      }
      if (pf.skipped > 0) {
        for (const r of recs) r.notes.push(`${pf.skipped} further instance report(s) for this profile were not read (cap ${MAX_INSTANCES_PER_PROFILE})`);
      }
      // #970: staleness is decided within this (runtime, profile), on evidence
      // only — the host table calling the runtime absent hides nothing. A
      // PRESENT runtime whose every report is stale keeps one non-green record
      // (the one it would get with no report at all); an absent one does not.
      const marked = markStaleRecords(recs);
      records.push(...marked);
      if (present.get(hostId) && marked.length > 0 && marked.every((r) => r.stale)) {
        records.push(noCurrentReportRecord(derive({ kind: 'absent' }), marked.length));
      }
    }
  }

  for (const runtime of ['codex', 'copilot'] as const) {
    const hostId = HOST_ID_FOR[runtime];
    const { installed } = probeInstalled(runtime, home, 'default');
    if (!present.get(hostId) && installed === 'no') continue;
    records.push(deriveMemoryOnlyRecord({ runtime, profile: 'default', installed, nowMs }));
  }

  return records;
}
