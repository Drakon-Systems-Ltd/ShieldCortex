/**
 * Read-only posture collector (#613).
 *
 * Reads, never writes: no directory is created, no config or consent file is
 * touched, Guard is never armed, no host binary is executed. The only probe
 * that looks outside the home is host-table's OpenClaw binary lookup, which
 * callers (and tests) can inject, and the Linux `/proc/<pid>/stat` read that
 * checks a reporting process's start identity.
 *
 * Self-reports live at
 *
 *     <configDir>/posture/<runtime>/<profile>/<instance>.json
 *
 * one file per reporting process, written by the runtime processes
 * themselves (Claude Code hook, OpenClaw plugin, Hermes plugin). Each file is
 * untrusted: the directories and the file must be owned by this user and not
 * writable by anyone else, the file must be a regular file (symlinks are not
 * followed) under the size cap, and its content must name the same runtime,
 * profile and instance as its path. Then `parseSelfReport` validates it.
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
 * It is trusted only when its mtime is NOT OLDER than the report it sits
 * beside: the writers rewrite it after every report write, so an older one is
 * from before the report's last write and vouches for nothing. (The basename
 * is the process's start identity — pid + start ticks, or pid + a random
 * token — so a different process does not share it; the mtime rule also
 * covers a sidecar whose rewrite failed.)
 */
export function readPidNsSidecar(reportFile: string, reportMtimeMs: number, uid: number | undefined): string | null {
  const file = pidNsSidecarPath(reportFile);
  let fd: number | null = null;
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size > PID_NS_SIDECAR_MAX_BYTES) return null;
    if (process.platform !== 'win32') {
      if (uid !== undefined && st.uid !== uid) return null;
      if ((st.mode & 0o077) !== 0) return null;
    }
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(fd);
    if (opened.ino !== st.ino || opened.mtimeMs < reportMtimeMs) return null;
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
  const contentInvalid = (reason: string): SelfReportRead => ({ kind: 'invalid', reason, instance: expect.instance, rejection: 'content' });
  let st: fs.Stats;
  try {
    st = fs.lstatSync(file);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code === 'ENOENT' || code === 'ENOTDIR' ? { kind: 'absent' } : invalid('unreadable');
  }
  if (!st.isFile()) return invalid('not a regular file');
  if (process.platform !== 'win32') {
    if (uid !== undefined && st.uid !== uid) return invalid('owned by another user');
    if ((st.mode & 0o077) !== 0) return invalid('readable or writable by group or others (must be owner-only)');
  }
  if (st.size > SELF_REPORT_MAX_BYTES) {
    return invalid(`size ${st.size} bytes exceeds the ${SELF_REPORT_MAX_BYTES}-byte cap`);
  }
  let fd: number | null = null;
  try {
    // O_NOFOLLOW closes the lstat→open race for a swapped-in symlink.
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const buf = Buffer.alloc(SELF_REPORT_MAX_BYTES + 1);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    const read = parseSelfReport(buf.subarray(0, n).toString('utf8'), n);
    // parseSelfReport classifies its own rejections (oversize is trust); an
    // unclassified one stays trust.
    if (read.kind === 'invalid') return read.rejection === 'content' ? contentInvalid(read.reason) : invalid(read.reason);
    if (read.kind === 'valid') {
      const r = read.report;
      if (r.runtime !== expect.runtime) return contentInvalid('report names a different runtime than its path');
      if (r.profile !== expect.profile) return contentInvalid('report names a different profile than its path (wrong profile)');
      if (r.instance.key !== expect.instance) return contentInvalid('report names a different instance than its file');
      // #970: join the namespace sidecar, against the mtime of the report actually read.
      r.instance.pid_ns = readPidNsSidecar(file, fs.fstatSync(fd).mtimeMs, uid);
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

/** Profiles and instance files a gate runtime has reported from (names only). */
function reportingProfiles(dir: string, runtime: GateRuntimeId, uid: number | undefined): ProfileFiles[] {
  const rtDir = path.join(dir, runtime);
  const rootNames = listNames(dir);
  // Unlistable posture root: the runtime name was never seen. That loss sits
  // above this directory (#1133); do not invent a runtime here.
  if (rootNames === null || rootNames.indexOf(runtime) < 0) return [];
  const rootInsecure = insecureDir(dir, uid) ?? insecureDir(rtDir, uid);
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

/** mtime of a self-report file, or null. lstat: a symlink is never followed. */
function fileMtimeMs(file: string): number | null {
  try {
    return fs.lstatSync(file).mtimeMs;
  } catch {
    return null;
  }
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

  for (const runtime of GATE_RUNTIMES) {
    const hostId = HOST_ID_FOR[runtime];
    const profiles = reportingProfiles(dir, runtime, uid);
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
        // #970: a file's mtime ages only a CONTENT rejection; a trust rejection
        // (insecure dir, symlink, foreign owner, mode, oversize, unreadable) is
        // judged whatever its age, exactly as before #970.
        recs.push(derive(read, checkLiveness(read, deps, collectorNs), rejectionMayAge(read) ? fileMtimeMs(file) : null));
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
