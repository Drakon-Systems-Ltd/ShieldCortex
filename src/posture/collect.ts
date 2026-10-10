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
 * reporter is still the process that wrote it.
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
  parseSelfReport,
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

const defaultDeps: Required<CollectDeps> = {
  processStart: linuxProcessStart,
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

function listNames(dir: string): string[] {
  try {
    return fs.readdirSync(dir).sort();
  } catch {
    return [];
  }
}

/** Read one self-report as untrusted input. Never follows a symlink. */
export function readSelfReportFile(
  file: string,
  expect: { runtime: GateRuntimeId; profile: string; instance: string },
  uid: number | undefined,
): SelfReportRead {
  const invalid = (reason: string): SelfReportRead => ({ kind: 'invalid', reason, instance: expect.instance });
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
    if (read.kind === 'invalid') return invalid(read.reason);
    if (read.kind === 'valid') {
      const r = read.report;
      if (r.runtime !== expect.runtime) return invalid('report names a different runtime than its path');
      if (r.profile !== expect.profile) return invalid('report names a different profile than its path (wrong profile)');
      if (r.instance.key !== expect.instance) return invalid('report names a different instance than its file');
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

function checkLiveness(read: SelfReportRead, deps: Required<CollectDeps>): LivenessCheck {
  if (read.kind !== 'valid') return 'unsupported';
  const { pid, process_start: start, liveness } = read.report.instance;
  if (liveness !== 'process' || pid === null) return 'unsupported';
  let seen: string | null | undefined;
  try {
    seen = deps.processStart(pid);
  } catch {
    seen = undefined;
  }
  if (seen === undefined) return 'unsupported';
  if (seen === null) return 'ended';
  // Pid exists. Without a reported start token a reused pid is indistinguishable.
  if (start === null) return 'unsupported';
  return seen === start ? 'alive' : 'ended';
}

interface ProfileFiles {
  profile: string;
  insecure: string | null;
  instances: string[];
  skipped: number;
}

/** Profiles and instance files a gate runtime has reported from (names only). */
function reportingProfiles(dir: string, runtime: GateRuntimeId, uid: number | undefined): ProfileFiles[] {
  const rtDir = path.join(dir, runtime);
  if (listNames(dir).indexOf(runtime) < 0) return [];
  const rootInsecure = insecureDir(dir, uid) ?? insecureDir(rtDir, uid);
  const out: ProfileFiles[] = [];
  for (const profile of listNames(rtDir)) {
    if (!isValidProfileId(profile)) continue;
    const pDir = path.join(rtDir, profile);
    const insecure = rootInsecure ?? insecureDir(pDir, uid);
    // Newest first, so the cap drops the oldest leftovers, never a live report.
    const mtime = (n: string) => {
      try {
        return fs.lstatSync(path.join(pDir, `${n}.json`)).mtimeMs;
      } catch {
        return 0;
      }
    };
    const all = listNames(pDir)
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
      const derive = (read: SelfReportRead, liveness: LivenessCheck = 'unsupported') => deriveToolGateRecord({
        runtime,
        profile: pf.profile,
        installed: inst.installed,
        installedNote: inst.note,
        read,
        liveness,
        nowMs,
        maxAgeMs: opts.maxAgeMs,
      });
      const recs: PostureRecord[] = [];
      if (pf.instances.length === 0) {
        recs.push(derive({ kind: 'absent' }));
      }
      for (const instance of pf.instances) {
        let read: SelfReportRead;
        if (pf.insecure) {
          read = { kind: 'invalid', reason: `insecure self-report directory: ${pf.insecure}`, instance };
        } else if (!isGateRuntime(runtime)) {
          read = { kind: 'invalid', reason: 'unknown runtime', instance };
        } else {
          read = readSelfReportFile(path.join(dir, runtime, pf.profile, `${instance}.json`), { runtime, profile: pf.profile, instance }, uid);
        }
        recs.push(derive(read, checkLiveness(read, deps)));
      }
      if (pf.skipped > 0) {
        for (const r of recs) r.notes.push(`${pf.skipped} further instance report(s) for this profile were not read (cap ${MAX_INSTANCES_PER_PROFILE})`);
      }
      records.push(...recs);
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
