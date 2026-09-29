/**
 * Process-side posture self-report for the OpenClaw plugin (#613).
 *
 * `shieldcortex doctor` and `shieldcortex policy-evidence` run in another
 * process and cannot see what THIS gateway process resolved: whether the
 * before_tool_call gate registered, what Action Guard posture the interceptor
 * was built with, whether the defence module loaded. So the plugin says so
 * itself, in a small versioned file:
 *
 *     <config dir>/posture/openclaw/<profile>/<instance>.json
 *
 * One file per gateway PROCESS: `<instance>` is this process's start identity
 * (pid + Linux start ticks where the host exposes them), so two gateways on
 * one profile never overwrite each other and a restarted gateway never
 * inherits the previous one's denials.
 *
 * The schema is closed and mirrored by src/posture/posture-record.ts
 * (parseSelfReport), the Claude Code hook and the Hermes plugin's posture.py —
 * build units that cannot share an import, pinned together by tests that feed
 * each writer's output to the CLI validator.
 *
 * Contract: atomic (temp + rename), owner-only (0600 file, 0700 dirs), bounded
 * (8 KiB), and best-effort. Nothing here throws, and nothing here is read by
 * the gate: a report that cannot be written changes no decision.
 *
 * Host-integrity limitation: this is a host-local file. It records what this
 * process said about itself; it is not attestation.
 */

import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const POSTURE_SCHEMA = 'shieldcortex.posture.self-report';
export const POSTURE_VERSION = 1;
export const POSTURE_MAX_BYTES = 8192;
const MAX_INTERVALS = 8;
const REASON_MAX = 120;
/** Rewrite at least this often while calls keep arriving. */
export const POSTURE_HEARTBEAT_MS = 10 * 60 * 1000;
/** Sibling reports untouched this long are from processes long gone. */
const PRUNE_AFTER_MS = 7 * 24 * 60 * 60 * 1000;
const PLUGIN_ID = 'shieldcortex-realtime';

export type PostureValue = 'enforce' | 'advisory' | 'intentionally-off' | 'unavailable' | 'unknown';
export type ScannerValue = 'available' | 'degraded' | 'unknown';
export type DenialKind = 'blocked-action' | 'synthetic-probe';

const POSTURES: readonly string[] = ['enforce', 'advisory', 'intentionally-off', 'unavailable', 'unknown'];
const SCANNERS: readonly string[] = ['available', 'degraded', 'unknown'];
const PROFILE_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const IDENT_RE = /^[A-Za-z0-9@/._:+-]{1,64}$/;

interface Denial {
  at: string;
  tested_path: string;
  instance: string;
  plugin_hash: string | null;
  policy_hash: string | null;
  configured_posture: PostureValue;
}

interface Interval { from: string; to: string | null; reason: string }

interface ProfileState {
  loaded: boolean;
  configuredPosture: PostureValue;
  scanner: ScannerValue;
  policyHash: string | null;
  intervals: Interval[];
  blocked: Denial | null;
  probe: Denial | null;
  blockedCount: number;
  lastWriteMs: number | null;
  lastBody: string | null;
}

// ── This process's identity, computed once ──────────────────────────────────

function linuxSelfStart(): string | null {
  if (process.platform !== 'linux') return null;
  try {
    const text = fs.readFileSync('/proc/self/stat', 'utf8');
    const start = text.slice(text.lastIndexOf(')') + 2).split(' ')[19];
    return start && /^[0-9]{1,20}$/.test(start) ? start : null;
  } catch {
    return null;
  }
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

let identity: { key: string; pid: number; start: string | null; startedAt: string } | null = null;
function processIdentity() {
  if (!identity) {
    const start = linuxSelfStart();
    identity = {
      key: start ? `p${process.pid}-s${start}` : `p${process.pid}-r${randomBytes(4).toString('hex')}`,
      pid: process.pid,
      start,
      startedAt: iso(Date.now() - Math.round(process.uptime() * 1000)),
    };
  }
  return identity;
}

let pluginHashMemo: string | null | undefined;
function pluginHash(): string | null {
  if (pluginHashMemo === undefined) {
    try {
      pluginHashMemo = `sha256:${createHash('sha256').update(fs.readFileSync(fileURLToPath(import.meta.url))).digest('hex')}`;
    } catch {
      pluginHashMemo = null;
    }
  }
  return pluginHashMemo;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stable(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

/** Hash of the effective guard policy. Callers leave secrets (notify) out. */
export function posturePolicyHash(policy: unknown): string | null {
  if (policy === undefined || policy === null) return null;
  try {
    return `sha256:${createHash('sha256').update(stable(policy)).digest('hex')}`;
  } catch {
    return null;
  }
}

function reason(text: unknown): string {
  const clean = String(text ?? '').replace(/[^\x20-\x7e]/g, '?').slice(0, REASON_MAX);
  return clean || 'unspecified';
}

/** A tool name reduced to the report's identifier grammar. */
export function testedPath(hook: string, toolName: unknown): string {
  const tool = String(toolName ?? 'unknown').replace(/[^A-Za-z0-9._:+-]/g, '_').slice(0, 40) || 'unknown';
  return `${hook}:${tool}`.slice(0, 64);
}

export function resolvePostureConfigDir(): string {
  const override = process.env.SHIELDCORTEX_CONFIG_DIR?.trim();
  return override ? override : path.join(os.homedir(), '.shieldcortex');
}

/** The OpenClaw profile this gateway serves, as a closed-grammar id. */
export function resolveOpenClawProfile(env: NodeJS.ProcessEnv = process.env): string {
  const raw = (env.OPENCLAW_PROFILE ?? '').trim().toLowerCase();
  return PROFILE_RE.test(raw) ? raw : 'default';
}

function secureDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('not a directory');
  if ((st.mode & 0o077) !== 0) fs.chmodSync(dir, 0o700);
}

function prune(dir: string, keep: string, nowMs: number): void {
  try {
    for (const name of fs.readdirSync(dir)) {
      if (name === keep) continue;
      const full = path.join(dir, name);
      try {
        const st = fs.lstatSync(full);
        const tmp = name.includes('.tmp-');
        if (!st.isFile()) continue;
        if ((tmp && nowMs - st.mtimeMs > 60 * 60 * 1000) || (!tmp && name.endsWith('.json') && nowMs - st.mtimeMs > PRUNE_AFTER_MS)) {
          fs.unlinkSync(full);
        }
      } catch { /* raced */ }
    }
  } catch { /* best-effort */ }
}

const states = new Map<string, ProfileState>();

function stateFor(configDir: string, profile: string): ProfileState {
  const k = `${configDir}\0${profile}`;
  let s = states.get(k);
  if (!s) {
    s = {
      loaded: true,
      configuredPosture: 'unknown',
      scanner: 'unknown',
      policyHash: null,
      intervals: [],
      blocked: null,
      probe: null,
      blockedCount: 0,
      lastWriteMs: null,
      lastBody: null,
    };
    states.set(k, s);
  }
  return s;
}

export function __resetPostureStateForTest(): void {
  states.clear();
  identity = null;
}

export interface PostureReportInput {
  configDir?: string;
  profile?: string;
  loaded?: boolean;
  configuredPosture?: PostureValue;
  scanner?: ScannerValue;
  /** The effective policy to hash (leave secrets out). `undefined` keeps the last one. */
  policy?: unknown;
  degradedReason?: string;
  denial?: { kind: DenialKind; testedPath: string };
  pluginVersion?: string | null;
  runtimeVersion?: string | null;
  nowMs?: number;
  /** Write even when nothing changed and the heartbeat is not due. Default true. */
  force?: boolean;
}

/**
 * Record this process's current posture and write it. Returns false on any
 * failure, or when an unforced write was not due. Never throws.
 */
export function writePostureSelfReport(input: PostureReportInput): boolean {
  let tmp: string | null = null;
  try {
    const configDir = input.configDir ?? resolvePostureConfigDir();
    const profile = input.profile ?? resolveOpenClawProfile();
    if (!PROFILE_RE.test(profile)) return false;
    if (input.configuredPosture !== undefined && !POSTURES.includes(input.configuredPosture)) return false;
    if (input.scanner !== undefined && !SCANNERS.includes(input.scanner)) return false;
    const nowMs = input.nowMs ?? Date.now();
    const nowIso = iso(nowMs);
    const id = processIdentity();
    const s = stateFor(configDir, profile);

    if (input.loaded !== undefined) s.loaded = input.loaded;
    if (input.configuredPosture !== undefined) s.configuredPosture = input.configuredPosture;
    if (input.policy !== undefined) s.policyHash = posturePolicyHash(input.policy);
    if (input.scanner !== undefined) {
      s.scanner = input.scanner;
      const last = s.intervals[s.intervals.length - 1];
      const open = !!last && last.to === null;
      if (input.scanner === 'degraded' && !open) s.intervals.push({ from: nowIso, to: null, reason: reason(input.degradedReason ?? 'scanner-degraded') });
      else if (input.scanner === 'available' && open) last.to = nowIso;
      s.intervals = s.intervals.slice(-MAX_INTERVALS);
    }
    if (input.denial) {
      const d: Denial = {
        at: nowIso,
        tested_path: IDENT_RE.test(input.denial.testedPath) ? input.denial.testedPath : 'unknown',
        instance: id.key,
        plugin_hash: pluginHash(),
        policy_hash: s.policyHash,
        configured_posture: s.configuredPosture,
      };
      if (input.denial.kind === 'synthetic-probe') s.probe = d;
      else {
        s.blocked = d;
        s.blockedCount = Math.min(s.blockedCount + 1, 1_000_000_000);
      }
    }

    const body = {
      schema: POSTURE_SCHEMA,
      version: POSTURE_VERSION,
      runtime: 'openclaw',
      profile,
      plane: 'tool-gate',
      instance: { key: id.key, pid: id.pid, process_start: id.start, started_at: id.startedAt, liveness: 'process' },
      runtime_version: typeof input.runtimeVersion === 'string' && IDENT_RE.test(input.runtimeVersion) ? input.runtimeVersion : null,
      plugin: {
        id: PLUGIN_ID,
        version: typeof input.pluginVersion === 'string' && IDENT_RE.test(input.pluginVersion) ? input.pluginVersion : null,
        hash: pluginHash(),
      },
      heartbeat_at: nowIso,
      loaded: s.loaded,
      configured_posture: s.configuredPosture,
      scanner: s.scanner,
      policy_hash: s.policyHash,
      degraded_intervals: s.intervals,
      denials: { blocked_action: s.blocked, synthetic_probe: s.probe, blocked_action_count: s.blockedCount },
    };
    const comparable = JSON.stringify({ ...body, heartbeat_at: null });
    const due = s.lastWriteMs === null || nowMs - s.lastWriteMs >= POSTURE_HEARTBEAT_MS;
    if (input.force === false && comparable === s.lastBody && !due) return false;

    const data = JSON.stringify(body);
    if (Buffer.byteLength(data) > POSTURE_MAX_BYTES) return false;
    const root = path.join(configDir, 'posture');
    const dir = path.join(root, 'openclaw', profile);
    secureDir(root);
    secureDir(path.join(root, 'openclaw'));
    secureDir(dir);
    const file = path.join(dir, `${id.key}.json`);
    tmp = `${file}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    fs.writeFileSync(tmp, data, { flag: 'wx', mode: 0o600 });
    fs.renameSync(tmp, file);
    tmp = null;
    s.lastWriteMs = nowMs;
    s.lastBody = comparable;
    prune(dir, `${id.key}.json`, nowMs);
    return true;
  } catch {
    return false;
  } finally {
    if (tmp) {
      try { fs.unlinkSync(tmp); } catch { /* already gone */ }
    }
  }
}
