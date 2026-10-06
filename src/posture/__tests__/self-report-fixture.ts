/**
 * #613 test fixtures: a valid v1 self-report body and a writer that lays it
 * out exactly where the runtimes do, with the permissions they use. Not a
 * test file itself (no `.test.ts`).
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { SELF_REPORT_SCHEMA, SELF_REPORT_VERSION } from '../posture-record.js';
import { postureSelfReportDir, type CollectDeps } from '../collect.js';

export const NOW = Date.parse('2026-09-29T12:00:00.000Z');
export const iso = (ms: number) => new Date(ms).toISOString();
export const H = (c: string) => `sha256:${c.repeat(64)}`;

export const PID = 4242;
export const START = '100';
export const INSTANCE = `p${PID}-s${START}`;

type Obj = Record<string, unknown>;

export function denial(over: Obj = {}): Obj {
  return {
    at: iso(NOW - 10_000),
    tested_path: 'pre_tool_call:terminal',
    instance: INSTANCE,
    plugin_hash: H('b'),
    policy_hash: H('a'),
    configured_posture: 'enforce',
    ...over,
  };
}

/** A fresh, valid Hermes report from a live process on the default profile. */
export function reportBody(over: Obj = {}): Obj {
  const base: Obj = {
    schema: SELF_REPORT_SCHEMA,
    version: SELF_REPORT_VERSION,
    runtime: 'hermes',
    profile: 'default',
    plane: 'tool-gate',
    instance: { key: INSTANCE, pid: PID, process_start: START, started_at: iso(NOW - 3_600_000), liveness: 'process' },
    runtime_version: null,
    plugin: { id: 'shieldcortex', version: '0.1.0', hash: H('b') },
    heartbeat_at: iso(NOW - 60_000),
    loaded: true,
    configured_posture: 'enforce',
    scanner: 'available',
    policy_hash: H('a'),
    degraded_intervals: [],
    denials: { blocked_action: null, synthetic_probe: null, blocked_action_count: 0 },
  };
  return { ...base, ...over };
}

/** Same process, different pid/start: a second instance on the same profile. */
export function otherInstance(pid: number, start: string): Obj {
  return { key: `p${pid}-s${start}`, pid, process_start: start, started_at: iso(NOW - 1_800_000), liveness: 'process' };
}

export function writeRaw(configDir: string, runtime: string, profile: string, instance: string, text: string): string {
  const root = postureSelfReportDir(configDir);
  const dir = path.join(root, runtime, profile);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const d of [root, path.join(root, runtime), dir]) fs.chmodSync(d, 0o700);
  const file = path.join(dir, `${instance}.json`);
  fs.writeFileSync(file, text, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return file;
}

export function writeReport(configDir: string, body: Obj, fileInstance?: string, fileProfile?: string): string {
  return writeRaw(
    configDir,
    String(body.runtime),
    fileProfile ?? String(body.profile),
    fileInstance ?? String((body.instance as Obj).key),
    JSON.stringify(body),
  );
}

/** Deps with a fake process table: pid → start token. Absent pids have exited. */
export function processTable(table: Record<number, string>): CollectDeps {
  return {
    processStart: (pid) => (Object.prototype.hasOwnProperty.call(table, pid) ? table[pid] : null),
    uid: () => (typeof process.getuid === 'function' ? process.getuid() : undefined),
  };
}

export const LIVE = processTable({ [PID]: START });

/** Every path under `dir` with its mtime and content hash (dirs: mtime + listing). */
export function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (p: string) => {
    const st = fs.lstatSync(p);
    if (st.isDirectory()) {
      out[p] = `dir:${st.mtimeMs}:${st.mode}:${fs.readdirSync(p).sort().join(',')}`;
      for (const e of fs.readdirSync(p)) walk(path.join(p, e));
    } else if (st.isSymbolicLink()) {
      out[p] = `link:${fs.readlinkSync(p)}`;
    } else {
      out[p] = `file:${st.mtimeMs}:${st.mode}:${crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')}`;
    }
  };
  walk(dir);
  return out;
}

export function hermesPluginArtefacts(home: string, base = path.join(home, '.hermes')): void {
  const dir = path.join(base, 'plugins', 'shieldcortex');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'plugin.yaml'), 'name: shieldcortex\n');
  fs.writeFileSync(path.join(dir, '__init__.py'), 'def register(ctx):\n    pass\n');
}

export function hermesHome(home: string): void {
  fs.mkdirSync(path.join(home, '.hermes'), { recursive: true });
  fs.writeFileSync(path.join(home, '.hermes', 'config.yaml'), 'model: x\n');
}
