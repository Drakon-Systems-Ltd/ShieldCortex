/**
 * #970 — the stale-posture behaviour through the BUILT CLI, because the three
 * surfaces differ only inside `runDoctor`: the default report folds stale
 * records into one line per runtime, `--verbose` lists them, and `--json`
 * keeps every record and marks each `stale: true|false` with a reason.
 *
 * The home is a temp dir and the child gets a closed environment (no
 * inherited variable can point it at a real home). Claude Code is present
 * with one recent session and two idle ones (superseded by the newer current
 * one); Hermes is absent (`~/.hermes` holds only a leftover state dir) with
 * two reports from pids that do not exist, in this host's PID namespace.
 *
 * Round 2: a second home has Hermes PRESENT with only an ended report beside
 * an enforcing Claude Code session — the host must not be judged green, and
 * Hermes keeps one "present, no current report" row.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { requireFreshBuiltArtefacts } from './built-artefact-freshness.js';
import { reportBody, writeReport } from '../posture/__tests__/self-report-fixture.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIST_ENTRY = join(repoRoot, 'dist', 'index.js');
const HOUR = 60 * 60 * 1000;
/** Above the Linux pid ceiling (2^22): never a running process. */
const DEAD_PIDS = [2 ** 22 + 9701, 2 ** 22 + 9702];
const linux = process.platform === 'linux';
/** The child doctor runs in this PID namespace, so a report naming it can be proven ended. */
const hostPidNs = linux ? statSync('/proc/self/ns/pid', { bigint: true }).ino.toString() : null;

let home: string;
let configDir: string;
let home2: string;

const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

function claudeReport(key: string, heartbeatAgoMs: number, dir = configDir, posture = 'advisory'): void {
  writeReport(dir, reportBody({
    runtime: 'claude_code',
    plugin: { id: 'shieldcortex-pre-tool-hook', version: '5.20.4', hash: null },
    instance: { key, pid: null, process_start: null, started_at: ago(47 * HOUR), liveness: 'per-call' },
    heartbeat_at: ago(heartbeatAgoMs),
    configured_posture: posture,
  }));
}

function deadHermesReport(dir: string, pid: number): void {
  writeReport(dir, reportBody({
    instance: { key: `p${pid}-s1`, pid, process_start: '1', pid_ns: hostPidNs, started_at: ago(3 * HOUR), liveness: 'process' },
    heartbeat_at: ago(60_000),
  }));
}

beforeAll(() => {
  requireFreshBuiltArtefacts({
    repoRoot,
    sources: [
      join(repoRoot, 'src', 'cli', 'doctor.ts'),
      join(repoRoot, 'src', 'cli', 'doctor-report.ts'),
      join(repoRoot, 'src', 'posture', 'collect.ts'),
      join(repoRoot, 'src', 'posture', 'posture-record.ts'),
    ],
    artefacts: [DIST_ENTRY, join(repoRoot, 'dist', 'cli', 'doctor.js'), join(repoRoot, 'dist', 'posture', 'posture-record.js')],
  });
  home = mkdtempSync(join(tmpdir(), 'sc-970-dist-home-'));
  configDir = join(home, '.shieldcortex');
  mkdirSync(configDir, { recursive: true, mode: 0o700 });
  mkdirSync(join(home, '.claude'), { recursive: true });
  mkdirSync(join(home, '.hermes', 'ekho-state'), { recursive: true });
  claudeReport('c-live', 60_000);
  claudeReport('c-idle1', 30 * HOUR);
  claudeReport('c-idle2', 40 * HOUR);
  for (const pid of DEAD_PIDS) deadHermesReport(configDir, pid);

  // Home 2: Hermes present (config + plugin artefacts), its only report ended; Claude Code enforcing.
  home2 = mkdtempSync(join(tmpdir(), 'sc-970-dist-home2-'));
  const configDir2 = join(home2, '.shieldcortex');
  mkdirSync(configDir2, { recursive: true, mode: 0o700 });
  mkdirSync(join(home2, '.claude'), { recursive: true });
  mkdirSync(join(home2, '.hermes', 'plugins', 'shieldcortex'), { recursive: true });
  writeFileSync(join(home2, '.hermes', 'config.yaml'), 'model: x\n');
  writeFileSync(join(home2, '.hermes', 'plugins', 'shieldcortex', 'plugin.yaml'), 'name: shieldcortex\n');
  writeFileSync(join(home2, '.hermes', 'plugins', 'shieldcortex', '__init__.py'), 'def register(ctx):\n    pass\n');
  claudeReport('c-live', 60_000, configDir2, 'enforce');
  deadHermesReport(configDir2, DEAD_PIDS[0]);
});

afterAll(() => {
  if (home) rmSync(home, { recursive: true, force: true });
  if (home2) rmSync(home2, { recursive: true, force: true });
});

function doctor(args: string[], h = home): string {
  const run = spawnSync(process.execPath, [DIST_ENTRY, 'doctor', ...args], {
    env: {
      PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
      HOME: h,
      USERPROFILE: h,
      SHIELDCORTEX_CONFIG_DIR: join(h, '.shieldcortex'),
      TMPDIR: tmpdir(),
      COLUMNS: '200',
      NO_COLOR: '1',
    },
    encoding: 'utf8',
    timeout: 120_000,
  });
  return run.stdout ?? '';
}

interface JsonRow { label: string; status: string; message: string; stale?: boolean; staleReason?: string | null }

(linux ? describe : describe.skip)('#970 built doctor: stale posture records', () => {
  it('--json keeps every record, marks each stale: true|false with a reason, and removes no field', () => {
    const stdout = doctor(['--json']);
    const body = JSON.parse(stdout.slice(stdout.indexOf('{'), stdout.lastIndexOf('}') + 1)) as { results: JsonRow[] };
    const records = body.results.filter((r) => /^Runtime posture: (Claude Code|Hermes) \(/.test(r.label));
    expect(records).toHaveLength(5);
    for (const r of records) {
      expect(typeof r.stale).toBe('boolean');
      expect(Object.keys(r)).toEqual(expect.arrayContaining(['label', 'status', 'message', 'stale', 'staleReason']));
    }
    const mark = Object.fromEntries(records.map((r) => [r.label.replace('Runtime posture: ', ''), [r.stale, r.staleReason]]));
    expect(mark).toEqual({
      'Claude Code (tool-gate, c-live)': [false, null],
      'Claude Code (tool-gate, c-idle1)': [true, 'superseded'],
      'Claude Code (tool-gate, c-idle2)': [true, 'superseded'],
      [`Hermes (tool-gate, p${DEAD_PIDS[0]}-s1)`]: [true, 'process-ended'],
      [`Hermes (tool-gate, p${DEAD_PIDS[1]}-s1)`]: [true, 'process-ended'],
    });
    const host = body.results.find((r) => r.label === 'Runtime posture (host)')!;
    expect(host.message).toMatch(/^weakest of 1 record\(s\) judged \(5 found, 4 stale not judged\): advisory \(Claude Code, tool-gate\)/);
    expect(host).not.toHaveProperty('stale');
    // Rows that are not posture records are unchanged in shape.
    for (const r of body.results.filter((x) => !x.label.startsWith('Runtime posture: '))) expect(r).not.toHaveProperty('stale');
  }, 150_000);

  it('default report: the live row, then ONE collapsed line per runtime; no stale instance is named', () => {
    const out = doctor([]);
    expect(out).toContain('Runtime posture: Claude Code (tool-gate, c-live)');
    expect(out.match(/1 current, 2 stale hidden \(--verbose to list\)/g)).toHaveLength(1);
    expect(out.match(/0 current, 2 stale hidden \(--verbose to list\)/g)).toHaveLength(1);
    expect(out).toMatch(/Runtime posture: Claude Code\n[^\n]*1 current, 2 stale hidden/);
    expect(out).toMatch(/Runtime posture: Hermes\n[^\n]*0 current, 2 stale hidden/);
    // The current row prints first, the collapsed line after it.
    expect(out.indexOf('(tool-gate, c-live)')).toBeLessThan(out.indexOf('1 current, 2 stale hidden'));
    for (const hidden of ['c-idle1', 'c-idle2', ...DEAD_PIDS.map((p) => `p${p}-s1`)]) expect(out).not.toContain(hidden);
    expect(out).toContain('weakest of 1 record(s) judged (5 found, 4 stale not judged): advisory (Claude Code, tool-gate)');
  }, 150_000);

  it('--verbose lists every record as before, with no collapsed line', () => {
    const out = doctor(['--verbose']);
    for (const shown of ['c-live', 'c-idle1', 'c-idle2', ...DEAD_PIDS.map((p) => `p${p}-s1`)]) expect(out).toContain(shown);
    expect(out).not.toMatch(/stale hidden/);
  }, 150_000);

  it('r2: present Hermes with only an ended report beside enforcing Claude Code is not a green host', () => {
    const stdout = doctor(['--json'], home2);
    const body = JSON.parse(stdout.slice(stdout.indexOf('{'), stdout.lastIndexOf('}') + 1)) as { results: JsonRow[] };
    const hermes = body.results.filter((r) => r.label.startsWith('Runtime posture: Hermes ('));
    expect(hermes.map((r) => [r.label, r.stale, r.staleReason, r.status])).toEqual([
      [`Runtime posture: Hermes (tool-gate, p${DEAD_PIDS[0]}-s1)`, true, 'process-ended', 'info'],
      ['Runtime posture: Hermes (tool-gate)', false, null, 'info'],
    ]);
    expect(hermes[1].message).toMatch(/present, no current report/);
    const host = body.results.find((r) => r.label === 'Runtime posture (host)')!;
    expect(host.status).toBe('info');
    expect(host.message).toMatch(/^weakest of 2 record\(s\) judged \(3 found, 1 stale not judged\): unobserved \(Hermes, tool-gate\)/);

    const out = doctor([], home2);
    expect(out).toMatch(/Runtime posture: Hermes\n[^\n]*0 current, 1 stale hidden/);
    expect(out).toContain('Runtime posture: Hermes (tool-gate)');
    expect(out).not.toContain(`p${DEAD_PIDS[0]}-s1`);
  }, 150_000);
});
