import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkRuntimePosture, RUNTIME_POSTURE_LABEL, type CheckResult } from '../doctor.js';
import { collapseStalePostureRows, formatDoctorReport, sanitiseDoctorRowsForDisplay } from '../doctor-report.js';
import { buildPolicyEvidence } from '../policy-evidence.js';
import { collectPostureRecords, type CollectDeps } from '../../posture/collect.js';
import { STALE_NOT_SEEN_MS, parseSelfReport, rollupRecords, summarisePosture } from '../../posture/posture-record.js';
import { scanHostTable } from '../../setup/host-table.js';
import { NOW, PID_NS, hermesHome, hermesPluginArtefacts, iso, processTable, reportBody, writeReport } from '../../posture/__tests__/self-report-fixture.js';

/**
 * #970 — stale runtime-posture records flooded doctor and set the host
 * posture. Field shape (clawdbot1, 5.20.4): one live OpenClaw gateway, a pile
 * of OpenClaw reports from dead pids, and two Hermes reports on a host whose
 * HOSTS table says `Hermes absent`.
 *
 * Every case builds its own fake home under the OS temp dir, injects the
 * process table and the OpenClaw binary probe, and never reads the real home.
 */

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const LIVE_PID = 5000;
const LIVE_START = '500';
const DEAD_OPENCLAW = [5001, 5002, 5003, 5004];
const DEAD_HERMES = [6001, 6002];
const hostDeps = { openclawBinaryPresent: () => true };
/** Only the live gateway is in the process table: every other pid has exited. */
const deps = processTable({ [LIVE_PID]: LIVE_START });

let root: string;
let home: string;
let configDir: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-stale-posture-970-'));
  home = path.join(root, 'home');
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
  // OpenClaw present: its config and (injected) binary.
  fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
  fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), '{}\n');
  // Hermes ABSENT, the field shape: ~/.hermes holds only a leftover state dir.
  fs.mkdirSync(path.join(home, '.hermes', 'ekho-state'), { recursive: true });
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

function instance(pid: number, start: string, startedAgoMs = HOUR): Record<string, unknown> {
  return { key: `p${pid}-s${start}`, pid, process_start: start, pid_ns: PID_NS, started_at: iso(NOW - startedAgoMs), liveness: 'process' };
}

function openclawReport(pid: number, start: string, over: Record<string, unknown> = {}): void {
  writeReport(configDir, reportBody({
    runtime: 'openclaw',
    plugin: { id: 'shieldcortex-realtime', version: '5.20.4', hash: null },
    instance: instance(pid, start),
    ...over,
  }));
}

/** 1 live OpenClaw + 4 dead OpenClaw + 2 dead Hermes, Hermes absent from the host. */
function fieldFixture(live: Record<string, unknown> = { configured_posture: 'advisory' }): void {
  openclawReport(LIVE_PID, LIVE_START, live);
  DEAD_OPENCLAW.forEach((pid, i) => openclawReport(pid, String(pid), {
    // Two died recently, two have also gone quiet for days.
    heartbeat_at: iso(NOW - (i < 2 ? 60_000 : 5 * DAY)),
    instance: instance(pid, String(pid), 6 * DAY),
  }));
  for (const pid of DEAD_HERMES) writeReport(configDir, reportBody({ instance: instance(pid, String(pid), 3 * DAY) }));
}

const opts = (over: { deps?: CollectDeps; nowMs?: number } = {}) =>
  ({ home, configDir, nowMs: over.nowMs ?? NOW, hostDeps, deps: over.deps ?? deps });
const hostRow = (rows: CheckResult[]) => rows.find((r) => r.label === `${RUNTIME_POSTURE_LABEL} (host)`)!;
const recordRows = <T extends { label: string }>(rows: readonly T[], runtime: string): T[] =>
  rows.filter((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: ${runtime} (`));

describe('#970 the fixture is the field shape', () => {
  it('the HOSTS detector says OpenClaw present and Hermes absent', () => {
    const present = Object.fromEntries(scanHostTable(home, hostDeps).rows.map((r) => [r.id, r.present]));
    expect(present.openclaw).toBe(true);
    expect(present.hermes).toBe(false);
  });
});

describe('#970 the host posture is judged on live instances only', () => {
  it('1 live + 4 dead OpenClaw + 2 Hermes on a Hermes-absent host: only the live one is judged', async () => {
    fieldFixture();
    const records = collectPostureRecords(opts());
    expect(records).toHaveLength(7);
    const judged = rollupRecords(records);
    expect(judged.map((r) => r.key.instance)).toEqual([`p${LIVE_PID}-s${LIVE_START}`]);
    const summary = summarisePosture(records);
    expect(summary).toMatchObject({ level: 'advisory', rollup_count: 1, record_count: 7, stale_count: 6 });

    const host = hostRow(await checkRuntimePosture(opts()));
    expect(host.message).toMatch(/^weakest of 1 record\(s\) judged \(7 found, 6 stale not judged\): advisory \(OpenClaw, tool-gate\)/);
    expect(host.message).not.toMatch(/Hermes/);
    // The #613 caveats stay.
    expect(host.message).toMatch(/records found only/);
    expect(host.message).toMatch(/not attestation/);
  });

  it('a dead process is stale whether or not its last heartbeat is still fresh', () => {
    fieldFixture();
    const dead = collectPostureRecords(opts()).filter((r) => r.runtime === 'openclaw' && r.key.instance !== `p${LIVE_PID}-s${LIVE_START}`);
    expect(dead).toHaveLength(4);
    for (const r of dead) expect({ stale: r.stale, reason: r.stale_reason }).toEqual({ stale: true, reason: 'process-ended' });
  });

  it('a stale Hermes report on a Hermes-absent host never sets the host posture, even alone', async () => {
    for (const pid of DEAD_HERMES) writeReport(configDir, reportBody({ instance: instance(pid, String(pid)) }));
    fs.rmSync(path.join(home, '.openclaw'), { recursive: true });
    const records = collectPostureRecords(opts());
    expect(records.map((r) => r.runtime)).toEqual(['hermes', 'hermes']);
    expect(rollupRecords(records)).toEqual([]);
    const host = hostRow(await checkRuntimePosture(opts()));
    expect(host.message).toMatch(/^no live instances reporting \(2 found, 2 stale not judged\)/);
    expect(host.message).not.toMatch(/unknown|unobserved|weakest/);
    expect(host.status).toBe('info');
  });

  it('a record for an absent runtime is stale by that rule alone, when the host cannot check its process', () => {
    writeReport(configDir, reportBody({ instance: instance(6001, '6001') }));
    const cannotTell: CollectDeps = { processStart: () => undefined };
    const [rec] = collectPostureRecords(opts({ deps: cannotTell })).filter((r) => r.runtime === 'hermes');
    expect(rec.liveness.value).toBe('unverified');
    expect({ stale: rec.stale, reason: rec.stale_reason }).toEqual({ stale: true, reason: 'runtime-absent' });
    expect(rollupRecords([rec])).toEqual([]);
  });

  it('a process the host confirms is running is judged even when HOSTS says its runtime is absent', () => {
    writeReport(configDir, reportBody({ instance: instance(6001, '6001') }));
    const [rec] = collectPostureRecords(opts({ deps: processTable({ 6001: '6001' }) })).filter((r) => r.runtime === 'hermes');
    expect(rec.liveness.value).toBe('alive');
    expect(rec.stale).toBe(false);
    expect(rollupRecords([rec])).toHaveLength(1);
  });
});

describe('#970 a live record with posture unknown still counts', () => {
  it('a live instance reporting posture unknown is judged, listed, and sets the host posture', async () => {
    fieldFixture({ configured_posture: 'unknown' });
    const rows = await checkRuntimePosture(opts());
    const host = hostRow(rows);
    expect(host.message).toMatch(/^weakest of 1 record\(s\) judged \(7 found, 6 stale not judged\): unknown \(OpenClaw, tool-gate\)/);
    const shown = collapseStalePostureRows(rows);
    const live = recordRows(shown, 'OpenClaw');
    expect(live).toHaveLength(1);
    expect(live[0].message).toMatch(/\(current\).*posture unknown/);
    expect(live[0].posture).toMatchObject({ stale: false, staleReason: null });
  });

  it('a running process that stopped reporting long ago is a real unknown, not a stale leftover', async () => {
    openclawReport(LIVE_PID, LIVE_START, { heartbeat_at: iso(NOW - STALE_NOT_SEEN_MS - DAY) });
    const [rec] = collectPostureRecords(opts());
    expect(rec.liveness.value).toBe('alive');
    expect(rec.stale).toBe(false);
    const host = hostRow(await checkRuntimePosture(opts()));
    expect(host.message).toMatch(/^weakest of 1 record\(s\) judged \(1 found\): unknown \(OpenClaw, tool-gate\)/);
  });

  it('a present runtime that never reported keeps its placeholder row and is still judged', async () => {
    const rows = await checkRuntimePosture(opts());
    const host = hostRow(rows);
    // No plugin artefacts in this fixture, so the placeholder reads `unavailable`.
    expect(recordRows(rows, 'OpenClaw')[0].message).toMatch(/no reporting instance \(unobserved\)/);
    expect(host.message).toMatch(/^weakest of 1 record\(s\) judged \(1 found\): unavailable \(OpenClaw, tool-gate\)/);
    expect(collapseStalePostureRows(rows)).toEqual(rows);
  });
});

describe('#970 output: stale rows fold into one line per runtime', () => {
  it('default report: the live row as before, one collapsed line each for OpenClaw and Hermes', async () => {
    fieldFixture();
    const rows = await checkRuntimePosture(opts());
    expect(recordRows(rows, 'OpenClaw')).toHaveLength(5);
    expect(recordRows(rows, 'Hermes')).toHaveLength(2);

    const shown = collapseStalePostureRows(rows);
    expect(recordRows(shown, 'OpenClaw').map((r) => r.label)).toEqual([
      `${RUNTIME_POSTURE_LABEL}: OpenClaw (tool-gate, p${LIVE_PID}-s${LIVE_START})`,
    ]);
    expect(recordRows(shown, 'Hermes')).toEqual([]);
    const collapsed = shown.filter((r) => /stale hidden/.test(r.message));
    expect(collapsed.map((r) => `${r.label} — ${r.message}`)).toEqual([
      `${RUNTIME_POSTURE_LABEL}: OpenClaw — 1 current, 4 stale hidden (--verbose to list)`,
      `${RUNTIME_POSTURE_LABEL}: Hermes — 0 current, 2 stale hidden (--verbose to list)`,
    ]);
    for (const r of collapsed) expect(r.status).toBe('info');
    // 7 record rows became 1 live + 2 collapsed; nothing else moved.
    expect(shown).toHaveLength(rows.length - 4);
    expect(shown.find((r) => r.label === `${RUNTIME_POSTURE_LABEL} (host)`)).toEqual(hostRow(rows));

    // The default report does the folding itself, from the full row set.
    const text = formatDoctorReport(sanitiseDoctorRowsForDisplay(rows), { width: 200 }).join('\n');
    expect(text).toMatch(/Runtime posture: OpenClaw\n\s+1 current, 4 stale hidden \(--verbose to list\)/);
    expect(text).toMatch(/Runtime posture: Hermes\n\s+0 current, 2 stale hidden \(--verbose to list\)/);
    expect(text).not.toMatch(/\blive\b, \d+ stale/);
    for (const pid of [...DEAD_OPENCLAW, ...DEAD_HERMES]) expect(text).not.toContain(`p${pid}-s${pid}`);
    expect(text).toContain(`p${LIVE_PID}-s${LIVE_START}`);
  });

  it('one current, one stale', async () => {
    openclawReport(LIVE_PID, LIVE_START);
    openclawReport(5001, '5001');
    const shown = collapseStalePostureRows(await checkRuntimePosture(opts()));
    expect(shown.find((r) => r.label === `${RUNTIME_POSTURE_LABEL}: OpenClaw`)!.message)
      .toBe('1 current, 1 stale hidden (--verbose to list)');
  });

  it('--verbose lists every record: the uncollapsed rows name each stale instance and why', async () => {
    fieldFixture();
    const rows = await checkRuntimePosture(opts());
    const text = formatDoctorReport(sanitiseDoctorRowsForDisplay(rows), { width: 200, verbose: true }).join('\n');
    for (const pid of [...DEAD_OPENCLAW, ...DEAD_HERMES]) expect(text).toContain(`p${pid}-s${pid}`);
    expect(text).not.toMatch(/stale hidden/);
    const stale = rows.filter((r) => r.posture?.stale);
    expect(stale).toHaveLength(6);
    for (const r of stale) {
      expect(r.message).toMatch(/stale \(the reporting process has ended\); not judged for the host posture/);
      expect(r.status).toBe('info');
    }
  });

  it('no stale records: the rows are returned untouched', async () => {
    openclawReport(LIVE_PID, LIVE_START);
    const rows = await checkRuntimePosture(opts());
    expect(collapseStalePostureRows(rows)).toEqual(rows);
    expect(hostRow(rows).message).toMatch(/^weakest of 1 record\(s\) judged \(1 found\): loaded-enforce/);
    expect(hostRow(rows).status).toBe('pass');
  });

  it('posture rows stay pass or info: collapsing cannot change the exit code or the pass / warn / fail counts', async () => {
    fieldFixture();
    const rows = await checkRuntimePosture(opts());
    const count = (rs: ReadonlyArray<{ status: string }>, s: string) => rs.filter((r) => r.status === s).length;
    const shown = collapseStalePostureRows(rows);
    for (const s of ['pass', 'warn', 'fail']) expect(count(shown, s)).toBe(count(rows, s));
    for (const r of rows) expect(['pass', 'info']).toContain(r.status);
  });
});

describe('#970 every record is kept and marked stale: true|false with a reason (built-CLI --json: doctor-stale-posture-dist-970)', () => {
  it('every posture record row carries the stale mark doctor --json emits; other rows carry none', async () => {
    fieldFixture();
    const rows = await checkRuntimePosture(opts());
    const records = rows.filter((r) => /^Runtime posture: (OpenClaw|Hermes) \(/.test(r.label));
    expect(records).toHaveLength(7);
    for (const r of records) expect(typeof r.posture?.stale).toBe('boolean');
    expect(records.filter((r) => !r.posture!.stale).map((r) => [r.label, r.posture!.staleReason])).toEqual([
      [`${RUNTIME_POSTURE_LABEL}: OpenClaw (tool-gate, p${LIVE_PID}-s${LIVE_START})`, null],
    ]);
    expect(records.filter((r) => r.posture!.stale).map((r) => r.posture!.staleReason)).toEqual(Array(6).fill('process-ended'));
    expect(hostRow(rows).posture).toBeUndefined();
  });

  it('policy-evidence: every record carries stale / stale_reason and the summary judges the same set as doctor', () => {
    fieldFixture();
    const evidence = JSON.parse(JSON.stringify(buildPolicyEvidence(opts())));
    expect(evidence.records).toHaveLength(7);
    for (const r of evidence.records) expect(typeof r.stale).toBe('boolean');
    expect(evidence.records.filter((r: { stale: boolean }) => !r.stale)).toHaveLength(1);
    expect(evidence.summary).toMatchObject({ level: 'advisory', rollup_count: 1, record_count: 7, stale_count: 6 });
  });
});

describe('#970 stale rules where the host cannot check a process', () => {
  const cannotTell: CollectDeps = { processStart: () => undefined };

  it('two concurrent fresh reporters: a later start supersedes nothing, both are judged (r2)', () => {
    openclawReport(7001, '1', { instance: instance(7001, '1', 3 * HOUR) });
    openclawReport(7002, '2', { instance: instance(7002, '2', HOUR) });
    const recs = collectPostureRecords(opts({ deps: cannotTell }));
    for (const r of recs) expect({ instance: r.key.instance, stale: r.stale, liveness: r.liveness.value }).toEqual({ instance: r.key.instance, stale: false, liveness: 'unverified' });
    expect(summarisePosture(recs)).toMatchObject({ level: 'unknown', rollup_count: 2, stale_count: 0 });
  });

  it('not seen for STALE_NOT_SEEN_MS is stale; seen more recently is a judged unknown', () => {
    expect(STALE_NOT_SEEN_MS).toBe(7 * DAY);
    openclawReport(7001, '1', { heartbeat_at: iso(NOW - STALE_NOT_SEEN_MS - HOUR) });
    let [rec] = collectPostureRecords(opts({ deps: cannotTell }));
    expect({ stale: rec.stale, reason: rec.stale_reason }).toEqual({ stale: true, reason: 'not-seen' });

    openclawReport(7001, '1', { heartbeat_at: iso(NOW - 2 * DAY) });
    [rec] = collectPostureRecords(opts({ deps: cannotTell }));
    expect(rec.stale).toBe(false);
    expect(summarisePosture([rec])).toMatchObject({ level: 'unknown', rollup_count: 1 });
  });

  it('a rejected report is aged by its file: old is stale, recent is a judged unknown', () => {
    const file = writeReport(configDir, { ...reportBody({ runtime: 'openclaw', instance: instance(7001, '1') }), extra: 1 });
    fs.utimesSync(file, new Date(NOW - HOUR), new Date(NOW - HOUR));
    let [rec] = collectPostureRecords(opts());
    expect(rec.notes.join(' ')).toMatch(/self-report rejected/);
    expect(rec.stale).toBe(false);
    expect(rollupRecords([rec])).toHaveLength(1);

    fs.utimesSync(file, new Date(NOW - 8 * DAY), new Date(NOW - 8 * DAY));
    [rec] = collectPostureRecords(opts());
    expect({ stale: rec.stale, reason: rec.stale_reason }).toEqual({ stale: true, reason: 'not-seen' });
  });
});

describe('#970 per-call hooks (Claude Code): silence is not proof a session ended', () => {
  function claudeReport(key: string, heartbeatAgoMs: number, over: Record<string, unknown> = {}): void {
    writeReport(configDir, reportBody({
      runtime: 'claude_code',
      plugin: { id: 'shieldcortex-pre-tool-hook', version: '5.20.4', hash: null },
      instance: { key, pid: null, process_start: null, started_at: iso(NOW - 2 * DAY), liveness: 'per-call' },
      heartbeat_at: iso(NOW - heartbeatAgoMs),
      ...over,
    }));
  }

  beforeEach(() => {
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    fs.rmSync(path.join(home, '.openclaw'), { recursive: true });
  });

  it('silent past max_age beside a NEWER current session: superseded and hidden', async () => {
    claudeReport('c-live', 10 * 60_000, { configured_posture: 'advisory' });
    claudeReport('c-old1', 30 * HOUR);
    claudeReport('c-old2', 40 * HOUR);
    const recs = collectPostureRecords(opts()).filter((r) => r.runtime === 'claude_code');
    const by = Object.fromEntries(recs.map((r) => [r.key.instance, r]));
    expect(by['c-live'].stale).toBe(false);
    expect(by['c-old1'].stale_reason).toBe('superseded');
    expect(by['c-old2'].stale_reason).toBe('superseded');

    const rows = await checkRuntimePosture(opts());
    expect(hostRow(rows).message).toMatch(/^weakest of 1 record\(s\) judged \(3 found, 2 stale not judged\): advisory \(Claude Code, tool-gate\)/);
    const shown = collapseStalePostureRows(rows);
    expect(shown.find((r) => r.label === `${RUNTIME_POSTURE_LABEL}: Claude Code`)!.message)
      .toBe('1 current, 2 stale hidden (--verbose to list)');
  });

  it('silent past max_age with NO newer current session: not stale, judged as unknown (r2)', async () => {
    claudeReport('c-quiet', 25 * HOUR, { configured_posture: 'intentionally-off' });
    claudeReport('c-quieter', 30 * HOUR);
    const recs = collectPostureRecords(opts()).filter((r) => r.runtime === 'claude_code');
    for (const r of recs) expect({ k: r.key.instance, stale: r.stale }).toEqual({ k: r.key.instance, stale: false });
    expect(summarisePosture(recs)).toMatchObject({ level: 'unknown', green: false, rollup_count: 2, stale_count: 0 });
  });

  it('a silent session is not superseded by a newer one that is itself past max_age (r2)', () => {
    claudeReport('c-a', 26 * HOUR);
    claudeReport('c-b', 40 * HOUR);
    const recs = collectPostureRecords(opts()).filter((r) => r.runtime === 'claude_code');
    expect(recs.filter((r) => r.stale)).toEqual([]);
  });

  it('a current session with a future-dated start supersedes nothing (r2)', () => {
    claudeReport('c-future', 60_000, { instance: { key: 'c-future', pid: null, process_start: null, started_at: iso(NOW + DAY), liveness: 'per-call' } });
    claudeReport('c-old', 30 * HOUR);
    const by = Object.fromEntries(collectPostureRecords(opts()).filter((r) => r.runtime === 'claude_code').map((r) => [r.key.instance, r]));
    expect(by['c-future'].membership).toBe('current');
    expect(by['c-old'].stale).toBe(false);
  });

  it('not seen for STALE_NOT_SEEN_MS: stale; a present Claude whose sessions are ALL stale keeps one non-green row (r2)', async () => {
    claudeReport('c-gone', STALE_NOT_SEEN_MS + HOUR);
    const recs = collectPostureRecords(opts()).filter((r) => r.runtime === 'claude_code');
    expect(recs.map((r) => [r.key.instance, r.stale, r.stale_reason])).toEqual([['c-gone', true, 'not-seen'], [null, false, null]]);
    expect(recs[1].notes.join(' ')).toMatch(/present, no current report: all 1 report\(s\) found for this runtime are stale/);
    expect(summarisePosture(recs)).toMatchObject({ green: false, rollup_count: 1, stale_count: 1 });
  });

  it('a Hermes home that is really there keeps its dead reports stale by process, not by absence', () => {
    hermesHome(home);
    writeReport(configDir, reportBody({ instance: instance(6001, '6001') }));
    const hermes = collectPostureRecords(opts()).filter((r) => r.runtime === 'hermes');
    // The dead report, then the present runtime's one no-current-report record (r2).
    expect(hermes.map((r) => [r.key.instance, r.stale, r.stale_reason])).toEqual([['p6001-s6001', true, 'process-ended'], [null, false, null]]);
  });
});

// ── Round 2: silence or heuristics are not proof that something ended ────────

describe('#970 r2: an old report never judges a host greener than no report', () => {
  function claudeEnforcing(): void {
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    writeReport(configDir, reportBody({
      runtime: 'claude_code',
      plugin: { id: 'shieldcortex-pre-tool-hook', version: '5.20.4', hash: null },
      instance: { key: 'c-live', pid: null, process_start: null, started_at: iso(NOW - HOUR), liveness: 'per-call' },
    }));
  }

  beforeEach(() => {
    fs.rmSync(path.join(home, '.openclaw'), { recursive: true });
    hermesHome(home);
    hermesPluginArtefacts(home);
    claudeEnforcing();
  });

  it('present Hermes with only an ended report, plus enforcing Claude: not green, and the marker row is there', async () => {
    writeReport(configDir, reportBody({ instance: instance(6001, '6001') }));
    const records = collectPostureRecords(opts());
    const hermes = records.filter((r) => r.runtime === 'hermes');
    expect(hermes.map((r) => [r.key.instance, r.stale, r.stale_reason])).toEqual([['p6001-s6001', true, 'process-ended'], [null, false, null]]);
    const summary = summarisePosture(records);
    expect(summary).toMatchObject({ green: false, level: 'unobserved', weakest: 'sc://posture/hermes/default/tool-gate/none' });

    const rows = await checkRuntimePosture(opts());
    const host = hostRow(rows);
    expect(host.status).toBe('info');
    expect(host.message).toMatch(/^weakest of 2 record\(s\) judged \(3 found, 1 stale not judged\): unobserved \(Hermes, tool-gate\)/);
    const shown = collapseStalePostureRows(rows);
    const marker = recordRows(shown, 'Hermes');
    expect(marker).toHaveLength(1);
    expect(marker[0]).toMatchObject({ label: `${RUNTIME_POSTURE_LABEL}: Hermes (tool-gate)`, status: 'info' });
    expect(marker[0].message).toMatch(/no reporting instance \(unobserved\).*present, no current report: all 1 report\(s\) found for this runtime are stale/);
    expect(shown.find((r) => r.label === `${RUNTIME_POSTURE_LABEL}: Hermes`)!.message).toBe('0 current, 1 stale hidden (--verbose to list)');

    // Exactly what the host says with no Hermes report at all.
    fs.rmSync(path.join(configDir, 'posture', 'hermes'), { recursive: true });
    const none = summarisePosture(collectPostureRecords(opts()));
    expect({ level: none.level, green: none.green, weakest: none.weakest }).toEqual({ level: summary.level, green: summary.green, weakest: summary.weakest });
  });

  it('policy-evidence carries the same marker and the same non-green summary', () => {
    writeReport(configDir, reportBody({ instance: instance(6001, '6001') }));
    const evidence = JSON.parse(JSON.stringify(buildPolicyEvidence(opts())));
    expect(evidence.summary).toMatchObject({ green: false, level: 'unobserved' });
    expect(evidence.records.filter((r: { runtime: string; stale: boolean }) => r.runtime === 'hermes' && !r.stale)).toHaveLength(1);
  });

  it('every Hermes report not seen for STALE_NOT_SEEN_MS: still one non-green row, not a green host', () => {
    writeReport(configDir, reportBody({ heartbeat_at: iso(NOW - STALE_NOT_SEEN_MS - HOUR), instance: instance(6001, '6001') }));
    const summary = summarisePosture(collectPostureRecords(opts({ deps: { processStart: () => undefined } })));
    expect(summary).toMatchObject({ green: false, stale_count: 1, rollup_count: 2 });
  });

  it('an absent runtime still drops out entirely: no marker', () => {
    fs.rmSync(path.join(home, '.hermes'), { recursive: true });
    fs.mkdirSync(path.join(home, '.hermes', 'ekho-state'), { recursive: true });
    writeReport(configDir, reportBody({ instance: instance(6001, '6001') }));
    const hermes = collectPostureRecords(opts()).filter((r) => r.runtime === 'hermes');
    expect(hermes.map((r) => [r.stale, r.stale_reason])).toEqual([[true, 'process-ended']]);
    expect(summarisePosture(collectPostureRecords(opts()))).toMatchObject({ green: true, level: 'loaded-enforce' });
  });
});

describe('#970 r2: supersession needs evidence', () => {
  beforeEach(() => {
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    writeReport(configDir, reportBody({
      runtime: 'claude_code',
      plugin: { id: 'shieldcortex-pre-tool-hook', version: '5.20.4', hash: null },
      instance: { key: 'c-live', pid: null, process_start: null, started_at: iso(NOW - HOUR), liveness: 'per-call' },
    }));
  });

  /** 7001 cannot be checked here; 7002 is shown gone. */
  const mixed: CollectDeps = { processStart: (pid) => (pid === 7002 ? null : undefined), pidNamespace: () => PID_NS };

  it('an older fresh reporter plus a newer ENDED reporter: the fresh one stays judged, the host is not green', () => {
    openclawReport(7001, '1', { instance: instance(7001, '1', 3 * HOUR), heartbeat_at: iso(NOW - 60_000) });
    openclawReport(7002, '2', { instance: instance(7002, '2', HOUR), heartbeat_at: iso(NOW - 10 * 60_000) });
    const recs = collectPostureRecords(opts({ deps: mixed }));
    const by = Object.fromEntries(recs.map((r) => [r.key.instance, r]));
    expect([by['p7001-s1'].stale, by['p7001-s1'].liveness.value]).toEqual([false, 'unverified']);
    expect([by['p7002-s2'].stale, by['p7002-s2'].stale_reason]).toEqual([true, 'process-ended']);
    expect(rollupRecords(recs).map((r) => r.key.instance).sort()).toEqual(['c-live', 'p7001-s1']);
    expect(summarisePosture(recs)).toMatchObject({ green: false, level: 'unknown' });
  });

  it('an older fresh reporter plus a newer NOT-SEEN reporter: the fresh one stays judged', () => {
    const cannotTell: CollectDeps = { processStart: () => undefined, pidNamespace: () => PID_NS };
    openclawReport(7001, '1', { instance: instance(7001, '1', 10 * DAY), heartbeat_at: iso(NOW - 60_000) });
    openclawReport(7002, '2', { instance: instance(7002, '2', 9 * DAY), heartbeat_at: iso(NOW - 8 * DAY) });
    const recs = collectPostureRecords(opts({ deps: cannotTell }));
    const by = Object.fromEntries(recs.map((r) => [r.key.instance, r]));
    expect(by['p7001-s1'].stale).toBe(false);
    expect(by['p7002-s2'].stale_reason).toBe('not-seen');
    expect(summarisePosture(recs)).toMatchObject({ green: false, level: 'unknown' });
  });

  it('a newer reporter with a future-dated start supersedes nothing', () => {
    const cannotTell: CollectDeps = { processStart: () => undefined, pidNamespace: () => PID_NS };
    openclawReport(7001, '1', { instance: instance(7001, '1', 3 * HOUR) });
    openclawReport(7002, '2', { instance: instance(7002, '2', -DAY) });
    const recs = collectPostureRecords(opts({ deps: cannotTell }));
    expect(recs.filter((r) => r.stale)).toEqual([]);
  });

  it('two concurrent fresh reporters with process checks unsupported: both judged, the host is not green', () => {
    const cannotTell: CollectDeps = { processStart: () => undefined, pidNamespace: () => null };
    openclawReport(7001, '1', { instance: instance(7001, '1', 3 * HOUR) });
    openclawReport(7002, '2', { instance: instance(7002, '2', HOUR) });
    const recs = collectPostureRecords(opts({ deps: cannotTell }));
    expect(rollupRecords(recs).map((r) => r.key.instance).sort()).toEqual(['c-live', 'p7001-s1', 'p7002-s2']);
    expect(summarisePosture(recs)).toMatchObject({ green: false, level: 'unknown', stale_count: 0 });
  });
});

describe('#970 r2: a pid lookup proves an exit only inside the report\'s own PID namespace', () => {
  const OTHER_NS = '4026532999';
  function hermesReport(pidNs: string | null | undefined, over: Record<string, unknown> = {}): void {
    const inst: Record<string, unknown> = instance(6001, '6001');
    if (pidNs === undefined) delete inst.pid_ns;
    else inst.pid_ns = pidNs;
    writeReport(configDir, reportBody({ instance: inst, ...over }));
  }
  const hermes = (d: CollectDeps = deps) => collectPostureRecords(opts({ deps: d })).filter((r) => r.runtime === 'hermes')[0];

  beforeEach(() => {
    fs.rmSync(path.join(home, '.openclaw'), { recursive: true });
    hermesHome(home);
    hermesPluginArtefacts(home);
  });

  it('same namespace, pid gone: ended and stale', () => {
    hermesReport(PID_NS);
    expect([hermes().liveness.value, hermes().stale_reason]).toEqual(['ended', 'process-ended']);
  });

  it('a different namespace: not stale by pid, judged as unverified', () => {
    hermesReport(OTHER_NS);
    const rec = hermes();
    expect([rec.liveness.value, rec.stale, rec.membership]).toEqual(['unverified', false, 'unobserved']);
    expect(rec.liveness.note).toMatch(/another PID namespace, or did not record one/);
    expect(rec.liveness.process_identity?.pid_ns).toBe(OTHER_NS);
    // Even a pid that exists here with the same start is not this process.
    expect(hermes(processTable({ 6001: '6001' })).liveness.value).toBe('unverified');
  });

  it('no namespace recorded (an earlier writer): not stale by pid; an exact pid + start match is still alive', () => {
    hermesReport(undefined);
    const rec = hermes();
    expect([rec.liveness.value, rec.stale]).toEqual(['unverified', false]);
    expect(rec.liveness.process_identity?.pid_ns).toBeNull();
    expect(hermes(processTable({ 6001: '999' })).stale).toBe(false);
    expect(hermes(processTable({ 6001: '6001' })).liveness.value).toBe('alive');
  });

  it('pid_ns: null, or a collector that cannot read its own namespace: not stale by pid', () => {
    hermesReport(null);
    expect(hermes().stale).toBe(false);
    hermesReport(PID_NS);
    expect(hermes(processTable({}, null)).stale).toBe(false);
  });

  it('the age rule still applies outside the namespace', () => {
    hermesReport(OTHER_NS, { heartbeat_at: iso(NOW - STALE_NOT_SEEN_MS - HOUR) });
    expect(hermes().stale_reason).toBe('not-seen');
  });

  it('a mismatched namespace beside enforcing Claude does not turn the host green', () => {
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    writeReport(configDir, reportBody({
      runtime: 'claude_code',
      plugin: { id: 'shieldcortex-pre-tool-hook', version: '5.20.4', hash: null },
      instance: { key: 'c-live', pid: null, process_start: null, started_at: iso(NOW - HOUR), liveness: 'per-call' },
    }));
    hermesReport(OTHER_NS);
    expect(summarisePosture(collectPostureRecords(opts()))).toMatchObject({ green: false, level: 'unknown' });
  });

  it('the self-report schema: pid_ns is optional, digits or null, nothing else', () => {
    const parse = (inst: Record<string, unknown>) => {
      const text = JSON.stringify(reportBody({ instance: inst }));
      return parseSelfReport(text, Buffer.byteLength(text));
    };
    const base = instance(6001, '6001');
    const { pid_ns: _drop, ...legacy } = base;
    const ok = parse(legacy);
    expect(ok.kind === 'valid' && ok.report.instance.pid_ns).toBeNull();
    for (const v of [PID_NS, null]) expect(parse({ ...base, pid_ns: v }).kind).toBe('valid');
    for (const v of ['', 'pid:[1]', 4026531836, '-1', '1'.repeat(21)]) expect(parse({ ...base, pid_ns: v }).kind).toBe('invalid');
    expect(parse({ ...base, other: 1 }).kind).toBe('invalid');
  });
});

describe('#970 r2: the clawdbot1 field shape', () => {
  it('Hermes absent with dead reports, 1 live + many dead OpenClaw: Hermes not judged, one line per runtime, host on the live OpenClaw only', async () => {
    fieldFixture();
    const records = collectPostureRecords(opts());
    expect(records.filter((r) => r.runtime === 'hermes').every((r) => r.stale && r.key.instance !== null)).toBe(true);
    expect(rollupRecords(records).map((r) => r.key.instance)).toEqual([`p${LIVE_PID}-s${LIVE_START}`]);
    const shown = collapseStalePostureRows(await checkRuntimePosture(opts()));
    expect(shown.filter((r) => /stale hidden/.test(r.message)).map((r) => r.label)).toEqual([
      `${RUNTIME_POSTURE_LABEL}: OpenClaw`, `${RUNTIME_POSTURE_LABEL}: Hermes`,
    ]);
    expect(recordRows(shown, 'Hermes')).toEqual([]);
  });

  it('the same shape from earlier writers (no pid_ns): still judged on the live OpenClaw only', () => {
    fieldFixture();
    for (const dir of ['openclaw', 'hermes']) {
      const d = path.join(configDir, 'posture', dir, 'default');
      for (const f of fs.readdirSync(d)) {
        const body = JSON.parse(fs.readFileSync(path.join(d, f), 'utf8'));
        delete body.instance.pid_ns;
        fs.writeFileSync(path.join(d, f), JSON.stringify(body));
      }
    }
    const records = collectPostureRecords(opts());
    expect(records.filter((r) => r.runtime === 'hermes').every((r) => r.stale_reason === 'runtime-absent')).toBe(true);
    expect(rollupRecords(records).map((r) => r.key.instance)).toEqual([`p${LIVE_PID}-s${LIVE_START}`]);
    expect(summarisePosture(records)).toMatchObject({ level: 'advisory', rollup_count: 1 });
  });
});

describe('#970 r2: the collapsed line never calls an unverified report live', () => {
  it('a recent malformed report beside a dead one: "1 current (1 unverified)"', async () => {
    writeReport(configDir, { ...reportBody({ runtime: 'openclaw', instance: instance(7001, '1') }), extra: 1 });
    openclawReport(5001, '5001');
    const shown = collapseStalePostureRows(await checkRuntimePosture(opts()));
    expect(shown.find((r) => r.label === `${RUNTIME_POSTURE_LABEL}: OpenClaw`)!.message)
      .toBe('1 current (1 unverified), 1 stale hidden (--verbose to list)');
  });

  it('a fresh unverifiable report beside a dead one: "1 current (1 unverified)"', async () => {
    openclawReport(7001, '1');
    openclawReport(5001, '5001');
    const d: CollectDeps = { processStart: (pid) => (pid === 5001 ? null : undefined), pidNamespace: () => PID_NS };
    const shown = collapseStalePostureRows(await checkRuntimePosture(opts({ deps: d })));
    expect(shown.find((r) => r.label === `${RUNTIME_POSTURE_LABEL}: OpenClaw`)!.message)
      .toBe('1 current (1 unverified), 1 stale hidden (--verbose to list)');
  });
});
