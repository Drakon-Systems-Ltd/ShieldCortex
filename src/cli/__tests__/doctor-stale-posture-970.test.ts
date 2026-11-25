import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkRuntimePosture, RUNTIME_POSTURE_LABEL, type CheckResult } from '../doctor.js';
import { collapseStalePostureRows, formatDoctorReport, sanitiseDoctorRowsForDisplay } from '../doctor-report.js';
import { buildPolicyEvidence } from '../policy-evidence.js';
import { collectPostureRecords, pidNsSidecarPath, readSelfReportFile, type CollectDeps } from '../../posture/collect.js';
import { STALE_NOT_SEEN_MS, deriveToolGateRecord, parseSelfReport, rollupRecords, summarisePosture, type SelfReportRead } from '../../posture/posture-record.js';
import { scanHostTable } from '../../setup/host-table.js';
import { NOW, PID_NS, hermesHome, hermesPluginArtefacts, iso, processTable, reportBody, writePidNsSidecar, writeReport } from '../../posture/__tests__/self-report-fixture.js';
import { legacyListInstances, legacyReadProfile } from '../../posture/__tests__/legacy-self-report-gate.js';

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

  it('absence alone never hides a fresh record the host cannot check: it is judged as unverified (r3)', () => {
    writeReport(configDir, reportBody({ instance: instance(6001, '6001') }));
    const cannotTell: CollectDeps = { processStart: () => undefined };
    const hermes = collectPostureRecords(opts({ deps: cannotTell })).filter((r) => r.runtime === 'hermes');
    // The report itself and no marker: an absent runtime never gets one.
    expect(hermes).toHaveLength(1);
    expect([hermes[0].liveness.value, hermes[0].stale, hermes[0].stale_reason]).toEqual(['unverified', false, null]);
    expect(rollupRecords(hermes)).toHaveLength(1);
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
    inst.pid_ns = pidNs;
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

  it('the self-report schema stays closed v1 (r4): pid_ns is never a report key, and there is no v2', () => {
    const parse = (inst: Record<string, unknown>, version = 1) => {
      const text = JSON.stringify({ ...reportBody({ instance: inst }), version });
      return parseSelfReport(text, Buffer.byteLength(text));
    };
    const { pid_ns: _drop, ...v1 } = instance(6001, '6001');
    const ok = parse(v1);
    expect(ok.kind === 'valid' && [ok.report.version, ok.report.instance.pid_ns]).toEqual([1, null]);
    expect(parse(instance(6001, '6001'))).toEqual({ kind: 'invalid', reason: 'invalid instance', rejection: 'content' });
    expect(parse(v1, 2)).toEqual({ kind: 'invalid', reason: 'version 2 is not supported', rejection: 'content' });
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

  /** Make every fixture report an earlier writer's (no `.pidns` sidecar), heard from `heardAgoMs` ago. */
  function asEarlierWriters(heardAgoMs?: number): void {
    for (const dir of ['openclaw', 'hermes']) {
      const d = path.join(configDir, 'posture', dir, 'default');
      for (const f of fs.readdirSync(d)) {
        if (f.endsWith('.pidns')) {
          fs.rmSync(path.join(d, f));
          continue;
        }
        const body = JSON.parse(fs.readFileSync(path.join(d, f), 'utf8'));
        if (heardAgoMs !== undefined && body.instance.pid !== LIVE_PID) body.heartbeat_at = iso(NOW - heardAgoMs);
        fs.writeFileSync(path.join(d, f), JSON.stringify(body));
      }
    }
  }

  it('the same shape from earlier writers (no pid_ns), heard within 7 days: the dead reports are judged as unverified, not hidden (r3)', () => {
    fieldFixture();
    asEarlierWriters();
    const records = collectPostureRecords(opts());
    const hermes = records.filter((r) => r.runtime === 'hermes');
    expect(hermes.map((r) => [r.liveness.value, r.stale])).toEqual([['unverified', false], ['unverified', false]]);
    expect(summarisePosture(records)).toMatchObject({ level: 'unknown', green: false });
  });

  it('the same shape from earlier writers, not heard for 7 days: judged on the live OpenClaw only, no Hermes marker', () => {
    fieldFixture();
    asEarlierWriters(STALE_NOT_SEEN_MS + HOUR);
    const records = collectPostureRecords(opts());
    expect(records.filter((r) => r.runtime === 'hermes').map((r) => [r.key.instance !== null, r.stale_reason]))
      .toEqual([[true, 'not-seen'], [true, 'not-seen']]);
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

// ── Round 3: heuristic absence never hides a fresh report ───────────────────

describe('#970 r3: HOSTS absence alone never hides a record', () => {
  const OTHER_NS = '4026532999';
  /** A 30-second-old intentionally-off report from another PID namespace (a container, say). */
  const offFromContainer = (runtime: 'hermes' | 'openclaw', heardAgoMs = 30_000) => writeReport(configDir, reportBody({
    runtime,
    configured_posture: 'intentionally-off',
    heartbeat_at: iso(NOW - heardAgoMs),
    instance: { ...instance(6001, '6001'), pid_ns: OTHER_NS },
  }));
  const noOpenClaw = { openclawBinaryPresent: () => false };
  const absentOpts = () => ({ ...opts(), hostDeps: noOpenClaw });

  beforeEach(() => {
    // Neither runtime has a home here; only Claude Code is present, and enforcing.
    fs.rmSync(path.join(home, '.openclaw'), { recursive: true });
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    writeReport(configDir, reportBody({
      runtime: 'claude_code',
      plugin: { id: 'shieldcortex-pre-tool-hook', version: '5.20.4', hash: null },
      instance: { key: 'c-live', pid: null, process_start: null, started_at: iso(NOW - HOUR), liveness: 'per-call' },
    }));
  });

  it('the fixture: HOSTS says Hermes and OpenClaw are absent', () => {
    const present = Object.fromEntries(scanHostTable(home, noOpenClaw).rows.map((r) => [r.id, r.present]));
    expect([present.openclaw, present.hermes, present.claude]).toEqual([false, false, true]);
  });

  for (const [runtime, name] of [['hermes', 'Hermes'], ['openclaw', 'OpenClaw']] as const) {
    it(`a fresh foreign-namespace intentionally-off ${name} report: judged, and the host is not green`, async () => {
      offFromContainer(runtime);
      const records = collectPostureRecords(absentOpts());
      const recs = records.filter((r) => r.runtime === runtime);
      // The report itself, judged; no marker for an absent runtime.
      expect(recs.map((r) => [r.key.instance, r.liveness.value, r.stale, r.stale_reason])).toEqual([['p6001-s6001', 'unverified', false, null]]);
      expect(summarisePosture(records)).toMatchObject({ green: false, level: 'unknown', rollup_count: 2, stale_count: 0 });

      const host = hostRow(await checkRuntimePosture(absentOpts()));
      expect(host.status).not.toBe('pass');
      expect(host.message).toMatch(new RegExp(`^weakest of 2 record\\(s\\) judged \\(2 found\\): unknown \\(${name}, tool-gate\\)`));
      expect(JSON.parse(JSON.stringify(buildPolicyEvidence(absentOpts()))).summary).toMatchObject({ green: false });
    });

    it(`a ${name} report aged past STALE_NOT_SEEN_MS on an absent runtime: hidden, no marker, the host on Claude alone`, async () => {
      offFromContainer(runtime, STALE_NOT_SEEN_MS + HOUR);
      const records = collectPostureRecords(absentOpts());
      expect(records.filter((r) => r.runtime === runtime).map((r) => [r.key.instance, r.stale_reason])).toEqual([['p6001-s6001', 'not-seen']]);
      expect(summarisePosture(records)).toMatchObject({ green: true, level: 'loaded-enforce', rollup_count: 1, stale_count: 1 });
      expect(hostRow(await checkRuntimePosture(absentOpts())).status).toBe('pass');
    });
  }

  it('absence keeps one effect: an absent runtime whose reports are all stale gets no marker, a present one does', () => {
    offFromContainer('hermes', STALE_NOT_SEEN_MS + HOUR);
    expect(collectPostureRecords(absentOpts()).filter((r) => r.runtime === 'hermes').map((r) => r.key.instance)).toEqual(['p6001-s6001']);
    hermesHome(home);
    expect(collectPostureRecords(absentOpts()).filter((r) => r.runtime === 'hermes').map((r) => [r.key.instance, r.stale]))
      .toEqual([['p6001-s6001', true], [null, false]]);
  });
});

// ── Round 4: the namespace rides in a sidecar old readers never see ────────

describe('#970 r4: the PID namespace sidecar is evidence only when it is sound', () => {
  const hermes = (d: CollectDeps = deps) => collectPostureRecords(opts({ deps: d })).filter((r) => r.runtime === 'hermes')[0];
  /** A same-namespace Hermes report whose pid is gone, with its sidecar. */
  const sameNsDead = () => writeReport(configDir, reportBody({ instance: instance(6001, '6001') }));
  const ended = () => [hermes().liveness.value, hermes().stale_reason];
  const unknownNs = () => {
    const rec = hermes();
    expect(rec.liveness.process_identity?.pid_ns).toBeNull();
    return [rec.liveness.value, rec.stale];
  };

  beforeEach(() => {
    fs.rmSync(path.join(home, '.openclaw'), { recursive: true });
    hermesHome(home);
    hermesPluginArtefacts(home);
  });

  it('a sound sidecar: the pid lookup proves the exit', () => {
    sameNsDead();
    expect(ended()).toEqual(['ended', 'process-ended']);
  });

  it('missing, `null`, malformed or oversized: namespace unknown, the record falls back to the age rule', () => {
    const file = sameNsDead();
    for (const text of [null, 'null', '', 'abc', `${PID_NS}\n`, ` ${PID_NS}`, '-1', '1'.repeat(21), '9'.repeat(40)]) {
      if (text === null) fs.rmSync(pidNsSidecarPath(file));
      else writePidNsSidecar(file, text);
      expect(unknownNs()).toEqual(['unverified', false]);
    }
    writeReport(configDir, reportBody({ instance: instance(6001, '6001'), heartbeat_at: iso(NOW - STALE_NOT_SEEN_MS - HOUR) }));
    fs.rmSync(pidNsSidecarPath(file));
    expect(hermes().stale_reason).toBe('not-seen');
  });

  it('a sidecar older than its report vouches for nothing (it predates the report\'s last write)', () => {
    const file = sameNsDead();
    // Pin both files to whole seconds: copying a stat mtime through Date drops
    // sub-millisecond precision and could make the "equal" sidecar older.
    const t = new Date(Math.floor(Date.now() / 1000) * 1000);
    fs.utimesSync(file, t, t);
    fs.utimesSync(pidNsSidecarPath(file), new Date(t.getTime() - 1000), new Date(t.getTime() - 1000));
    expect(unknownNs()).toEqual(['unverified', false]);
    // Same mtime is not older: trusted.
    fs.utimesSync(pidNsSidecarPath(file), t, t);
    expect(ended()).toEqual(['ended', 'process-ended']);
  });

  it('a symlinked, group-readable or foreign-owned sidecar is untrusted', () => {
    const file = sameNsDead();
    const sidecar = pidNsSidecarPath(file);
    fs.chmodSync(sidecar, 0o640);
    expect(unknownNs()).toEqual(['unverified', false]);
    fs.rmSync(sidecar);
    const target = path.join(root, 'ns');
    fs.writeFileSync(target, PID_NS, { mode: 0o600 });
    fs.symlinkSync(target, sidecar);
    expect(unknownNs()).toEqual(['unverified', false]);
    fs.rmSync(sidecar);
    writePidNsSidecar(file, PID_NS);
    const uid = process.getuid?.();
    if (uid !== undefined) expect(hermes({ ...deps, uid: () => uid + 1 }).liveness.value).not.toBe('ended');
  });

  it('a rejected report never reads its sidecar', () => {
    const file = writeReport(configDir, { ...reportBody({ instance: instance(6001, '6001') }), extra: 1 });
    expect(fs.existsSync(pidNsSidecarPath(file))).toBe(true);
    const rec = hermes();
    expect(rec.notes.join(' ')).toMatch(/self-report rejected/);
    expect([rec.liveness.value, rec.stale]).toEqual(['not-applicable', false]);
  });
});

describe('#970 r4: a pre-#970 CLI reads the new writers\' reports exactly as before', () => {
  const both = processTable({ 6001: '6001', 6002: '6002' });
  const profileDir = () => path.join(configDir, 'posture', 'hermes', 'default');
  /** An earlier writer: v1, no sidecar. */
  const oldEnforce = () => writeReport(configDir, reportBody({ instance: { ...instance(6001, '6001'), pid_ns: undefined }, configured_posture: 'enforce' }));
  /** A #970 writer: v1 report, namespace in the sidecar. */
  const newOff = () => writeReport(configDir, reportBody({ instance: instance(6002, '6002'), configured_posture: 'intentionally-off' }));

  beforeEach(() => {
    fs.rmSync(path.join(home, '.openclaw'), { recursive: true });
    hermesHome(home);
    hermesPluginArtefacts(home);
  });

  it('the old enumeration lists only `*.json`: the sidecar is never opened, counted or rejected', () => {
    const file = newOff();
    expect(fs.readdirSync(profileDir()).sort()).toEqual(['p6002-s6002.json', 'p6002-s6002.pidns']);
    expect(fs.readFileSync(pidNsSidecarPath(file), 'utf8')).toBe(PID_NS);
    expect(legacyListInstances(profileDir())).toEqual(['p6002-s6002']);
    expect(legacyReadProfile(profileDir())).toEqual({ 'p6002-s6002': null });
  });

  it('the old reader sees a #970 writer\'s report as it sees an earlier writer\'s: read, with the same bytes', () => {
    const file = newOff();
    const withSidecar = { files: legacyReadProfile(profileDir()), bytes: fs.readFileSync(file, 'utf8') };
    fs.rmSync(pidNsSidecarPath(file));
    expect({ files: legacyReadProfile(profileDir()), bytes: fs.readFileSync(file, 'utf8') }).toEqual(withSidecar);
  });

  it('mixed group — an earlier enforcing writer beside a #970 intentionally-off one: the old reader reads both; this CLI says off, not green', () => {
    oldEnforce();
    newOff();
    // Both files reach a pre-#970 CLI's rollup: no rejected sibling to drop out of it.
    expect(legacyReadProfile(profileDir())).toEqual({ 'p6001-s6001': null, 'p6002-s6002': null });
    const records = collectPostureRecords(opts({ deps: both })).filter((r) => r.runtime === 'hermes');
    expect(records.map((r) => [r.key.instance, r.liveness.process_identity?.pid_ns, r.liveness.value, r.stale]).sort())
      .toEqual([['p6001-s6001', null, 'alive', false], ['p6002-s6002', PID_NS, 'alive', false]]);
    expect(summarisePosture(records)).toMatchObject({ level: 'off', green: false, rollup_count: 2 });
  });
});

// ── Round 5: a trust-rejected report is never aged out ─────────────────────

describe('#970 r5: a trust-rejected self-report is judged whatever its age (as before #970)', () => {
  /** Eight days: past STALE_NOT_SEEN_MS. In an untrusted place that mtime is whoever planted the file. */
  const OLD = NOW - 8 * DAY;
  const noOpenClaw = { openclawBinaryPresent: () => false };
  const absentOpts = (over: { deps?: CollectDeps } = {}) => ({ ...opts(over), hostDeps: noOpenClaw });
  const realUid = () => (typeof process.getuid === 'function' ? process.getuid() : undefined);
  const profileDir = (profile = 'default') => path.join(configDir, 'posture', 'hermes', profile);
  const age = (file: string) => fs.utimesSync(file, new Date(OLD), new Date(OLD));
  /** An 8-day-old Hermes report (file and heartbeat) on the default profile. */
  const oldHermes = (): string => {
    const file = writeReport(configDir, reportBody({ heartbeat_at: iso(OLD), instance: instance(6001, '6001', 9 * DAY) }));
    age(file);
    return file;
  };

  beforeEach(() => {
    // Hermes ABSENT from HOSTS (only ~/.hermes/ekho-state), no OpenClaw; Claude Code present and enforcing, fresh.
    fs.rmSync(path.join(home, '.openclaw'), { recursive: true });
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    writeReport(configDir, reportBody({
      runtime: 'claude_code',
      plugin: { id: 'shieldcortex-pre-tool-hook', version: '5.20.4', hash: null },
      instance: { key: 'c-live', pid: null, process_start: null, started_at: iso(NOW - HOUR), liveness: 'per-call' },
    }));
  });

  it('the fixture: Hermes absent, and Claude alone makes the host green', () => {
    const present = Object.fromEntries(scanHostTable(home, noOpenClaw).rows.map((r) => [r.id, r.present]));
    expect([present.hermes, present.openclaw, present.claude]).toEqual([false, false, true]);
    expect(summarisePosture(collectPostureRecords(absentOpts()))).toMatchObject({ green: true, level: 'loaded-enforce' });
  });

  const trustRejections: Array<[string, RegExp, () => void]> = [
    ['in a group-writable self-report directory', /insecure self-report directory: directory writable by group or others/, () => {
      oldHermes();
      fs.chmodSync(profileDir(), 0o770);
    }],
    ['that is a symlink', /not a regular file/, () => {
      const file = oldHermes();
      const planted = path.join(root, 'planted.json');
      fs.renameSync(file, planted);
      fs.symlinkSync(planted, file);
      fs.lutimesSync(file, new Date(OLD), new Date(OLD));
    }],
    ['with mode 0640', /must be owner-only/, () => {
      fs.chmodSync(oldHermes(), 0o640);
    }],
    ['of 9000 bytes (over the cap)', /size 9000 bytes exceeds/, () => {
      const file = oldHermes();
      fs.writeFileSync(file, ' '.repeat(9000));
      age(file);
    }],
    ['that cannot be read', /self-report rejected: unreadable/, () => {
      fs.chmodSync(oldHermes(), 0o000);
    }],
  ];

  for (const [what, reason, plant] of trustRejections) {
    it(`an 8-day-old Hermes report ${what}: not stale, judged unknown, and the host is not green`, async () => {
      plant();
      const records = collectPostureRecords(absentOpts());
      const hermes = records.filter((r) => r.runtime === 'hermes');
      expect(hermes.map((r) => [r.key.instance, r.stale, r.stale_reason, r.runtime_loaded.value])).toEqual([['p6001-s6001', false, null, 'unknown']]);
      expect(hermes[0].notes.join(' ')).toMatch(reason);
      expect(summarisePosture(records)).toMatchObject({ green: false, level: 'unknown', rollup_count: 2, stale_count: 0 });

      const rows = await checkRuntimePosture(absentOpts());
      expect(hostRow(rows).status).not.toBe('pass');
      expect(hostRow(rows).message).toMatch(/^weakest of 2 record\(s\) judged \(2 found\): unknown \(Hermes, tool-gate\)/);
      // Shown as its own row, never folded into a "stale hidden" line.
      const shown = collapseStalePostureRows(rows);
      expect(shown.filter((r) => /stale hidden/.test(r.message))).toEqual([]);
      expect(recordRows(shown, 'Hermes')).toHaveLength(1);
      expect(JSON.parse(JSON.stringify(buildPolicyEvidence(absentOpts()))).summary).toMatchObject({ green: false, stale_count: 0 });
    });
  }

  it('an 8-day-old report under directories owned by another user: not stale, and the host is not green', () => {
    oldHermes();
    const uid = realUid();
    if (uid === undefined) return; // no uids on this platform: nothing to own
    const records = collectPostureRecords(absentOpts({ deps: { ...deps, uid: () => uid + 1 } }));
    const hermes = records.filter((r) => r.runtime === 'hermes');
    expect(hermes.map((r) => [r.key.instance, r.stale, r.stale_reason])).toEqual([['p6001-s6001', false, null]]);
    expect(hermes[0].notes.join(' ')).toMatch(/insecure self-report directory: directory owned by another user/);
    expect(summarisePosture(records)).toMatchObject({ green: false, stale_count: 0 });
  });

  it('a file owned by another user is a trust rejection, and an 8-day-old one is never aged out', () => {
    // Chowning needs root, so the reader is told it runs as another uid; the
    // record is then derived with the old file mtime the collector would pass.
    const file = oldHermes();
    const uid = realUid();
    if (uid === undefined) return;
    const read = readSelfReportFile(file, { runtime: 'hermes', profile: 'default', instance: 'p6001-s6001' }, uid + 1);
    expect(read).toMatchObject({ kind: 'invalid', reason: 'owned by another user', rejection: 'trust' });
    const rec = deriveToolGateRecord({ runtime: 'hermes', profile: 'default', installed: 'no', read, nowMs: NOW, lastSeenMs: OLD });
    expect([rec.stale, rec.stale_reason, rec.runtime_loaded.value]).toEqual([false, null, 'unknown']);
  });

  it('defence in depth: only a content rejection is aged, whatever lastSeenMs a caller passes; unclassified is trust', () => {
    const derive = (read: SelfReportRead) =>
      deriveToolGateRecord({ runtime: 'hermes', profile: 'default', installed: 'no', read, nowMs: NOW, lastSeenMs: OLD });
    const stale = (extra: Record<string, unknown>) => derive({ kind: 'invalid', reason: 'x', instance: 'p6001-s6001', ...extra } as SelfReportRead).stale;
    expect(stale({})).toBe(false);
    expect(stale({ rejection: 'trust' })).toBe(false);
    expect(stale({ rejection: 'bogus' })).toBe(false);
    expect(stale({ rejection: 'content' })).toBe(true);
  });

  it('cross-profile: a live enforcing hermes/work beside an insecure 8-day-old hermes/default — default stays, judged and non-green', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({ profile: 'work', instance: instance(LIVE_PID, LIVE_START) }));
    oldHermes();
    fs.chmodSync(profileDir('default'), 0o770);
    const records = collectPostureRecords(absentOpts());
    const hermes = records.filter((r) => r.runtime === 'hermes');
    expect(hermes.map((r) => [r.profile, r.key.instance, r.stale, r.liveness.value]).sort()).toEqual([
      ['default', 'p6001-s6001', false, 'not-applicable'],
      ['work', `p${LIVE_PID}-s${LIVE_START}`, false, 'alive'],
    ]);
    const dflt = hermes.find((r) => r.profile === 'default')!;
    expect(dflt.notes.join(' ')).toMatch(/insecure self-report directory/);
    expect(rollupRecords(records).map((r) => r.source)).toContain(dflt.source);
    expect(summarisePosture(records)).toMatchObject({ green: false, level: 'unknown', weakest: dflt.source, stale_count: 0 });
    expect(hostRow(await checkRuntimePosture(absentOpts())).status).not.toBe('pass');
  });

  it('positive control: an 8-day-old CONTENT-invalid owner-only report in a secure directory still goes stale', async () => {
    const file = writeReport(configDir, { ...reportBody({ heartbeat_at: iso(OLD), instance: instance(6001, '6001') }), extra: 1 });
    age(file);
    const records = collectPostureRecords(absentOpts());
    const hermes = records.filter((r) => r.runtime === 'hermes');
    expect(hermes.map((r) => [r.stale, r.stale_reason])).toEqual([[true, 'not-seen']]);
    expect(hermes[0].notes.join(' ')).toMatch(/self-report rejected: unknown keys/);
    expect(summarisePosture(records)).toMatchObject({ green: true, level: 'loaded-enforce', stale_count: 1 });
    // The same file seen recently is a judged unknown.
    fs.utimesSync(file, new Date(NOW - HOUR), new Date(NOW - HOUR));
    expect(summarisePosture(collectPostureRecords(absentOpts()))).toMatchObject({ green: false, level: 'unknown', stale_count: 0 });
  });

  // #1153 slice 1. Root can readdir a mode-030 directory, so a green=false
  // assertion there would not prove the unlistable branch. Windows has no
  // owner/mode check. Skip both; do not treat a skip as a pass of that branch.
  const proveUnlistable = process.platform !== 'win32'
    && typeof process.getuid === 'function'
    && process.getuid() !== 0;
  const itUnlistable = proveUnlistable ? it : it.skip;
  const itPosix = process.platform === 'win32' ? it.skip : it;
  const postureRoot = () => path.join(configDir, 'posture');
  const siblingGreen = () => {
    expect(summarisePosture(collectPostureRecords(absentOpts()))).toMatchObject({ green: true, level: 'loaded-enforce' });
  };
  const expectZeroInstanceRejection = (records: ReturnType<typeof collectPostureRecords>) => {
    const hermes = records.filter((r) => r.runtime === 'hermes');
    expect(hermes).toHaveLength(1);
    expect(hermes[0].key.instance).toBeNull();
    expect(hermes[0].source).toBe('sc://posture/hermes/default/tool-gate/none');
    expect([hermes[0].stale, hermes[0].stale_reason, hermes[0].runtime_loaded.value, hermes[0].liveness.value])
      .toEqual([false, null, 'unknown', 'not-applicable']);
    expect(hermes[0].notes.join(' ')).toMatch(/insecure self-report directory: directory writable by group or others/);
    expect(hermes[0].notes.join(' ')).not.toMatch(/no self-report/);
    expect(records.some((r) => r.runtime === 'claude_code' && !r.stale)).toBe(true);
    expect(rollupRecords(records).map((r) => r.source)).toContain(hermes[0].source);
    expect(summarisePosture(records)).toMatchObject({ green: false, level: 'unknown', rollup_count: 2, stale_count: 0 });
  };

  itUnlistable('a listed runtime directory that this uid cannot list is one non-stale trust rejection, not an omission', () => {
    siblingGreen();
    const hermesDir = path.join(postureRoot(), 'hermes');
    fs.mkdirSync(hermesDir);
    try {
      fs.chmodSync(hermesDir, 0o030);
      expect(fs.lstatSync(hermesDir).mode & 0o777).toBe(0o030);
      expect(fs.readdirSync(postureRoot())).toContain('hermes');
      expect(() => fs.readdirSync(hermesDir)).toThrow();
      expectZeroInstanceRejection(collectPostureRecords(absentOpts()));
    } finally {
      fs.chmodSync(hermesDir, 0o700);
    }
  });

  itUnlistable('a listable runtime whose profile directory this uid cannot list is one non-stale trust rejection, not absent', () => {
    siblingGreen();
    const rtDir = path.join(postureRoot(), 'hermes');
    const pDir = path.join(rtDir, 'default');
    fs.mkdirSync(pDir, { recursive: true });
    fs.chmodSync(rtDir, 0o700);
    try {
      fs.chmodSync(pDir, 0o030);
      expect(fs.lstatSync(pDir).mode & 0o777).toBe(0o030);
      expect(fs.readdirSync(rtDir)).toEqual(['default']);
      expect(() => fs.readdirSync(pDir)).toThrow();
      expectZeroInstanceRejection(collectPostureRecords(absentOpts()));
    } finally {
      fs.chmodSync(pDir, 0o700);
    }
  });

  it('a secure, successfully listed, empty runtime directory stays omitted, and the host stays green', () => {
    siblingGreen();
    const hermesDir = path.join(postureRoot(), 'hermes');
    fs.mkdirSync(hermesDir, { recursive: true });
    fs.chmodSync(hermesDir, 0o700);
    expect(fs.readdirSync(hermesDir)).toEqual([]);
    const records = collectPostureRecords(absentOpts());
    expect(records.filter((r) => r.runtime === 'hermes')).toEqual([]);
    expect(summarisePosture(records)).toMatchObject({ green: true, level: 'loaded-enforce' });
  });

  itPosix('a listable group-writable profile directory that holds a report stays one trust rejection, not rejection plus absent', () => {
    oldHermes();
    fs.chmodSync(profileDir(), 0o770);
    try {
      expect(fs.readdirSync(profileDir()).some((n) => n.endsWith('.json'))).toBe(true);
      const records = collectPostureRecords(absentOpts());
      const hermes = records.filter((r) => r.runtime === 'hermes');
      expect(hermes).toHaveLength(1);
      expect(hermes[0].key.instance).toBe('p6001-s6001');
      expect(hermes[0].stale).toBe(false);
      expect(hermes[0].runtime_loaded.value).toBe('unknown');
      expect(hermes[0].notes.join(' ')).toMatch(/insecure self-report directory: directory writable by group or others/);
      expect(summarisePosture(records)).toMatchObject({ green: false, level: 'unknown', stale_count: 0 });
    } finally {
      fs.chmodSync(profileDir(), 0o700);
    }
  });
});

describe('#1135 a mode-0640 rejection beside a current same-group sibling is still judged', () => {
  const OLD = NOW - 8 * DAY;
  const REJECTED = 'sc://posture/hermes/default/tool-gate/p6001-s6001';
  const noOpenClaw = { openclawBinaryPresent: () => false };
  const caseOpts = () => ({
    ...opts({ deps: processTable({ 5000: '500' }) }),
    hostDeps: noOpenClaw,
  });

  function plant(): string {
    fs.rmSync(path.join(home, '.openclaw'), { recursive: true, force: true });
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    writeReport(configDir, reportBody({
      runtime: 'claude_code',
      plugin: { id: 'shieldcortex-pre-tool-hook', version: '5.20.4', hash: null },
      instance: { key: 'c-live', pid: null, process_start: null, started_at: iso(NOW - HOUR), liveness: 'per-call' },
    }));
    writeReport(configDir, reportBody({ instance: instance(5000, '500') }));
    const file = writeReport(configDir, reportBody({
      heartbeat_at: iso(OLD),
      instance: instance(6001, '6001', 8 * DAY),
    }));
    // Writers reset modes. The bad mode is applied after those writes, and the directories stay owner-only.
    fs.chmodSync(file, 0o640);
    fs.utimesSync(file, new Date(OLD), new Date(OLD));
    return file;
  }

  it('keeps the rejected hermes/default report in the rollup, the summary and doctor output', async () => {
    const file = plant();
    expect(fs.statSync(file).mode & 0o777).toBe(0o640);
    expect(fs.statSync(path.dirname(file)).mode & 0o777).toBe(0o700);
    expect(fs.statSync(path.join(configDir, 'posture')).mode & 0o777).toBe(0o700);

    const records = collectPostureRecords(caseOpts());
    expect(records.map((r) => `${r.runtime}/${r.profile}/${r.key.instance}`).sort()).toEqual([
      'claude_code/default/c-live',
      'hermes/default/p5000-s500',
      'hermes/default/p6001-s6001',
    ]);
    const rejected = records.find((r) => r.key.instance === 'p6001-s6001')!;
    expect(rejected.source).toBe(REJECTED);
    expect(rejected.runtime_loaded.value).toBe('unknown');
    expect(rejected.membership).toBe('unobserved');
    expect(rejected.liveness.value).toBe('not-applicable');
    expect(rejected.stale).toBe(false);
    expect(rejected.stale_reason).toBeNull();
    expect(rejected.notes.join(' ')).toMatch(/must be owner-only/);
    expect(rejected.notes.join(' ')).not.toMatch(/insecure self-report directory/);
    expect(records.find((r) => r.key.instance === 'p5000-s500')).toMatchObject({ membership: 'current', liveness: { value: 'alive' } });
    expect(records.find((r) => r.key.instance === 'c-live')).toMatchObject({ membership: 'current', liveness: { value: 'per-call' } });

    expect(rollupRecords(records).map((r) => r.source).sort()).toEqual([
      'sc://posture/claude_code/default/tool-gate/c-live',
      'sc://posture/hermes/default/tool-gate/p5000-s500',
      REJECTED,
    ]);
    expect(summarisePosture(records)).toEqual({
      level: 'unknown',
      green: false,
      weakest: REJECTED,
      record_count: 3,
      rollup_count: 3,
      stale_count: 0,
      completeness: 'not-claimed',
    });

    const evidence = JSON.parse(JSON.stringify(buildPolicyEvidence(caseOpts()))) as {
      summary: { green: boolean; weakest: string | null; level: string; record_count: number; rollup_count: number; stale_count: number };
      records: Array<{ source: string; runtime_loaded: { value: string }; membership: string; liveness: { value: string }; stale: boolean; stale_reason: string | null }>;
    };
    const evidenced = evidence.records.find((r) => r.source === REJECTED);
    expect(evidenced).toMatchObject({
      runtime_loaded: { value: 'unknown' },
      membership: 'unobserved',
      liveness: { value: 'not-applicable' },
      stale: false,
      stale_reason: null,
    });
    expect(evidence.summary).toMatchObject({
      green: false,
      level: 'unknown',
      weakest: REJECTED,
      record_count: 3,
      rollup_count: 3,
      stale_count: 0,
    });

    const rows = await checkRuntimePosture(caseOpts());
    const host = hostRow(rows);
    expect(host.status).toBe('info');
    expect(host.message).toMatch(/^weakest of 3 record\(s\) judged \(3 found\): unknown \(Hermes, tool-gate\)/);
    expect(host.status).not.toBe('pass');
    for (const r of rows) expect(['pass', 'info']).toContain(r.status);

    const rejectedRow = rows.find((r) => r.label.includes('p6001-s6001'))!;
    expect(rejectedRow.status).toBe('info');
    expect(rejectedRow.message).toMatch(/self-report rejected/);
    expect(rejectedRow.message).toMatch(/must be owner-only/);
    expect(rejectedRow.message).not.toMatch(/stale \(/);
    expect(rejectedRow.posture).toEqual({
      group: `${RUNTIME_POSTURE_LABEL}: Hermes`,
      stale: false,
      staleReason: null,
      instance: true,
      verified: false,
    });
    const shown = collapseStalePostureRows(rows);
    expect(shown.find((r) => r.label.includes('p6001-s6001'))).toBe(rejectedRow);
    expect(shown.filter((r) => /stale hidden/.test(r.message))).toEqual([]);

    for (const verbose of [false, true]) {
      const text = formatDoctorReport(sanitiseDoctorRowsForDisplay(rows), { width: 240, verbose }).join('\n');
      expect(text).toContain('p6001-s6001');
      expect(text).toContain('self-report rejected');
      expect(text).toContain('must be owner-only');
      expect(text).toContain('weakest of 3 record(s) judged (3 found): unknown');
      expect(text).not.toMatch(/stale hidden/);
      expect(text).not.toMatch(/not judged for the host posture/);
    }
  });
});
