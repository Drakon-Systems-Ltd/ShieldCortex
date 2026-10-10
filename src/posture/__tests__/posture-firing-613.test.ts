import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { collectPostureRecords, postureSelfReportDir, type CollectDeps } from '../collect.js';
import { postureLevel, summarisePosture, type PostureRecord } from '../posture-record.js';
import { buildPolicyEvidence, runPolicyEvidence, type PolicyEvidence } from '../../cli/policy-evidence.js';
import { checkRuntimePosture, RUNTIME_POSTURE_LABEL } from '../../cli/doctor.js';
import {
  H,
  INSTANCE,
  LIVE,
  NOW,
  PID,
  START,
  denial,
  hermesHome,
  hermesPluginArtefacts,
  iso,
  otherInstance,
  processTable,
  reportBody,
  snapshot,
  writeRaw,
  writeReport,
} from './self-report-fixture.js';

/**
 * #613 — the Tars r2.1 §1 firing cases. Each case is driven through the
 * shared model (collectPostureRecords + summarisePosture) AND both consumers:
 * the `policy-evidence` export and doctor's posture rows. Every case builds
 * its own fake home; no `openclaw` / `hermes` binary is consulted (the
 * OpenClaw binary probe is injected) and the process table is injected.
 */

const hostDeps = { openclawBinaryPresent: () => false };
const DAY = 24 * 60 * 60 * 1000;

let root: string;
let home: string;
let configDir: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-posture-firing-613-'));
  home = path.join(root, 'home');
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

interface Observed {
  records: PostureRecord[];
  evidence: PolicyEvidence;
  rows: Awaited<ReturnType<typeof checkRuntimePosture>>;
}

async function observe(deps: CollectDeps = LIVE, maxAgeMs?: number): Promise<Observed> {
  const opts = { home, configDir, nowMs: NOW, hostDeps, deps, maxAgeMs };
  const records = collectPostureRecords(opts);
  // Round-trip through JSON: consumers see the serialised export, not objects.
  const evidence = JSON.parse(JSON.stringify(buildPolicyEvidence(opts))) as PolicyEvidence;
  const rows = await checkRuntimePosture(opts);
  return { records, evidence, rows };
}

const hermes = (o: Observed) => o.records.filter((r) => r.runtime === 'hermes');
const evHermes = (o: Observed) => o.evidence.records.filter((r) => r.runtime === 'hermes');
const hermesRows = (o: Observed) => o.rows.filter((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Hermes`));
const hostRow = (o: Observed) => o.rows.find((r) => r.label === `${RUNTIME_POSTURE_LABEL} (host)`)!;

function noGreenWords(o: Observed): void {
  expect(JSON.stringify(o.evidence)).not.toMatch(/enforced|protected|proves/i);
  for (const r of o.rows) expect(r.message).not.toMatch(/enforced|protected|proves/i);
}

describe('two-instances-conflicting-posture', () => {
  it('two live processes on one profile are both retained, and the weaker one decides the summary', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody());
    writeReport(configDir, reportBody({ instance: otherInstance(5151, '200'), configured_posture: 'advisory' }));
    const o = await observe(processTable({ [PID]: START, 5151: '200' }));

    // Shared model: two records, distinct keys, both current.
    const recs = hermes(o);
    expect(recs).toHaveLength(2);
    expect(new Set(recs.map((r) => r.key.instance))).toEqual(new Set([INSTANCE, 'p5151-s200']));
    expect(recs.every((r) => r.membership === 'current')).toBe(true);
    expect(recs.map((r) => r.configured_posture.value).sort()).toEqual(['advisory', 'enforce']);
    const s = summarisePosture(o.records);
    expect(s.level).toBe('advisory');
    expect(s.green).toBe(false);
    expect(s.completeness).toBe('not-claimed');

    // policy-evidence: both records exported, no completeness claim.
    const ev = evHermes(o);
    expect(ev.map((r) => r.source).sort()).toEqual([
      `sc://posture/hermes/default/tool-gate/${INSTANCE}`,
      'sc://posture/hermes/default/tool-gate/p5151-s200',
    ]);
    expect(o.evidence.summary.level).toBe('advisory');
    expect(o.evidence.summary.green).toBe(false);
    expect(o.evidence.summary.completeness).toBe('not-claimed');
    expect(o.evidence.limitations.join(' ')).toMatch(/Nothing here claims there are no others/);

    // doctor: one row per instance; only the enforce one passes; host row does not.
    const rows = hermesRows(o);
    expect(rows).toHaveLength(2);
    expect(rows.find((r) => r.label.includes(INSTANCE))!.status).toBe('pass');
    const adv = rows.find((r) => r.label.includes('p5151-s200'))!;
    expect(adv.status).toBe('info');
    expect(adv.message).toMatch(/advisory/);
    expect(hostRow(o).status).toBe('info');
    expect(hostRow(o).message).toMatch(/records found only/);
    noGreenWords(o);
  });
});

describe('restart-pid-reuse', () => {
  it('a report whose pid now belongs to another process is ended, and its denial is not carried to the new process', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    // Old gateway: denied something, then the host restarted it. Its pid has
    // been reused by an unrelated process with a different start token.
    writeReport(configDir, reportBody({
      denials: { blocked_action: denial(), synthetic_probe: null, blocked_action_count: 3 },
    }));
    // New gateway: its own file, no denials yet.
    writeReport(configDir, reportBody({ instance: otherInstance(6000, '900'), heartbeat_at: iso(NOW - 5000) }));
    const o = await observe(processTable({ [PID]: '777', 6000: '900' }));

    const old = hermes(o).find((r) => r.key.instance === INSTANCE)!;
    const fresh = hermes(o).find((r) => r.key.instance === 'p6000-s900')!;
    expect(old.membership).toBe('ended');
    expect(old.liveness.value).toBe('ended');
    expect(old.runtime_loaded.value).toBe('unobserved');
    expect(old.observed_denial.value).toBe('obsolete');
    expect(postureLevel(old)).toBe('unobserved');
    expect(fresh.membership).toBe('current');
    expect(fresh.observed_denial.value).toBe('not-observed');
    expect(fresh.incidents.value).toBe(0);
    // The ended leftover is listed but does not decide the summary.
    expect(summarisePosture(o.records).green).toBe(true);

    const evOld = evHermes(o).find((r) => r.key.instance === INSTANCE)!;
    expect(evOld.membership).toBe('ended');
    expect(evOld.observed_denial.value).toBe('obsolete');
    const rowOld = hermesRows(o).find((r) => r.label.includes(INSTANCE))!;
    expect(rowOld.status).toBe('info');
    expect(rowOld.message).toMatch(/ended/);
    noGreenWords(o);
  });

  it('a pid that no longer exists is ended; alone it is never green', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody());
    const o = await observe(processTable({}));
    expect(hermes(o)[0].membership).toBe('ended');
    expect(summarisePosture(o.records).green).toBe(false);
    expect(o.evidence.summary.green).toBe(false);
    expect(hostRow(o).status).toBe('info');
  });

  it('a fresh file from a process this host cannot check is unobserved, not loaded', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody());
    const o = await observe({ processStart: () => undefined });
    const [rec] = hermes(o);
    expect(rec.liveness.value).toBe('unverified');
    expect(rec.runtime_loaded.value).toBe('unknown');
    expect(evHermes(o)[0].runtime_loaded.value).toBe('unknown');
    expect(hermesRows(o)[0].status).toBe('info');
  });
});

describe('fresh-heartbeat-plus-stale-deny', () => {
  it('a heartbeat written now does not refresh a denial from two days ago', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({
      instance: { key: INSTANCE, pid: PID, process_start: START, started_at: iso(NOW - 3 * DAY), liveness: 'process' },
      heartbeat_at: iso(NOW - 1000),
      denials: { blocked_action: denial({ at: iso(NOW - 2 * DAY) }), synthetic_probe: null, blocked_action_count: 1 },
    }));
    const o = await observe();
    const [rec] = hermes(o);
    expect(rec.runtime_loaded.value).toBe('yes');
    expect(rec.runtime_loaded.observed_at).toBe(iso(NOW - 1000));
    expect(rec.observed_denial.value).toBe('obsolete');
    expect(rec.observed_denial.observed_at).toBe(iso(NOW - 2 * DAY));
    expect(rec.observed_denial.note).toMatch(/older than max_age/);

    const [ev] = evHermes(o);
    expect(ev.observed_denial.value).toBe('obsolete');
    expect(ev.observed_denial.observed_at).toBe(iso(NOW - 2 * DAY));
    expect(ev.runtime_loaded.observed_at).toBe(iso(NOW - 1000));
    expect(hermesRows(o)[0].message).toMatch(/older than max_age/);
    expect(hermesRows(o)[0].message).not.toMatch(/blocked action at/);
  });
});

describe('policy-change-after-deny', () => {
  it('a denial observed under another effective policy is obsolete', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({
      policy_hash: H('c'),
      denials: { blocked_action: denial({ policy_hash: H('a') }), synthetic_probe: null, blocked_action_count: 1 },
    }));
    const o = await observe();
    expect(hermes(o)[0].observed_denial.value).toBe('obsolete');
    expect(hermes(o)[0].observed_denial.note).toMatch(/effective policy changed/);
    expect(hermes(o)[0].observed_denial.effective_policy_hash).toBe(H('a'));
    expect(hermes(o)[0].effective_policy_hash.value).toBe(H('c'));
    expect(evHermes(o)[0].observed_denial.value).toBe('obsolete');
    expect(hermesRows(o)[0].message).toMatch(/effective policy changed/);
  });

  it('a process now intentionally off is never shown as enforcing because it denied earlier', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({
      configured_posture: 'intentionally-off',
      denials: { blocked_action: denial({ configured_posture: 'enforce' }), synthetic_probe: null, blocked_action_count: 1 },
    }));
    const o = await observe();
    const [rec] = hermes(o);
    expect(rec.observed_denial.value).toBe('obsolete');
    expect(postureLevel(rec)).toBe('off');
    expect(o.evidence.summary.level).toBe('off');
    expect(o.evidence.summary.green).toBe(false);
    expect(hermesRows(o)[0].status).toBe('info');
    expect(hermesRows(o)[0].message).toMatch(/intentionally off/);
    noGreenWords(o);
  });
});

describe('plugin-change-after-deny', () => {
  it('a denial observed against other plugin bytes is obsolete', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({
      plugin: { id: 'shieldcortex', version: '0.2.0', hash: H('d') },
      denials: { blocked_action: denial({ plugin_hash: H('b') }), synthetic_probe: null, blocked_action_count: 1 },
    }));
    const o = await observe();
    const [rec] = hermes(o);
    expect(rec.observed_denial.value).toBe('obsolete');
    expect(rec.observed_denial.note).toMatch(/plugin changed/);
    expect(rec.observed_denial.plugin_identity!.hash).toBe(H('b'));
    expect(rec.runtime_loaded.plugin_identity!.hash).toBe(H('d'));
    expect(evHermes(o)[0].observed_denial.value).toBe('obsolete');
    expect(hermesRows(o)[0].message).toMatch(/plugin changed/);
  });

  it('scanner degradation after a denial makes it obsolete too', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({
      degraded_intervals: [{ from: iso(NOW - 5000), to: iso(NOW - 2000), reason: 'scanner-unreachable' }],
      denials: { blocked_action: denial({ at: iso(NOW - 10_000) }), synthetic_probe: null, blocked_action_count: 1 },
    }));
    const o = await observe();
    expect(hermes(o)[0].observed_denial.value).toBe('obsolete');
    expect(hermes(o)[0].observed_denial.note).toMatch(/scanner degraded/);
    expect(evHermes(o)[0].observed_denial.value).toBe('obsolete');
  });
});

describe('malformed-self-report', () => {
  const cases: Array<[string, (dir: string) => void]> = [
    ['truncated JSON', (d) => { writeRaw(d, 'hermes', 'default', INSTANCE, '{"schema":'); }],
    ['unknown version', (d) => { writeReport(d, reportBody({ version: 99 })); }],
    ['oversize', (d) => { writeRaw(d, 'hermes', 'default', INSTANCE, ' '.repeat(64 * 1024)); }],
    ['group-readable file', (d) => { fs.chmodSync(writeReport(d, reportBody()), 0o644); }],
    ['symlink', (d) => {
      const target = path.join(root, 'elsewhere.json');
      fs.writeFileSync(target, JSON.stringify(reportBody()), { mode: 0o600 });
      const file = writeReport(d, reportBody());
      fs.rmSync(file);
      fs.symlinkSync(target, file);
    }],
    ['group-writable directory', (d) => {
      writeReport(d, reportBody());
      fs.chmodSync(path.join(postureSelfReportDir(d), 'hermes'), 0o777);
    }],
  ];
  for (const [name, setup] of cases) {
    it(`${name}: rejected, runtime_loaded unknown, never green`, async () => {
      hermesHome(home);
      hermesPluginArtefacts(home);
      setup(configDir);
      const o = await observe();
      const [rec] = hermes(o);
      expect(rec.runtime_loaded.value).toBe('unknown');
      expect(rec.notes.join(' ')).toMatch(/rejected/);
      expect(postureLevel(rec)).toBe('unknown');
      expect(evHermes(o)[0].runtime_loaded.value).toBe('unknown');
      expect(o.evidence.summary.green).toBe(false);
      expect(hermesRows(o)[0].status).toBe('info');
      expect(hermesRows(o)[0].message).toMatch(/rejected/);
    });
  }
});

describe('future-dated-self-report', () => {
  it('a heartbeat from the future is unknown', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({ heartbeat_at: iso(NOW + 60 * 60_000) }));
    const o = await observe();
    expect(hermes(o)[0].runtime_loaded.value).toBe('unknown');
    expect(hermes(o)[0].runtime_loaded.note).toMatch(/future/);
    expect(evHermes(o)[0].runtime_loaded.value).toBe('unknown');
    expect(hermesRows(o)[0].status).toBe('info');
    expect(hermesRows(o)[0].message).toMatch(/future/);
  });

  it('a denial dated in the future is obsolete even beside a fresh heartbeat', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({
      denials: { blocked_action: denial({ at: iso(NOW + 60 * 60_000) }), synthetic_probe: null, blocked_action_count: 1 },
    }));
    const o = await observe();
    expect(hermes(o)[0].runtime_loaded.value).toBe('yes');
    expect(hermes(o)[0].observed_denial.value).toBe('obsolete');
    expect(hermes(o)[0].observed_denial.note).toMatch(/future/);
    expect(evHermes(o)[0].observed_denial.value).toBe('obsolete');
  });
});

describe('self-report-from-wrong-profile', () => {
  it('a report under profile "work" that names profile "default" is rejected and speaks for neither', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({ profile: 'default' }), INSTANCE, 'work');
    const o = await observe();
    const recs = hermes(o);
    expect(recs.map((r) => r.profile)).toEqual(['work']);
    expect(recs[0].runtime_loaded.value).toBe('unknown');
    expect(recs[0].notes.join(' ')).toMatch(/wrong profile/);
    expect(o.evidence.summary.green).toBe(false);
    expect(evHermes(o)[0].profile).toBe('work');
    expect(evHermes(o)[0].runtime_loaded.value).toBe('unknown');
    expect(hermesRows(o)[0].message).toMatch(/wrong profile/);
  });

  it('a report whose file name is another instance than its content is rejected', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody(), 'p1-s1');
    const o = await observe();
    expect(hermes(o)[0].runtime_loaded.value).toBe('unknown');
    expect(hermes(o)[0].notes.join(' ')).toMatch(/different instance/);
  });
});

describe('directory-only', () => {
  it('a Hermes home with no ShieldCortex plugin: installed no, never yes, never green', async () => {
    hermesHome(home);
    const o = await observe();
    const [rec] = hermes(o);
    expect(rec.installed.value).toBe('no');
    expect(rec.runtime_loaded.value).toBe('unobserved');
    expect(summarisePosture(o.records).green).toBe(false);
    expect(evHermes(o)[0].installed.value).toBe('no');
    expect(hermesRows(o)[0].message).toMatch(/installed no/);
    expect(hermesRows(o)[0].status).toBe('info');
  });

  it('an empty shieldcortex plugin directory: installed unknown, never yes', async () => {
    hermesHome(home);
    fs.mkdirSync(path.join(home, '.hermes', 'plugins', 'shieldcortex'), { recursive: true });
    const o = await observe();
    const [rec] = hermes(o);
    expect(rec.installed.value).toBe('unknown');
    expect(rec.installed.note).toMatch(/missing/);
    expect(evHermes(o)[0].installed.value).toBe('unknown');
    expect(hermesRows(o)[0].message).toMatch(/installed unknown/);
    expect(o.evidence.summary.green).toBe(false);
  });

  it('plugin.yaml alone is not the plugin: installed unknown', async () => {
    hermesHome(home);
    const dir = path.join(home, '.hermes', 'plugins', 'shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.yaml'), 'name: shieldcortex\n');
    const o = await observe();
    expect(hermes(o)[0].installed.value).toBe('unknown');
  });
});

describe('plugin-present-unloaded', () => {
  it('plugin artefacts present, no process reported: installed yes, loaded not yes, not green', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    const o = await observe();
    const [rec] = hermes(o);
    expect(rec.installed.value).toBe('yes');
    expect(rec.runtime_loaded.value).toBe('unobserved');
    expect(rec.membership).toBe('unobserved');
    expect(summarisePosture(o.records).green).toBe(false);
    expect(evHermes(o)[0].installed.value).toBe('yes');
    expect(evHermes(o)[0].runtime_loaded.value).toBe('unobserved');
    expect(o.evidence.summary.green).toBe(false);
    expect(hermesRows(o)[0].status).toBe('info');
    expect(hermesRows(o)[0].message).toMatch(/installed yes/);
    expect(hermesRows(o)[0].message).toMatch(/unobserved/);
    expect(hostRow(o).status).toBe('info');
  });

  it('a process that reports loaded:false is off, not loaded', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({ loaded: false }));
    const o = await observe();
    expect(hermes(o)[0].runtime_loaded.value).toBe('no');
    expect(postureLevel(hermes(o)[0])).toBe('off');
    expect(hermesRows(o)[0].status).toBe('info');
  });
});

describe('collector-leaves-config-and-consent-unchanged', () => {
  it('collect, policy-evidence and the doctor rows leave every file under home byte-, mode- and mtime-identical', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify({ hooks: {} }));
    fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
    fs.writeFileSync(path.join(home, '.codex', 'config.toml'), '');
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({ plugins: { entries: {} } }));
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: false, enforce: false } }));
    fs.writeFileSync(path.join(configDir, '.config-sig'), 'sig');
    fs.mkdirSync(path.join(configDir, 'consent'), { recursive: true });
    fs.writeFileSync(path.join(configDir, 'consent', 'live-canary.json'), '{"granted":false}');
    writeReport(configDir, reportBody({ denials: { blocked_action: denial(), synthetic_probe: null, blocked_action_count: 1 } }));
    // A stale report the collector must NOT prune (pruning is the writer's job).
    writeReport(configDir, reportBody({ instance: otherInstance(9, '9'), heartbeat_at: iso(NOW - 30 * DAY) }));
    const before = snapshot(home);

    const o = await observe();
    runPolicyEvidence([], { home, configDir, nowMs: NOW, hostDeps, deps: LIVE });
    runPolicyEvidence(['--compact'], { home, configDir, nowMs: NOW, hostDeps, deps: LIVE });

    expect(snapshot(home)).toEqual(before);
    // Guard stays off: collection never arms it or edits config to look better.
    expect(JSON.parse(fs.readFileSync(path.join(configDir, 'config.json'), 'utf8'))).toEqual({ actionGuard: { enabled: false, enforce: false } });
    expect(o.records.length).toBeGreaterThan(0);
  });

  it('does not create the posture directory when it is missing', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    await observe();
    expect(fs.existsSync(postureSelfReportDir(configDir))).toBe(false);
  });
});

describe('probe-vs-blocked-action-distinct', () => {
  it('a synthetic probe is tagged as such and never counted as an incident', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({
      denials: { blocked_action: null, synthetic_probe: denial({ tested_path: 'probe:terminal' }), blocked_action_count: 0 },
    }));
    const o = await observe();
    const [rec] = hermes(o);
    expect(rec.observed_denial.value).toBe('observed');
    expect(rec.observed_denial.kind).toBe('synthetic-probe');
    expect(rec.observed_denial.tested_path).toBe('probe:terminal');
    expect(rec.denials.blocked_action).toBeNull();
    expect(rec.denials.synthetic_probe!.kind).toBe('synthetic-probe');
    expect(rec.incidents.value).toBe(0);
    const [ev] = evHermes(o);
    expect(ev.observed_denial.kind).toBe('synthetic-probe');
    expect(ev.incidents.value).toBe(0);
    expect(hermesRows(o)[0].message).toMatch(/synthetic probe denied/);
    expect(hermesRows(o)[0].message).not.toMatch(/blocked action/);
  });

  it('both kinds side by side stay separate; only the blocked action is counted', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({
      denials: {
        blocked_action: denial({ at: iso(NOW - 20_000) }),
        synthetic_probe: denial({ at: iso(NOW - 5_000), tested_path: 'probe:terminal' }),
        blocked_action_count: 1,
      },
    }));
    const o = await observe();
    const [rec] = hermes(o);
    expect(rec.denials.blocked_action!.kind).toBe('blocked-action');
    expect(rec.denials.synthetic_probe!.kind).toBe('synthetic-probe');
    expect(rec.incidents.value).toBe(1);
    const [ev] = evHermes(o);
    expect(ev.denials.blocked_action!.tested_path).toBe('pre_tool_call:terminal');
    expect(ev.denials.synthetic_probe!.tested_path).toBe('probe:terminal');
    expect(ev.incidents.value).toBe(1);
  });

  it('an intentionally-off runtime is not probed into green', async () => {
    hermesHome(home);
    hermesPluginArtefacts(home);
    writeReport(configDir, reportBody({
      configured_posture: 'intentionally-off',
      denials: { blocked_action: null, synthetic_probe: denial({ configured_posture: 'intentionally-off' }), blocked_action_count: 0 },
    }));
    const o = await observe();
    expect(postureLevel(hermes(o)[0])).toBe('off');
    expect(o.evidence.summary.green).toBe(false);
    expect(hermesRows(o)[0].status).toBe('info');
  });
});
