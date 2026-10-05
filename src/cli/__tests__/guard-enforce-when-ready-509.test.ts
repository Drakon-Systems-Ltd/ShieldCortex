/**
 * #509 — the operator surfaces of enforce-when-ready: `guard test-approval`
 * (synthetic, TTY-only, cannot approve anything real), the doctor readiness
 * row (demotion FAILs), the setup posture question, and `config` flags/help.
 *
 * HOME and SHIELDCORTEX_CONFIG_DIR point at a throwaway tree for every test;
 * the live ~/.shieldcortex is never read or written.
 */
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { statSync, writeFileSync } from 'node:fs';

import { runGuardCommand, runTestApproval, buildReadinessSummary, type ReadinessSummary } from '../guard.js';
import {
  currentReadinessPin,
  initReadinessTransitions,
  readTransitionRecord,
  readinessPaths,
  transitionsPathFor,
} from '../../defence/iron-dome/guard-readiness.js';
import { checkActionGuardReadiness } from '../doctor.js';
import { offerActionGuardPosture, POSTURE_CHOICES } from '../../setup/action-guard-posture.js';
import { handleCloudConfig } from '../../cloud/cli.js';
import {
  clearCloudConfigCache,
  getActionGuardCoreConfig,
  setActionGuardCoreConfig,
  setActionGuardNotifyConfig,
} from '../../cloud/config.js';
import { consumeApproval, listApprovals, recordPending } from '../../defence/iron-dome/action-approvals.js';

const here = dirname(fileURLToPath(import.meta.url));
const DAY = 24 * 60 * 60 * 1000;
const REAL_CALL = { command: 'sudo modprobe softdog' };

let home: string;
let saved: Record<string, string | undefined>;

/** Posture enforce-when-ready, plus the given notify channel, via the signed setters. */
function setNotify(notify: { enabled?: boolean; openclaw?: boolean; webhookUrl?: string } | undefined): void {
  setActionGuardCoreConfig({ enabled: true, enforce: true, readinessGate: true });
  if (notify) setActionGuardNotifyConfig(notify);
  clearCloudConfigCache();
}

function auditRows(): Array<Record<string, unknown>> {
  const dirs = [join(home, '.shieldcortex', 'audit')];
  return dirs
    .filter((d) => existsSync(d))
    .flatMap((d) => readdirSync(d).map((f) => join(d, f)))
    .flatMap((f) => readFileSync(f, 'utf8').split('\n').filter(Boolean))
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-509-cli-'));
  mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  saved = {
    HOME: process.env.HOME,
    SHIELDCORTEX_CONFIG_DIR: process.env.SHIELDCORTEX_CONFIG_DIR,
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
  };
  process.env.HOME = home;
  process.env.SHIELDCORTEX_CONFIG_DIR = join(home, '.shieldcortex');
  process.env.OPENCLAW_HOME = join(home, 'openclaw-home');
  clearCloudConfigCache();
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  clearCloudConfigCache();
  rmSync(home, { recursive: true, force: true });
});

// ── test-approval ────────────────────────────────────────────────────────────

describe('#509 guard test-approval', () => {
  it('refuses without a TTY and records nothing', async () => {
    setNotify({ enabled: true, openclaw: true });
    const r = await runTestApproval({ isTTY: false, log: () => {}, error: () => {} });
    expect(r.code).toBe(2);
    expect(auditRows()).toHaveLength(0);
  });

  it('refuses with no configured channel', async () => {
    setNotify(undefined);
    const errors: string[] = [];
    const r = await runTestApproval({ isTTY: true, log: () => {}, error: (l) => errors.push(l) });
    expect(r.code).toBe(1);
    expect(errors.join('\n')).toMatch(/No human approval channel/);
  });

  it('an "allow-once" tap on the TEST card cannot approve a real pending request (exact-call binding untouched)', async () => {
    setNotify({ enabled: true, openclaw: true });
    // A real, pending hold on the box while the test runs.
    const pending = recordPending({ tool: 'Bash', input: REAL_CALL, summary: 'sudo modprobe softdog', signals: ['privilege-escalation'] }, { home });
    let sentParams = '';
    const r = await runTestApproval({
      isTTY: true,
      log: () => {},
      error: () => {},
      openclawBin: async () => '/nonexistent/openclaw',
      cardRoundTrip: async (paramsJson) => {
        sentParams = paramsJson;
        return { ok: true, decision: 'allow-once' };
      },
    });
    expect(r).toEqual({ code: 0, answer: 'approve' });
    // The card was clearly labelled and carried a hash that is NOT the real one.
    expect(sentParams).toMatch(/TEST/);
    expect(sentParams).not.toContain(pending.hash.slice(0, 12));
    // The store is untouched: still pending, and the real call cannot spend anything.
    const records = listApprovals({ home });
    expect(records).toHaveLength(1);
    expect(records[0].hash).toBe(pending.hash);
    expect(records[0].approvedAt).toBeUndefined();
    expect(consumeApproval('Bash', REAL_CALL, { home })).toBeNull();
    // Evidence only: a synthetic request + answer pair.
    const reach = auditRows().filter((x) => x.type === 'approval_reach');
    expect(reach.map((x) => [x.phase, x.answer ?? null, x.synthetic])).toEqual([
      ['request', null, true],
      ['answer', 'approve', true],
    ]);
  });

  it('guard.ts does not import the approval store at all', () => {
    const src = readFileSync(resolve(here, '..', 'guard.ts'), 'utf8');
    expect(src).not.toMatch(/action-approvals/);
    expect(src).not.toMatch(/approveRequest|denyRequest|grantRetry/);
  });

  it('an unanswered card is recorded as a timeout (not a reach)', async () => {
    setNotify({ enabled: true, openclaw: true });
    const r = await runTestApproval({
      isTTY: true, log: () => {}, error: () => {},
      openclawBin: async () => '/nonexistent/openclaw',
      cardRoundTrip: async () => ({ ok: true, decision: null }),
    });
    expect(r).toEqual({ code: 1, answer: 'timeout' });
  });

  it('webhook: the typed code closes the round-trip; a wrong code does not', async () => {
    setNotify({ enabled: true, webhookUrl: 'https://hooks.example.invalid/x' });
    let sent: { command?: string } = {};
    const channel = { name: 'webhook', send: async (n: unknown) => { sent = n as { command?: string }; return { delivered: true as const }; } };
    const ok = await runTestApproval({
      isTTY: true, log: () => {}, error: () => {},
      webhookChannel: async () => channel,
      askCode: async () => /code[^:]*: (\d{6})/.exec(String(sent.command))?.[1] ?? null,
    });
    expect(ok).toEqual({ code: 0, answer: 'approve' });
    const bad = await runTestApproval({
      isTTY: true, log: () => {}, error: () => {},
      webhookChannel: async () => channel,
      askCode: async () => '000000',
    });
    expect(bad.answer).toBe('unreached');
  });
});

// ── doctor ──────────────────────────────────────────────────────────────────

function fakeSummary(over: Partial<ReadinessSummary>): () => ReadinessSummary {
  const base = buildReadinessSummary({ home });
  return () => ({ ...base, posture: 'enforce-when-ready', ...over });
}

describe('#509 doctor readiness row', () => {
  it('says nothing for off / watch-only / enforce (checkActionGuard already WARNs those)', async () => {
    for (const posture of ['off', 'watch-only', 'enforce'] as const) {
      expect(await checkActionGuardReadiness({ summary: fakeSummary({ posture, lockOverrides: false }) })).toEqual([]);
    }
  });

  it('PASS while enforcing, WARN while not yet proven, FAIL once demoted', async () => {
    const [pass] = await checkActionGuardReadiness({ summary: fakeSummary({ mode: 'enforcing', demoted: false }) });
    expect(pass.status).toBe('pass');
    const [warn] = await checkActionGuardReadiness({ summary: fakeSummary({ mode: 'shadow', demoted: false }) });
    expect(warn.status).toBe('warn');
    expect(warn.message).toMatch(/not ready yet/);
    const [fail] = await checkActionGuardReadiness({ summary: fakeSummary({ mode: 'shadow', demoted: true }) });
    expect(fail.status).toBe('fail');
    expect(fail.message).toMatch(/DEMOTED/);
  });

  it('a real demotion in the audit makes the real doctor row FAIL (recomputed from evidence)', async () => {
    setNotify({ enabled: true, openclaw: true });
    const auditDir = join(home, '.shieldcortex', 'audit');
    mkdirSync(auditDir, { recursive: true });
    const now = Date.now();
    const rows = [
      { type: 'readiness_transition', origin: 'claude-code-hook', to: 'enforcing', ts: new Date(now - 2 * DAY).toISOString(), auditEventId: 't1' },
      { type: 'readiness_transition', origin: 'claude-code-hook', to: 'shadow', ts: new Date(now - DAY).toISOString(), auditEventId: 't2', reason: 'forged' },
    ];
    for (const r of rows) appendFileSync(join(auditDir, `realtime-${r.ts.slice(0, 10)}.jsonl`), `${JSON.stringify(r)}\n`);
    // `home` pinned: under Jest os.homedir() ignores a HOME override, and the
    // default summary also reads the hook's ~/.shieldcortex/audit.
    const [row] = await checkActionGuardReadiness({ summary: () => buildReadinessSummary({ home }) });
    expect(row.status).toBe('fail');
  });

  it('a fresh install under the posture (record started by config) is WARN, not FAIL', async () => {
    setNotify({ enabled: true, openclaw: true });
    initReadinessTransitions({ postureChanged: true, reason: 'test', home });
    const [row] = await checkActionGuardReadiness({ summary: () => buildReadinessSummary({ home }) });
    expect(row.status).toBe('warn');
    expect(row.message).toMatch(/only 0 of the 500/);
  });

  it('r3: the posture with NO transition record is unknown ⇒ doctor FAIL (potentially demoted), and doctor writes nothing', async () => {
    setNotify({ enabled: true, openclaw: true, webhookUrl: 'https://hooks.example/x' });
    const [row] = await checkActionGuardReadiness({ summary: () => buildReadinessSummary({ home }) });
    expect(row.status).toBe('fail');
    expect(row.message).toMatch(/transition record missing/);
    expect(row.message).toMatch(/potentially DEMOTED/);
    expect(existsSync(transitionsPathFor(readinessPaths({ home })))).toBe(false);
  });

  it('r3: a recent tamper report in the record is shown by doctor', async () => {
    setNotify({ enabled: true, openclaw: true, webhookUrl: 'https://hooks.example/x' });
    initReadinessTransitions({ postureChanged: true, reason: 'test', home });
    appendFileSync(transitionsPathFor(readinessPaths({ home })), `${JSON.stringify({ ts: new Date().toISOString(), event: 'tamper', reason: 'the readiness cache said shadow while the durable transition record says enforcing' })}\n`);
    const rows = await checkActionGuardReadiness({ summary: () => buildReadinessSummary({ home }) });
    const tamper = rows.find((r) => r.label === 'Action guard readiness tamper');
    expect(tamper?.status).toBe('warn');
    expect(tamper?.message).toMatch(/cache said shadow/);
  });
});

// ── setup ───────────────────────────────────────────────────────────────────

describe('#509 setup posture question', () => {
  it('offers exactly Off / Watch only / Enforce when ready, none marked recommended, each explained', () => {
    expect(POSTURE_CHOICES.map((c) => c.title)).toEqual(['Off', 'Watch only', 'Enforce when ready']);
    const ewr = POSTURE_CHOICES[2].body;
    expect(ewr).toMatch(/2%/);
    expect(ewr).toMatch(/98%/);
    expect(ewr).toMatch(/approval channel/);
    expect(ewr).toMatch(/Starts exactly like Watch only/);
    // Addendum 1 (B): the third condition is stated, and so is today's consequence.
    expect(ewr).toMatch(/independently reviewed evidence/);
    expect(ewr).toMatch(/keeps watching and does not enforce/);
  });

  it('Addendum 1 (F): no setup text says or implies safe/protected, and nothing is marked recommended', async () => {
    const lines: string[] = [];
    await offerActionGuardPosture({ tty: true, ask: async () => '3', log: (l) => lines.push(l), apply: () => {}, current: () => 'off', channelConfigured: () => false });
    await offerActionGuardPosture({ tty: false, ask: async () => '', log: (l) => lines.push(l) });
    const text = [...POSTURE_CHOICES.flatMap((c) => [c.title, c.body]), ...lines].join('\n');
    expect(text).not.toMatch(/\bsafe(ly|ty)?\b/i);
    expect(text).not.toMatch(/protect/i);
    expect(text).not.toMatch(/recommended/i);
    expect(text).not.toMatch(/false.positive|§5B/i);
  });

  it('non-interactive: changes nothing, prints how to choose', async () => {
    const lines: string[] = [];
    const apply = jest.fn();
    const out = await offerActionGuardPosture({ tty: false, ask: async () => '3', log: (l) => lines.push(l), apply });
    expect(out).toBeNull();
    expect(apply).not.toHaveBeenCalled();
    expect(lines.join('\n')).toMatch(/--action-guard-enforce-when-ready/);
    expect(getActionGuardCoreConfig().enabled).toBe(false);
  });

  it('interactive: Enter keeps the current posture; 1/2/3 apply the named choice', async () => {
    const apply = jest.fn();
    const q = { tty: true, log: () => {}, apply, current: () => 'off' as const, channelConfigured: () => false };
    expect(await offerActionGuardPosture({ ...q, ask: async () => '' })).toBeNull();
    expect(apply).not.toHaveBeenCalled();
    expect(await offerActionGuardPosture({ ...q, ask: async () => '1' })).toBe('off');
    expect(await offerActionGuardPosture({ ...q, ask: async () => '2' })).toBe('watch-only');
    expect(await offerActionGuardPosture({ ...q, ask: async () => '3' })).toBe('enforce-when-ready');
    expect(apply.mock.calls.map((c) => c[0])).toEqual(['off', 'watch-only', 'enforce-when-ready']);
  });

  it('interactive "3" writes the signed posture and says a channel is still needed', async () => {
    const lines: string[] = [];
    await offerActionGuardPosture({ tty: true, ask: async () => '3', log: (l) => lines.push(l) });
    clearCloudConfigCache();
    expect(getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: true });
    expect(lines.join('\n')).toMatch(/will not enforce until you configure a human approval channel/);
    // r7: OpenClaw is gated too; Hermes is named plainly as not gated.
    expect(lines.join('\n')).not.toMatch(/OpenClaw plugin enforces from the start/);
    expect(lines.join('\n')).toMatch(/Claude Code hook and to the OpenClaw plugin; each is measured on its own/);
    expect(lines.join('\n')).toMatch(/Hermes plugin does not implement this gate: it ignores it and enforces immediately/);
  });
});

// ── config flags + help ─────────────────────────────────────────────────────

describe('#509 config flags and --help honesty', () => {
  it('--action-guard-enforce-when-ready sets the posture; --action-guard-enforce clears the gate', () => {
    handleCloudConfig(['--action-guard-enforce-when-ready']);
    clearCloudConfigCache();
    expect(getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: true });
    // r3: choosing the posture starts the durable transition record; choosing
    // it again (no change of posture) adds nothing.
    const rec = () => readTransitionRecord(transitionsPathFor(readinessPaths({ home })));
    expect(rec().entries.map((e) => e.event)).toEqual(['init']);
    // r7: each gated adapter has its own journal; the posture starts both.
    const ocRec = () => readTransitionRecord(transitionsPathFor(readinessPaths({ home, adapter: 'openclaw-interceptor' })));
    expect(ocRec().entries.map((e) => e.event)).toEqual(['init']);
    handleCloudConfig(['--action-guard-enforce-when-ready']);
    expect(rec().entries.map((e) => e.event)).toEqual(['init']);
    expect(ocRec().entries.map((e) => e.event)).toEqual(['init']);
    handleCloudConfig(['--action-guard-enforce']);
    clearCloudConfigCache();
    expect(getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: false });
  });

  it('--help no longer claims the guard defaults on, and documents the new posture truthfully', () => {
    const logs: string[] = [];
    (console.log as unknown as jest.Mock).mockImplementation((...a: unknown[]) => { logs.push(a.join(' ')); });
    handleCloudConfig([]);
    const help = logs.join('\n');
    expect(help).not.toMatch(/--action-guard-enable[^\n]*default: on/);
    expect(help).toMatch(/--action-guard-enable[^\n]*default: off/);
    expect(help).toMatch(/--action-guard-enforce-when-ready/);
    // r7: the OpenClaw plugin implements the gate now; Hermes still does not.
    expect(help).not.toMatch(/OpenClaw plugin enforces from the start/);
    expect(help).toMatch(/Claude Code hook and OpenClaw\s+plugin, each measured on its own calls/);
    expect(help).toMatch(/Hermes ignores the gate and\s+enforces immediately/);
    expect(help).toMatch(/reviewed[\s\S]{0,40}effectiveness evidence/);
    expect(help).not.toMatch(/false.positive|upper bound|§5B|protected/i);
  });
});

// ── Addendum 1 (E): doctor and `guard readiness` report, never flip ─────────

describe('#509 doctor and guard readiness are read-only (Addendum 1 E)', () => {
  /** Every file under the isolated config dir → mtime + sha256. */
  function snapshot(): Record<string, string> {
    const root = join(home, '.shieldcortex');
    const out: Record<string, string> = {};
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        const st = statSync(p);
        if (st.isDirectory()) walk(p);
        else out[p.slice(root.length)] = `${st.mtimeMs}:${createHash('sha256').update(readFileSync(p)).digest('hex')}`;
      }
    };
    walk(root);
    return out;
  }

  /** An enforcing install whose evidence has gone: the hook's NEXT call would
   *  demote and rewrite state. A reader must report that and change nothing. */
  function seedDueForDemotion(): void {
    setNotify({ enabled: true, openclaw: true });
    const now = Date.now();
    const pin = currentReadinessPin();
    const auditDir = join(home, '.shieldcortex', 'audit');
    mkdirSync(auditDir, { recursive: true });
    const t = { type: 'readiness_transition', origin: 'claude-code-hook', from: 'shadow', to: 'enforcing', ts: new Date(now - 2 * DAY).toISOString(), auditEventId: 'p1', readinessPin: pin };
    appendFileSync(join(auditDir, `realtime-${t.ts.slice(0, 10)}.jsonl`), `${JSON.stringify(t)}\n`);
    const statePath = readinessPaths({ home }).statePath;
    mkdirSync(dirname(statePath), { recursive: true });
    writeFileSync(statePath, JSON.stringify({
      version: 1,
      mode: 'enforcing',
      computedAt: new Date(now - 2 * 60 * 60_000).toISOString(),
      pin,
      failingSince: new Date(now - 3 * 60 * 60_000).toISOString(),
      lastPromotedAt: t.ts,
    }));
  }

  it('doctor\'s readiness row and `guard readiness` (text + --json) leave posture, mode and every file byte-identical', async () => {
    seedDueForDemotion();
    const coreBefore = getActionGuardCoreConfig();
    const before = snapshot();
    expect(Object.keys(before).some((k) => k.endsWith('guard-readiness.json'))).toBe(true);

    const [row] = await checkActionGuardReadiness({ summary: () => buildReadinessSummary({ home }) });
    // It reports the pending demotion as the FAIL it is…
    expect(row.status).toBe('fail');
    expect(row.message).toMatch(/DEMOTED/);
    expect(await runGuardCommand(['readiness'], { home })).toBe(1);
    expect(await runGuardCommand(['readiness', '--json'], { home })).toBe(1);

    // …and flips nothing: no promotion, no demotion, no state or audit write.
    expect(snapshot()).toEqual(before);
    clearCloudConfigCache();
    expect(getActionGuardCoreConfig()).toEqual(coreBefore);
    const state = JSON.parse(readFileSync(readinessPaths({ home }).statePath, 'utf8'));
    expect(state.mode).toBe('enforcing');
    expect(auditRows().filter((r) => r.type === 'readiness_transition').map((r) => r.to)).toEqual(['enforcing']);
  });

  it('the BUILT `shieldcortex guard readiness` leaves the isolated tree byte-identical too', () => {
    seedDueForDemotion();
    const before = snapshot();
    const cli = resolve(here, '..', '..', '..', 'dist', 'index.js');
    const run = spawnSync(process.execPath, [cli, 'guard', 'readiness'], {
      env: {
        PATH: process.env.PATH ?? '',
        HOME: home,
        USERPROFILE: home,
        SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'),
        OPENCLAW_HOME: join(home, 'openclaw-home'),
        NO_UPDATE_NOTIFIER: '1',
      },
      encoding: 'utf8',
      timeout: 60_000,
    });
    expect(run.stdout).toMatch(/DEMOTED from enforcing/);
    expect(run.stdout).toMatch(/Readiness proxies \(operability\)/);
    expect(run.stdout).not.toMatch(/upper bound|FP bar/);
    expect(run.status).toBe(1);
    expect(snapshot()).toEqual(before);
  });
});

// ── r7: per surface (Claude Code hook, OpenClaw plugin); Hermes named ──────

describe('#509 r7 — doctor and `guard readiness` report readiness per surface', () => {
  const OC = 'openclaw-interceptor' as const;
  const ocJournal = () => transitionsPathFor(readinessPaths({ home, adapter: OC }));

  function appendOc(entry: Record<string, unknown>): void {
    mkdirSync(dirname(ocJournal()), { recursive: true });
    appendFileSync(ocJournal(), `${JSON.stringify(entry)}\n`);
  }

  it('doctor: one row per surface, and a plain Hermes row; an OpenClaw demotion FAILs under the OpenClaw label only', async () => {
    setNotify({ enabled: true, webhookUrl: 'https://hooks.example.invalid/x' });
    initReadinessTransitions({ postureChanged: true, reason: 'test', home });
    appendOc({ ts: new Date(Date.now() - 3 * DAY).toISOString(), event: 'promote', to: 'enforcing' });
    appendOc({ ts: new Date(Date.now() - 2 * DAY).toISOString(), event: 'demote', to: 'shadow', reason: 'test demotion' });
    const rows = await checkActionGuardReadiness();
    const byLabel = Object.fromEntries(rows.map((r) => [r.label, r]));
    expect(byLabel['Action guard readiness (Claude Code hook)']?.status).toBe('warn');
    expect(byLabel['Action guard readiness (OpenClaw plugin)']?.status).toBe('fail');
    expect(byLabel['Action guard readiness (OpenClaw plugin)']?.message).toMatch(/DEMOTED to shadow/);
    expect(byLabel['Action guard last promotion (OpenClaw plugin)']).toBeDefined();
    expect(byLabel['Action guard last promotion (Claude Code hook)']).toBeUndefined();
    expect(byLabel['Action guard readiness (Hermes plugin)']).toMatchObject({
      status: 'info',
      message: expect.stringMatching(/Hermes plugin does not implement the enforce-when-ready gate: it ignores it and enforces immediately/),
    });
  });

  it('doctor: an unexplained OpenClaw demotion FAILs and names the OpenClaw journal', async () => {
    setNotify({ enabled: true, webhookUrl: 'https://hooks.example.invalid/x' });
    initReadinessTransitions({ postureChanged: true, reason: 'test', home });
    appendOc({ ts: new Date(Date.now() - 3 * DAY).toISOString(), event: 'promote', to: 'enforcing' });
    appendOc({ ts: new Date(Date.now() - DAY).toISOString(), event: 'init', to: 'shadow', reason: 'forged' });
    const rows = await checkActionGuardReadiness();
    const oc = rows.find((r) => r.label === 'Action guard readiness (OpenClaw plugin)')!;
    expect(oc.status).toBe('fail');
    expect(oc.message).toMatch(/UNEXPLAINED DEMOTION/);
    expect(oc.fix).toContain('guard-readiness-transitions.openclaw-interceptor.jsonl');
    expect(rows.find((r) => r.label === 'Action guard readiness (Claude Code hook)')?.status).toBe('warn');
  });

  it('doctor and `guard readiness` stay read-only for BOTH surfaces', async () => {
    setNotify({ enabled: true, webhookUrl: 'https://hooks.example.invalid/x' });
    initReadinessTransitions({ postureChanged: true, reason: 'test', home });
    appendOc({ ts: new Date(Date.now() - 3 * DAY).toISOString(), event: 'promote', to: 'enforcing' });
    const read = () => [readinessPaths({ home }), readinessPaths({ home, adapter: OC })]
      .flatMap((p) => [p.statePath, transitionsPathFor(p)])
      .map((f) => (existsSync(f) ? readFileSync(f, 'utf8') : null));
    const before = read();
    await checkActionGuardReadiness();
    await runGuardCommand(['readiness'], { home });
    await runGuardCommand(['readiness', '--surface', 'openclaw', '--json'], { home });
    expect(read()).toEqual(before);
    expect(auditRows()).toEqual([]);
  });

  it('`guard readiness` prints both surfaces and the Hermes line; `--surface openclaw --json` is that surface only', async () => {
    setNotify({ enabled: true, webhookUrl: 'https://hooks.example.invalid/x' });
    initReadinessTransitions({ postureChanged: true, reason: 'test', home });
    const logs: string[] = [];
    (console.log as unknown as jest.Mock).mockImplementation((...a: unknown[]) => { logs.push(a.join(' ')); });
    expect(await runGuardCommand(['readiness'], { home })).toBe(0);
    const text = logs.join('\n');
    expect(text).toMatch(/Surface: {7}Claude Code hook/);
    expect(text).toMatch(/Surface: {7}OpenClaw plugin/);
    expect(text).toMatch(/Version pin: {3}openclaw-interceptor@/);
    expect(text).toMatch(/Hermes plugin: does not implement the enforce-when-ready gate — it ignores it and enforces immediately/);
    logs.length = 0;
    await runGuardCommand(['readiness', '--surface', 'openclaw', '--json'], { home });
    const json = JSON.parse(logs.join('\n')) as ReadinessSummary;
    expect(json).toMatchObject({ adapter: OC, surface: 'OpenClaw plugin', posture: 'enforce-when-ready', mode: 'shadow' });
    expect(await runGuardCommand(['readiness', '--surface', 'hermes'], { home })).toBe(1);
  });

  it('`guard test-approval --surface openclaw` earns evidence for OpenClaw only', async () => {
    setNotify({ enabled: true, openclaw: true });
    const r = await runTestApproval({
      isTTY: true, log: () => {}, error: () => {}, adapter: OC,
      openclawBin: async () => '/nonexistent/openclaw',
      cardRoundTrip: async () => ({ ok: true, decision: 'allow-once' }),
    });
    expect(r).toEqual({ code: 0, answer: 'approve' });
    const request = auditRows().find((x) => x.type === 'approval_reach' && x.phase === 'request')!;
    expect((request.readinessPin as { adapter: string }).adapter).toBe(currentReadinessPin(OC)!.adapter);
    expect(buildReadinessSummary({ home, adapter: OC }).report.reachability.reached).toBe(1);
    expect(buildReadinessSummary({ home }).report.reachability.reached).toBe(0);
  });
});

// ── r8 ─────────────────────────────────────────────────────────────────────

describe('#509 r8 SF2 — CHANGELOG says which surface ignores the gate', () => {
  it('the Unreleased #509 entry does not say OpenClaw ignores readinessGate; it names Hermes', () => {
    const text = readFileSync(resolve(here, '../../../CHANGELOG.md'), 'utf8');
    const unreleased = text.slice(text.indexOf('## [Unreleased]'), text.indexOf('\n## [', text.indexOf('## [Unreleased]') + 5));
    const entry = unreleased.slice(unreleased.indexOf('**#509 Action Guard'), unreleased.indexOf('\n- **', unreleased.indexOf('**#509 Action Guard')));
    expect(entry).not.toMatch(/OpenClaw plugin ignores `?readinessGate/);
    expect(entry).not.toMatch(/OpenClaw[^.]*enforces from the start/);
    expect(entry).toMatch(/Hermes plugin does not implement[^.]*ignores `?readinessGate`? and enforces from the start/);
  });
});

describe('#509 r8 N4 — the OpenClaw config source is described as what it is', () => {
  it('nothing calls the shield config the plugin reads a "signed file": the plugin never checks its `_sig`', () => {
    const repo = resolve(here, '../../..');
    const runtime = readFileSync(join(repo, 'hooks/openclaw/cortex-memory/runtime.mjs'), 'utf8');
    // The loader parses config.json as plain JSON — no signature check.
    expect(runtime).toMatch(/JSON\.parse\(await fs\.readFile\(configPath/);
    expect(runtime).not.toMatch(/_sig/);
    for (const f of ['plugins/openclaw/index.ts', 'docs/design/2026-09-28-509-enforce-when-ready.md']) {
      expect(readFileSync(join(repo, f), 'utf8')).not.toMatch(/the signed file the CLI writes/);
    }
  });
});

describe('#509 r8 SF3 — remediation text names the surface it is about', () => {
  const OC = 'openclaw-interceptor' as const;
  const ocJournal = () => transitionsPathFor(readinessPaths({ home, adapter: OC }));
  function appendOc(entry: Record<string, unknown>): void {
    mkdirSync(dirname(ocJournal()), { recursive: true });
    appendFileSync(ocJournal(), `${JSON.stringify(entry)}\n`);
  }
  const textOf = (rows: Array<{ message: string; fix?: string }>) => rows.map((r) => `${r.message} ${r.fix ?? ''}`).join('\n');
  /** Every `guard test-approval` in the text carries `--surface openclaw`. */
  function expectOpenClawCommands(text: string): void {
    const uses = text.match(/shieldcortex guard test-approval[^`)]*/g) ?? [];
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u).toContain('--surface openclaw');
    expect(text).not.toMatch(/\bthe hook\b/i);
  }

  it('readiness "missing" lines: OpenClaw names `--surface openclaw`; the hook keeps the plain command', () => {
    setNotify({ enabled: true, webhookUrl: 'https://hooks.example.invalid/x' });
    initReadinessTransitions({ postureChanged: true, reason: 'test', home });
    const oc = buildReadinessSummary({ home, adapter: OC }).report.missing.join('\n');
    expect(oc).toContain('shieldcortex guard test-approval --surface openclaw');
    const hook = buildReadinessSummary({ home }).report.missing.join('\n');
    expect(hook).toContain('shieldcortex guard test-approval');
    expect(hook).not.toContain('--surface openclaw');
  });

  it('doctor OpenClaw rows (shadow, failed promotion notice, unknown record): OpenClaw command, never "the hook"', async () => {
    setNotify({ enabled: true, webhookUrl: 'https://hooks.example.invalid/x' });
    initReadinessTransitions({ postureChanged: true, reason: 'test', home });
    const promotedAt = new Date(Date.now() - 3 * DAY).toISOString();
    appendOc({ ts: promotedAt, event: 'promote', to: 'enforcing' });
    appendOc({ ts: promotedAt, event: 'notice', of: 'promote', transitionTs: promotedAt, delivered: false, reason: 'HTTP 503' });
    appendOc({ ts: new Date(Date.now() - 2 * DAY).toISOString(), event: 'demote', to: 'shadow', reason: 'test demotion' });
    const rows = (await checkActionGuardReadiness()).filter((r) => r.label.endsWith('(OpenClaw plugin)'));
    expect(rows.map((r) => r.label)).toEqual(['Action guard last promotion (OpenClaw plugin)', 'Action guard readiness (OpenClaw plugin)']);
    expectOpenClawCommands(textOf(rows));
    // A damaged OpenClaw record (it HAS a journal): still the loud FAIL, in OpenClaw's words.
    writeFileSync(ocJournal(), '{not json\n');
    const unknown = (await checkActionGuardReadiness()).find((r) => r.label === 'Action guard readiness (OpenClaw plugin)')!;
    expect(unknown.status).toBe('fail');
    expect(textOf([unknown])).not.toMatch(/\bthe hook\b/i);
    expect(unknown.fix).toMatch(/the OpenClaw plugin records the unknown state/i);
  });

  it('`guard readiness` text for OpenClaw: OpenClaw command, never "the hook"', async () => {
    setNotify({ enabled: true, webhookUrl: 'https://hooks.example.invalid/x' });
    initReadinessTransitions({ postureChanged: true, reason: 'test', home });
    const t = new Date(Date.now() - 3 * DAY).toISOString();
    appendOc({ ts: t, event: 'promote', to: 'enforcing' });
    appendOc({ ts: t, event: 'notice', of: 'promote', transitionTs: t, delivered: false, reason: 'HTTP 503' });
    appendOc({ ts: new Date(Date.now() - DAY).toISOString(), event: 'init', to: 'shadow', reason: 'forged' });
    const logs: string[] = [];
    (console.log as unknown as jest.Mock).mockImplementation((...a: unknown[]) => { logs.push(a.join(' ')); });
    await runGuardCommand(['readiness', '--surface', 'openclaw'], { home });
    expectOpenClawCommands(logs.join('\n'));
  });
});

describe('#509 r8 SF4 — upgrade path: a surface never used here is "not in use", not a FAIL', () => {
  const OC = 'openclaw-interceptor' as const;
  const ocPaths = () => readinessPaths({ home, adapter: OC });

  // `readinessPaths()` without a pinned `home` also reads
  // SHIELDCORTEX_AUDIT_DIR, which the jest sandbox points at a per-worker
  // directory that outlives the run — so OpenClaw rows left by an earlier
  // local run made this host look "in use". Each test gets its own empty one.
  let savedAuditDir: string | undefined;
  beforeEach(() => {
    savedAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;
    process.env.SHIELDCORTEX_AUDIT_DIR = join(home, 'interceptor-audit');
    mkdirSync(process.env.SHIELDCORTEX_AUDIT_DIR, { recursive: true });
  });
  afterEach(() => {
    if (savedAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
    else process.env.SHIELDCORTEX_AUDIT_DIR = savedAuditDir;
  });

  /** An install that chose the posture before OpenClaw was gated: the hook's
   *  journal only. */
  function upgradedInstall(): void {
    setNotify({ enabled: true, webhookUrl: 'https://hooks.example.invalid/x' });
    initReadinessTransitions({ postureChanged: true, reason: 'chosen before r7', home, adapter: 'claude-code-hook' });
    expect(existsSync(transitionsPathFor(ocPaths()))).toBe(false);
  }

  it('doctor: the OpenClaw row is info "not in use" — no FAIL anywhere; the hook row is unchanged', async () => {
    upgradedInstall();
    const rows = await checkActionGuardReadiness();
    expect(rows.filter((r) => r.status === 'fail')).toEqual([]);
    const oc = rows.find((r) => r.label === 'Action guard readiness (OpenClaw plugin)')!;
    expect(oc.status).toBe('info');
    expect(oc.message).toMatch(/not in use on this host/);
    expect(oc.message).toMatch(/watching first/);
    expect(rows.find((r) => r.label === 'Action guard readiness (Claude Code hook)')?.status).toBe('warn');
  });

  it('`guard readiness` exits 0 and says "not in use" for OpenClaw (all surfaces and --surface openclaw)', async () => {
    upgradedInstall();
    const logs: string[] = [];
    (console.log as unknown as jest.Mock).mockImplementation((...a: unknown[]) => { logs.push(a.join(' ')); });
    expect(await runGuardCommand(['readiness'], { home })).toBe(0);
    expect(logs.join('\n')).toMatch(/Current mode: {2}NOT IN USE on this host/);
    expect(await runGuardCommand(['readiness', '--surface', 'openclaw'], { home })).toBe(0);
    const json = buildReadinessSummary({ home, adapter: OC });
    expect(json).toMatchObject({ notInUse: true, recordUnknown: false, demoted: false });
  });

  it('OpenClaw HAS been used under the posture (its state file is there), journal gone: still the loud FAIL', async () => {
    upgradedInstall();
    mkdirSync(dirname(ocPaths().statePath), { recursive: true });
    writeFileSync(ocPaths().statePath, JSON.stringify({ version: 1, mode: 'shadow', computedAt: new Date(Date.now() - DAY).toISOString() }));
    const oc = (await checkActionGuardReadiness()).find((r) => r.label === 'Action guard readiness (OpenClaw plugin)')!;
    expect(oc.status).toBe('fail');
    expect(oc.message).toMatch(/transition record missing/);
    expect(buildReadinessSummary({ home, adapter: OC }).notInUse).toBe(false);
  });

  it('OpenClaw evidence in the audit (pinned OpenClaw rows), journal gone: still the loud FAIL', async () => {
    upgradedInstall();
    const auditDir = join(home, '.shieldcortex', 'audit');
    mkdirSync(auditDir, { recursive: true });
    const ts = new Date(Date.now() - DAY).toISOString();
    appendFileSync(join(auditDir, `realtime-${ts.slice(0, 10)}.jsonl`), `${JSON.stringify({
      type: 'intercept', origin: OC, tool: 'Bash', action: 'allow', outcome: 'allowed', ts, auditEventId: 'oc1',
      readinessPin: currentReadinessPin(OC), readinessTally: true,
    })}\n`);
    const oc = (await checkActionGuardReadiness()).find((r) => r.label === 'Action guard readiness (OpenClaw plugin)')!;
    expect(oc.status).toBe('fail');
  });

  it('the Claude Code hook with no journal is never "not in use": the r3 loud FAIL stands', async () => {
    setNotify({ enabled: true, webhookUrl: 'https://hooks.example.invalid/x' });
    initReadinessTransitions({ postureChanged: true, reason: 'test', home, adapter: OC });
    const hook = (await checkActionGuardReadiness()).find((r) => r.label === 'Action guard readiness (Claude Code hook)')!;
    expect(hook.status).toBe('fail');
    expect(buildReadinessSummary({ home }).notInUse).toBe(false);
  });
});
