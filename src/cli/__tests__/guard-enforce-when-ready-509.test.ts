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

import { runTestApproval, buildReadinessSummary, type ReadinessSummary } from '../guard.js';
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
    expect(warn.message).toMatch(/not proven yet/);
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

  it('a fresh install under the posture is WARN, not FAIL', async () => {
    setNotify({ enabled: true, openclaw: true });
    const [row] = await checkActionGuardReadiness({ summary: () => buildReadinessSummary({ home }) });
    expect(row.status).toBe('warn');
    expect(row.message).toMatch(/only 0 of the 500/);
  });
});

// ── setup ───────────────────────────────────────────────────────────────────

describe('#509 setup posture question', () => {
  it('offers exactly Off / Watch only / Enforce when ready (recommended), each explained', () => {
    expect(POSTURE_CHOICES.map((c) => c.title)).toEqual(['Off', 'Watch only', 'Enforce when ready (recommended)']);
    const ewr = POSTURE_CHOICES[2].body;
    expect(ewr).toMatch(/2%/);
    expect(ewr).toMatch(/98%/);
    expect(ewr).toMatch(/approval channel/);
    expect(ewr).toMatch(/Starts exactly like Watch only/);
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
  });
});

// ── config flags + help ─────────────────────────────────────────────────────

describe('#509 config flags and --help honesty', () => {
  it('--action-guard-enforce-when-ready sets the posture; --action-guard-enforce clears the gate', () => {
    handleCloudConfig(['--action-guard-enforce-when-ready']);
    clearCloudConfigCache();
    expect(getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: true });
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
    expect(help).toMatch(/the OpenClaw plugin enforces from the start/);
  });
});
