/**
 * #853 — never silently deny when nobody can be asked: HOLD + one card.
 *
 * Driven through the REAL Claude Code hook, on the same seam as
 * pre-tool-hook-retry-310.test.ts: the shipped guard, retry-control,
 * dnp-digest and dnp-retry-waiter from `dist`, with only the two edges that
 * leave the box faked — the webhook (file evidence) and the `openclaw` binary
 * (a shell script that answers with whatever decision the test wrote, or
 * fails when told to).
 *
 * What is pinned:
 *   - a cron-shaped and a sub-agent-shaped session each get HELD, not denied,
 *     when a card can hold the action — zero `denied_no_prompt_surface` rows;
 *   - the agent is told the truth: held, card REQUESTED (never "sent"), and
 *     approval grants ONE scoped retry — it does not run the call by itself;
 *   - one card per action identity: a second attempt says the card is open;
 *   - no card possible → still a denial, and it says why no card was asked;
 *   - Deny, expiry and a failed card request are each REPORTED, and each says
 *     nothing ran.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from '@jest/globals';
import { execSync, spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const REAL_DIST = join(repoRoot, 'dist', 'defence', 'iron-dome');

const IRREVERSIBLE = { command: 'sudo modprobe softdog' };

interface HookResult { decision?: string; reason?: string; stderr: string }
type Row = Record<string, unknown>;

describe('#853 — a no-prompt-surface call is HELD under one owner card', () => {
  let home: string;
  let distRoot: string;
  let jobCwd: string;
  let evidenceFile: string;
  let openclawBin: string;
  let decisionFile: string;
  let failFlag: string;

  beforeAll(() => {
    const probes = [
      'tool-action-guard.js', 'action-approvals.js', 'notify-config.js', 'operator-notify.js',
      'webhook-notify-channel.js', 'dnp-digest.js', 'retry-control.js', 'dnp-retry-waiter.js',
      'approval-card.js',
    ].map((f) => join(REAL_DIST, f));
    if (!probes.every((p) => existsSync(p))) {
      execSync('npm run build:ts', { cwd: repoRoot, stdio: 'ignore' });
    }
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-held-hook-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    jobCwd = mkdtempSync(join(tmpdir(), 'sc-held-cwd-'));
    evidenceFile = join(home, 'webhook-evidence.jsonl');

    distRoot = mkdtempSync(join(tmpdir(), 'sc-held-dist-'));
    const ironDomeDir = join(distRoot, 'defence', 'iron-dome');
    mkdirSync(ironDomeDir, { recursive: true });
    for (const f of [
      'tool-action-guard.js', 'action-approvals.js', 'notify-config.js', 'operator-notify.js',
      'script-source-resolver.js', 'dnp-digest.js', 'retry-control.js', 'dnp-retry-waiter.js',
      'openclaw-approval-channel.js', 'approval-card.js',
    ]) {
      const real = join(REAL_DIST, f);
      if (existsSync(real)) {
        writeFileSync(join(ironDomeDir, f), `export * from ${JSON.stringify(pathToFileURL(real).href)};\n`);
      }
    }
    writeFileSync(
      join(ironDomeDir, 'webhook-notify-channel.js'),
      [
        "import { appendFileSync as af } from 'node:fs';",
        'export function createWebhookNotifyChannel(opts) {',
        '  return {',
        "    name: 'webhook',",
        '    async send(notification) {',
        '      const u = new URL(opts.url);',
        "      const evidencePath = u.searchParams.get('evidence');",
        "      if (evidencePath) af(evidencePath, JSON.stringify(notification) + '\\n');",
        '      return { delivered: true };',
        '    },',
        '  };',
        '}',
      ].join('\n'),
    );

    // Fake gateway CLI: records each card's params, then answers with the
    // decision file — or fails outright while the fail flag exists.
    decisionFile = join(home, 'decision.json');
    failFlag = join(home, 'gateway-fail');
    writeFileSync(decisionFile, JSON.stringify({ decision: null }));
    openclawBin = join(home, 'fake-openclaw');
    const cardsLog = join(home, 'cards.log');
    writeFileSync(
      openclawBin,
      [
        '#!/bin/sh',
        `echo card >> ${JSON.stringify(cardsLog)}`,
        `while [ "$1" != "" ]; do if [ "$1" = "--params" ]; then shift; printf '%s\\n' "$1" >> ${JSON.stringify(join(home, 'card-params.jsonl'))}; fi; shift; done`,
        `if [ -f ${JSON.stringify(failFlag)} ]; then echo 'gateway unreachable' >&2; exit 2; fi`,
        `cat ${JSON.stringify(decisionFile)}`,
      ].join('\n') + '\n',
      { mode: 0o755 },
    );
    chmodSync(openclawBin, 0o755);
  });

  afterEach(() => {
    for (const dir of [home, distRoot, jobCwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function writeConfig(actionGuard: Record<string, unknown>): void {
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ actionGuard: { enabled: true, enforce: true, ...actionGuard } }),
    );
  }

  function cardsOn(opts: { openclaw?: boolean; retryCards?: unknown } = {}) {
    return {
      retryCards: opts.retryCards ?? true,
      notify: {
        enabled: true,
        webhookUrl: `http://fake-webhook.invalid/hook?evidence=${encodeURIComponent(evidenceFile)}`,
        openclaw: opts.openclaw ?? true,
      },
    };
  }

  /** Cron: bypassPermissions. Sub-agent: dontAsk with an agent id. */
  function runHook(
    input: Record<string, unknown>,
    opts: { shape?: 'cron' | 'subagent' | 'no-mode'; sessionId?: string; cwd?: string } = {},
  ): HookResult {
    const shape = opts.shape ?? 'cron';
    const payload: Record<string, unknown> = {
      session_id: opts.sessionId ?? (shape === 'cron' ? 'cron-tick-1' : 'subagent-1'),
      cwd: opts.cwd ?? jobCwd,
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: input,
    };
    if (shape === 'cron') payload.permission_mode = 'bypassPermissions';
    if (shape === 'subagent') {
      payload.permission_mode = 'dontAsk';
      payload.agent_id = 'agent-853';
      payload.agent_type = 'general-purpose';
    }
    const run = spawnSync('node', [HOOK], {
      input: JSON.stringify(payload),
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        SHIELDCORTEX_DIST_ROOT: distRoot,
        SHIELDCORTEX_OPENCLAW_BIN: openclawBin,
        SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'),
      } as NodeJS.ProcessEnv,
      timeout: 30_000,
      encoding: 'utf8',
    });
    const stdout = run.stdout ?? '';
    if (!stdout.trim()) return { stderr: run.stderr ?? '' };
    const out = JSON.parse(stdout).hookSpecificOutput ?? {};
    return { decision: out.permissionDecision, reason: out.permissionDecisionReason, stderr: run.stderr ?? '' };
  }

  function jsonl(file: string): Row[] {
    return existsSync(file)
      ? readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l) as Row)
      : [];
  }
  const denialRows = () => jsonl(join(home, '.shieldcortex', 'denials.jsonl'));
  const auditRows = () => jsonl(join(home, '.shieldcortex', 'audit', `realtime-${new Date().toISOString().slice(0, 10)}.jsonl`));
  const cardsRequested = () => {
    const f = join(home, 'cards.log');
    return existsSync(f) ? readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).length : 0;
  };
  const cardParams = () => jsonl(join(home, 'card-params.jsonl'));
  const retryStore = () => {
    const f = join(home, '.shieldcortex', 'approvals', 'retry-control.json');
    return existsSync(f)
      ? JSON.parse(readFileSync(f, 'utf8')) as { rows: Array<Row & { grant?: Row; claim?: Row; suppression?: Row }>; budget: { cards: number } | null }
      : null;
  };

  function waitFor(predicate: () => boolean, timeoutMs = 15_000): boolean {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (predicate()) return true;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
    }
    return predicate();
  }

  function expectHeldReason(reason: string | undefined): void {
    expect(reason).toMatch(/HELD, not run/);
    // Requested, never claimed delivered.
    expect(reason).toMatch(/requested, not confirmed delivered|already open/);
    expect(reason).not.toMatch(/card (was )?sent|delivered to/i);
    // Approval grants a scoped retry; it never runs the call by itself.
    expect(reason).toMatch(/Approval does NOT run it for you: it allows ONE retry of this same call, from this same directory/);
    expect(reason).toMatch(/nothing ran/);
    expect(reason).not.toMatch(/was denied/);
    expect(reason).not.toMatch(/enforce:\s*false(?!\.)/);
  }

  // ── The acceptance shapes ──────────────────────────────────────────────

  it.each([['cron', 'cron' as const], ['sub-agent', 'subagent' as const]])(
    'a %s-shaped session is HELD: one card, no denied_no_prompt_surface row',
    (_label, shape) => {
      writeConfig(cardsOn());
      const r = runHook(IRREVERSIBLE, { shape });

      // The harness still gets a decision NOW — a per-call hook cannot pend.
      expect(r.decision).toBe('deny');
      expectHeldReason(r.reason);
      expect(r.reason).toMatch(/requested, not confirmed delivered/);

      expect(waitFor(() => cardsRequested() === 1)).toBe(true);
      const outcomes = denialRows().filter((row) => row.event === 'action_guard_denial'
        && typeof row.tool === 'string').map((row) => row.outcome);
      expect(outcomes.length).toBeGreaterThan(0);
      expect(outcomes.every((o) => o === 'held_no_prompt_surface')).toBe(true);
      // The durable audit row agrees with denials.jsonl.
      const terminal = auditRows().filter((row) => String(row.outcome ?? '').endsWith('_no_prompt_surface'));
      expect(terminal.map((row) => row.outcome)).toEqual(['held_no_prompt_surface']);
      expect(JSON.stringify(denialRows())).not.toContain('"denied_no_prompt_surface"');
      expect(JSON.stringify(auditRows())).not.toContain('"denied_no_prompt_surface"');
    },
  );

  it('a session that reports no permission_mode is held the same way', () => {
    writeConfig(cardsOn());
    const r = runHook(IRREVERSIBLE, { shape: 'no-mode' });
    expect(r.decision).toBe('deny');
    expectHeldReason(r.reason);
  });

  it('the card is the plain-English held card: What / Why / Who and the outcome, values redacted', () => {
    writeConfig(cardsOn());
    runHook(IRREVERSIBLE);
    expect(waitFor(() => cardParams().length === 1)).toBe(true);
    const card = cardParams()[0] as { title: string; description: string; allowedDecisions: string[] };
    expect(card.title).toMatch(/^Held, not run: approve once\? Bash/);
    expect(card.description).toMatch(/What: .+ \| Why: .+ \| Who: .+ \| Outcome: held, NOT run\./);
    expect(card.description).toMatch(/Approve = allows ONE retry within \d+m/);
    expect(card.description).toMatch(/Deny, or no answer in \d+m = nothing runs\.$/);
    expect(card.description.length).toBeLessThanOrEqual(256);
    expect(card.allowedDecisions).toEqual(['allow-once', 'deny']);
  });

  // ── One card per action identity ───────────────────────────────────────

  it('a second attempt while the card is open is still HELD — and no second card', () => {
    writeConfig(cardsOn());
    // A gateway that never answers inside this test: the card stays open.
    writeFileSync(openclawBin, '#!/bin/sh\n' + `echo card >> ${JSON.stringify(join(home, 'cards.log'))}\nsleep 20\n`, { mode: 0o755 });
    runHook(IRREVERSIBLE, { sessionId: 'cron-tick-1' });
    expect(waitFor(() => cardsRequested() === 1)).toBe(true);

    const again = runHook(IRREVERSIBLE, { sessionId: 'cron-tick-2' });
    expect(again.decision).toBe('deny');
    expectHeldReason(again.reason);
    expect(again.reason).toMatch(/already open with the owner \(no second card is sent\)/);
    expect(retryStore()!.budget!.cards).toBe(1);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
    expect(cardsRequested()).toBe(1);
    expect(JSON.stringify(denialRows())).not.toContain('"denied_no_prompt_surface"');
  });

  // ── No card possible: still a denial, and honest about why ─────────────

  it.each([
    ['cards are off', { retryCards: false }, /No approval card was requested: approval cards are off/],
    ['there is no card channel', { openclaw: false }, /No approval card was requested: no card channel is configured/],
  ])('when %s it is a DENIAL that never claims a card', (_label, opts, why) => {
    writeConfig(cardsOn(opts as { openclaw?: boolean; retryCards?: unknown }));
    const r = runHook(IRREVERSIBLE);

    expect(r.decision).toBe('deny');
    expect(r.reason).toMatch(/the tool call was denied/);
    expect(r.reason).toMatch(why);
    expect(r.reason).not.toMatch(/HELD|card.*requested for the owner|already open/);
    expect(r.reason).toContain('shieldcortex approve --denial <actionId>');
    expect(denialRows().some((row) => row.outcome === 'denied_no_prompt_surface')).toBe(true);
    expect(denialRows().some((row) => row.outcome === 'held_no_prompt_surface')).toBe(false);
    expect(cardsRequested()).toBe(0);
  });

  // ── Approve, Deny, expiry, failed card ─────────────────────────────────

  it('Approve grants ONE scoped retry — it does not run anything by itself', () => {
    writeConfig(cardsOn());
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    const held = runHook(IRREVERSIBLE);
    expectHeldReason(held.reason);

    expect(waitFor(() => (retryStore()?.rows[0]?.grant ?? null) !== null)).toBe(true);
    expect(denialRows().some((row) => row.outcome === 'retry_granted')).toBe(true);
    // The approval alone ran nothing: no approved row until the job retries.
    expect(auditRows().some((row) => row.outcome === 'approved')).toBe(false);

    const retried = runHook(IRREVERSIBLE, { sessionId: 'cron-tick-2' });
    expect(retried.decision).toBeUndefined();
    expect(retried.stderr).toContain('consumed operator RETRY grant');
    expect(auditRows().some((row) => row.outcome === 'approved' && row.grantKind === 'retry')).toBe(true);
    // One shot.
    expect(runHook(IRREVERSIBLE, { sessionId: 'cron-tick-3' }).decision).toBe('deny');
  });

  it('Deny is reported, nothing ran, and no grant is left behind', () => {
    writeConfig(cardsOn());
    writeFileSync(decisionFile, JSON.stringify({ decision: 'deny' }));
    runHook(IRREVERSIBLE);

    expect(waitFor(() => denialRows().some((row) => row.outcome === 'retry_denied'))).toBe(true);
    expect(retryStore()!.rows[0].grant).toBeUndefined();
    expect(auditRows().some((row) => row.outcome === 'approved')).toBe(false);
  });

  it('expiry is reported and says nothing ran — and grants nothing', () => {
    writeConfig(cardsOn());
    // `decision: null` is the gateway's timed-out card.
    runHook(IRREVERSIBLE);

    expect(waitFor(() => denialRows().some((row) => row.outcome === 'retry_expired'))).toBe(true);
    const expired = denialRows().find((row) => row.outcome === 'retry_expired')!;
    expect(String(expired.reason)).toMatch(/expired unanswered; nothing ran/);
    expect(expired.actionId).toMatch(/^act-[0-9a-f]{16}$/);
    expect(retryStore()!.rows[0].grant).toBeUndefined();
    expect(runHook(IRREVERSIBLE, { sessionId: 'cron-tick-2' }).decision).toBe('deny');
  });

  it('a card request that fails is reported — the agent was only ever told "requested"', () => {
    writeConfig(cardsOn());
    writeFileSync(failFlag, '1');
    const r = runHook(IRREVERSIBLE);
    expect(r.reason).toMatch(/requested, not confirmed delivered/);

    expect(waitFor(() => denialRows().some((row) => row.outcome === 'retry_card_failed'))).toBe(true);
    const failed = denialRows().find((row) => row.outcome === 'retry_card_failed')!;
    expect(String(failed.reason)).toMatch(/may not have reached the owner; the action has NOT run/);
    // Host output is never copied into the row.
    expect(JSON.stringify(failed)).not.toContain('gateway unreachable');
    expect(retryStore()!.rows[0].grant).toBeUndefined();
  });
});
