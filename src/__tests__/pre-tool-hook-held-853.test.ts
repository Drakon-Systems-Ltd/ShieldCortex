/**
 * #853 Plane A — a no-prompt-surface call is HELD under one owner card and
 * the SAME call is answered `allow` on Approve, `deny` otherwise.
 *
 * Driven through the REAL Claude Code hook with the shipped dist modules;
 * only the `openclaw` binary is faked (a shell script that records the card
 * params and answers with whatever decision the test wrote). The hold window
 * comes from a real `~/.claude/settings.json` in the temp HOME.
 *
 * Pinned:
 *   - Approve → `allow` for this call, `held` + `approved` audit rows, no
 *     denial row; nothing spendable written (no approvals store entry);
 *   - Deny / expiry / a failed card → `deny`, each saying nothing ran;
 *   - one card per action identity: a concurrent identical call and a call
 *     right after a Deny get NO second card;
 *   - no hold without a usable harness timeout — honest denial, no card;
 *   - NO card route under enforce → advisory (allow + log), never a
 *     `denied_no_prompt_surface`; always-block still denies (ruling §1/§3);
 *   - an interactive session still gets `ask`, no card.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from '@jest/globals';
import { execSync, spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const REAL_DIST = join(repoRoot, 'dist');

const DANGEROUS = { command: 'sudo modprobe softdog' };

interface HookResult { decision?: string; reason?: string; stderr: string }
type Row = Record<string, unknown>;

describe('#853 Plane A — the hook holds the original call under one card', () => {
  let home: string;
  let jobCwd: string;
  let openclawBin: string;
  let decisionFile: string;
  let failFlag: string;
  let slowFlag: string;
  /** A stand-in Claude Code process: stays the hook's parent, so the hook can
   *  read and identify the harness command line (and its --settings). */
  let claudeBin: string;

  beforeAll(() => {
    if (!existsSync(join(REAL_DIST, 'defence', 'iron-dome', 'held-action.js'))) {
      execSync('npm run build:ts', { cwd: repoRoot, stdio: 'ignore' });
    }
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-hold-hook-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    jobCwd = mkdtempSync(join(tmpdir(), 'sc-hold-cwd-'));
    decisionFile = join(home, 'decision.json');
    failFlag = join(home, 'gateway-fail');
    slowFlag = join(home, 'gateway-slow');
    writeFileSync(decisionFile, JSON.stringify({ decision: 'deny' }));
    openclawBin = join(home, 'fake-openclaw');
    writeFileSync(
      openclawBin,
      [
        '#!/bin/sh',
        `while [ "$1" != "" ]; do if [ "$1" = "--params" ]; then shift; printf '%s\\n' "$1" >> ${JSON.stringify(join(home, 'card-params.jsonl'))}; fi; shift; done`,
        `if [ -f ${JSON.stringify(slowFlag)} ]; then sleep 4; fi`,
        `if [ -f ${JSON.stringify(failFlag)} ]; then echo 'gateway unreachable' >&2; exit 2; fi`,
        `cat ${JSON.stringify(decisionFile)}`,
      ].join('\n') + '\n',
    );
    chmodSync(openclawBin, 0o755);
    mkdirSync(join(home, 'bin'), { recursive: true });
    claudeBin = join(home, 'bin', 'claude');
    // NOT `exec`: the shell must stay alive as the hook's parent.
    writeFileSync(claudeBin, `#!/bin/sh\n${JSON.stringify(process.execPath)} ${JSON.stringify(HOOK)}\nexit $?\n`, { mode: 0o755 });
    chmodSync(claudeBin, 0o755);
    writeConfig();
    writeHarnessTimeout(45);
  });

  afterEach(() => {
    for (const dir of [home, jobCwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function writeConfig(opts: { openclaw?: boolean } = {}): void {
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({
        actionGuard: {
          enabled: true,
          enforce: true,
          notify: { enabled: true, openclaw: opts.openclaw ?? true },
        },
      }),
    );
  }

  /** The harness timeout the hook reads back. `null` = entry with no timeout. */
  function writeHarnessTimeout(seconds: number | null | 'absent'): void {
    mkdirSync(join(home, '.claude'), { recursive: true });
    const hook: Record<string, unknown> = { type: 'command', command: '/usr/local/bin/shieldcortex hook pre-tool' };
    if (typeof seconds === 'number') hook.timeout = seconds;
    const settings = seconds === 'absent' ? {} : { hooks: { PreToolUse: [{ matcher: '*', hooks: [hook] }] } };
    writeFileSync(join(home, '.claude', 'settings.json'), JSON.stringify(settings));
  }

  function hookEnv(): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      SHIELDCORTEX_DIST_ROOT: REAL_DIST,
      SHIELDCORTEX_OPENCLAW_BIN: openclawBin,
      SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'),
    };
    delete env.CLAUDE_PROJECT_DIR;
    return env;
  }

  function payload(input: Record<string, unknown>, mode: string | null = 'bypassPermissions'): string {
    return JSON.stringify({
      session_id: 'cron-tick-853',
      cwd: jobCwd,
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: input,
      ...(mode ? { permission_mode: mode } : {}),
    });
  }

  function parse(stdout: string, stderr: string): HookResult {
    if (!stdout.trim()) return { stderr };
    const out = JSON.parse(stdout).hookSpecificOutput ?? {};
    return { decision: out.permissionDecision, reason: out.permissionDecisionReason, stderr };
  }

  /** `harnessArgs` go on the stand-in Claude Code command line; `'none'`
   *  runs the hook with no Claude Code parent at all (an unproven harness). */
  function runHook(
    input: Record<string, unknown> = DANGEROUS,
    mode: string | null = 'bypassPermissions',
    harnessArgs: string[] | 'none' = [],
  ): HookResult {
    const run = harnessArgs === 'none'
      ? spawnSync('node', [HOOK], { input: payload(input, mode), env: hookEnv(), timeout: 30_000, encoding: 'utf8' })
      : spawnSync(claudeBin, harnessArgs, { input: payload(input, mode), env: hookEnv(), timeout: 30_000, encoding: 'utf8' });
    return parse(run.stdout ?? '', run.stderr ?? '');
  }

  function jsonl(file: string): Row[] {
    return existsSync(file)
      ? readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l) as Row)
      : [];
  }
  const cardParams = () => jsonl(join(home, 'card-params.jsonl'));
  const denialRows = () => jsonl(join(home, '.shieldcortex', 'denials.jsonl'));
  const auditRows = () => {
    const dir = join(home, '.shieldcortex', 'audit');
    if (!existsSync(dir)) return [];
    return readdirSync(dir).filter((f) => f.endsWith('.jsonl')).flatMap((f) => jsonl(join(dir, f)));
  };
  const outcomes = () => auditRows().map((r) => r.outcome);

  it('Approve answers ALLOW to the same call — no denial, no grant left behind', () => {
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    const r = runHook();
    expect(r.decision).toBe('allow');
    expect(r.reason).toMatch(/owner approved this held call/);
    expect(r.reason).toMatch(/runs once, now/);

    const cards = cardParams();
    expect(cards).toHaveLength(1);
    expect(cards[0].allowedDecisions).toEqual(['allow-once', 'deny']);
    // The card lives no longer than the hold: 45 s harness − 10 s margin − start-up.
    expect(Number(cards[0].timeoutMs)).toBeGreaterThanOrEqual(30_000);
    expect(Number(cards[0].timeoutMs)).toBeLessThanOrEqual(35_000);
    expect(JSON.stringify(cards[0])).not.toMatch(/retry/i);

    expect(outcomes()).toEqual(expect.arrayContaining(['held', 'approved']));
    expect(outcomes()).not.toContain('denied_no_prompt_surface');
    expect(denialRows()).toHaveLength(0);
    // Nothing spendable on disk: no one-shot approval, no retry grant.
    expect(existsSync(join(home, '.shieldcortex', 'approvals', 'retry-control.json'))).toBe(false);
    const holds = readdirSync(join(home, '.shieldcortex', 'holds'));
    expect(holds).toHaveLength(1);
    expect(JSON.parse(readFileSync(join(home, '.shieldcortex', 'holds', holds[0]), 'utf8'))).toMatchObject({ state: 'approved' });
  }, 40_000);

  it('Deny answers DENY, and the same call right after gets no second card', () => {
    const r = runHook();
    expect(r.decision).toBe('deny');
    expect(r.reason).toMatch(/HELD, then DENIED by the owner/);
    expect(r.reason).toMatch(/Nothing ran/);
    expect(cardParams()).toHaveLength(1);
    const denial = denialRows().at(-1);
    // #853 review: a card WAS the surface — its own outcome, never DNP.
    expect(denial?.outcome).toBe('held_denied');
    expect(outcomes()).not.toContain('denied_no_prompt_surface');
    expect(denial?.notify).toEqual({ status: 'delivered', deliveredVia: 'openclaw-approval' });
    expect(outcomes()).toContain('held');

    const again = runHook();
    expect(again.decision).toBe('deny');
    expect(again.reason).toMatch(/owner denied this exact call/);
    expect(cardParams()).toHaveLength(1);
    expect(denialRows().at(-1)?.notify).toEqual({ status: 'coalesced', deliveredVia: null });
    expect(denialRows().at(-1)?.outcome).toBe('held_duplicate');
    expect(outcomes()).not.toContain('denied_no_prompt_surface');
  }, 60_000);

  it('a card that expires unanswered is a DENY that says so', () => {
    writeFileSync(decisionFile, JSON.stringify({ decision: null }));
    const r = runHook();
    expect(r.decision).toBe('deny');
    expect(r.reason).toMatch(/did not answer the approval card, so it expired/);
    expect(outcomes()).not.toContain('approved');
    expect(outcomes()).toContain('held_expired');
    expect(denialRows().at(-1)?.outcome).toBe('held_expired');
    expect(outcomes()).not.toContain('denied_no_prompt_surface');
  }, 40_000);

  it('a card that cannot be raised is a DENY that says nobody could approve it', () => {
    writeFileSync(failFlag, '1');
    const r = runHook();
    expect(r.decision).toBe('deny');
    expect(r.reason).toMatch(/could not be raised or answered/);
    expect(outcomes()).not.toContain('approved');
    expect(denialRows().at(-1)?.outcome).toBe('held_card_failed');
    expect(outcomes()).not.toContain('denied_no_prompt_surface');
  }, 40_000);

  it('an unoffered allow-always answer runs nothing', () => {
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-always' }));
    const r = runHook();
    expect(r.decision).toBe('deny');
    expect(outcomes()).not.toContain('approved');
  }, 40_000);

  it('a concurrent identical call gets NO second card while the first is held', async () => {
    writeFileSync(slowFlag, '1');
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    const first = spawn(claudeBin, [], { env: hookEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
    let out1 = '';
    let err1 = '';
    first.stdout.on('data', (c) => { out1 += String(c); });
    first.stderr.on('data', (c) => { err1 += String(c); });
    const done = new Promise<void>((r) => first.on('close', () => r()));
    first.stdin.end(payload(DANGEROUS));

    const deadline = Date.now() + 15_000;
    while (cardParams().length === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    expect(cardParams()).toHaveLength(1);

    const second = runHook();
    expect(second.decision).toBe('deny');
    expect(second.reason).toMatch(/identical call is already held/);
    expect(cardParams()).toHaveLength(1);

    await done;
    expect(parse(out1, err1).decision).toBe('allow');
  }, 40_000);

  it('a harness timeout too short to hold safely keeps the old DENY, with no card', () => {
    writeHarnessTimeout(10);
    const r = runHook();
    expect(r.decision).toBe('deny');
    expect(r.reason).toMatch(/timeout in settings\.json is too short to hold it safely/);
    expect(cardParams()).toHaveLength(0);
    expect(denialRows().at(-1)?.outcome).toBe('denied_no_prompt_surface');
  }, 40_000);

  it.each([
    ['entry with no timeout', null],
    ['no entry at all', 'absent'],
  ] as const)('%s: no hold, no card', (_label, t) => {
    writeHarnessTimeout(t);
    const r = runHook();
    expect(r.decision).toBe('deny');
    expect(cardParams()).toHaveLength(0);
  }, 40_000);

  it('ruling §3: enforce + headless + NO card route is ADVISORY — allowed and logged, never denied', () => {
    writeConfig({ openclaw: false });
    for (const mode of ['bypassPermissions', 'dontAsk']) {
      const r = runHook(DANGEROUS, mode);
      // Advisory emits no decision: the harness's own permission rules apply.
      expect(r.decision).toBeUndefined();
      expect(r.stderr).toMatch(/NO card route/);
    }
    expect(cardParams()).toHaveLength(0);
    const rows = auditRows();
    expect(rows.map((x) => x.outcome)).toEqual(expect.arrayContaining(['warned']));
    expect(rows.map((x) => x.outcome)).not.toContain('denied_no_prompt_surface');
    expect(rows.filter((x) => x.outcome === 'warned').every((x) => (x.hold as Row | undefined)?.state === 'no-card-route')).toBe(true);
    expect(denialRows().map((x) => x.outcome)).not.toContain('denied_no_prompt_surface');
  }, 60_000);

  it('ruling §1: always-block (guard self-protection) still DENIES with no card route', () => {
    writeConfig({ openclaw: false });
    const r = runHook({ command: 'shieldcortex config --action-guard-disable' });
    expect(r.decision).toBe('deny');
    expect(outcomes()).not.toContain('warned');
    expect(cardParams()).toHaveLength(0);
  }, 40_000);

  it('always-block is never held even WITH a card route', () => {
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    const r = runHook({ command: 'shieldcortex config --action-guard-disable' });
    expect(r.decision).toBe('deny');
    expect(cardParams().filter((c) => /is held, not run/.test(String(c.title)))).toHaveLength(0);
    expect(outcomes()).not.toContain('approved');
  }, 40_000);

  it('an interactive session still gets ASK and is never held', () => {
    const r = runHook(DANGEROUS, 'default');
    expect(r.decision).toBe('ask');
    // The #143 live-ask card may be raised beside the prompt; a HELD card never is.
    expect(cardParams().filter((c) => /is held, not run/.test(String(c.title)))).toHaveLength(0);
    expect(outcomes()).not.toContain('held');
  }, 40_000);

  it.each([
    ['firewall rules', { command: 'sudo iptables -F' }],
    ['force push', { command: 'git push --force origin main' }],
  ])('ruling §1: %s are always-block — never advisory with no route, never held with one', (_label, input) => {
    writeConfig({ openclaw: false });
    const noRoute = runHook(input);
    expect(noRoute.decision).toBe('deny');
    expect(outcomes()).not.toContain('warned');

    writeConfig();
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    const routed = runHook(input);
    expect(routed.decision).toBe('deny');
    expect(cardParams().filter((c) => /is held, not run/.test(String(c.title)))).toHaveLength(0);
    expect(outcomes()).not.toContain('approved');
  }, 60_000);

  // ── #853 review (CRITICAL): hold only on a PROVEN harness budget ────────

  it('no identifiable Claude Code parent (macOS, no /proc, unknown launcher): never held', () => {
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    const r = runHook(DANGEROUS, 'bypassPermissions', 'none');
    expect(r.decision).toBe('deny');
    expect(r.reason).toMatch(/could not prove how long Claude Code lets it run/);
    expect(cardParams()).toHaveLength(0);
    expect(outcomes()).not.toContain('approved');
  }, 40_000);

  it('a --settings override with a SHORTER timeout on the harness command line prevents the hold', () => {
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    const override = join(home, 'override.json');
    writeFileSync(override, JSON.stringify({ hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'shieldcortex hook pre-tool', timeout: 10 }] }] } }));
    const r = runHook(DANGEROUS, 'bypassPermissions', ['--settings', override]);
    expect(r.decision).toBe('deny');
    expect(r.reason).toMatch(/too short to hold it safely/);
    expect(cardParams()).toHaveLength(0);
  }, 40_000);

  it('a --settings file named on the harness command line that cannot be read prevents the hold', () => {
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    const r = runHook(DANGEROUS, 'bypassPermissions', ['--settings', join(home, 'missing.json')]);
    expect(r.decision).toBe('deny');
    expect(r.reason).toMatch(/could not prove how long Claude Code lets it run/);
    expect(cardParams()).toHaveLength(0);
  }, 40_000);

  it('--setting-sources excluding user settings leaves no proven entry: no hold', () => {
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    const r = runHook(DANGEROUS, 'bypassPermissions', ['--setting-sources', 'project']);
    expect(r.decision).toBe('deny');
    expect(cardParams()).toHaveLength(0);
  }, 40_000);

  it('a plugin hooks.json with a shorter timeout prevents the hold', () => {
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    const dir = join(home, '.claude', 'plugins', 'cache', 'sc', 'hooks');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'hooks.json'), JSON.stringify({ hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'shieldcortex hook pre-tool', timeout: 12 }] }] } }));
    const r = runHook();
    expect(r.decision).toBe('deny');
    expect(cardParams()).toHaveLength(0);
  }, 40_000);

  // ── #853 review (HIGH): always-block has NO release path ───────────────

  it.each([
    ['guard self-protection', { command: 'shieldcortex config --action-guard-disable' }],
    ['firewall rules', { command: 'sudo iptables -F' }],
  ])('%s: an INTERACTIVE session is denied outright — no prompt to approve', (_label, input) => {
    const r = runHook(input, 'default');
    expect(r.decision).toBe('deny');
    expect(r.reason).toMatch(/ALWAYS-BLOCK|always-block|Catastrophic/i);
    expect(outcomes()).not.toContain('asked');
    expect(outcomes()).not.toContain('approved');
  }, 40_000);

  it('firewall rules under ADVISORY posture still block, never warn-and-allow', () => {
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({
      actionGuard: { enabled: true, enforce: false, notify: { enabled: true, openclaw: true }, autoApprove: ['modify-network-firewall'] },
    }));
    for (const mode of ['bypassPermissions', 'default']) {
      const r = runHook({ command: 'sudo iptables -F' }, mode);
      expect(r.decision).toBe('deny');
    }
    expect(outcomes()).not.toContain('warned');
    expect(outcomes()).not.toContain('approved');
  }, 60_000);
});
