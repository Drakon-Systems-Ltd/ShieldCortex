/**
 * #509 end to end: the BUILT scripts/pre-tool-hook.mjs under the
 * enforce-when-ready posture, against an isolated HOME / SHIELDCORTEX_CONFIG_DIR.
 *
 * The regression #509 asks for: on a fresh store with the bars not yet met,
 * a dangerous call is audited as a would-stop and NOT stopped; once the audit
 * history meets both bars, the SAME call is enforced. Plus the demotion path
 * through the real hook: forged would-block rows produce a loud demotion
 * (stderr, audited transition, notify row, channel notice), never a silent one.
 *
 * Everything real comes from `dist` except the one edge that would leave the
 * box — the webhook channel — swapped for a file-evidence fake through the
 * SHIELDCORTEX_DIST_ROOT seam (same technique as pre-tool-hook-notify-143).
 * The OpenClaw card channel is deliberately NOT configured here: it would
 * dial a real gateway.
 *
 * Addendum 1 / owner decision 29 Sep 2026 (option A): promotion ALWAYS needs
 * the two readiness proxies AND reviewed effectiveness evidence, and no
 * setting drops it. None ships, so the promotion tests run against a dist
 * whose guard-readiness.js carries a reviewed-evidence entry for the pin under
 * test (`writeReadinessShim(true)`) — standing for a future build that ships
 * reviewed evidence, never a config key. The shipped registry (empty) is
 * proven never to promote, including with the removed legacy key set to
 * `false` in config. Seeded evidence is pinned to the
 * adapter + policy version of the build under test. The floors — the
 * catastrophic tier and the session-lease freeze — are asserted identical in
 * shadow, enforcing and demoted states.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from '@jest/globals';
import { execSync, spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const REAL_DIST = join(repoRoot, 'dist');

const DANGEROUS = { command: 'sudo modprobe softdog' };
const BENIGN = { command: 'ls -la' };
const FROZEN_PUBLISH = { command: 'npm publish' };
const DAY = 24 * 60 * 60 * 1000;

interface HookResult { decision?: string; reason?: string; stderr: string }

describe('#509 — enforce-when-ready through the real Claude Code hook', () => {
  let home: string;
  let distRoot: string;
  let evidenceFile: string;
  let seq = 0;
  let pin: { adapter: string; policy: string };

  beforeAll(async () => {
    if (!existsSync(join(REAL_DIST, 'defence', 'iron-dome', 'guard-readiness.js'))) {
      execSync('npm run build:ts', { cwd: repoRoot, stdio: 'ignore' });
    }
    const mod = await import(pathToFileURL(join(REAL_DIST, 'defence', 'iron-dome', 'guard-readiness.js')).href);
    pin = mod.currentReadinessPin();
    expect(pin).toBeTruthy();
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-509-hook-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    evidenceFile = join(home, 'webhook-evidence.jsonl');
    // A parallel dist: every iron-dome module re-exported from the real build,
    // except the webhook channel, which records instead of POSTing.
    distRoot = mkdtempSync(join(tmpdir(), 'sc-509-dist-'));
    const realIron = join(REAL_DIST, 'defence', 'iron-dome');
    const shimIron = join(distRoot, 'defence', 'iron-dome');
    mkdirSync(shimIron, { recursive: true });
    for (const f of readdirSync(realIron)) {
      if (!f.endsWith('.js') || f === 'webhook-notify-channel.js' || f === 'guard-readiness.js') continue;
      writeFileSync(join(shimIron, f), `export * from ${JSON.stringify(pathToFileURL(join(realIron, f)).href)};\n`);
    }
    writeReadinessShim(true);
    writeFileSync(
      join(shimIron, 'webhook-notify-channel.js'),
      [
        "import { appendFileSync } from 'node:fs';",
        'export function createWebhookNotifyChannel(opts) {',
        '  return {',
        "    name: 'webhook',",
        '    async send(n) {',
        "      appendFileSync(new URL(opts.url).searchParams.get('evidence'), JSON.stringify(n) + '\\n');",
        '      return { delivered: true };',
        '    },',
        '  };',
        '}',
      ].join('\n'),
    );
    writeConfig({ readinessGate: true });
    // What `shieldcortex config --action-guard-enforce-when-ready` does:
    // start the durable transition record.
    appendRecord({ ts: new Date(Date.now() - 30 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'test posture' });
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(distRoot, { recursive: true, force: true });
  });

  /**
   * guard-readiness.js in the shim dist. `true`: the real module, except that
   * the hook's resolveReadiness sees one reviewed-evidence entry for the pin
   * in force — a build that ships reviewed evidence. `false`: the real module
   * as shipped (empty registry).
   */
  function writeReadinessShim(reviewed: boolean): void {
    const real = JSON.stringify(pathToFileURL(join(REAL_DIST, 'defence', 'iron-dome', 'guard-readiness.js')).href);
    const target = join(distRoot, 'defence', 'iron-dome', 'guard-readiness.js');
    if (!reviewed) {
      writeFileSync(target, `export * from ${real};\n`);
      return;
    }
    writeFileSync(target, [
      `import * as real from ${real};`,
      `export * from ${real};`,
      'const pin = real.currentReadinessPin();',
      'const REVIEWED = pin ? [{ ...pin, reviewedAt: new Date(Date.now() - 86400000).toISOString(),',
      "  reviewedBy: 'test fixture reviewer', reference: 'test fixture: a build shipping reviewed evidence', cases: 60 }] : [];",
      'export function resolveReadiness(opts) { return real.resolveReadiness({ ...opts, effectivenessRegistry: REVIEWED }); }',
    ].join('\n'));
  }

  function writeConfig(extra: Record<string, unknown>): void {
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({
        actionGuard: {
          enabled: true,
          enforce: true,
          notify: { enabled: true, webhookUrl: `http://fake-webhook.invalid/h?evidence=${encodeURIComponent(evidenceFile)}` },
          ...extra,
        },
      }),
    );
  }

  const auditDir = () => join(home, '.shieldcortex', 'audit');
  const statePath = () => join(home, '.shieldcortex', 'approvals', 'guard-readiness.json');
  const recordPath = () => join(home, '.shieldcortex', 'approvals', 'guard-readiness-transitions.jsonl');

  function appendRecord(entry: Record<string, unknown>): void {
    mkdirSync(dirname(recordPath()), { recursive: true });
    appendFileSync(recordPath(), `${JSON.stringify(entry)}\n`);
  }

  function recordEntries(): Array<Record<string, unknown>> {
    return readFileSync(recordPath(), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
  }

  function rows(): Array<Record<string, unknown>> {
    if (!existsSync(auditDir())) return [];
    return readdirSync(auditDir())
      .filter((f) => f.startsWith('realtime-'))
      .flatMap((f) => readFileSync(join(auditDir(), f), 'utf8').split('\n').filter(Boolean))
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  }

  function seed(list: Array<Record<string, unknown>>): void {
    mkdirSync(auditDir(), { recursive: true });
    for (const r of list) {
      seq += 1;
      const full = { auditEventId: `seed${seq}`, readinessPin: pin, ...r };
      appendFileSync(join(auditDir(), `realtime-${String(full.ts).slice(0, 10)}.jsonl`), `${JSON.stringify(full)}\n`);
    }
  }

  /** Synthetic history that meets both readiness proxies: 1000 calls over 8
   *  days at 0.5% would-stop, and 25 reached round-trips in the last day. */
  function seedReadyHistory(): void {
    const now = Date.now();
    const list: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 1000; i += 1) {
      const ts = new Date(now - 8 * DAY + Math.floor((i * 8 * DAY) / 1000) + 1000).toISOString();
      const stop = i < 5;
      list.push({ ts, type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: stop ? 'high' : 'low', action: stop ? 'require_approval' : 'allow', outcome: stop ? 'would_hold' : 'allowed' });
    }
    for (let i = 0; i < 25; i += 1) {
      const t = now - DAY + i * 60_000;
      list.push({ ts: new Date(t).toISOString(), type: 'approval_reach', reachId: `seed-${i}`, attemptId: `seed-a${i}`, phase: 'request' });
      list.push({ ts: new Date(t + 30_000).toISOString(), type: 'approval_reach', reachId: `seed-${i}`, attemptId: `seed-a${i}`, phase: 'answer', answer: 'approve' });
    }
    seed(list);
  }

  function runHook(input: Record<string, unknown>, permissionMode = 'default'): HookResult {
    const payload = JSON.stringify({
      session_id: 'sc-509', cwd: '/tmp', hook_event_name: 'PreToolUse',
      permission_mode: permissionMode, tool_name: 'Bash', tool_input: input,
    });
    const run = spawnSync('node', [HOOK], {
      input: payload,
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        SHIELDCORTEX_DIST_ROOT: distRoot,
        SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'),
      } as NodeJS.ProcessEnv,
      timeout: 30_000,
      encoding: 'utf8',
    });
    const stdout = run.stdout ?? '';
    const stderr = run.stderr ?? '';
    if (!stdout.trim()) return { stderr };
    const out = JSON.parse(stdout).hookSpecificOutput ?? {};
    return { decision: out.permissionDecision, reason: out.permissionDecisionReason, stderr };
  }

  it('#509 regression: proxies not met → audited as a would-stop and NOT stopped; proxies met + reviewed evidence in the build → the same call is enforced', () => {
    // Fresh isolated store, posture enforce-when-ready, no evidence.
    const shadowHeld = runHook(DANGEROUS, 'default');
    expect(shadowHeld.decision).toBeUndefined();
    expect(shadowHeld.stderr).toMatch(/shadow, enforce-when-ready/);
    const shadowBlocked = runHook(DANGEROUS, 'bypassPermissions');
    expect(shadowBlocked.decision).toBeUndefined();

    const verdictRows = rows().filter((r) => r.type === 'intercept' && r.action === 'require_approval');
    expect(verdictRows.map((r) => r.outcome)).toEqual(['would_hold', 'would_block']);
    expect(verdictRows.every((r) => r.shadow === true && r.origin === 'claude-code-hook')).toBe(true);
    expect(JSON.stringify(verdictRows)).not.toContain('modprobe');
    expect(rows().some((r) => r.outcome === 'asked' || r.outcome === 'denied_no_prompt_surface')).toBe(false);
    expect(JSON.parse(readFileSync(statePath(), 'utf8')).mode).toBe('shadow');

    // Bars met by synthetic history. The shadow answer is cached for one TTL,
    // so expire it the way time would.
    seedReadyHistory();
    rmSync(statePath());
    const enforced = runHook(DANGEROUS, 'default');
    expect(enforced.decision).toBe('ask');
    expect(enforced.stderr).toMatch(/now ENFORCING/);
    const promoted = rows().filter((r) => r.type === 'readiness_transition');
    expect(promoted.map((r) => r.to)).toEqual(['enforcing']);
    const blocked = runHook(DANGEROUS, 'bypassPermissions');
    expect(blocked.decision).toBe('deny');
  });

  it('benign calls leave a minimal tally row under the posture, and none under plain enforce', () => {
    runHook(BENIGN);
    const tally = rows().filter((r) => r.readinessTally === true);
    expect(tally).toHaveLength(1);
    expect(tally[0].outcome).toBe('allowed');
    expect(JSON.stringify(tally[0])).not.toContain('ls -la');

    rmSync(auditDir(), { recursive: true, force: true });
    writeConfig({});
    runHook(BENIGN);
    expect(rows().filter((r) => r.readinessTally === true)).toHaveLength(0);
  });

  it('plain enforce (no readiness gate) is unchanged: the dangerous call is asked', () => {
    writeConfig({});
    expect(runHook(DANGEROUS, 'default').decision).toBe('ask');
    expect(existsSync(statePath())).toBe(false);
  });

  it('option A: effectiveness evidence ALWAYS required — the shipped (empty) registry with perfect proxies stays in shadow, no promotion', () => {
    writeReadinessShim(false);
    writeConfig({ readinessGate: true });
    seedReadyHistory();
    for (let i = 0; i < 3; i += 1) {
      const r = runHook(DANGEROUS, 'default');
      expect(r.decision).toBeUndefined();
      expect(r.stderr).toMatch(/shadow, enforce-when-ready/);
      expect(r.stderr).not.toMatch(/now ENFORCING/);
      rmSync(statePath(), { force: true }); // expire the cache: recompute every call
    }
    expect(rows().filter((r) => r.type === 'readiness_transition')).toHaveLength(0);
    runHook(DANGEROUS, 'default');
    const st = JSON.parse(readFileSync(statePath(), 'utf8'));
    expect(st.mode).toBe('shadow');
    expect(st.missing).toEqual(['operability proxies met; awaiting reviewed effectiveness evidence']);
    // The hook's own rows carry the pin they were produced under.
    const own = rows().filter((r) => r.type === 'intercept' && r.shadow === true);
    expect(own.length).toBeGreaterThan(0);
    expect(own.every((r) => JSON.stringify(r.readinessPin) === JSON.stringify(pin))).toBe(true);
  });

  it('Addendum 1 (C): history pinned to another adapter/policy version does not promote', () => {
    const now = Date.now();
    const old = { adapter: 'claude-code-hook@0.0.1', policy: 'tool-action-guard:ffffffffffffffff' };
    const list: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 1000; i += 1) {
      list.push({ ts: new Date(now - 8 * DAY + i * 600_000).toISOString(), type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: 'low', action: 'allow', outcome: 'allowed', readinessPin: old });
    }
    for (let i = 0; i < 25; i += 1) {
      const t = now - DAY + i * 60_000;
      list.push({ ts: new Date(t).toISOString(), type: 'approval_reach', reachId: `old-${i}`, attemptId: `old-a${i}`, phase: 'request', readinessPin: old });
      list.push({ ts: new Date(t + 30_000).toISOString(), type: 'approval_reach', reachId: `old-${i}`, attemptId: `old-a${i}`, phase: 'answer', answer: 'approve', readinessPin: old });
    }
    seed(list);
    const r = runHook(DANGEROUS, 'default');
    expect(r.decision).toBeUndefined();
    expect(rows().filter((x) => x.type === 'readiness_transition')).toHaveLength(0);
  });

  it('an enforced hold put to the channel leaves approval-reach request evidence', () => {
    seedReadyHistory();
    const r = runHook(DANGEROUS, 'default');
    expect(r.decision).toBe('ask');
    const reach = rows().filter((x) => x.type === 'approval_reach' && !String(x.reachId).startsWith('seed-'));
    expect(reach).toHaveLength(1);
    expect(reach[0].phase).toBe('request');
    expect(reach[0].channel).toBe('webhook');
    // The attempt's correlation id is the one the approval store minted.
    const store = JSON.parse(readFileSync(join(home, '.shieldcortex', 'approvals', 'approvals.json'), 'utf8'));
    expect(typeof reach[0].attemptId).toBe('string');
    expect(store.records.map((r: { reachAttemptId?: string }) => r.reachAttemptId)).toContain(reach[0].attemptId);
  });

  it('forged would-block rows demote LOUDLY through the hook: stderr, audited transition, notify row, channel notice — then shadow', () => {
    seedReadyHistory();
    expect(runHook(BENIGN).stderr).toMatch(/now ENFORCING/);
    // Same-UID forgery appended to the audit.
    const now = Date.now();
    const forged: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 300; i += 1) {
      forged.push({ ts: new Date(now - 1000 + i).toISOString(), type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: 'high', action: 'require_approval', outcome: 'would_block' });
    }
    seed(forged);
    // Time passing, expressed through the cache: it expired, and the bars have
    // been failing since before the grace window.
    const st = JSON.parse(readFileSync(statePath(), 'utf8'));
    writeFileSync(statePath(), JSON.stringify({ ...st, computedAt: new Date(now - 11 * 60_000).toISOString(), failingSince: new Date(now - 2 * 60 * 60_000).toISOString() }));

    const demoting = runHook(BENIGN);
    expect(demoting.stderr).toMatch(/DEMOTED to shadow mode/);
    const transitions = rows().filter((r) => r.type === 'readiness_transition');
    expect(transitions.map((r) => r.to)).toEqual(['enforcing', 'shadow']);
    const notifyRow = rows().find((r) => r.action === 'notify' && r.readinessTransition === 'demote');
    expect(notifyRow?.outcome).toBe('notified');
    const notices = readFileSync(evidenceFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    expect(notices.some((n) => n.outcome === 'readiness_demoted' && /DEMOTED to shadow/.test(n.reason))).toBe(true);

    // And the demotion is real: the dangerous call now proceeds, recorded.
    expect(runHook(DANGEROUS, 'default').decision).toBeUndefined();
  });

  // ── Addendum 1 (D): the floors are untouched in every state ──────────────

  /** A DEMOTED install: it enforced, then the evidence failed and it dropped
   *  to shadow. Fresh cache, so the hook applies shadow without recomputing. */
  function seedDemoted(): void {
    const now = Date.now();
    seed([
      { ts: new Date(now - 2 * DAY).toISOString(), type: 'readiness_transition', origin: 'claude-code-hook', from: 'shadow', to: 'enforcing' },
      { ts: new Date(now - 10 * 60_000).toISOString(), type: 'readiness_transition', origin: 'claude-code-hook', from: 'enforcing', to: 'shadow', reason: 'test' },
    ]);
    appendRecord({ ts: new Date(now - 2 * DAY).toISOString(), event: 'promote', to: 'enforcing', pin });
    appendRecord({ ts: new Date(now - 10 * 60_000).toISOString(), event: 'demote', to: 'shadow', pin, reason: 'test' });
    mkdirSync(dirname(statePath()), { recursive: true });
    writeFileSync(statePath(), JSON.stringify({
      version: 1,
      mode: 'shadow',
      computedAt: new Date(now - 60_000).toISOString(),
      pin,
      lastPromotedAt: new Date(now - 2 * DAY).toISOString(),
      lastDemotedAt: new Date(now - 10 * 60_000).toISOString(),
      lastDemotionReason: 'test',
    }));
  }

  it('the session-lease floor denies identically in shadow, demoted and plain-enforce states', () => {
    const ledger = join(home, '.shieldcortex', 'DECISIONS.md');
    writeFileSync(ledger, '| FROZEN | 2026-09-28 | nobody publishes to npm until review |\n');
    const decide = () => {
      const r = runHook(FROZEN_PUBLISH, 'default');
      return { decision: r.decision, reason: r.reason };
    };

    // Shadow (fresh store): prove it IS shadow, then the freeze still binds.
    expect(runHook(DANGEROUS, 'default').decision).toBeUndefined();
    const inShadow = decide();

    // Demoted.
    rmSync(auditDir(), { recursive: true, force: true });
    rmSync(statePath(), { force: true });
    seedDemoted();
    expect(runHook(DANGEROUS, 'default').decision).toBeUndefined();
    const inDemoted = decide();

    // Plain enforce, no readiness gate: the reference behaviour.
    writeConfig({});
    const inEnforce = decide();

    expect(inEnforce.decision).toBe('deny');
    expect(inEnforce.reason).toMatch(/FROZEN/);
    expect(inShadow).toEqual(inEnforce);
    expect(inDemoted).toEqual(inEnforce);
  });

  it('the catastrophic floor is applied before the shadow branch can run (structural: the hook source order)', () => {
    // A catastrophic-tier fixture could not be written into this suite: the
    // Action Guard refuses to write catastrophic command text into a file
    // (write-content-catastrophic). So this asserts the wiring instead: the
    // terminal block (catastrophic/critical) and the session-lease refusal
    // both return BEFORE the one place shadow mode is consulted, and nothing
    // between the gate and that branch reads `shadow`.
    const src = readFileSync(HOOK, 'utf8');
    const gate = src.indexOf('const whenReady = cfg.enforce && cfg.readinessGate === true');
    const lease = src.indexOf("leaseGate && leaseGate.decision.verdict !== 'allow'");
    const terminal = src.indexOf("if (verdict.decision === 'block' && TERMINAL_BLOCK_SEVERITIES.has(verdict.severity))");
    const shadowBranch = src.indexOf('if (shadow && !unscannedBlock && !selfProtected)');
    for (const at of [gate, lease, terminal, shadowBranch]) expect(at).toBeGreaterThan(-1);
    expect(lease).toBeLessThan(gate);
    expect(gate).toBeLessThan(terminal);
    expect(terminal).toBeLessThan(shadowBranch);
    expect(src).toMatch(/const TERMINAL_BLOCK_SEVERITIES = new Set\(\['catastrophic', 'critical'\]\)/);
    const between = src.slice(gate, shadowBranch);
    const shadowReads = between.match(/\bshadow\b(?!:)/g) ?? [];
    // Declared, assigned from the resolved mode, reset on error — never branched on.
    expect(between).not.toMatch(/if \([^)]*\bshadow\b/);
    expect(shadowReads.length).toBeGreaterThan(0);
  });
  // ── Round 3 (GPT-6 review of a850d3ee) ──────────────────────────────────

  const WHEN_READY_FLAG = { command: 'shieldcortex config --action-guard-enforce-when-ready' };

  it('r3 finding 1: on a plain-enforcing install, `config --action-guard-enforce-when-ready` needs approval like --action-guard-advisory', () => {
    writeConfig({});
    const asked = runHook(WHEN_READY_FLAG, 'default');
    expect(asked.decision).toBe('ask');
    const audited = rows().filter((r) => r.type === 'intercept' && r.action === 'require_approval');
    // (The signal name itself is not on the audit's safe-signal list, so the
    // row records the gated verdict, not which rule fired.)
    expect(audited).toHaveLength(1);
    expect(runHook(WHEN_READY_FLAG, 'bypassPermissions').decision).toBe('deny');
    expect(runHook({ command: 'shieldcortex config --action-guard-advisory' }, 'default').decision).toBe('ask');
  });

  it('r3 finding 1: from OFF it is a tightening and stays ungated; from watch-only the R4-1 self-protection floor holds it', () => {
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: false } }));
    expect(runHook(WHEN_READY_FLAG, 'default').decision).toBeUndefined();
    // R4-1 (ROUND4.md): `disable-action-guard`, including this flag, is on the
    // floor in EVERY posture — watch-only too. A tightening held for approval
    // is the disclosed cost (design doc, residuals).
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: false } }));
    expect(runHook(WHEN_READY_FLAG, 'default').decision).toBe('ask');
  });

  it('r3 finding 2: promoted, then a forged fresh shadow cache + failing evidence ⇒ a LOUD demotion through the hook, never a silent one', () => {
    seedReadyHistory();
    expect(runHook(BENIGN).stderr).toMatch(/now ENFORCING/);
    const now = Date.now();
    const forged: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 300; i += 1) {
      forged.push({ ts: new Date(now - 1000 + i).toISOString(), type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: 'high', action: 'require_approval', outcome: 'would_block' });
    }
    seed(forged);
    writeFileSync(statePath(), JSON.stringify({ version: 1, mode: 'shadow', computedAt: new Date().toISOString(), pin }));

    const r = runHook(BENIGN);
    expect(r.stderr).toMatch(/tamper signal/);
    expect(r.stderr).toMatch(/DEMOTED to shadow mode/);
    expect(rows().filter((x) => x.type === 'readiness_transition').map((x) => x.to)).toEqual(['enforcing', 'shadow']);
    expect(rows().some((x) => x.type === 'readiness_tamper')).toBe(true);
    const notices = readFileSync(evidenceFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    expect(notices.some((n) => n.outcome === 'readiness_demoted')).toBe(true);
    expect(recordEntries().map((e) => e.event).filter((e) => e !== 'notice')).toEqual(['init', 'promote', 'tamper', 'demote']);
    // r5: both transitions were announced, and the journal says so.
    expect(recordEntries().filter((e) => e.event === 'notice').map((e) => [e.of, e.delivered])).toEqual([['promote', true], ['demote', true]]);
  });

  it('r3 finding 2: promoted, forged fresh shadow cache, evidence still ready ⇒ the dangerous call is still ENFORCED', () => {
    seedReadyHistory();
    expect(runHook(BENIGN).stderr).toMatch(/now ENFORCING/);
    for (let i = 0; i < 3; i += 1) {
      writeFileSync(statePath(), JSON.stringify({ version: 1, mode: 'shadow', computedAt: new Date().toISOString(), pin }));
      expect(runHook(DANGEROUS, 'default').decision).toBe('ask');
    }
  });

  it('r3 finding 3: a lost transition record is announced as a demotion by the hook, never read as never-ready', () => {
    rmSync(recordPath());
    const r = runHook(BENIGN);
    expect(r.stderr).toMatch(/DEMOTED to shadow mode/);
    expect(r.stderr).toMatch(/transition record is missing or unreadable/);
    expect(recordEntries().map((e) => e.event).filter((e) => e !== 'notice')).toEqual(['demote']);
  });

  // ── Round 5 ────────────────────────────────────────────────────────────

  it('r5 finding 2: GPT-6 fixture — 500 calls / 8 days / 20 answered, valid webhook, EMPTY registry, legacy key false ⇒ never promotes', () => {
    writeReadinessShim(false);
    writeConfig({ readinessGate: true, readinessRequireEffectivenessEvidence: false });
    const now = Date.now();
    const list: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 500; i += 1) {
      list.push({ ts: new Date(now - 8 * DAY + Math.floor((i * 8 * DAY) / 500) + 1000).toISOString(), type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: 'low', action: 'allow', outcome: 'allowed' });
    }
    for (let i = 0; i < 20; i += 1) {
      const t = now - DAY + i * 60_000;
      list.push({ ts: new Date(t).toISOString(), type: 'approval_reach', reachId: `g-${i}`, attemptId: `g-a${i}`, phase: 'request' });
      list.push({ ts: new Date(t + 30_000).toISOString(), type: 'approval_reach', reachId: `g-${i}`, attemptId: `g-a${i}`, phase: 'answer', answer: 'approve' });
    }
    seed(list);
    const r = runHook(DANGEROUS, 'default');
    expect(r.decision).toBeUndefined();
    expect(r.stderr).not.toMatch(/now ENFORCING/);
    expect(rows().filter((x) => x.type === 'readiness_transition')).toHaveLength(0);
    const st = JSON.parse(readFileSync(statePath(), 'utf8'));
    expect(st.mode).toBe('shadow');
    expect(st.missing).toEqual(['operability proxies met; awaiting reviewed effectiveness evidence']);
    expect(recordEntries().some((e) => e.event === 'promote')).toBe(false);
  });

  it('r5 finding 1: a promotion is announced on the push channel when it happens, and the journal records the notice as delivered', () => {
    seedReadyHistory();
    const r = runHook(BENIGN);
    expect(r.stderr).toMatch(/now ENFORCING/);
    const notices = readFileSync(evidenceFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    expect(notices.filter((n) => n.outcome === 'readiness_promoted')).toHaveLength(1);
    const promote = recordEntries().find((e) => e.event === 'promote')!;
    const notice = recordEntries().find((e) => e.event === 'notice')!;
    expect(notice).toMatchObject({ of: 'promote', transitionTs: promote.ts, delivered: true, channel: 'webhook' });
    expect(rows().some((x) => x.action === 'notify' && x.readinessTransition === 'promote' && x.outcome === 'notified')).toBe(true);
  });

  it('r5 finding 1: a promotion whose notice was NOT delivered is recorded as such, and the readiness summary reports it', async () => {
    writeFileSync(
      join(distRoot, 'defence', 'iron-dome', 'webhook-notify-channel.js'),
      "export function createWebhookNotifyChannel() { return { name: 'webhook', async send() { return { delivered: false, reason: 'receiver down' }; } }; }\n",
    );
    seedReadyHistory();
    expect(runHook(BENIGN).stderr).toMatch(/now ENFORCING/);
    const promote = recordEntries().find((e) => e.event === 'promote')!;
    const notice = recordEntries().find((e) => e.event === 'notice')!;
    expect(notice).toMatchObject({ of: 'promote', transitionTs: promote.ts, delivered: false });
    const mod = await import(pathToFileURL(join(REAL_DIST, 'defence', 'iron-dome', 'guard-readiness.js')).href);
    const p = mod.lastPromotion(mod.readTransitionRecord(recordPath()));
    expect(p).toMatchObject({ promotedAt: promote.ts, notice: 'failed' });
  });

  it('r5 finding 1: a promotion with NO notice attempt (the hook died, or a forged journal) reads as "none"', async () => {
    const mod = await import(pathToFileURL(join(REAL_DIST, 'defence', 'iron-dome', 'guard-readiness.js')).href);
    const at = new Date(Date.now() - DAY).toISOString();
    appendRecord({ ts: at, event: 'promote', to: 'enforcing', pin });
    expect(mod.lastPromotion(mod.readTransitionRecord(recordPath()))).toEqual({ promotedAt: at, notice: 'none' });
    const { describePromotionNotice } = await import(pathToFileURL(join(REAL_DIST, 'cli', 'guard.js')).href);
    expect(describePromotionNotice({ promotedAt: at, notice: 'none' })).toMatch(/NO notice attempt recorded/);
  });
});
