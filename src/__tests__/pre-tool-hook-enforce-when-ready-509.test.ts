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
 * Addendum 1: promotion needs the two readiness proxies AND reviewed
 * effectiveness evidence (required by default, none shipped), so the
 * promotion tests set `readinessRequireEffectivenessEvidence: false` and one
 * test proves the default never promotes. Seeded evidence is pinned to the
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
/** Promotion on the two proxies alone (Addendum 1 B switched off). */
const PROXIES_ONLY = { readinessRequireEffectivenessEvidence: false };

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
      if (!f.endsWith('.js') || f === 'webhook-notify-channel.js') continue;
      writeFileSync(join(shimIron, f), `export * from ${JSON.stringify(pathToFileURL(join(realIron, f)).href)};\n`);
    }
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
    writeConfig({ readinessGate: true, ...PROXIES_ONLY });
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(distRoot, { recursive: true, force: true });
  });

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
      list.push({ ts: new Date(t).toISOString(), type: 'approval_reach', reachId: `seed-${i}`, phase: 'request' });
      list.push({ ts: new Date(t + 30_000).toISOString(), type: 'approval_reach', reachId: `seed-${i}`, phase: 'answer', answer: 'approve' });
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

  it('#509 regression: proxies not met → audited as a would-stop and NOT stopped; proxies met (evidence not required) → the same call is enforced', () => {
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

  it('Addendum 1 (B) default: effectiveness evidence REQUIRED — perfect proxies, and the same call stays in shadow with no promotion', () => {
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
      list.push({ ts: new Date(t).toISOString(), type: 'approval_reach', reachId: `old-${i}`, phase: 'request', readinessPin: old });
      list.push({ ts: new Date(t + 30_000).toISOString(), type: 'approval_reach', reachId: `old-${i}`, phase: 'answer', answer: 'approve', readinessPin: old });
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
    const shadowBranch = src.indexOf('if (shadow && !unscannedBlock)');
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
});
