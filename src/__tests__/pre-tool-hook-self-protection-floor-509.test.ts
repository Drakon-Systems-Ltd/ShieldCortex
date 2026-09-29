/**
 * #509 round 4 (R4-1): the guard self-protection floor, through the BUILT
 * scripts/pre-tool-hook.mjs against an isolated HOME / SHIELDCORTEX_CONFIG_DIR.
 *
 * GPT-6's r2 confirmation: after a promotion aged out of the audit, an agent
 * in SHADOW mode could append a valid-looking `init → shadow` entry to the
 * transition record and write a fresh shadow cache. Both writes classify as
 * `require_approval` — but shadow turns that into a would-hold and the call
 * proceeds, so the guard's own state was writable exactly when it mattered.
 *
 * The floor: a verdict carrying a guard self-protection signal
 * (GUARD_SELF_PROTECTION_SIGNALS) is enforced in every posture and mode —
 * shadow, demoted, enforcing and watch-only — like the catastrophic tier and
 * the lease floor. An ordinary dangerous-tier call in shadow is still only
 * would-held, so the posture keeps its meaning.
 *
 * The webhook channel is swapped for a file-evidence fake through the
 * SHIELDCORTEX_DIST_ROOT seam (same technique as the sibling #509 suite).
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
const DAY = 24 * 60 * 60 * 1000;
const DANGEROUS = { command: 'sudo modprobe softdog' };
const BENIGN = { command: 'ls -la' };

interface HookResult { decision?: string; stderr: string }

describe('#509 R4-1 — the guard self-protection floor through the real hook', () => {
  let home: string;
  let distRoot: string;
  let pin: { adapter: string; policy: string };
  let seq = 0;

  beforeAll(async () => {
    if (!existsSync(join(REAL_DIST, 'defence', 'iron-dome', 'guard-readiness.js'))) {
      execSync('npm run build:ts', { cwd: repoRoot, stdio: 'ignore' });
    }
    const mod = await import(pathToFileURL(join(REAL_DIST, 'defence', 'iron-dome', 'guard-readiness.js')).href);
    pin = mod.currentReadinessPin();
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-509-floor-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    distRoot = mkdtempSync(join(tmpdir(), 'sc-509-floor-dist-'));
    const realIron = join(REAL_DIST, 'defence', 'iron-dome');
    const shimIron = join(distRoot, 'defence', 'iron-dome');
    mkdirSync(shimIron, { recursive: true });
    for (const f of readdirSync(realIron)) {
      if (!f.endsWith('.js') || f === 'webhook-notify-channel.js') continue;
      writeFileSync(join(shimIron, f), `export * from ${JSON.stringify(pathToFileURL(join(realIron, f)).href)};\n`);
    }
    writeFileSync(
      join(shimIron, 'webhook-notify-channel.js'),
      "export function createWebhookNotifyChannel() { return { name: 'webhook', async send() { return { delivered: true }; } }; }\n",
    );
    writeConfig({ enforce: true, readinessGate: true, readinessRequireEffectivenessEvidence: false });
    appendRecord({ ts: new Date(Date.now() - 30 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'test posture' });
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(distRoot, { recursive: true, force: true });
  });

  const shieldDir = () => join(home, '.shieldcortex');
  const auditDir = () => join(shieldDir(), 'audit');
  const statePath = () => join(shieldDir(), 'approvals', 'guard-readiness.json');
  const recordPath = () => join(shieldDir(), 'approvals', 'guard-readiness-transitions.jsonl');

  function writeConfig(guard: Record<string, unknown>): void {
    writeFileSync(join(shieldDir(), 'config.json'), JSON.stringify({
      actionGuard: { enabled: true, notify: { enabled: true, webhookUrl: 'http://fake-webhook.invalid/h' }, ...guard },
    }));
  }

  function appendRecord(entry: Record<string, unknown>): void {
    mkdirSync(dirname(recordPath()), { recursive: true });
    appendFileSync(recordPath(), `${JSON.stringify(entry)}\n`);
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

  function runHook(toolName: string, input: Record<string, unknown>, permissionMode = 'default'): HookResult {
    const payload = JSON.stringify({
      session_id: 'sc-509-floor', cwd: '/tmp', hook_event_name: 'PreToolUse',
      permission_mode: permissionMode, tool_name: toolName, tool_input: input,
    });
    const run = spawnSync('node', [HOOK], {
      input: payload,
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        SHIELDCORTEX_DIST_ROOT: distRoot,
        SHIELDCORTEX_CONFIG_DIR: shieldDir(),
      } as NodeJS.ProcessEnv,
      timeout: 30_000,
      encoding: 'utf8',
    });
    const stdout = run.stdout ?? '';
    if (!stdout.trim()) return { stderr: run.stderr ?? '' };
    const out = JSON.parse(stdout).hookSpecificOutput ?? {};
    return { decision: out.permissionDecision, stderr: run.stderr ?? '' };
  }

  /** The r2 forgery, as the three agent tool calls that would perform it,
   *  plus the other guard-state and guard-config writes the floor covers. */
  function guardStateWrites(): Array<[string, Record<string, unknown>]> {
    const forgedInit = JSON.stringify({ ts: new Date().toISOString(), event: 'init', to: 'shadow', reason: 'forged' });
    const forgedCache = JSON.stringify({ version: 1, mode: 'shadow', computedAt: new Date().toISOString(), pin });
    return [
      ['Bash', { command: `printf '%s\\n' '${forgedInit}' >> ~/.shieldcortex/approvals/guard-readiness-transitions.jsonl` }],
      ['Write', { file_path: statePath(), content: forgedCache }],
      ['Write', { file_path: recordPath(), content: `${forgedInit}\n` }],
      ['Edit', { file_path: statePath(), old_string: '"enforcing"', new_string: '"shadow"' }],
      ['Bash', { command: 'echo {} > ~/.shieldcortex/approvals/approvals.json' }],
      ['Write', { file_path: join(shieldDir(), 'config.json'), content: '{"actionGuard":{"enabled":false}}' }],
      ['Bash', { command: 'shieldcortex config --action-guard-disable' }],
    ];
  }

  /** Every write must be HELD: `ask` where a prompt can be raised, `deny`
   *  where it cannot. Never a silent pass, never a would-hold row. */
  function expectAllHeld(label: string): void {
    for (const [tool, input] of guardStateWrites()) {
      const asked = runHook(tool, input, 'default');
      expect({ label, tool, input, decision: asked.decision }).toEqual({ label, tool, input, decision: 'ask' });
      const denied = runHook(tool, input, 'bypassPermissions');
      expect({ label, tool, input, decision: denied.decision }).toEqual({ label, tool, input, decision: 'deny' });
    }
  }

  function stateSnapshot(): string {
    return [statePath(), recordPath()].map((p) => (existsSync(p) ? readFileSync(p, 'utf8') : '<absent>')).join('\n---\n');
  }

  function seedDemoted(): void {
    const now = Date.now();
    appendRecord({ ts: new Date(now - 2 * DAY).toISOString(), event: 'promote', to: 'enforcing', pin });
    appendRecord({ ts: new Date(now - 10 * 60_000).toISOString(), event: 'demote', to: 'shadow', pin, reason: 'test' });
    mkdirSync(dirname(statePath()), { recursive: true });
    writeFileSync(statePath(), JSON.stringify({
      version: 1, mode: 'shadow', computedAt: new Date(now - 60_000).toISOString(), pin,
      lastPromotedAt: new Date(now - 2 * DAY).toISOString(), lastDemotedAt: new Date(now - 10 * 60_000).toISOString(), lastDemotionReason: 'test',
    }));
  }

  it('SHADOW: guard-state, transition-record, approval-store and guard-config writes are HELD, not would-held', () => {
    expect(runHook('Bash', BENIGN).stderr).not.toMatch(/now ENFORCING/);
    expect(JSON.parse(readFileSync(statePath(), 'utf8')).mode).toBe('shadow');
    expectAllHeld('shadow');
    const floorRows = rows().filter((r) => r.type === 'intercept' && r.action === 'require_approval');
    expect(floorRows.length).toBeGreaterThan(0);
    expect(floorRows.some((r) => r.outcome === 'would_hold' || r.outcome === 'would_block')).toBe(false);
  });

  it('SHADOW: an ordinary dangerous-tier call is still only would-held — the posture keeps its meaning', () => {
    const r = runHook('Bash', DANGEROUS, 'default');
    expect(r.decision).toBeUndefined();
    expect(r.stderr).toMatch(/shadow, enforce-when-ready/);
    const b = runHook('Bash', DANGEROUS, 'bypassPermissions');
    expect(b.decision).toBeUndefined();
    const outcomes = rows().filter((x) => x.type === 'intercept' && x.action === 'require_approval').map((x) => x.outcome);
    expect(outcomes).toEqual(['would_hold', 'would_block']);
  });

  it('DEMOTED: the same writes are HELD', () => {
    seedDemoted();
    expect(runHook('Bash', DANGEROUS, 'default').decision).toBeUndefined(); // really demoted
    expectAllHeld('demoted');
  });

  it('ENFORCING and WATCH-ONLY: the same writes are HELD', () => {
    seedReadyHistory();
    expect(runHook('Bash', BENIGN).stderr).toMatch(/now ENFORCING/);
    expectAllHeld('enforcing');
    writeConfig({ enforce: false });
    expectAllHeld('watch-only');
  });

  it('the r2 forgery (promotion aged out, forged init → shadow + fresh shadow cache) cannot be performed through the hook in any mode', () => {
    for (const mode of ['shadow', 'demoted', 'enforcing']) {
      rmSync(shieldDir(), { recursive: true, force: true });
      mkdirSync(shieldDir(), { recursive: true });
      writeConfig({ enforce: true, readinessGate: true, readinessRequireEffectivenessEvidence: false });
      appendRecord({ ts: new Date(Date.now() - 30 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'test posture' });
      if (mode === 'demoted') seedDemoted();
      if (mode === 'enforcing') {
        seedReadyHistory();
        expect(runHook('Bash', BENIGN).stderr).toMatch(/now ENFORCING/);
      } else {
        runHook('Bash', BENIGN);
      }
      const before = stateSnapshot();
      const [appendInit, writeCache] = guardStateWrites();
      for (const [tool, input] of [appendInit, writeCache]) {
        expect({ mode, tool, d: runHook(tool, input, 'bypassPermissions').decision }).toEqual({ mode, tool, d: 'deny' });
        expect({ mode, tool, d: runHook(tool, input, 'dontAsk').decision }).toEqual({ mode, tool, d: 'deny' });
        expect({ mode, tool, d: runHook(tool, input, 'default').decision }).toEqual({ mode, tool, d: 'ask' });
      }
      // The hook only decides; nothing it did wrote a forged entry.
      expect(stateSnapshot().includes('"forged"')).toBe(false);
      expect(before.includes('"forged"')).toBe(false);
    }
  });
});
