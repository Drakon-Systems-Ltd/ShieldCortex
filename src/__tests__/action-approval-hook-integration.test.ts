/**
 * #118 end-to-end: the PreToolUse guard hook, spawned as a real subprocess,
 * honours a one-shot operator approval for the exact command it refused.
 *
 * Asserts the whole loop the issue specified:
 *   refuse (and name the hash) → operator approves → same command passes once
 *   → the next identical call is refused again.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from '@jest/globals';
import { execFileSync, execSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const DANGEROUS = { command: 'sudo modprobe softdog' };

/** Run the hook against one tool call and return whatever it emitted on stdout. */
function runHook(home: string, input: Record<string, unknown>): { decision?: string; reason?: string } {
  const payload = JSON.stringify({
    session_id: 'approval-it',
    cwd: '/tmp',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: input,
    // #139: an attended mode, so this suite exercises the ONE-SHOT APPROVAL
    // path rather than the prompt-surface rule. With the field absent the hook
    // now denies outright — correct (a harness that will not say whether it can
    // prompt cannot be trusted to honour one), but a different test's subject.
    permission_mode: 'default',
  });
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  for (const key of Object.keys(env)) {
    if (key.startsWith('SHIELDCORTEX_')) delete (env as Record<string, string | undefined>)[key];
  }

  let stdout = '';
  try {
    stdout = execFileSync('node', [HOOK], { input: payload, env, timeout: 30_000, stdio: ['pipe', 'pipe', 'pipe'] }).toString();
  } catch (e) {
    stdout = (e as { stdout?: Buffer }).stdout?.toString() ?? '';
  }
  if (!stdout.trim()) return {};
  const parsed = JSON.parse(stdout);
  const out = parsed.hookSpecificOutput ?? {};
  return { decision: out.permissionDecision, reason: out.permissionDecisionReason };
}

describe('#118 — one-shot approval through the real guard hook', () => {
  let home: string;

  beforeAll(() => {
    // Build only when dist is absent: `build:ts` wipes dist, and doing that
    // mid-run races every parallel suite that reads a dist artefact (#125).
    const probes = [
      join(repoRoot, 'dist', 'index.js'),
      join(repoRoot, 'dist', 'defence', 'iron-dome', 'tool-action-guard.js'),
      join(repoRoot, 'dist', 'defence', 'iron-dome', 'action-approvals.js'),
    ];
    if (!probes.every((p) => existsSync(p))) {
      execSync('npm run build:ts', { cwd: repoRoot, stdio: 'ignore' });
    }
  }, 180_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-approval-it-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ actionGuard: { enabled: true, enforce: true } }),
    );
  });

  afterEach(() => {
    try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  it('refuses, names the approve hash, then passes exactly once after approval', async () => {
    // 1. Refused, and told how to approve.
    const refused = runHook(home, DANGEROUS);
    expect(refused.decision).toBe('ask');
    expect(refused.reason).toMatch(/shieldcortex approve [0-9a-f]{12}/);

    const hash = refused.reason!.match(/shieldcortex approve ([0-9a-f]{12})/)![1];

    // 2. The operator approves it in a terminal (TTY gate covered by the unit
    //    tests; here we call the store the CLI drives).
    const { approveRequest } = await import(
      join(repoRoot, 'dist', 'defence', 'iron-dome', 'action-approvals.js')
    );
    expect(approveRequest(hash, { home }).ok).toBe(true);

    // 3. Same command now passes: no decision emitted = deferred to the harness.
    expect(runHook(home, DANGEROUS).decision).toBeUndefined();

    // 4. Single use — the next identical call is refused again.
    const again = runHook(home, DANGEROUS);
    expect(again.decision).toBe('ask');
  }, 60_000);

  it('an approval for one command does not release a different one', async () => {
    const refused = runHook(home, DANGEROUS);
    const hash = refused.reason!.match(/shieldcortex approve ([0-9a-f]{12})/)![1];
    const { approveRequest } = await import(
      join(repoRoot, 'dist', 'defence', 'iron-dome', 'action-approvals.js')
    );
    approveRequest(hash, { home });

    // A different dangerous-tier command (not catastrophic — that path never
    // consults approvals at all, asserted separately below).
    expect(runHook(home, { command: 'sudo modprobe evdev' }).decision).toBe('ask');
  }, 60_000);

  it('leaves the catastrophic tier alone — approvals never reach it', async () => {
    const denied = runHook(home, { command: 'rm -rf /' });
    expect(denied.decision).toBe('deny');
    // Nothing was offered for approval on the hard-block path.
    expect(denied.reason ?? '').not.toMatch(/shieldcortex approve/);
  }, 60_000);
});
