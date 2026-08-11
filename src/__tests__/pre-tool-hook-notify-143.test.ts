/**
 * Failing-first end-to-end spec for the operator-notification transport on
 * the Claude Code hook path (#143).
 *
 * This is the surface the design doc names explicitly: every one of the 433
 * real stops measured on the Jarvis box in July happened here, where a
 * `require_approval` hold had no channel at all — only a hash printed in a
 * transcript nobody was watching. This test drives the REAL hook as a
 * subprocess with the REAL guard, approvals store, notify-config and
 * operator-notify modules from `dist` — everything except the one edge that
 * actually leaves the box, the webhook channel, which is swapped for a
 * file-evidence fake via `SHIELDCORTEX_DIST_ROOT` (the same seam
 * pre-tool-hook-broker-143.test.ts uses to swap in a fake `claude` binary
 * instead of a real model call). The fake's own contract (what a `send()`
 * result must look like) is pinned against the real implementation in
 * webhook-notify-channel.test.ts; this file is about the WIRING — does a held
 * request actually reach a configured channel, unaffected by success or
 * failure — not about HTTP semantics.
 *
 * Scope: this hook is one process per tool call with no attended-TUI concept
 * of its own (Claude Code's own "ask" dialog already covers that tier when a
 * session is interactive — see scripts/pre-tool-hook.mjs's existing,
 * unchanged `emitDecision('ask', ...)`). What this wiring adds is the
 * configured-channel tier: a best-effort ping fired ALONGSIDE the unchanged
 * hash-in-terminal fallback, never instead of it.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from '@jest/globals';
import { execSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const REAL_DIST = join(repoRoot, 'dist', 'defence', 'iron-dome');

const IRREVERSIBLE = { command: 'sudo modprobe softdog' };
const CATASTROPHIC = { command: 'rm -rf /' };
/** A dangerous command carried under `script`, not `command` (#183/#241). */
const WORKFLOW_FORCE_PUSH = 'await $`git push --force origin main`;';

interface HookResult { decision?: string; reason?: string; stderr: string }

describe('#143 — the operator-notify transport through the real Claude Code hook', () => {
  let home: string;
  let distRoot: string;
  let evidenceFile: string;

  beforeAll(() => {
    const probes = [
      'tool-action-guard.js', 'action-approvals.js',
      'notify-config.js', 'operator-notify.js', 'webhook-notify-channel.js',
    ].map((f) => join(REAL_DIST, f));
    if (!probes.every((p) => existsSync(p))) {
      execSync('npm run build:ts', { cwd: repoRoot, stdio: 'ignore' });
    }
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-notify-hook-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    evidenceFile = join(home, 'webhook-evidence.json');

    // A parallel "dist" that is the REAL build for every module except the
    // one that would leave the box. Re-exporting via a file:// specifier
    // keeps this a thin shim, not a reimplementation — every other test in
    // this file drives the ACTUAL notify-config.js / operator-notify.js /
    // action-approvals.js / tool-action-guard.js from `npm run build:ts`.
    distRoot = mkdtempSync(join(tmpdir(), 'sc-notify-dist-'));
    const ironDomeDir = join(distRoot, 'defence', 'iron-dome');
    mkdirSync(ironDomeDir, { recursive: true });
    for (const f of ['tool-action-guard.js', 'action-approvals.js', 'notify-config.js', 'operator-notify.js', 'script-source-resolver.js']) {
      const real = join(REAL_DIST, f);
      if (existsSync(real)) {
        writeFileSync(join(ironDomeDir, f), `export * from ${JSON.stringify(pathToFileURL(real).href)};\n`);
      }
    }
    // The fake channel. Its behaviour is steered by the query string on the
    // configured webhookUrl (`mode=success|fail|throw`), which is otherwise
    // just an ordinary http: URL as far as notify-config.ts's validation is
    // concerned — this file never makes a network call.
    writeFileSync(
      join(ironDomeDir, 'webhook-notify-channel.js'),
      [
        "import { writeFileSync as wf } from 'node:fs';",
        'export function createWebhookNotifyChannel(opts) {',
        '  return {',
        "    get name() { return new URL(opts.url).searchParams.get('channelName') || 'webhook'; },",
        '    async send(notification) {',
        '      const u = new URL(opts.url);',
        "      const mode = u.searchParams.get('mode') || 'success';",
        "      const evidencePath = u.searchParams.get('evidence');",
        "      const secret = u.searchParams.get('secret') || '';",
        "      if (mode === 'fail') return { delivered: false, reason: `simulated failure ${secret}` };",
        "      if (mode === 'throw') throw new Error(`simulated throw ${secret}`);",
        "      if (mode === 'hang') return new Promise(() => {});",
        '      if (evidencePath) wf(evidencePath, JSON.stringify(notification));',
        '      return { delivered: true };',
        '    },',
        '  };',
        '}',
      ].join('\n'),
    );
  });

  afterEach(() => {
    try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
    try { rmSync(distRoot, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  function writeConfig(notify?: Record<string, unknown>): void {
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ actionGuard: { enabled: true, enforce: true, notify } }),
    );
  }

  function webhookUrl(mode: 'success' | 'fail' | 'throw' | 'hang' = 'success'): string {
    return `http://fake-webhook.invalid/hook?mode=${mode}&evidence=${encodeURIComponent(evidenceFile)}`;
  }

  function auditRows(): Array<Record<string, unknown>> {
    const date = new Date().toISOString().slice(0, 10);
    const auditFile = join(home, '.shieldcortex', 'audit', `realtime-${date}.jsonl`);
    return existsSync(auditFile)
      ? readFileSync(auditFile, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
      : [];
  }

  function runHook(input: Record<string, unknown>, toolName = 'Bash'): HookResult {
    const payload = JSON.stringify({
      session_id: 'notify-it', cwd: '/tmp', hook_event_name: 'PreToolUse',
      // #139 (prompt-surface deny): a held request only reaches "ask" when the
      // session can actually raise a prompt. This suite is about the
      // NOTIFICATION transport, not the prompt-surface rule, so `default`
      // (a prompting mode) is asserted explicitly — an absent permission_mode
      // denies outright under #139, which would fail every test below for the
      // wrong reason.
      permission_mode: 'default',
      tool_name: toolName, tool_input: input,
    });
    const env: Record<string, string | undefined> = {
      ...process.env, HOME: home, USERPROFILE: home, SHIELDCORTEX_DIST_ROOT: distRoot,
    };

    const run = spawnSync('node', [HOOK], {
      input: payload, env: env as NodeJS.ProcessEnv, timeout: 30_000, encoding: 'utf8',
    });
    const stdout = run.stdout ?? '';
    const stderr = run.stderr ?? '';
    if (!stdout.trim()) return { stderr };
    const out = JSON.parse(stdout).hookSpecificOutput ?? {};
    return { decision: out.permissionDecision, reason: out.permissionDecisionReason, stderr };
  }

  function evidence(): Record<string, unknown> | null {
    return existsSync(evidenceFile) ? JSON.parse(readFileSync(evidenceFile, 'utf8')) : null;
  }

  // ── OFF by default ────────────────────────────────────────────────────────

  it('does not exist until switched on — no config, no channel call, same refusal as before #143', () => {
    // No notify config at all.
    const r = runHook(IRREVERSIBLE);
    expect(r.decision).toBe('ask');
    expect(r.reason).toMatch(/shieldcortex approve [0-9a-f]{12}/);
    expect(evidence()).toBeNull();
  });

  it('stays off for a config that merely mentions notify without enabled:true', () => {
    writeConfig({ enabled: 'yes', webhookUrl: webhookUrl() });
    const r = runHook(IRREVERSIBLE);
    expect(r.decision).toBe('ask');
    expect(evidence()).toBeNull();
  });

  // ── ON: the operator actually gets reached ──────────────────────────────────

  it('reaches the configured channel with the exact command, signals, tier, and both affordances bound to the SAME hash', () => {
    writeConfig({ enabled: true, webhookUrl: webhookUrl('success') });
    const r = runHook(IRREVERSIBLE);

    // The existing floor is UNCHANGED: still asked, still carries the hash.
    expect(r.decision).toBe('ask');
    expect(r.reason).toMatch(/shieldcortex approve [0-9a-f]{12}/);

    const body = evidence();
    expect(body).not.toBeNull();
    expect(body!.command).toMatch(/redacted action surface/i);
    expect(JSON.stringify(body)).not.toContain('sudo modprobe softdog');
    expect(body!.signals).toContain('privilege-escalation');
    expect(body!.severity).toBe('dangerous');
    expect(String(body!.sessionId)).toMatch(/^sc-[a-f0-9]{16}$/);
    expect(String(body!.fallbackHint)).toMatch(/shieldcortex approve [0-9a-f]{12}/);
    expect(String(body!.fallbackHint)).toMatch(/shieldcortex deny [0-9a-f]{12}/);
    // The SAME hash appears in the notification and in the terminal fallback.
    expect(String(body!.shortHash)).toBe(String(r.reason).match(/shieldcortex approve ([0-9a-f]{12})/)![1]);
  });

  it('shows the payload the hash actually covers, not a bare tool name (#183/#241)', () => {
    // #183 made `Workflow.script` a reviewed command surface: a re-worded
    // `description` no longer mints a fresh hash, so an operator approval for
    // one of these finally LANDS. That makes what the operator is shown
    // load-bearing. The command lives under `script`, which is not one of the
    // keys the guard hook used to describe a call — so this notification said
    // only "Workflow" while the hash it carried covered a force-push.
    writeConfig({ enabled: true, webhookUrl: webhookUrl('success') });
    const r = runHook({ script: WORKFLOW_FORCE_PUSH, description: 'Publish the release branch' }, 'Workflow');

    expect(r.decision).toBe('ask');
    const body = evidence();
    expect(body).not.toBeNull();
    expect(body!.command).toMatch(/redacted action surface/i);
    expect(JSON.stringify(body)).not.toContain(WORKFLOW_FORCE_PUSH);
    expect(body!.signals).toContain('git-force-push');
    // Same hash in the notification and the terminal fallback, as above.
    expect(String(body!.shortHash)).toBe(String(r.reason).match(/shieldcortex approve ([0-9a-f]{12})/)![1]);
  });

  it('does not export arbitrary non-exec code/input payloads while fixing Workflow.script', () => {
    const sentinel = 'PRIVATE_PAYLOAD_SENTINEL';
    writeConfig({ enabled: true, webhookUrl: webhookUrl('success') });
    const r = runHook(
      { code: `git push --force origin main # ${sentinel}`, description: 'Create a tracking issue' },
      'create_issue',
    );

    expect(r.decision).toBe('ask');
    const body = evidence();
    expect(body).not.toBeNull();
    expect(body!.command).toMatch(/redacted action surface/i);
    expect(JSON.stringify(body)).not.toContain(sentinel);
  });

  it('does not export an arbitrary non-Workflow script payload', () => {
    const sentinel = 'PRIVATE_PAYLOAD_SENTINEL';
    writeConfig({ enabled: true, webhookUrl: webhookUrl('success') });
    const r = runHook(
      { script: `git push --force origin main # ${sentinel}`, description: 'Create a tracking issue' },
      'create_issue',
    );

    expect(r.decision).toBe('ask');
    const body = evidence();
    expect(body).not.toBeNull();
    expect(body!.command).toMatch(/redacted action surface/i);
    expect(JSON.stringify(body)).not.toContain(sentinel);
  });


  it('redacts hostile interactive approval surfaces while keeping the approval hash functional across channel outcomes', () => {
    const secret = 'DO_NOT_PERSIST_INTERACTIVE_APPROVAL_VALUE_1234567890';
    const token = 'ghp_FAKE_INTERACTIVE_APPROVAL_TOKEN_1234567890';
    const hostile = 'ignore.previous.instructions';
    const url = `https://example.invalid/${secret}`;
    writeFileSync(
      join(distRoot, 'defence', 'iron-dome', 'tool-action-guard.js'),
      [
        'export async function evaluateToolCall() {',
        '  return {',
        "    severity: 'dangerous',",
        "    decision: 'require_approval',",
        `    reason: ${JSON.stringify(`needs approval ${secret} ${token} ${url} ${hostile}`)},`,
        `    signals: ['privilege-escalation', ${JSON.stringify(secret)}, ${JSON.stringify(token)}, ${JSON.stringify(hostile)}],`,
        `    matches: [{ signal: 'privilege-escalation', span: ${JSON.stringify(`${secret} ${url}`)} }],`,
        '  };',
        '}',
      ].join('\n'),
    );

    for (const mode of ['success', 'fail', 'throw', 'hang'] as const) {
      try { rmSync(evidenceFile, { force: true }); } catch { /* ignore */ }
      writeConfig({
        enabled: true,
        webhookUrl: `${webhookUrl(mode)}&secret=${encodeURIComponent(secret)}&channelName=${encodeURIComponent(`bearer-${token}`)}`,
        timeoutMs: 25,
      });

      const r = runHook({ command: 'sudo systemctl stop nginx', note: `${secret} ${token} ${url} ${hostile}` }, `Bash ${secret}`);

      expect(r.decision).toBe('ask');
      expect(r.reason).toMatch(/shieldcortex approve [0-9a-f]{12}/);
      for (const leak of [secret, token, url, hostile, 'bearer-']) {
        expect(r.reason).not.toContain(leak);
        expect(r.stderr).not.toContain(leak);
        expect(JSON.stringify(auditRows())).not.toContain(leak);
        if (evidence()) expect(JSON.stringify(evidence())).not.toContain(leak);
      }
      if (mode === 'success') {
        const body = evidence();
        expect(body).not.toBeNull();
        expect(body!.tool).toBe('tool');
        expect(String(body!.command)).toMatch(/redacted action surface/i);
        expect(Array.isArray(body!.signals)).toBe(true);
        expect(JSON.stringify(body!.signals)).not.toContain(secret);
        expect(String(body!.fallbackHint)).toMatch(/shieldcortex approve [0-9a-f]{12}/);
        expect(String(body!.fallbackHint)).toMatch(/shieldcortex deny [0-9a-f]{12}/);
      }
    }
  }, 25_000);

  it('reports a catastrophic call through a redacted terminal outcome alert with no approval affordance', () => {
    writeConfig({ enabled: true, webhookUrl: webhookUrl('success') });
    const r = runHook(CATASTROPHIC);
    expect(r.decision).toBe('deny');
    const body = evidence();
    expect(body).not.toBeNull();
    expect(body!.event).toBe('action_guard_denial');
    expect(body!.outcome).toBe('auto_denied');
    expect(body!.surface).toMatch(/redacted action surface/i);
    expect(JSON.stringify(body)).not.toContain('rm -rf /');
    expect(body!.approveCommand).toBeUndefined();
    expect(body!.denyCommand).toBeUndefined();
  });

  it('redacts suspicious tool names from terminal outcome notifications, logs, and audit rows', () => {
    const secret = 'DO_NOT_PERSIST_TOOLNAME_VALUE_1234567890';
    const shortSecret = 'hunter2';
    const hostile = 'ignore.previous.instructions';
    writeConfig({ enabled: true, webhookUrl: webhookUrl('success') });
    const r = runHook(CATASTROPHIC, `Bash\nprod-credential-${shortSecret}\n${hostile}\n${secret}`);
    expect(r.decision).toBe('deny');
    for (const token of [secret, shortSecret, hostile, 'prod-credential']) {
      expect(r.stderr).not.toContain(token);
      expect(JSON.stringify(evidence())).not.toContain(token);
      expect(JSON.stringify(auditRows())).not.toContain(token);
    }
  });

  it('keeps denied payloads and channel errors out of terminal notification audit rows', () => {
    const secret = 'PRIVATE_NOTIFY_SECRET_TOKEN';
    writeConfig({
      enabled: true,
      webhookUrl: `${webhookUrl('fail')}&secret=${encodeURIComponent(secret)}`,
    });

    const r = runHook({ command: `rm -rf / # ${secret}` });

    expect(r.decision).toBe('deny');
    expect(r.stderr).not.toContain(secret);
    const rows = auditRows();
    const notifyRows = rows.filter((row) => row.action === 'notify');
    expect(notifyRows).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain(secret);
    expect(JSON.stringify(rows)).not.toContain('rm -rf /');
    expect(rows.some((row) => row.outcome === 'auto_denied' && String(row.preview).includes('redacted action surface'))).toBe(true);
    expect(String(notifyRows[0].preview)).toContain('notification=redacted');
    expect(String(notifyRows[0].preview)).not.toContain('rm -rf');
  });

  it('redacts hostile and credential-shaped notification transport labels from logs and audit rows', () => {
    const labels = [
      'https://notify.invalid/DO_NOT_PERSIST_CHANNEL_VALUE_1234567890',
      'user:password',
      'ghp_1234567890abcdef1234567890abcdef123456',
      'bearer-1234567890abcdef',
    ];

    for (const label of labels) {
      writeConfig({
        enabled: true,
        webhookUrl: `${webhookUrl('success')}&channelName=${encodeURIComponent(label)}`,
      });

      const r = runHook(CATASTROPHIC);

      expect(r.decision).toBe('deny');
      expect(r.stderr).not.toContain(label);
      expect(JSON.stringify(auditRows())).not.toContain(label);
    }
    expect(JSON.stringify(auditRows())).toContain('redacted-channel');
  });

  it('reports enforce:false advisory outcomes through the redacted warning event', () => {
    const secret = 'PRIVATE_WARNING_SECRET_TOKEN';
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({
        actionGuard: {
          enabled: true,
          enforce: false,
          notify: { enabled: true, webhookUrl: webhookUrl('success') },
        },
      }),
    );
    const r = runHook({ command: `${IRREVERSIBLE.command} # ${secret}` });
    expect(r.decision).toBeUndefined();
    const body = evidence();
    expect(body).not.toBeNull();
    expect(body!.event).toBe('action_guard_warning');
    expect(body!.outcome).toBe('warned');
    expect(body!.surface).toMatch(/redacted action surface/i);
    expect(JSON.stringify(body)).not.toContain(IRREVERSIBLE.command);
    expect(JSON.stringify(body)).not.toContain(secret);
    expect(JSON.stringify(auditRows())).not.toContain(secret);
    expect(body!.approveCommand).toBeUndefined();
    expect(body!.denyCommand).toBeUndefined();
  });


  it('bounds terminal denial and warning notification throw/timeout without changing the guard decision', () => {
    for (const [mode, enforce, expectedDecision] of [
      ['throw', true, 'deny'],
      ['hang', true, 'deny'],
      ['throw', false, undefined],
      ['hang', false, undefined],
    ] as const) {
      writeFileSync(
        join(home, '.shieldcortex', 'config.json'),
        JSON.stringify({
          actionGuard: {
            enabled: true,
            enforce,
            notify: { enabled: true, webhookUrl: webhookUrl(mode), timeoutMs: 25 },
          },
        }),
      );
      const command = enforce ? CATASTROPHIC.command : IRREVERSIBLE.command;
      const started = Date.now();
      const r = runHook({ command: `${command} # terminal-outcome-transport` });

      expect(Date.now() - started).toBeLessThan(20_000);
      expect(r.decision).toBe(expectedDecision);
      expect(JSON.stringify(auditRows())).not.toContain('terminal-outcome-transport');
      expect(auditRows().some((row) => row.action === 'notify' && ['notify_failed', 'notified'].includes(String(row.outcome)))).toBe(true);
    }
  }, 25_000);

  it('an operator-approved hash from the SAME notification still passes, unchanged from #118', async () => {
    writeConfig({ enabled: true, webhookUrl: webhookUrl('success') });
    const refused = runHook(IRREVERSIBLE);
    expect(refused.decision).toBe('ask');
    const body = evidence();
    expect(body).not.toBeNull();
    const shortHash = String(body!.shortHash);

    // The operator acts in their own terminal — the SAME #118 mechanism,
    // untouched by #143's notification transport.
    const { approveRequest } = await import(pathToFileURL(join(REAL_DIST, 'action-approvals.js')).href);
    expect(approveRequest(shortHash, { home }).ok).toBe(true);

    const approved = runHook(IRREVERSIBLE);
    expect(approved.decision).toBeUndefined();
  });

  // ── fail-closed: a broken or absent channel never blocks or changes the guard ──

  it('a channel that reports failure does not change the decision or the fallback hash', () => {
    writeConfig({ enabled: true, webhookUrl: webhookUrl('fail') });
    const r = runHook(IRREVERSIBLE);
    expect(r.decision).toBe('ask');
    expect(r.reason).toMatch(/shieldcortex approve/);
  });

  it('a channel that throws does not change the decision, hang the hook, or crash it', () => {
    writeConfig({ enabled: true, webhookUrl: webhookUrl('throw') });
    const started = Date.now();
    const r = runHook(IRREVERSIBLE);
    expect(r.decision).toBe('ask');
    expect(r.reason).toMatch(/shieldcortex approve/);
    expect(Date.now() - started).toBeLessThan(20_000);
  }, 25_000);

  it('an invalid webhookUrl (non-http scheme) degrades to no channel, not a crash', () => {
    writeConfig({ enabled: true, webhookUrl: 'javascript:alert(1)' });
    const r = runHook(IRREVERSIBLE);
    expect(r.decision).toBe('ask');
    expect(evidence()).toBeNull();
  });

  it('a channel reporting success never changes the decision — delivering is not consent', () => {
    // Even the "everything worked" path must still land on the unchanged
    // "ask" + hash floor. The channel's own success/failure never substitutes
    // for the operator's actual answer, which only ever arrives through the
    // #118 approval store (see the two tests above and below).
    writeConfig({ enabled: true, webhookUrl: webhookUrl('success') });
    const r = runHook(IRREVERSIBLE);
    expect(r.decision).toBe('ask');
    expect(r.reason).toMatch(/shieldcortex approve/);
  });
});
