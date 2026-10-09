/**
 * #648 — the approval card the Claude Code hook raises must be readable, and
 * nothing else the hook emits may change.
 *
 * The owner received a card that read, in full:
 *
 *   ShieldCortex: approve Bash? [1ae99749ee74]
 *   Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command
 *   Tripped: touch-sensitive-path (dangerous)
 *
 * This drives the REAL hook (scripts/pre-tool-hook.mjs) over a shimmed dist,
 * fake HOME and fake config dir — never the operator's live ~/.shieldcortex.
 * The OpenClaw card channel is replaced by a recorder that renders the card
 * with the REAL `buildCardFields`, and the webhook channel is the REAL module
 * with its fetch replaced by a recorder, so what is asserted is the exact text
 * and the exact POST body.
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

const REAL_MODULES = [
  'tool-action-guard.js', 'action-approvals.js', 'notify-config.js', 'operator-notify.js',
  'script-source-resolver.js', 'dnp-digest.js', 'retry-control.js', 'dnp-retry-waiter.js',
  'approval-card.js',
];

interface CardRecord { notification: Record<string, unknown>; card: { title: string; description: string } }

describe('#648 — readable approval card through the real Claude Code hook', () => {
  let home: string;
  let distRoot: string;
  let jobCwd: string;
  let cardEvidence: string;
  let webhookEvidence: string;

  beforeAll(() => {
    const probes = ['tool-action-guard.js', 'operator-notify.js', 'openclaw-approval-channel.js', 'webhook-notify-channel.js']
      .map((f) => join(REAL_DIST, f));
    if (!probes.every((p) => existsSync(p))) {
      execSync('npm run build:ts', { cwd: repoRoot, stdio: 'ignore' });
    }
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-648-hook-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    jobCwd = mkdtempSync(join(tmpdir(), 'sc-648-cwd-'));
    cardEvidence = join(home, 'card-evidence.jsonl');
    webhookEvidence = join(home, 'webhook-evidence.jsonl');

    distRoot = mkdtempSync(join(tmpdir(), 'sc-648-dist-'));
    const ironDomeDir = join(distRoot, 'defence', 'iron-dome');
    mkdirSync(ironDomeDir, { recursive: true });
    for (const f of REAL_MODULES) {
      const real = join(REAL_DIST, f);
      if (existsSync(real)) {
        writeFileSync(join(ironDomeDir, f), `export * from ${JSON.stringify(pathToFileURL(real).href)};\n`);
      }
    }
    // The card channel: real card rendering, recorded instead of spawning a waiter.
    const realCard = pathToFileURL(join(REAL_DIST, 'openclaw-approval-channel.js')).href;
    writeFileSync(
      join(ironDomeDir, 'openclaw-approval-channel.js'),
      [
        "import { appendFileSync } from 'node:fs';",
        `import { buildCardFields } from ${JSON.stringify(realCard)};`,
        `export * from ${JSON.stringify(realCard)};`,
        "export function resolveOpenClawBinaryLite() { return '/bin/true'; }",
        'export function createOpenClawApprovalChannel() {',
        '  return {',
        "    name: 'openclaw-approval',",
        '    async send(notification) {',
        "      if (notification.event !== 'approval_requested') return { delivered: false, reason: 'interactive-only' };",
        `      appendFileSync(${JSON.stringify(cardEvidence)}, JSON.stringify({ notification, card: buildCardFields(notification) }) + '\\n');`,
        '      return { delivered: true };',
        '    },',
        '  };',
        '}',
      ].join('\n'),
    );
    // The webhook channel: the REAL payload builder, fetch replaced by a recorder.
    const realWebhook = pathToFileURL(join(REAL_DIST, 'webhook-notify-channel.js')).href;
    writeFileSync(
      join(ironDomeDir, 'webhook-notify-channel.js'),
      [
        "import { appendFileSync } from 'node:fs';",
        `import { createWebhookNotifyChannel as real } from ${JSON.stringify(realWebhook)};`,
        'export function createWebhookNotifyChannel(opts) {',
        '  return real({ ...opts, fetchImpl: async (_url, init) => {',
        `    appendFileSync(${JSON.stringify(webhookEvidence)}, String(init.body) + '\\n');`,
        '    return new Response(null, { status: 200 });',
        '  } });',
        '}',
      ].join('\n'),
    );
  });

  afterEach(() => {
    for (const dir of [home, distRoot, jobCwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function writeConfig(notify: Record<string, unknown>): void {
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ actionGuard: { enabled: true, enforce: true, notify: { enabled: true, ...notify } } }),
    );
  }

  function runHook(input: Record<string, unknown>, opts: { tool?: string; permissionMode?: string } = {}) {
    const run = spawnSync('node', [HOOK], {
      input: JSON.stringify({
        session_id: '648-session',
        cwd: jobCwd,
        hook_event_name: 'PreToolUse',
        permission_mode: opts.permissionMode ?? 'default',
        tool_name: opts.tool ?? 'Bash',
        tool_input: input,
      }),
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
    const out = stdout.trim() ? (JSON.parse(stdout).hookSpecificOutput ?? {}) : {};
    return { decision: out.permissionDecision as string | undefined, stderr: run.stderr ?? '' };
  }

  function lines(file: string): string[] {
    return existsSync(file) ? readFileSync(file, 'utf8').trim().split('\n').filter(Boolean) : [];
  }
  function cards(): CardRecord[] {
    return lines(cardEvidence).map((l) => JSON.parse(l) as CardRecord);
  }

  /** Fields that are random per run (salted session key, attempt id, clock)
   *  are pinned; every other byte is compared. */
  function normaliseWebhookBody(body: string): string {
    return body
      .replace(/"ts":"[^"]+"/g, '"ts":"<ts>"')
      .replace(/"detectedAt":"[^"]+"/g, '"detectedAt":"<ts>"')
      .replace(/sc-[0-9a-f]{16}/g, 'sc-<session>')
      .replace(/act-[0-9a-f]{16}/g, 'act-<action>')
      .replace(/--attempt [0-9a-f]+/g, '--attempt <attempt>')
      .replace(/"attemptId":"[0-9a-f]+"/g, '"attemptId":"<attempt>"');
  }

  function denialRows(): string[] {
    return lines(join(home, '.shieldcortex', 'denials.jsonl')).map((l) => {
      const row = JSON.parse(l) as Record<string, unknown>;
      for (const k of ['ts', 'timestamp', 'at', 'detectedAt']) if (k in row) row[k] = '<ts>';
      return JSON.stringify(row)
        .replace(/sc-[0-9a-f]{16}/g, 'sc-<session>')
        .replace(/act-[0-9a-f]{16}/g, 'act-<action>');
    });
  }

  // `cat ~/.ssh/config` — the screenshot case (Bash, touch-sensitive-path).
  const SSH_READ = { command: 'cat ~/.ssh/config' };

  it('the screenshot case: the card names the target and the plain reason, not the placeholder', () => {
    writeConfig({ openclaw: true });
    const r = runHook(SSH_READ);
    expect(r.decision).toBe('ask');
    const got = cards();
    expect(got).toHaveLength(1);
    const { title, description } = got[0].card;
    // The defect, verbatim from the owner's screenshot.
    expect(description).not.toContain('redacted action surface');
    expect(description).not.toContain('fields=');
    expect(description).not.toContain('(dangerous)');
    // What it wants to do, naming the target.
    expect(description).toContain('Read a file in your SSH folder: "~/.ssh/config"');
    // Why ShieldCortex stopped it, in plain English.
    expect(description).toContain('Why: touches a sensitive file (keys, passwords or credentials)');
    // Who: agent, box, session.
    expect(description).toMatch(/Who: Claude Code on [A-Za-z0-9_…-]+ · session sc-[0-9a-f]{16}/);
    // Kept: short hash, allow-once|deny, expiry.
    expect(title).toMatch(/\[[0-9a-f]{12}\]$/);
    expect(description).toContain('Allow once or deny · expires in 10 min');
    expect(description.length).toBeLessThanOrEqual(256);
    expect(title.length).toBeLessThanOrEqual(80);
  });

  it('#648 r3: a command outside the understood subset gets the generic WHAT and the real WHY', () => {
    writeConfig({ openclaw: true });
    expect(runHook({ command: 'echo $(cat ~/.ssh/config)' }).decision).toBe('ask');
    const { description } = cards()[0].card;
    expect(description.split('\n')[0]).toBe("Run a complex shell command (couldn't summarise it safely)");
    expect(description).toMatch(/^Why: touches a sensitive file/m);
    expect(description).toMatch(/Who: Claude Code on [A-Za-z0-9_…-]+ · session sc-[0-9a-f]{16}/);
  });

  it('the card summary never rides on the webhook (notify stays values-free)', () => {
    writeConfig({ openclaw: true });
    runHook(SSH_READ);
    const n = cards()[0].notification;
    // The notification's `command` is still the values-free surface the
    // webhook would carry; only the card channel reads `card`.
    expect(n.command).toBe('Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command');
  });

  // Secret fixtures are built at runtime so no secret-shaped literal is ever
  // committed (GitHub push protection rejects them, and rightly).
  const GH = ['gh', 'p_'].join('') + 'Z'.repeat(4) + 'q7Lm2Xr9Tb4Vc8Nd1Fh6Jk3Wp5Ys0Ua';
  const AWS_ID = ['AK', 'IA'].join('') + 'Q3XZ7LMN2PRT6VWY';
  const SLACK = ['xo', 'xb-'].join('') + '2468135790-1357924680-' + 'Kq8Lm3Np5Rt7Vx9Zb2Dc4Fg';
  const OPAQUE = 'Q'.repeat(3) + 'f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2';

  it.each([
    ['an AWS key id in a sensitive path', `cat ~/.ssh/${AWS_ID}`, AWS_ID],
    ['a GitHub token in a pkill pattern', `pkill -f "relay --token=${GH}"`, GH],
    ['credentials in a git push URL', `git push --force https://bot:${GH}@github.com/acme/app.git main`, GH],
    ['a Slack token as a process name', `killall ${SLACK}`, SLACK],
    ['an env-assigned secret before a global install', `NPM_TOKEN=${OPAQUE} npm install -g typescript`, OPAQUE],
  ])('a credential-shaped command never puts the secret on the card: %s', (_label, command, secret) => {
    writeConfig({ openclaw: true });
    expect(runHook({ command }).decision).toBe('ask');
    const got = cards();
    expect(got).toHaveLength(1);
    const blob = JSON.stringify(got);
    expect(blob).not.toContain(secret);
    expect(blob).not.toContain(secret.slice(0, 12));
    expect(blob).not.toContain(secret.slice(-12));
    // The card still says something useful, not the placeholder.
    expect(got[0].card.description).not.toContain('redacted action surface');
    expect(got[0].card.description).toMatch(/^Why: /m);
  });

  // ── Byte-identical notify / denials surfaces ─────────────────────────────
  // Goldens captured from origin/main (ee87c5c5) by running this exact
  // harness before the #648 change. Random fields are pinned by the
  // normalisers above; every other byte must match.

  it('webhook approval_requested body is byte-identical to main', () => {
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook' });
    expect(runHook(SSH_READ).decision).toBe('ask');
    const bodies = lines(webhookEvidence).map(normaliseWebhookBody);
    expect(bodies).toEqual([GOLDEN_WEBHOOK_ASK]);
  });

  it('webhook denial body and denials.jsonl rows are byte-identical to main', () => {
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    expect(runHook(SSH_READ, { permissionMode: 'bypassPermissions' }).decision).toBe('deny');
    const bodies = lines(webhookEvidence).map(normaliseWebhookBody);
    expect(bodies).toEqual([GOLDEN_WEBHOOK_DNP]);
    expect(denialRows()).toEqual(GOLDEN_DENIALS_DNP);
  });
});

const GOLDEN_WEBHOOK_ASK = "{\"event\":\"approval_requested\",\"hash\":\"1d3e3c896ae2a9a396eacda6e9c44cf16bb9d3b69550ec941f95ca76a9151178\",\"shortHash\":\"1d3e3c896ae2\",\"attemptId\":\"<attempt>\",\"tool\":\"Bash\",\"command\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"touch-sensitive-path\"],\"severity\":\"dangerous\",\"reason\":\"Action Guard requires approval; inspect local audit for details.\",\"judge\":null,\"text\":\"🛡️ ShieldCortex — approval needed\\n\\nTool:      Bash\\nCommand:   Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\\nTripped:   touch-sensitive-path\\nTier:      dangerous\\nReason:    Action Guard requires approval; inspect local audit for details.\\n\\nAI judge:  no judge ran — this verdict is rules-only\\n\\n[Approve]  shieldcortex approve 1d3e3c896ae2 --attempt <attempt>\\n[Deny]     shieldcortex deny 1d3e3c896ae2 --attempt <attempt>\",\"approveCommand\":\"shieldcortex approve 1d3e3c896ae2 --attempt <attempt>\",\"ts\":\"<ts>\",\"denyCommand\":\"shieldcortex deny 1d3e3c896ae2 --attempt <attempt>\",\"sessionId\":\"sc-<session>\"}";
const GOLDEN_WEBHOOK_DNP = "{\"event\":\"action_guard_denial\",\"outcome\":\"denied_no_prompt_surface\",\"tool\":\"Bash\",\"surface\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"touch-sensitive-path\"],\"severity\":\"dangerous\",\"reason\":\"Action Guard required approval but this session has no prompt surface; the tool call was denied.\",\"correlationId\":\"act-<action>\",\"actionId\":\"act-<action>\",\"sessionId\":\"sc-<session>\",\"origin\":\"claude-code-hook\",\"detectedAt\":\"<ts>\",\"text\":\"ShieldCortex — held (headless, no prompt)\\n\\nWhat:    1 dangerous step(s) blocked in this 15m window\\nTools:   Bash×1\\nWhy:     touch-sensitive-path×1\\nLast:    act-<action>\\n\\nRetry:   No Approve card this time (retry cards off).\\n\\nOne-shot from a real terminal on that host:\\n  shieldcortex approve --denial act-<action>\\nThen retry the same action once. Approve is not forever.\\n\\nNote:    First hold in this window; further holds are quiet (coalesced).\\nForensics: ~/.shieldcortex/denials.jsonl (command not included here).\\nThis message is visibility — not a tappable Approve surface.\",\"ts\":\"<ts>\"}";
const GOLDEN_DENIALS_DNP: string[] = [
  "{\"event\":\"action_guard_denial\",\"outcome\":\"denied_no_prompt_surface\",\"origin\":\"claude-code-hook\",\"tool\":\"Bash\",\"surface\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"touch-sensitive-path\"],\"matches\":[{\"signal\":\"touch-sensitive-path\",\"spanWithheld\":\"command-text\",\"argc\":1}],\"severity\":\"dangerous\",\"reason\":\"Action Guard required approval but this session has no prompt surface; the tool call was denied.\",\"sessionId\":\"sc-<session>\",\"actionId\":\"act-<action>\",\"correlationId\":\"act-<action>\",\"detectedAt\":\"<ts>\",\"notify\":{\"status\":\"pending\",\"deliveredVia\":null}}",
  "{\"event\":\"action_guard_denial\",\"outcome\":\"denied_no_prompt_surface\",\"origin\":\"claude-code-hook\",\"tool\":\"Bash\",\"surface\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"touch-sensitive-path\"],\"matches\":[{\"signal\":\"touch-sensitive-path\",\"spanWithheld\":\"command-text\",\"argc\":1}],\"severity\":\"dangerous\",\"reason\":\"Action Guard required approval but this session has no prompt surface; the tool call was denied.\",\"sessionId\":\"sc-<session>\",\"actionId\":\"act-<action>\",\"correlationId\":\"act-<action>\",\"detectedAt\":\"<ts>\",\"notify\":{\"status\":\"delivered\",\"deliveredVia\":\"webhook\"}}",
];
