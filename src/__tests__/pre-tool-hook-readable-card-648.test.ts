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

  /** #815 A fold 4: a test-owned preload that pins THIS hook process's
   *  `os.hostname()` (the WHO line's box name), so Linux CI drives the
   *  generated names a macOS runner carries. Nothing in shipped code reads it. */
  function hostnamePreload(name: string): string {
    const file = join(home, 'hostname-preload.mjs');
    writeFileSync(file, [
      "import os from 'node:os';",
      "import { syncBuiltinESMExports } from 'node:module';",
      `os.hostname = () => ${JSON.stringify(name)};`,
      'syncBuiltinESMExports();',
    ].join('\n'));
    return pathToFileURL(file).href;
  }

  function runHook(input: Record<string, unknown>, opts: { tool?: string; permissionMode?: string; hostname?: string } = {}) {
    // Git config the card builder may read comes from the fake HOME and the
    // job's own repository only: no GIT_CONFIG* override, no real XDG dir.
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^GIT_/.test(k)));
    const args = opts.hostname === undefined ? [HOOK] : ['--import', hostnamePreload(opts.hostname), HOOK];
    const run = spawnSync('node', args, {
      input: JSON.stringify({
        session_id: '648-session',
        cwd: jobCwd,
        hook_event_name: 'PreToolUse',
        permission_mode: opts.permissionMode ?? 'default',
        tool_name: opts.tool ?? 'Bash',
        tool_input: input,
      }),
      env: {
        ...env,
        HOME: home,
        USERPROFILE: home,
        XDG_CONFIG_HOME: join(home, '.config'),
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

  it('the notification keeps the values-free command surface beside the card', () => {
    writeConfig({ openclaw: true });
    runHook(SSH_READ);
    const n = cards()[0].notification;
    // The notification's `command` is still the values-free surface; the
    // readable summary rides separately on `card` (read by the card channel
    // and, since #815 A, laid out as the webhook's versioned `card` block).
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

  // #815 A: the webhook body gains ONE key, `card`, appended last. Every
  // pre-#815 byte is still compared against the golden; the card is asserted
  // on its own below. denials.jsonl stays byte-identical and card-free.
  function splitCard(body: string): { rest: string; card: Record<string, unknown> | undefined } {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    const keys = Object.keys(parsed);
    if ('card' in parsed) expect(keys.at(-1)).toBe('card');
    const { card, ...rest } = parsed;
    return { rest: JSON.stringify(rest), card: card as Record<string, unknown> | undefined };
  }
  const WHO = /^Claude Code on [A-Za-z0-9_…-]+ · session sc-<session>$/;
  /** A card without its WHO line: the box's own hostname, which a CI runner
   *  names freely, is the one line that is not fixed text. */
  const sansWho = (c: Record<string, string>) => JSON.stringify({ ...c, who: '', text: String(c.text).replace(/^Who: .*$/mu, '') });

  it('webhook approval_requested body is byte-identical to main, plus the #815 card', () => {
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook' });
    expect(runHook(SSH_READ).decision).toBe('ask');
    const bodies = lines(webhookEvidence).map(normaliseWebhookBody).map(splitCard);
    expect(bodies.map((b) => b.rest)).toEqual([GOLDEN_WEBHOOK_ASK]);
    const card = bodies[0].card!;
    expect(card).toMatchObject({
      version: 1,
      kind: 'approval',
      what: 'Read a file in your SSH folder',
      why: 'touches a sensitive file (keys, passwords or credentials)',
      approveCommand: 'shieldcortex approve 1d3e3c896ae2 --attempt <attempt>',
      denyCommand: 'shieldcortex deny 1d3e3c896ae2 --attempt <attempt>',
    });
    expect(card.who).toMatch(WHO);
    expect(card).not.toHaveProperty('actions');
  });

  it('webhook denial body and denials.jsonl rows are byte-identical to main, plus the #815 card', () => {
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    expect(runHook(SSH_READ, { permissionMode: 'bypassPermissions' }).decision).toBe('deny');
    const bodies = lines(webhookEvidence).map(normaliseWebhookBody).map(splitCard);
    expect(bodies.map((b) => b.rest)).toEqual([GOLDEN_WEBHOOK_DNP]);
    const card = bodies[0].card!;
    expect(card).toMatchObject({
      version: 1,
      kind: 'denial',
      what: 'Read a file in your SSH folder',
      why: 'touches a sensitive file (keys, passwords or credentials)',
      approveCommand: 'shieldcortex approve --denial act-<action>',
      actions: [
        { action: 'approve', label: 'Approve retry', actionId: 'act-<action>' },
        { action: 'deny', label: 'Deny', actionId: 'act-<action>' },
      ],
    });
    expect(card.who).toMatch(WHO);
    // The card names the same action the alert's own actionId does.
    expect(JSON.parse(bodies[0].rest).actionId).toBe('act-<action>');
    expect(denialRows()).toEqual(GOLDEN_DENIALS_DNP);
    expect(denialRows().join('\n')).not.toContain('"card"');
  });

  // #815 A fold 4: on the macOS runner the whole WHO line was withheld. The
  // egress gate's every-space-removed reading ran the redactor's entropy net
  // over `Claude Code on <the runner's generated name>`, one long token, and
  // the hostname check's own entropy net made other generated names "this
  // machine". The hook's os.hostname() is pinned below, so every CI runs these.
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const MAC_HOSTS: Array<[host: string, shown: string]> = [
    ['Mac-1730678123456.local', 'Mac-1730678123456'],
    ['iMac-Pro', 'iMac-Pro'],
    ['Mac-4A6B2C1D8E.lan', 'Mac-4A6B2C1D8E'],
    ['sat12-bq108-ee49b2ab-4824-1047-6e4e-63f098a4fbca-3D9B5B6AFE4B.local', 'sat12-b…3D9B5B6AFE4B'],
    ['ghost-runner-66971413203657598', 'ghost-r…413203657598'],
    ['Mac-mini-runner-e3b7f48922d7a40f510823bb5e6b3a72d6543729.local', 'Mac-min…3a72d6543729'],
  ];

  it.each(MAC_HOSTS)('#815 A fold 4: a macOS hostname (%s) is named on the held card, beside the session', (host, shown) => {
    writeConfig({ openclaw: true });
    expect(runHook(SSH_READ, { hostname: host }).decision).toBe('ask');
    const got = cards();
    expect(got).toHaveLength(1);
    const { description } = got[0].card;
    expect(description).toContain('Read a file in your SSH folder: "~/.ssh/config"');
    expect(description).toMatch(new RegExp(`^Who: Claude Code on ${esc(shown)} · session sc-[0-9a-f]{16}$`, 'mu'));
  });

  it.each(MAC_HOSTS)('#815 A fold 4: a macOS hostname (%s) is named on the webhook card; the rest of the body is still main\'s', (host, shown) => {
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    expect(runHook(SSH_READ, { permissionMode: 'bypassPermissions', hostname: host }).decision).toBe('deny');
    const bodies = lines(webhookEvidence).map(normaliseWebhookBody).map(splitCard);
    expect(bodies.map((b) => b.rest)).toEqual([GOLDEN_WEBHOOK_DNP]);
    expect(bodies[0].card!.who).toBe(`Claude Code on ${shown} · session sc-<session>`);
    expect(bodies[0].card!.text).toContain(`Who:  Claude Code on ${shown} · session sc-<session>`);
  });

  it('#815 A fold 4: a credential-shaped hostname withholds the host only; the agent and the session stay', () => {
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    expect(runHook(SSH_READ, { permissionMode: 'bypassPermissions', hostname: `${AWS_ID}.local` }).decision).toBe('deny');
    const raw = lines(webhookEvidence);
    expect(raw).toHaveLength(1);
    expect(splitCard(normaliseWebhookBody(raw[0])).card!.who).toBe('Claude Code on this machine · session sc-<session>');
    for (const needle of [AWS_ID, AWS_ID.slice(0, 10), AWS_ID.slice(-10)]) {
      expect(raw[0].toUpperCase()).not.toContain(needle.toUpperCase());
    }
  });

  it('#815 A: a credential-shaped command never puts the secret on the webhook card (headless denial)', () => {
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    const command = `git push --force https://bot:${GH}@github.com/acme/app.git main`;
    expect(runHook({ command }, { permissionMode: 'bypassPermissions' }).decision).toBe('deny');
    const raw = lines(webhookEvidence);
    expect(raw).toHaveLength(1);
    expect(raw[0]).toContain('"card":');
    for (const needle of [GH, GH.slice(0, 12), GH.slice(-12), command]) {
      expect(raw[0]).not.toContain(needle);
      expect(denialRows().join('\n')).not.toContain(needle);
    }
  });

  // #815 A review B1 — the reviewer's fixture. The card's remote-name fallback
  // skipped the credential redactor, and the webhook card carried the name
  // out. The command is hook INPUT only; nothing runs git. The old-body and
  // denials goldens were captured at the comparison base (1525b204), where no
  // card existed, so they also prove the fix leaves every pre-#815 byte alone.
  // Since the descope the webhook card is a fixed template: it names no remote.
  const REMOTE = ['AK', 'IA'].join('') + 'Q3XZ7LMN2PRT6VWY';
  const REMOTE_PUSH = { command: `git push --force ${REMOTE} main` };
  const REMOTE_WHAT = 'Force-push to a remote';
  function expectNoRemote(raw: string[]): void {
    const rows = denialRows().join('\n');
    for (const needle of [REMOTE, REMOTE.slice(0, 8), REMOTE.slice(-8), REMOTE_PUSH.command]) {
      for (const body of raw) expect(body).not.toContain(needle);
      expect(rows).not.toContain(needle);
    }
  }

  it('#815 A review B1: a credential-shaped git remote name never reaches the webhook card (headless denial)', () => {
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    expect(runHook(REMOTE_PUSH, { permissionMode: 'bypassPermissions' }).decision).toBe('deny');
    const raw = lines(webhookEvidence);
    expect(raw).toHaveLength(1);
    const { rest, card } = splitCard(normaliseWebhookBody(raw[0]));
    expect(rest).toBe(GOLDEN_WEBHOOK_DNP_REMOTE);
    expect(card).toMatchObject({
      version: 1,
      kind: 'denial',
      what: REMOTE_WHAT,
      why: 'pushes to a remote branch (may overwrite history)',
      approveCommand: 'shieldcortex approve --denial act-<action>',
    });
    expect(card!.text).toContain(`What: ${REMOTE_WHAT}`);
    expect(denialRows()).toEqual(GOLDEN_DENIALS_DNP_REMOTE);
    expect(denialRows().join('\n')).not.toContain('"card"');
    expectNoRemote(raw);
  });

  it('#815 A review B1: a credential-shaped git remote name never reaches the webhook card (held approval)', () => {
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook' });
    expect(runHook(REMOTE_PUSH).decision).toBe('ask');
    const raw = lines(webhookEvidence);
    expect(raw).toHaveLength(1);
    const { rest, card } = splitCard(normaliseWebhookBody(raw[0]));
    expect(rest).toBe(GOLDEN_WEBHOOK_ASK_REMOTE);
    expect(card).toMatchObject({
      version: 1,
      kind: 'approval',
      what: REMOTE_WHAT,
      why: 'pushes to a remote branch (may overwrite history)',
      approveCommand: 'shieldcortex approve 0b740047d8ed --attempt <attempt>',
      denyCommand: 'shieldcortex deny 0b740047d8ed --attempt <attempt>',
    });
    expect(card!.text).toContain(`What: ${REMOTE_WHAT}`);
    // A held call writes no denial row, at the base and now.
    expect(denialRows()).toEqual([]);
    expectNoRemote(raw);
  });

  // #815 A review B2 — the HOST, not the remote name. `hostOf` lower-cased a
  // URL or scp host before the target gate saw it, and the AWS key-id shape is
  // upper-case only, so the folded key passed every recogniser and the card
  // read `Force-push to akia….example.invalid`: upper-casing that gives the
  // key back exactly. Three destination forms, each on the held and the
  // headless path. A scratch repository (config only; nothing runs git) lets
  // the card builder establish the host. The legacy body and the denial rows
  // are compared with goldens captured at the comparison base (1525b204),
  // where no card existed: they differ from the remote-name goldens above
  // only by the per-command hash. Since the descope the card names no host.
  const HOST_KEY = ['AK', 'IA'].join('') + 'W7NQ4KPJ2XZT6RHM';
  const KEY_HOST = `${HOST_KEY}.example.invalid`;
  const HOST_WHAT = 'Force-push to a remote';
  const ORDINARY_ORIGIN = 'https://github.com/acme/app.git';
  const HOST_FORMS: Array<[form: string, command: string, origin: string, hash: string]> = [
    ['typed URL', `git push --force https://${KEY_HOST}/acme/app.git main`, ORDINARY_ORIGIN, '6d9d6a34b0504681cae491ec34992357698909f6a5adf80cbdc5dc24b036b106'],
    ['configured remote', 'git push --force origin main', `https://${KEY_HOST}/acme/app.git`, '3f33515788426f3b10a1e4eefaee2d56d386736c46c3c9c773a892c5ef54f13a'],
    ['scp-style', `git push --force user@${KEY_HOST}:acme/app.git main`, ORDINARY_ORIGIN, 'e3f91de531bea670398ee6d1c154282f7490c6bfcd8c031260a16c7436c33a51'],
  ];

  function scratchRepo(originUrl: string): void {
    mkdirSync(join(jobCwd, '.git', 'refs', 'heads'), { recursive: true });
    mkdirSync(join(jobCwd, '.git', 'objects'), { recursive: true });
    writeFileSync(join(jobCwd, '.git', 'HEAD'), 'ref: refs/heads/main\n');
    writeFileSync(
      join(jobCwd, '.git', 'config'),
      `[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n\turl = ${originUrl}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n`,
    );
  }
  const askGolden = (hash: string) => GOLDEN_WEBHOOK_ASK_REMOTE
    .split(REMOTE_ASK_HASH).join(hash)
    .split(REMOTE_ASK_HASH.slice(0, 12)).join(hash.slice(0, 12));
  /** The original key, the lower-cased form the card used to print, and the
   *  reconstruction (upper-casing everything that left the box). */
  function expectNoHostKey(raw: string[]): void {
    const rowsRaw = lines(join(home, '.shieldcortex', 'denials.jsonl')).join('\n');
    for (const text of [...raw, rowsRaw]) {
      expect(text).not.toContain(HOST_KEY);
      expect(text).not.toContain(HOST_KEY.toLowerCase());
      for (const needle of [HOST_KEY, HOST_KEY.slice(0, 8), HOST_KEY.slice(-8)]) expect(text.toUpperCase()).not.toContain(needle);
    }
  }

  it('control: an ordinary host gets the same fixed WHAT on both paths: the webhook card names no host at all', () => {
    scratchRepo(ORDINARY_ORIGIN);
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    const what = 'Force-push to a remote';
    expect(runHook({ command: `git push --force ${ORDINARY_ORIGIN} main` }).decision).toBe('ask');
    expect(runHook({ command: 'git push --force origin main' }, { permissionMode: 'bypassPermissions' }).decision).toBe('deny');
    expect(runHook({ command: 'git push --force git@github.com:acme/app.git main' }).decision).toBe('ask');
    const got = lines(webhookEvidence).map((b) => splitCard(normaliseWebhookBody(b)).card as Record<string, string>);
    expect(got.map((c) => [c.kind, c.what])).toEqual([['approval', what], ['denial', what], ['approval', what]]);
    for (const c of got) expect(sansWho(c)).not.toMatch(/github|acme|main/);
  });

  it.each(HOST_FORMS)('#815 A review B2: a credential-shaped host (%s) never reaches the webhook card (headless denial)', (_form, command, origin) => {
    scratchRepo(origin);
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    expect(runHook({ command }, { permissionMode: 'bypassPermissions' }).decision).toBe('deny');
    const raw = lines(webhookEvidence);
    expect(raw).toHaveLength(1);
    const { rest, card } = splitCard(normaliseWebhookBody(raw[0]));
    expect(rest).toBe(GOLDEN_WEBHOOK_DNP_REMOTE);
    expect(card).toMatchObject({
      version: 1,
      kind: 'denial',
      what: HOST_WHAT,
      why: 'pushes to a remote branch (may overwrite history)',
      approveCommand: 'shieldcortex approve --denial act-<action>',
    });
    expect(card!.text).toContain(`What: ${HOST_WHAT}`);
    expect(denialRows()).toEqual(GOLDEN_DENIALS_DNP_REMOTE);
    expect(denialRows().join('\n')).not.toContain('"card"');
    expectNoHostKey(raw);
  });

  it.each(HOST_FORMS)('#815 A review B2: a credential-shaped host (%s) never reaches the webhook card (held approval)', (_form, command, origin, hash) => {
    scratchRepo(origin);
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook' });
    expect(runHook({ command }).decision).toBe('ask');
    const raw = lines(webhookEvidence);
    expect(raw).toHaveLength(1);
    const { rest, card } = splitCard(normaliseWebhookBody(raw[0]));
    expect(rest).toBe(askGolden(hash));
    expect(card).toMatchObject({
      version: 1,
      kind: 'approval',
      what: HOST_WHAT,
      why: 'pushes to a remote branch (may overwrite history)',
      approveCommand: `shieldcortex approve ${hash.slice(0, 12)} --attempt <attempt>`,
      denyCommand: `shieldcortex deny ${hash.slice(0, 12)} --attempt <attempt>`,
    });
    expect(card!.text).toContain(`What: ${HOST_WHAT}`);
    expect(denialRows()).toEqual([]);
    expectNoHostKey(raw);
  });

  // #815 A review r4 — the reviewers' r3 rows, through the real hook. A key
  // split by NBSP or U+3000 (Grok r3), or typed full-width or math-bold
  // (Astra r3 B3), as a branch or in an SSH-folder path, reached the webhook
  // card because no recogniser read the form a reader (or NFKC) sees. Since
  // the descope every row's card is the fixed template, held and headless,
  // and the legacy body and the denial rows are the base goldens byte for byte.
  const R4_KEY_SPLIT = ['AK', 'IA'].join('') + 'W7NQ4KPJ2XZT6RHM';
  const R4_KEY_WIDE = ['AK', 'IA'].join('') + 'M6ZQ3RVN5TXP7LKH';
  const R4_JWT = `${['ey', 'J'].join('')}hbGciOiJIUzI1NiJ9.${['ey', 'J'].join('')}zdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`;
  const wide = (s: string) => [...s].map((c) => (c >= '!' && c <= '~' ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c)).join('');
  const bold = (s: string) => [...s].map((c) => (/[A-Z]/.test(c) ? String.fromCodePoint(0x1d400 + c.charCodeAt(0) - 65)
    : /[a-z]/.test(c) ? String.fromCodePoint(0x1d41a + c.charCodeAt(0) - 97)
      : /[0-9]/.test(c) ? String.fromCodePoint(0x1d7ce + c.charCodeAt(0) - 48) : c)).join('');
  const splitBy = (sep: string) => `${R4_KEY_SPLIT.slice(0, 10)}${sep}${R4_KEY_SPLIT.slice(10)}`;
  const R4_PUSH_WHAT = 'Force-push to a remote';
  const R4_READ_WHAT = 'Read a file in your SSH folder';
  const R4_ROWS: Array<[row: string, command: string, secret: string, what: string]> = [
    ['Grok r3: NBSP-split branch', `git push --force origin ${splitBy('\u00a0')}`, R4_KEY_SPLIT, R4_PUSH_WHAT],
    ['Grok r3: U+3000-split branch', `git push --force origin ${splitBy('\u3000')}`, R4_KEY_SPLIT, R4_PUSH_WHAT],
    ['Astra r3 B3: full-width branch', `git push --force origin ${wide(R4_KEY_WIDE)}`, R4_KEY_WIDE, R4_PUSH_WHAT],
    ['Astra r3 B3: math-bold branch', `git push --force origin ${bold(R4_KEY_WIDE)}`, R4_KEY_WIDE, R4_PUSH_WHAT],
    ['Astra r3 B3: full-width JWT-shaped branch', `git push --force origin ${wide(R4_JWT)}`, R4_JWT, R4_PUSH_WHAT],
    ['Astra r3 B3: full-width key in an SSH-folder path', `cat ~/.ssh/${wide(R4_KEY_WIDE)}`, R4_KEY_WIDE, R4_READ_WHAT],
    ['Astra r3 B3: math-bold key in an SSH-folder path', `cat ~/.ssh/${bold(R4_KEY_WIDE)}`, R4_KEY_WIDE, R4_READ_WHAT],
    ['Astra r3 B3: full-width JWT-shaped SSH-folder path', `cat ~/.ssh/${wide(R4_JWT)}`, R4_JWT, R4_READ_WHAT],
    ['NBSP-split key in an SSH-folder path', `cat ~/.ssh/${splitBy('\u00a0')}`, R4_KEY_SPLIT, R4_READ_WHAT],
    ['U+3000-split key in an SSH-folder path', `cat ~/.ssh/${splitBy('\u3000')}`, R4_KEY_SPLIT, R4_READ_WHAT],
  ];
  /** Raw bytes, NFKC, every case, and every 10-character window of the
   *  secret (the split halves included): no meaningful fragment leaves. */
  function expectNoR4Secret(raw: string[], secret: string): void {
    const rowsRaw = lines(join(home, '.shieldcortex', 'denials.jsonl')).join('\n');
    const windows = Array.from({ length: secret.length - 9 }, (_, i) => secret.slice(i, i + 10).toUpperCase());
    for (const text of [...raw, rowsRaw]) {
      const read = text.normalize('NFKC').toUpperCase();
      expect(text).not.toContain(R4_KEY_SPLIT.slice(0, 10));
      expect(text).not.toContain(R4_KEY_SPLIT.slice(10));
      expect(text.normalize('NFKC')).not.toContain(secret);
      for (const w of windows) expect(read).not.toContain(w);
    }
  }
  const withHash = (golden: string, from: string, to: string) => golden
    .split(from).join(to)
    .split(from.slice(0, 12)).join(to.slice(0, 12));

  it('#815 A review r4 control: an ordinary branch and an ordinary SSH-folder path get the same fixed WHAT', () => {
    scratchRepo(ORDINARY_ORIGIN);
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    expect(runHook({ command: 'git push --force upstream feature/login-form' }).decision).toBe('ask');
    expect(runHook({ command: 'git push --force origin main' }, { permissionMode: 'bypassPermissions' }).decision).toBe('deny');
    expect(runHook({ command: 'cat ~/.ssh/known_hosts' }).decision).toBe('ask');
    const got = lines(webhookEvidence).map((b) => splitCard(normaliseWebhookBody(b)).card as Record<string, string>);
    expect(got.map((c) => [c.kind, c.what])).toEqual([
      ['approval', R4_PUSH_WHAT],
      ['denial', R4_PUSH_WHAT],
      ['approval', R4_READ_WHAT],
    ]);
    for (const c of got) expect(sansWho(c)).not.toMatch(/upstream|feature|login-form|github|known_hosts/);
  });

  it.each(R4_ROWS)('#815 A review r4: %s never reaches the webhook card (headless denial)', (_row, command, secret, what) => {
    scratchRepo(ORDINARY_ORIGIN);
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    expect(runHook({ command }, { permissionMode: 'bypassPermissions' }).decision).toBe('deny');
    const raw = lines(webhookEvidence);
    expect(raw).toHaveLength(1);
    const { rest, card } = splitCard(normaliseWebhookBody(raw[0]));
    const push = what === R4_PUSH_WHAT;
    expect(rest).toBe(push ? GOLDEN_WEBHOOK_DNP_REMOTE : GOLDEN_WEBHOOK_DNP);
    expect(card).toMatchObject({ version: 1, kind: 'denial', what, approveCommand: 'shieldcortex approve --denial act-<action>' });
    expect(card!.text).toContain(`What: ${what}`);
    expect(denialRows()).toEqual(push ? GOLDEN_DENIALS_DNP_REMOTE : GOLDEN_DENIALS_DNP);
    expect(denialRows().join('\n')).not.toContain('"card"');
    expectNoR4Secret(raw, secret);
  });

  it.each(R4_ROWS)('#815 A review r4: %s never reaches the webhook card (held approval)', (_row, command, secret, what) => {
    scratchRepo(ORDINARY_ORIGIN);
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook' });
    expect(runHook({ command }).decision).toBe('ask');
    const raw = lines(webhookEvidence);
    expect(raw).toHaveLength(1);
    const { rest, card } = splitCard(normaliseWebhookBody(raw[0]));
    const hash = String(JSON.parse(rest).hash);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    const push = what === R4_PUSH_WHAT;
    expect(rest).toBe(push ? withHash(GOLDEN_WEBHOOK_ASK_REMOTE, REMOTE_ASK_HASH, hash) : withHash(GOLDEN_WEBHOOK_ASK, ASK_HASH, hash));
    expect(card).toMatchObject({
      version: 1,
      kind: 'approval',
      what,
      approveCommand: `shieldcortex approve ${hash.slice(0, 12)} --attempt <attempt>`,
      denyCommand: `shieldcortex deny ${hash.slice(0, 12)} --attempt <attempt>`,
    });
    expect(card!.text).toContain(`What: ${what}`);
    expect(denialRows()).toEqual([]);
    expectNoR4Secret(raw, secret);
  });

  // #815 A review r5 — the reviewers' r4 rows, through the real hook. B4 (Astra
  // and Grok r4): a key with some or all of its characters written as `%XX`
  // reached the card, because no recogniser read the decoded text. B5 (Astra
  // r4): a key the shell split into two words showed its first word as the
  // branch; the card builder chose that word before anything read the whole
  // command. Since the descope every row's card is the fixed template, held
  // and headless; the WHO line and
  // the approve command stay; the legacy body and the denial rows are the
  // base goldens byte for byte, but for `argc`: the guard's own count of the
  // tokens in the span it matched, which differs with the command's shape.
  const pct = (s: string, n = s.length) => [...s.slice(0, n)].map((c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`).join('') + s.slice(n);
  const R5_AWS = ['AK', 'IA'].join('') + 'T3VQ7XWN4ZRK2PLD';
  const R5_STS = ['AS', 'IA'].join('') + 'T3VQ7XWN4ZRK2PLD';
  const R5_GH = ['ghp', '_'].join('') + ['t7K2mQ', 'z4R9vN', 'p6L3wB', 'h8D5xF', 'c1J0sA', 'y2U4eG'].join('');
  const R5_SPLIT = `${R5_GH.slice(0, 20)} ${R5_GH.slice(20)}`;
  const R5_READ2_WHAT = R4_READ_WHAT;
  const R5_ROWS: Array<[row: string, command: string, secret: string, what: string, argc: number]> = [
    ['B4 (Astra r4): AWS key id, prefix as %XX, as a branch', `git push --force origin ${pct(R5_AWS, 4)}`, R5_AWS, R4_PUSH_WHAT, 3],
    ['B4 (Astra r4): AWS key id, prefix as %XX, in an SSH-folder path', `cat ~/.ssh/${pct(R5_AWS, 4)}`, R5_AWS, R4_READ_WHAT, 1],
    ['B4 (Astra r4): STS key id, prefix as %XX, as a branch', `git push --force origin ${pct(R5_STS, 4)}`, R5_STS, R4_PUSH_WHAT, 3],
    ['B4 (Astra r4): STS key id, prefix as %XX, in an SSH-folder path', `cat ~/.ssh/${pct(R5_STS, 4)}`, R5_STS, R4_READ_WHAT, 1],
    ['B4 (Grok r4): key id, first character as %XX, as a branch', `git push --force origin ${pct(R4_KEY_SPLIT, 1)}`, R4_KEY_SPLIT, R4_PUSH_WHAT, 3],
    ['B4 (Grok r4): key id, first character as %XX, in an SSH-folder path', `cat ~/.ssh/${pct(R4_KEY_SPLIT, 1)}`, R4_KEY_SPLIT, R4_READ_WHAT, 1],
    ['B4 (Grok r4): key id, prefix as %XX, as a branch', `git push --force origin ${pct(R4_KEY_SPLIT, 4)}`, R4_KEY_SPLIT, R4_PUSH_WHAT, 3],
    ['B4 sibling (Astra r4): AWS key id, every character as %XX, as a branch', `git push --force origin ${pct(R5_AWS)}`, R5_AWS, R4_PUSH_WHAT, 3],
    ['B4 sibling (Astra r4): GitHub token, every character as %XX, as a branch', `git push --force origin ${pct(R5_GH)}`, R5_GH, R4_PUSH_WHAT, 3],
    ['B4 sibling: key id, first character as %XX twice over, as a branch', `git push --force origin %25${pct(R4_KEY_SPLIT, 1).slice(1)}`, R4_KEY_SPLIT, R4_PUSH_WHAT, 3],
    ['B5 (Astra r4): GitHub token as two unquoted words, as a branch', `git push --force origin ${R5_SPLIT}`, R5_GH, R4_PUSH_WHAT, 3],
    ['B5 (Astra r4): GitHub token as two quoted words, as a branch', `git push --force origin '${R5_GH.slice(0, 20)}' '${R5_GH.slice(20)}'`, R5_GH, R4_PUSH_WHAT, 6],
    ['B5 (Astra r4): GitHub token split inside one quoted word, as a branch', `git push --force origin '${R5_SPLIT}'`, R5_GH, R4_PUSH_WHAT, 5],
    ['B5 (Astra r4): contiguous GitHub token, as a branch', `git push --force origin ${R5_GH}`, R5_GH, R4_PUSH_WHAT, 3],
    ['B5 sibling: GitHub token as two unquoted words, the first in an SSH-folder path', `cat ~/.ssh/${R5_SPLIT}`, R5_GH, R5_READ2_WHAT, 1],
  ];
  /** Raw, NFKC, %-decoded, every case and every 10-character window of the
   *  secret: no fragment a reader could rebuild leaves the box. */
  const decodeAll = (s: string) => {
    let t = s;
    for (let i = 0; i < 3; i += 1) t = t.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => { try { return decodeURIComponent(run); } catch { return run; } });
    return t;
  };
  function expectNoR5Secret(raw: string[], secret: string): void {
    const rowsRaw = lines(join(home, '.shieldcortex', 'denials.jsonl')).join('\n');
    const windows = Array.from({ length: secret.length - 9 }, (_, i) => secret.slice(i, i + 10).toUpperCase());
    for (const text of [...raw, rowsRaw]) {
      for (const reading of [text, decodeAll(text)]) {
        const read = reading.normalize('NFKC').toUpperCase();
        expect(read).not.toContain(secret.toUpperCase());
        for (const w of windows) expect(read).not.toContain(w);
      }
    }
  }
  const withArgc = (rows: string[], argc: number) => rows.map((r) => r.replace(/"argc":\d+/, `"argc":${argc}`));

  it('#815 A review r5 control: an ordinary branch or path with a % in it, and a word beside a whole key, get the fixed WHAT', () => {
    scratchRepo(ORDINARY_ORIGIN);
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    expect(runHook({ command: 'git push --force origin release/50%-off' }).decision).toBe('ask');
    expect(runHook({ command: 'cat ~/.ssh/old%20config' }, { permissionMode: 'bypassPermissions' }).decision).toBe('deny');
    expect(runHook({ command: `git push --force ${R4_KEY_SPLIT} main` }).decision).toBe('ask');
    const got = lines(webhookEvidence).map((b) => splitCard(normaliseWebhookBody(b)).card as Record<string, string>);
    expect(got.map((c) => [c.kind, c.what])).toEqual([
      ['approval', R4_PUSH_WHAT],
      ['denial', R4_READ_WHAT],
      ['approval', R4_PUSH_WHAT],
    ]);
    for (const c of got) expect(sansWho(c)).not.toMatch(/release|50%|old%20|config|github|main/);
  });

  it.each(R5_ROWS)('#815 A review r5: %s never reaches the webhook card (headless denial)', (_row, command, secret, what, argc) => {
    scratchRepo(ORDINARY_ORIGIN);
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook', digestWindowMs: 0 });
    expect(runHook({ command }, { permissionMode: 'bypassPermissions' }).decision).toBe('deny');
    const raw = lines(webhookEvidence);
    expect(raw).toHaveLength(1);
    const { rest, card } = splitCard(normaliseWebhookBody(raw[0]));
    const push = what === R4_PUSH_WHAT;
    expect(rest).toBe(push ? GOLDEN_WEBHOOK_DNP_REMOTE : GOLDEN_WEBHOOK_DNP);
    expect(card).toMatchObject({ version: 1, kind: 'denial', what, approveCommand: 'shieldcortex approve --denial act-<action>' });
    expect(card!.who).toMatch(WHO);
    expect(card!.text).toContain(`What: ${what}`);
    expect(card!.text).toContain('  shieldcortex approve --denial act-<action>');
    expect(denialRows()).toEqual(withArgc(push ? GOLDEN_DENIALS_DNP_REMOTE : GOLDEN_DENIALS_DNP, argc));
    expect(denialRows().join('\n')).not.toContain('"card"');
    expectNoR5Secret(raw, secret);
  });

  it.each(R5_ROWS)('#815 A review r5: %s never reaches the webhook card (held approval)', (_row, command, secret, what) => {
    scratchRepo(ORDINARY_ORIGIN);
    writeConfig({ webhookUrl: 'http://fake-webhook.invalid/hook' });
    expect(runHook({ command }).decision).toBe('ask');
    const raw = lines(webhookEvidence);
    expect(raw).toHaveLength(1);
    const { rest, card } = splitCard(normaliseWebhookBody(raw[0]));
    const hash = String(JSON.parse(rest).hash);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    const push = what === R4_PUSH_WHAT;
    expect(rest).toBe(push ? withHash(GOLDEN_WEBHOOK_ASK_REMOTE, REMOTE_ASK_HASH, hash) : withHash(GOLDEN_WEBHOOK_ASK, ASK_HASH, hash));
    expect(card).toMatchObject({
      version: 1,
      kind: 'approval',
      what,
      approveCommand: `shieldcortex approve ${hash.slice(0, 12)} --attempt <attempt>`,
      denyCommand: `shieldcortex deny ${hash.slice(0, 12)} --attempt <attempt>`,
    });
    expect(card!.who).toMatch(WHO);
    expect(card!.text).toContain(`What: ${what}`);
    expect(denialRows()).toEqual([]);
    expectNoR5Secret(raw, secret);
  });
});

// The hash of `cat ~/.ssh/config`, as the ask golden below carries it.
const ASK_HASH = '1d3e3c896ae2a9a396eacda6e9c44cf16bb9d3b69550ec941f95ca76a9151178';
const GOLDEN_WEBHOOK_ASK = "{\"event\":\"approval_requested\",\"hash\":\"1d3e3c896ae2a9a396eacda6e9c44cf16bb9d3b69550ec941f95ca76a9151178\",\"shortHash\":\"1d3e3c896ae2\",\"attemptId\":\"<attempt>\",\"tool\":\"Bash\",\"command\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"touch-sensitive-path\"],\"severity\":\"dangerous\",\"reason\":\"Action Guard requires approval; inspect local audit for details.\",\"judge\":null,\"text\":\"🛡️ ShieldCortex — approval needed\\n\\nTool:      Bash\\nCommand:   Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\\nTripped:   touch-sensitive-path\\nTier:      dangerous\\nReason:    Action Guard requires approval; inspect local audit for details.\\n\\nAI judge:  no judge ran — this verdict is rules-only\\n\\n[Approve]  shieldcortex approve 1d3e3c896ae2 --attempt <attempt>\\n[Deny]     shieldcortex deny 1d3e3c896ae2 --attempt <attempt>\",\"approveCommand\":\"shieldcortex approve 1d3e3c896ae2 --attempt <attempt>\",\"ts\":\"<ts>\",\"denyCommand\":\"shieldcortex deny 1d3e3c896ae2 --attempt <attempt>\",\"sessionId\":\"sc-<session>\"}";
const GOLDEN_WEBHOOK_DNP = "{\"event\":\"action_guard_denial\",\"outcome\":\"denied_no_prompt_surface\",\"tool\":\"Bash\",\"surface\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"touch-sensitive-path\"],\"severity\":\"dangerous\",\"reason\":\"Action Guard required approval but this session has no prompt surface; the tool call was denied.\",\"correlationId\":\"act-<action>\",\"actionId\":\"act-<action>\",\"sessionId\":\"sc-<session>\",\"origin\":\"claude-code-hook\",\"detectedAt\":\"<ts>\",\"text\":\"ShieldCortex — held (headless, no prompt)\\n\\nWhat:    1 dangerous step(s) blocked in this 15m window\\nTools:   Bash×1\\nWhy:     touch-sensitive-path×1\\nLast:    act-<action>\\n\\nRetry:   No Approve card this time (retry cards off).\\n\\nOne-shot from a real terminal on that host:\\n  shieldcortex approve --denial act-<action>\\nThen retry the same action once. Approve is not forever.\\n\\nNote:    First hold in this window; further holds are quiet (coalesced).\\nForensics: ~/.shieldcortex/denials.jsonl (command not included here).\\nThis message is visibility — not a tappable Approve surface.\",\"ts\":\"<ts>\"}";
const GOLDEN_DENIALS_DNP: string[] = [
  "{\"event\":\"action_guard_denial\",\"outcome\":\"denied_no_prompt_surface\",\"origin\":\"claude-code-hook\",\"tool\":\"Bash\",\"surface\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"touch-sensitive-path\"],\"matches\":[{\"signal\":\"touch-sensitive-path\",\"spanWithheld\":\"command-text\",\"argc\":1}],\"severity\":\"dangerous\",\"reason\":\"Action Guard required approval but this session has no prompt surface; the tool call was denied.\",\"sessionId\":\"sc-<session>\",\"actionId\":\"act-<action>\",\"correlationId\":\"act-<action>\",\"detectedAt\":\"<ts>\",\"notify\":{\"status\":\"pending\",\"deliveredVia\":null}}",
  "{\"event\":\"action_guard_denial\",\"outcome\":\"denied_no_prompt_surface\",\"origin\":\"claude-code-hook\",\"tool\":\"Bash\",\"surface\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"touch-sensitive-path\"],\"matches\":[{\"signal\":\"touch-sensitive-path\",\"spanWithheld\":\"command-text\",\"argc\":1}],\"severity\":\"dangerous\",\"reason\":\"Action Guard required approval but this session has no prompt surface; the tool call was denied.\",\"sessionId\":\"sc-<session>\",\"actionId\":\"act-<action>\",\"correlationId\":\"act-<action>\",\"detectedAt\":\"<ts>\",\"notify\":{\"status\":\"delivered\",\"deliveredVia\":\"webhook\"}}",
];

// #815 A review B1 — captured at the comparison base (1525b204) with the
// reviewer's real-hook harness, normalised exactly as above.
const GOLDEN_WEBHOOK_DNP_REMOTE = "{\"event\":\"action_guard_denial\",\"outcome\":\"denied_no_prompt_surface\",\"tool\":\"Bash\",\"surface\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"git-force-push\"],\"severity\":\"dangerous\",\"reason\":\"Action Guard required approval but this session has no prompt surface; the tool call was denied.\",\"correlationId\":\"act-<action>\",\"actionId\":\"act-<action>\",\"sessionId\":\"sc-<session>\",\"origin\":\"claude-code-hook\",\"detectedAt\":\"<ts>\",\"text\":\"ShieldCortex — held (headless, no prompt)\\n\\nWhat:    1 dangerous step(s) blocked in this 15m window\\nTools:   Bash×1\\nWhy:     git-force-push×1\\nLast:    act-<action>\\n\\nRetry:   No Approve card this time (retry cards off).\\n\\nOne-shot from a real terminal on that host:\\n  shieldcortex approve --denial act-<action>\\nThen retry the same action once. Approve is not forever.\\n\\nNote:    First hold in this window; further holds are quiet (coalesced).\\nForensics: ~/.shieldcortex/denials.jsonl (command not included here).\\nThis message is visibility — not a tappable Approve surface.\",\"ts\":\"<ts>\"}";
// The hash of `git push --force <AKIA…> main`, as the ask golden below carries it.
const REMOTE_ASK_HASH = '0b740047d8ed51addcaa4c5030f993a71dfdde02f1ca634c70da3de41b9e57c4';
const GOLDEN_WEBHOOK_ASK_REMOTE = "{\"event\":\"approval_requested\",\"hash\":\"0b740047d8ed51addcaa4c5030f993a71dfdde02f1ca634c70da3de41b9e57c4\",\"shortHash\":\"0b740047d8ed\",\"attemptId\":\"<attempt>\",\"tool\":\"Bash\",\"command\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"git-force-push\"],\"severity\":\"dangerous\",\"reason\":\"Action Guard requires approval; inspect local audit for details.\",\"judge\":null,\"text\":\"🛡️ ShieldCortex — approval needed\\n\\nTool:      Bash\\nCommand:   Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\\nTripped:   git-force-push\\nTier:      dangerous\\nReason:    Action Guard requires approval; inspect local audit for details.\\n\\nAI judge:  no judge ran — this verdict is rules-only\\n\\n[Approve]  shieldcortex approve 0b740047d8ed --attempt <attempt>\\n[Deny]     shieldcortex deny 0b740047d8ed --attempt <attempt>\",\"approveCommand\":\"shieldcortex approve 0b740047d8ed --attempt <attempt>\",\"ts\":\"<ts>\",\"denyCommand\":\"shieldcortex deny 0b740047d8ed --attempt <attempt>\",\"sessionId\":\"sc-<session>\"}";
const GOLDEN_DENIALS_DNP_REMOTE: string[] = [
  "{\"event\":\"action_guard_denial\",\"outcome\":\"denied_no_prompt_surface\",\"origin\":\"claude-code-hook\",\"tool\":\"Bash\",\"surface\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"git-force-push\"],\"matches\":[{\"signal\":\"git-force-push\",\"spanWithheld\":\"command-text\",\"argc\":3}],\"severity\":\"dangerous\",\"reason\":\"Action Guard required approval but this session has no prompt surface; the tool call was denied.\",\"sessionId\":\"sc-<session>\",\"actionId\":\"act-<action>\",\"correlationId\":\"act-<action>\",\"detectedAt\":\"<ts>\",\"notify\":{\"status\":\"pending\",\"deliveredVia\":null}}",
  "{\"event\":\"action_guard_denial\",\"outcome\":\"denied_no_prompt_surface\",\"origin\":\"claude-code-hook\",\"tool\":\"Bash\",\"surface\":\"Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command\",\"signals\":[\"git-force-push\"],\"matches\":[{\"signal\":\"git-force-push\",\"spanWithheld\":\"command-text\",\"argc\":3}],\"severity\":\"dangerous\",\"reason\":\"Action Guard required approval but this session has no prompt surface; the tool call was denied.\",\"sessionId\":\"sc-<session>\",\"actionId\":\"act-<action>\",\"correlationId\":\"act-<action>\",\"detectedAt\":\"<ts>\",\"notify\":{\"status\":\"delivered\",\"deliveredVia\":\"webhook\"}}",
];
