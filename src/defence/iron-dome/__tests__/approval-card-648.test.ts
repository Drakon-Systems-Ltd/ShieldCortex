/**
 * #648 — the plain-English approval card: what it wants to do (naming the
 * target), why ShieldCortex stopped it, and who is asking.
 *
 * Secret fixtures are assembled at runtime so no secret-shaped literal is ever
 * committed (GitHub push protection); destructive command fixtures likewise
 * (the guard's own write-content scan, same convention as the #436 suite).
 */
import { describe, it, expect } from '@jest/globals';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SIGNAL_PHRASES,
  WITHHELD_SECRET,
  buildApprovalCard,
  describeAction,
  describeSignal,
  describeSignals,
  describeWho,
  formatApprovalCardLines,
  safeTarget,
} from '../approval-card.js';
import { buildCardFields } from '../openclaw-approval-channel.js';
import { GUARD_SELF_PROTECTION_SIGNALS, evaluateToolCall } from '../tool-action-guard.js';
import type { OperatorNotification } from '../operator-notify.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..', '..', '..');

const GH = ['gh', 'p_'].join('') + 'Z'.repeat(4) + 'q7Lm2Xr9Tb4Vc8Nd1Fh6Jk3Wp5Ys0Ua';
const AWS_ID = ['AK', 'IA'].join('') + 'Q3XZ7LMN2PRT6VWY';
const SLACK = ['xo', 'xb-'].join('') + '2468135790-1357924680-' + 'Kq8Lm3Np5Rt7Vx9Zb2Dc4Fg';
const OPAQUE = 'Q'.repeat(3) + 'f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2';
const RM_RF = ['r', 'm', ' -', 'r', 'f'].join('');

const bash = (command: string, signals: string[] = evaluateToolCall('Bash', { command }).signals) =>
  describeAction({ tool: 'Bash', input: { command }, signals });

function notification(over: Partial<OperatorNotification> = {}): OperatorNotification {
  return {
    event: 'approval_requested',
    hash: '1ae99749ee74'.padEnd(64, '0'),
    shortHash: '1ae99749ee74',
    tool: 'Bash',
    command: 'Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command',
    signals: ['touch-sensitive-path'],
    severity: 'dangerous',
    reason: 'Action Guard requires approval; inspect local audit for details.',
    judge: null,
    fallbackHint: 'shieldcortex approve 1ae99749ee74',
    ...over,
  };
}

describe('#648 — the screenshot card', () => {
  it('without a summary, the redacted surface is no longer the card: plain WHY, honest WHAT', () => {
    const { description } = buildCardFields(notification());
    expect(description).not.toContain('redacted action surface');
    expect(description).not.toContain('fields=');
    expect(description).not.toContain('(dangerous)');
    expect(description).toContain('Why: touches a sensitive file (keys, passwords or credentials)');
    expect(description).toContain('details withheld: could not summarise safely');
  });

  it('with the summary: what, why, who, plus allow-once/deny and the expiry', () => {
    const card = buildApprovalCard({
      tool: 'Bash',
      input: { command: 'cat ~/.ssh/config' },
      signals: ['touch-sensitive-path'],
      plane: 'claude-code',
      host: 'veronica-box',
      sessionId: 'sc-0123456789abcdef',
    });
    const { title, description } = buildCardFields(notification({ card }));
    expect(title).toBe('ShieldCortex: approve Bash? [1ae99749ee74]');
    expect(description.split('\n')).toEqual([
      'Read a file in your SSH folder: "~/.ssh/config"',
      'Why: touches a sensitive file (keys, passwords or credentials)',
      'Who: Claude Code on veronica-box · session sc-0123456789abcdef',
      'Allow once or deny · expires in 10 min',
    ]);
  });

  it('the guard test round-trip card (no summary, not a redacted surface) is unchanged', () => {
    const { description } = buildCardFields(notification({
      command: 'SYNTHETIC ROUND-TRIP TEST. Type this confirmation code: 123456',
      signals: ['approval-round-trip-test'],
    }));
    expect(description).toBe('SYNTHETIC ROUND-TRIP TEST. Type this confirmation code: 123456\nTripped: approval-round-trip-test (dangerous)');
  });
});

describe('#648 — WHAT: plain English with a named target', () => {
  it.each([
    ['cat ~/.ssh/config', 'Read a file in your SSH folder: "~/.ssh/config"'],
    ['cat .env', 'Read a file of secret settings: ".env"'],
    [`${RM_RF} ./build`, 'Delete a folder and everything in it: "./build"'],
    ['pkill -f relay.mjs', 'Stop every program whose command line matches: "relay.mjs"'],
    ['killall node', 'Stop every program named "node"'],
    ['sudo systemctl stop nginx', 'Stop the service: "nginx", as administrator (sudo)'],
    ['npm install -g typescript', 'Install a package: "typescript" (npm, whole machine)'],
    ['npm install --registry https://registry.npmjs.org left-pad', 'Install a package: "left-pad" (npm)'],
    ['git branch -D feature/x', 'Delete a git branch: "feature/x"'],
    ['git push --force https://github.com/acme/app.git main', 'Force-push to github.com (branch "main"), which may overwrite history (git push --force)'],
    ['crontab -e', 'Change scheduled jobs (crontab)'],
    ['chmod -R 777 /var/www', 'Change who can access a folder and everything in it: "/var/www"'],
    ['scp ./db.sql backup@files.example.org:/srv/', 'Copy files to files.example.org (scp)'],
    ['cd /tmp && echo hi > ~/.bashrc', 'Write to a file: "~/.bashrc" (+1 more step)'],
  ])('%s', (command, expected) => {
    expect(bash(command)).toBe(expected);
  });

  it('an egress hold names the host: "Send data to <host> (<command>)"', () => {
    expect(bash('curl -d @report.json https://collector.example.net/in', ['external-egress']))
      .toBe('Send data to collector.example.net (curl)');
  });

  it('git fetch names the host behind the remote, read from the repo config on this box', () => {
    const repo = mkdtempSync(join(tmpdir(), 'sc-648-git-'));
    try {
      mkdirSync(join(repo, '.git'));
      writeFileSync(join(repo, '.git', 'config'), '[core]\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:acme/app.git\n');
      expect(describeAction({ tool: 'Bash', input: { command: 'git fetch origin' }, signals: ['external-egress'], cwd: repo }))
        .toBe('Send data to github.com (git fetch)');
      // An unknown remote is named as a remote, not invented as a host.
      expect(describeAction({ tool: 'Bash', input: { command: 'git fetch upstream' }, signals: ['external-egress'], cwd: repo }))
        .toBe('Send data to the "upstream" remote (git fetch)');
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it('a stopped PID is described from on-box facts, including whether the agent started it', () => {
    const proc = mkdtempSync(join(tmpdir(), 'sc-648-proc-'));
    try {
      const stat = (pid: number, comm: string, ppid: number, startTicks: number) =>
        `${pid} (${comm}) S ${ppid} ${Array(17).fill('0').join(' ')} ${startTicks} 0 0\n`;
      writeFileSync(join(proc, 'uptime'), '1000.00 4000.00\n');
      for (const [pid, comm, ppid] of [[4242, 'node', 4000], [4000, 'bash', 999]] as const) {
        mkdirSync(join(proc, String(pid)));
        writeFileSync(join(proc, String(pid), 'stat'), stat(pid, comm, ppid, (1000 - 240) * 100));
        writeFileSync(join(proc, String(pid), 'comm'), `${comm}\n`);
      }
      symlinkSync('/tmp/relay', join(proc, '4242', 'cwd'));
      const input = { tool: 'Bash', input: { command: 'kill 4242' }, signals: ['stop-process-or-service'], procRoot: proc };
      expect(describeAction({ ...input, agentPid: 999 })).toBe('Stop a program it started 4 minutes ago (node, in "/tmp/relay")');
      expect(describeAction({ ...input, agentPid: 31337 })).toBe('Stop a running program (node, in "/tmp/relay", PID 4242, running for 4 minutes)');
      expect(describeAction({ ...input, input: { command: 'kill 777' } })).toBe('Stop a running program (PID 777)');
    } finally {
      rmSync(proc, { recursive: true, force: true });
    }
  });

  it('non-shell tools', () => {
    expect(describeAction({ tool: 'Read', input: { file_path: '/root/.ssh/id_ed25519' }, signals: [] }))
      .toBe('Read a file in your SSH folder: "/root/.ssh/id_ed25519"');
    expect(describeAction({ tool: 'WebFetch', input: { url: 'https://docs.example.com/a?key=v', prompt: 'x' }, signals: [] }))
      .toBe('Fetch a web page from docs.example.com');
    expect(describeAction({ tool: 'KillShell', input: { shell_id: 'b1' }, signals: [] })).toBe('Stop a background command it started');
    expect(describeAction({ tool: 'process', input: { action: 'kill', sessionId: 's' }, signals: [] })).toBe('Stop a running background command');
    expect(describeAction({ tool: 'exec', input: { command: 'killall node' }, signals: [] })).toBe('Stop every program named "node"');
  });

  it('says so honestly when nothing can be derived — never the raw command', () => {
    expect(describeAction({ tool: 'mystery_tool', input: { a: 1 }, signals: [] }))
      .toBe('Use mystery_tool (details withheld: could not summarise safely)');
    expect(describeAction({ tool: 'Bash', input: {}, signals: [] }))
      .toBe('Run a shell command (details withheld: could not summarise safely)');
    expect(bash('python3 -c "print(1)"')).toBe('Run inline python3 code (details withheld: could not summarise safely)');
    expect(bash('frobnicate --all ./x')).toBe('Run frobnicate (other details not shown)');
  });

  it('a long target is clipped in the middle, never past the card budget', () => {
    const deep = `/srv/${'a'.repeat(30)}/${'b'.repeat(30)}/${'c'.repeat(30)}/final.txt`;
    const shown = safeTarget(deep);
    expect(shown.length).toBeLessThanOrEqual(60);
    expect(shown).toContain('…');
    expect(shown.endsWith('final.txt')).toBe(true);
  });
});

describe('#648 — a credential-shaped target never reaches the card', () => {
  it.each([
    ['an AWS key id in a path (a shape only the redactor knows)', `cat ~/.ssh/${AWS_ID}`, AWS_ID],
    ['a GitHub token in a pkill pattern', `pkill -f "relay --token=${GH}"`, GH],
    ['credentials in a git URL', `git push --force https://bot:${GH}@github.com/acme/app.git main`, GH],
    ['a Slack token as a process name', `killall ${SLACK}`, SLACK],
    ['an env-assigned secret', `NPM_TOKEN=${OPAQUE} npm install -g typescript`, OPAQUE],
    ['a long opaque string as a path', `${RM_RF} /tmp/${OPAQUE}`, OPAQUE],
    ['a token in a curl URL', `curl https://${GH}@api.github.com/user`, GH],
  ])('%s', (_label, command, secret) => {
    const card = buildApprovalCard({ tool: 'Bash', input: { command }, signals: evaluateToolCall('Bash', { command }).signals, plane: 'claude-code' });
    const text = JSON.stringify(card) + buildCardFields(notification({ card })).description;
    expect(text).not.toContain(secret);
    expect(text).not.toContain(secret.slice(0, 10));
    expect(text).not.toContain(secret.slice(-10));
  });

  it('the AWS-key path is withheld by the credential redactor (the mutation target)', () => {
    // `looksSecretish` does not know vendor prefixes; only `redactCredentials`
    // does. Remove the redactor call from `safeTarget` and this fails.
    expect(safeTarget(`/home/u/.ssh/${AWS_ID}`)).toBe(WITHHELD_SECRET);
    expect(bash(`cat ~/.ssh/${AWS_ID}`)).toBe(`Read a file in your SSH folder: ${WITHHELD_SECRET}`);
  });

  // A short, dictionary-shaped password has no credential SHAPE, so it is
  // kept off the card by where it sits, not by what it looks like.
  const PLAIN_PW = ['hun', 'ter', '2'].join('');

  it("a flag's value is never printed as the subcommand of an unknown program", () => {
    const line = bash(`sshpass -p ${PLAIN_PW} ssh deploy@build.example.org`, ['external-egress']);
    expect(line).not.toContain(PLAIN_PW);
    expect(line).toBe('Run sshpass (other details not shown)');
    expect(bash('frobnicate sync ./x', [])).toBe('Run frobnicate (other details not shown)');
  });

  it('a password passed as `--password <value>` in a shown pattern is withheld', () => {
    const line = bash(`pkill -f "relay --password ${PLAIN_PW}"`, ['stop-process-or-service']);
    expect(line).not.toContain(PLAIN_PW);
    expect(line).toBe(`Stop every program whose command line matches: ${WITHHELD_SECRET}`);
  });

  it('ssh option values are not mistaken for the destination host', () => {
    expect(bash('ssh -p 2222 -i ~/.ssh/deploy_key deploy@build.example.org', ['external-egress']))
      .toBe('Log in to build.example.org over SSH');
  });
});

describe('#648 — WHY: one table, every signal the guard can emit', () => {
  /** Kebab-case literals in tool-action-guard.ts that are NOT signal ids. */
  const NOT_SIGNALS = new Set([
    'attributes-only', 'copy-contents', 'no-clobber', 'no-dereference', 'no-preserve', 'no-target-directory',
    'one-file-system', 'remove-destination', 'strip-trailing-slashes', 'symbolic-link', 'target-directory',
    'firewall-cmd', 'send-keys',
  ]);

  function stripComments(src: string): string {
    return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\\])\/\/.*$/gm, '$1');
  }
  function kebabLiterals(src: string): string[] {
    return [...stripComments(src).matchAll(/'([a-z][a-z0-9]*(?:-[a-z0-9]+)+)'/g)].map((m) => m[1]);
  }
  function setLiteral(src: string, name: string): string[] {
    const block = new RegExp(`const ${name} = new Set\\(\\[([\\s\\S]*?)\\]\\);`).exec(src);
    if (!block) throw new Error(`${name} not found`);
    return [...block[1].matchAll(/'([a-z0-9-]+)'/g)].map((m) => m[1]);
  }

  const emitted = (() => {
    const read = (p: string) => readFileSync(join(REPO, p), 'utf8');
    const guard = kebabLiterals(read('src/defence/iron-dome/tool-action-guard.ts')).filter((s) => !NOT_SIGNALS.has(s));
    // Schema refusals: `invalid-tool-input` plus the code, kebab-cased.
    const schemaCodes = /code: ((?:'[A-Z_]+'\s*\|?\s*)+);/.exec(read('src/defence/iron-dome/tool-input-schema.ts'))![1]
      .match(/[A-Z_]+/g)!.map((c) => c.toLowerCase().replace(/_/g, '-'));
    // Lease refusals ride `[session-lease, <verdict>]`.
    const leaseVerdicts = /export type LeaseVerdict = ([^;]+);/.exec(read('src/defence/iron-dome/session-lease.ts'))![1]
      .match(/'([a-z]+)'/g)!.map((v) => v.slice(1, -1)).filter((v) => v !== 'allow');
    const hookVocabulary = setLiteral(read('scripts/pre-tool-hook.mjs'), 'SAFE_SIGNALS');
    const notifyVocabulary = setLiteral(read('src/defence/iron-dome/operator-notify.ts'), 'SAFE_ACTION_GUARD_SIGNALS');
    return [...new Set([
      ...guard, ...schemaCodes, ...leaseVerdicts, ...hookVocabulary, ...notifyVocabulary,
      ...GUARD_SELF_PROTECTION_SIGNALS, 'fallback-scan', 'session-lease', 'redacted-signal',
    ])].sort();
  })();

  it('the extraction found the guard vocabulary (harness validity)', () => {
    for (const known of ['touch-sensitive-path', 'external-egress', 'stop-process-or-service', 'recursive-force-delete', 'unknown-keys', 'frozen', 'touch-guard-config']) {
      expect(emitted).toContain(known);
    }
    expect(emitted.length).toBeGreaterThan(60);
  });

  it('every signal id the guard can emit has a plain-English entry', () => {
    const missing = emitted.filter((s) => !Object.prototype.hasOwnProperty.call(SIGNAL_PHRASES, s));
    expect(missing).toEqual([]);
  });

  it("the brief's examples", () => {
    expect(describeSignal('touch-sensitive-path')).toBe('touches a sensitive file (keys, passwords or credentials)');
    expect(describeSignal('external-egress')).toBe('sends data off this machine');
    expect(describeSignal('stop-process-or-service')).toBe('stops a running program');
    expect(describeSignal('recursive-force-delete')).toBe('deletes files permanently');
  });

  it('an unknown id falls back to the id itself; a non-id never prints', () => {
    expect(describeSignal('brand-new-rule')).toBe('brand-new-rule');
    expect(describeSignal(`token=${GH}`)).toBe('matched another safety rule');
  });

  it('phrases are never cut mid-phrase; extras become a count', () => {
    expect(describeSignals(['privilege-escalation', 'stop-process-or-service', 'external-egress']))
      .toBe('runs with administrator (root) rights (+2 more reasons)');
    expect(describeSignals(['file-delete', 'git-mutate'])).toBe('deletes files; changes the git repository');
    expect(describeSignals([])).toBe('matched a safety rule');
  });
});

describe('#648 — WHO: agent, box, session', () => {
  it('Claude Code hook plane', () => {
    expect(describeWho({ plane: 'claude-code', host: 'veronica-box', sessionId: 'sc-0123456789abcdef' }))
      .toBe('Claude Code on veronica-box · session sc-0123456789abcdef');
    expect(describeWho({ plane: 'claude-code', host: 'veronica-box', sessionId: 'raw-session-uuid' }))
      .toBe('Claude Code on veronica-box');
  });

  it('OpenClaw plane: agent id, host, the session kind and a digest — never the raw key', () => {
    const key = 'agent:main:telegram:group:-1001234567890:topic:10';
    const who = describeWho({ plane: 'openclaw', agentId: 'main', host: 'clawdbot1', sessionId: key });
    expect(who).toMatch(/^OpenClaw agent "main" on clawdbot1 · Telegram chat #[0-9a-f]{8}$/);
    expect(who).not.toContain('1001234567890');
    expect(describeWho({ plane: 'openclaw', host: 'h', sessionId: 'agent:ops:cron:nightly' })).toMatch(/^OpenClaw agent "ops" on h · scheduled job #/);
  });

  it('a hostile hostname is not printed', () => {
    expect(describeWho({ plane: 'claude-code', host: 'evil\nhost' })).toBe('Claude Code on this machine');
  });

  it("a long generated hostname (CI, cloud) is shortened, and the session still fits the card's WHO line", () => {
    const host = `sat12-bq${'7'.repeat(20)}-${'a1b2c3d4'.repeat(4)}.local`;
    const who = describeWho({ plane: 'claude-code', host, sessionId: 'sc-0123456789abcdef' });
    expect(who).toMatch(/^Claude Code on sat12-b…[a-d0-9]{12} · session sc-0123456789abcdef$/);
    expect(describeWho({ plane: 'claude-code', host: 'veronica-box.tail1234.ts.net' })).toBe('Claude Code on veronica-box');
    const [, , whoLine] = formatApprovalCardLines({ action: 'x', reason: 'y', who }, { expiresInMs: 600_000 });
    expect(whoLine).toContain('session sc-0123456789abcdef');
  });
});

describe('#648 — layout fits the 256-character card', () => {
  it('long fields are clipped per line and the footer survives', () => {
    const lines = formatApprovalCardLines(
      { action: `Read a file: ${'x'.repeat(300)}`, reason: 'r'.repeat(200), who: 'w'.repeat(200) },
      { expiresInMs: 600_000 },
    );
    expect(lines.join('\n').length).toBeLessThanOrEqual(256);
    expect(lines[3]).toBe('Allow once or deny · expires in 10 min');
  });
});
