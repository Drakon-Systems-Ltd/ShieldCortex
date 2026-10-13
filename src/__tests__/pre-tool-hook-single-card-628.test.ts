/**
 * #628 — one approval card per guarded call when claude-cli runs under an
 * OpenClaw gateway with the ShieldCortex interceptor armed.
 *
 * Drives the REAL hook (scripts/pre-tool-hook.mjs) over a shimmed dist, a fake
 * HOME and a fake config dir — never the operator's live ~/.shieldcortex. The
 * process tree is real, so the kernel proof runs against the real /proc:
 *
 *   jest worker  ── plays the OpenClaw gateway: registers the REAL plugin and
 *   │               holds the REAL card-owner marker (plugins/openclaw/card-owner.ts)
 *   └─ fake-claude ── stands in for claude-cli (argv as OpenClaw launches it)
 *      └─ node scripts/pre-tool-hook.mjs ── the Claude Code PreToolUse hook
 *
 * The hook's own card goes to a recorder (the OpenClaw approval channel
 * shim, as in #648); the interceptor's card is the plugin's `requireApproval`
 * result. "Cards shown" = interceptor cards + hook cards.
 *
 * Command payloads that a guard would refuse are assembled at runtime; none
 * is written here as a literal.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from '@jest/globals';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { evaluateToolCall } from '../defence/iron-dome/tool-action-guard.js';
import {
  cardOwnerSocketName,
  holdCardOwnerMarker,
  selfHolderIdentity,
  type CardOwnerMarker,
} from '../../plugins/openclaw/card-owner.js';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../../plugins/openclaw/index.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const REAL_DIST = join(repoRoot, 'dist', 'defence', 'iron-dome');
const linux = process.platform === 'linux';
const itLinux = linux ? it : it.skip;

const REAL_MODULES = [
  'tool-action-guard.js', 'action-approvals.js', 'notify-config.js', 'operator-notify.js',
  'script-source-resolver.js', 'dnp-digest.js', 'retry-control.js', 'dnp-retry-waiter.js',
  'approval-card.js', 'enforcement-binding.js', 'card-owner.js', 'webhook-notify-channel.js',
];

/** The argv OpenClaw's claude-cli transport launches claude with (the part
 *  the hook's wait trigger looks at). */
const OPENCLAW_CLAUDE_FLAGS = [
  '--print', '--input-format', 'stream-json', '--output-format', 'stream-json',
  '--permission-prompt-tool', 'stdio', '--permission-mode', 'default',
];

/** cat of a credentials file: the guard's dangerous tier → approval. */
const SSH_READ = { command: 'cat ~/.ssh/config' };
/** Recursive forced delete of the filesystem root: the catastrophic tier.
 *  Assembled at runtime. */
const CATASTROPHIC = { command: ['r', 'm'].join('') + ' -' + 'rf' + ' /' };

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

let seq = 0;
const newToolUseId = () => `toolu_628${process.pid}x${Date.now().toString(36)}x${seq++}`;

/** Binds a listening socket — abstract (`IMPOSTOR_ABSTRACT`) or at a path
 *  (`IMPOSTOR_PATH`) — and keeps it: a same-user process impersonating the
 *  gateway's marker. */
const IMPOSTOR_SRC = [
  "const net = require('net');",
  "const target = process.env.IMPOSTOR_ABSTRACT ? '\\0' + process.env.IMPOSTOR_ABSTRACT : process.env.IMPOSTOR_PATH;",
  'const s = net.createServer((c) => c.destroy());',
  "s.on('error', (e) => process.stdout.write('ERR ' + e.code + '\\n'));",
  "s.listen(target, () => process.stdout.write('ready\\n'));",
  'setInterval(() => {}, 1e6);',
].join('\n');

describe('#628 — one card per call: claude-cli under OpenClaw', () => {
  let home: string;
  let distRoot: string;
  let jobCwd: string;
  let cardEvidence: string;
  let fakeClaude: string;
  let interceptorAuditDir: string;
  const markers: CardOwnerMarker[] = [];
  const children: ChildProcess[] = [];
  const originalAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;

  beforeAll(() => {
    const probes = ['tool-action-guard.js', 'operator-notify.js', 'openclaw-approval-channel.js', 'card-owner.js']
      .map((f) => join(REAL_DIST, f));
    if (!probes.every((p) => existsSync(p))) {
      spawnSync('npm', ['run', 'build:ts'], { cwd: repoRoot, stdio: 'ignore' });
    }
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-628-hook-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    jobCwd = mkdtempSync(join(tmpdir(), 'sc-628-cwd-'));
    cardEvidence = join(home, 'card-evidence.jsonl');

    distRoot = mkdtempSync(join(tmpdir(), 'sc-628-dist-'));
    const ironDomeDir = join(distRoot, 'defence', 'iron-dome');
    mkdirSync(ironDomeDir, { recursive: true });
    for (const f of REAL_MODULES) {
      const real = join(REAL_DIST, f);
      if (existsSync(real)) {
        writeFileSync(join(ironDomeDir, f), `export * from ${JSON.stringify(pathToFileURL(real).href)};\n`);
      }
    }
    // The hook's card: recorded instead of spawning a waiter.
    const realCard = pathToFileURL(join(REAL_DIST, 'openclaw-approval-channel.js')).href;
    writeFileSync(
      join(ironDomeDir, 'openclaw-approval-channel.js'),
      [
        "import { appendFileSync } from 'node:fs';",
        `export * from ${JSON.stringify(realCard)};`,
        "export function resolveOpenClawBinaryLite() { return '/bin/true'; }",
        'export function createOpenClawApprovalChannel() {',
        '  return {',
        "    name: 'openclaw-approval',",
        '    async send(notification) {',
        "      if (notification.event !== 'approval_requested') return { delivered: false, reason: 'interactive-only' };",
        `      appendFileSync(${JSON.stringify(cardEvidence)}, JSON.stringify({ event: notification.event }) + '\\n');`,
        '      return { delivered: true };',
        '    },',
        '  };',
        '}',
      ].join('\n'),
    );

    // Stand-in for claude-cli: runs the hook as its own child and relays.
    fakeClaude = join(home, 'fake-claude.mjs');
    writeFileSync(
      fakeClaude,
      [
        "import { spawnSync } from 'node:child_process';",
        "let input = '';",
        "process.stdin.on('data', (d) => { input += d; });",
        "process.stdin.on('end', () => {",
        "  const r = spawnSync(process.execPath, [process.env.FAKE_CLAUDE_HOOK], { input, env: process.env, encoding: 'utf8', timeout: 30000 });",
        "  process.stdout.write(JSON.stringify({ stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status }));",
        '});',
      ].join('\n'),
    );

    writeConfig({});

    // The gateway side: the REAL plugin, auditing into a temp dir.
    interceptorAuditDir = mkdtempSync(join(tmpdir(), 'sc-628-plug-'));
    process.env.SHIELDCORTEX_AUDIT_DIR = interceptorAuditDir;
    __resetConfigStateForTest();
    __setRuntimeForTest({
      callCortex: async () => null,
      isOpenClawAutoMemoryEnabled: () => false,
      loadShieldConfig: async () => ({}),
    } as never);
    __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall } as never);
  });

  afterEach(() => {
    for (const m of markers.splice(0)) m.close();
    for (const c of children.splice(0)) { try { c.kill('SIGKILL'); } catch { /* gone */ } }
    __setDefenceModuleForTest(undefined);
    __setRuntimeForTest(null);
    __resetConfigStateForTest();
    if (originalAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
    else process.env.SHIELDCORTEX_AUDIT_DIR = originalAuditDir;
    for (const dir of [home, distRoot, jobCwd, interceptorAuditDir]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  // ── harness ──────────────────────────────────────────────────────────────

  function writeConfig(extra: Record<string, unknown>): void {
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ actionGuard: { enabled: true, enforce: true, notify: { enabled: true, openclaw: true }, ...extra } }),
    );
  }

  type Hooks = Record<string, (...args: any[]) => any>;

  /** A host build that holds the claude-cli call on the card (the field
   *  host, OpenClaw 2026.10.1). */
  const HOLDING_HOST = '2026.10.1';

  function registerPlugin(
    config: unknown = { interceptor: { actionGuard: { enabled: true } } },
    hostVersion: string | null = HOLDING_HOST,
  ): Hooks {
    const hooks: Hooks = {};
    const api = {
      id: 'shieldcortex-realtime',
      name: 'ShieldCortex Real-time Scanner',
      logger: { info: () => {}, warn: () => {} },
      on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
      registerCommand: () => {},
      runtime: {
        ...(hostVersion ? { version: hostVersion } : {}),
        config: { current: () => ({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config } } } }) },
      },
    };
    plugin.register(api as never);
    return hooks;
  }

  /** What OpenClaw's SDK PreToolUse callback does for the same call: the
   *  interceptor's card, if it raises one. */
  async function interceptorCall(hooks: Hooks, toolUseId: string | undefined, params: Record<string, unknown>, ctx: Record<string, unknown> = { sessionId: 'agent:main:chat:628' }) {
    return hooks.before_tool_call(
      { toolName: 'exec', params, ...(toolUseId ? { toolCallId: toolUseId } : {}) },
      ctx,
    );
  }

  interface HookRun { decision: string | undefined; stderr: string; elapsedMs: number }

  function hookEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
    return {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      SHIELDCORTEX_DIST_ROOT: distRoot,
      SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'),
      FAKE_CLAUDE_HOOK: HOOK,
      ...extra,
    } as NodeJS.ProcessEnv;
  }

  function hookInput(toolUseId: string | undefined, toolInput: Record<string, unknown>, permissionMode = 'default'): string {
    return JSON.stringify({
      session_id: '628-session',
      cwd: jobCwd,
      hook_event_name: 'PreToolUse',
      permission_mode: permissionMode,
      tool_name: 'Bash',
      tool_input: toolInput,
      ...(toolUseId ? { tool_use_id: toolUseId } : {}),
    });
  }

  function parseDecision(stdout: string): string | undefined {
    return stdout.trim() ? (JSON.parse(stdout).hookSpecificOutput ?? {}).permissionDecision : undefined;
  }

  function runHookUnder(
    harness: 'openclaw-claude' | 'plain-claude' | 'direct',
    toolUseId: string | undefined,
    toolInput: Record<string, unknown>,
    opts: { env?: Record<string, string>; waitMs?: number; permissionMode?: string } = {},
  ): HookRun {
    const input = hookInput(toolUseId, toolInput, opts.permissionMode);
    const env = hookEnv({
      ...(opts.waitMs !== undefined ? { SHIELDCORTEX_CARD_OWNER_WAIT_MS: String(opts.waitMs) } : {}),
      ...(opts.env ?? {}),
    });
    const started = Date.now();
    let stdout: string;
    let stderr: string;
    if (harness === 'direct') {
      const r = spawnSync(process.execPath, [HOOK], { input, env, encoding: 'utf8', timeout: 30_000 });
      stdout = r.stdout ?? '';
      stderr = r.stderr ?? '';
    } else {
      const argv = harness === 'openclaw-claude' ? [fakeClaude, ...OPENCLAW_CLAUDE_FLAGS] : [fakeClaude];
      const r = spawnSync(process.execPath, argv, { input, env, encoding: 'utf8', timeout: 30_000 });
      const relayed = JSON.parse(r.stdout || '{}') as { stdout?: string; stderr?: string };
      stdout = relayed.stdout ?? '';
      stderr = relayed.stderr ?? '';
    }
    return { decision: parseDecision(stdout), stderr, elapsedMs: Date.now() - started };
  }

  function hookCards(): number {
    return existsSync(cardEvidence) ? readFileSync(cardEvidence, 'utf8').trim().split('\n').filter(Boolean).length : 0;
  }

  function jsonlRows(dir: string): Array<Record<string, any>> {
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter((f) => /^realtime-.*\.jsonl$/.test(f))
      .flatMap((f) => readFileSync(join(dir, f), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)));
  }
  const hookAuditRows = () => jsonlRows(join(home, '.shieldcortex', 'audit'));
  const interceptorAuditRows = () => jsonlRows(interceptorAuditDir);

  function hold(toolUseId: string, params: Record<string, unknown>, holder?: { pid: number; startTime: string }): CardOwnerMarker {
    const m = holdCardOwnerMarker({ toolCallId: toolUseId, params, ...(holder ? { holder } : {}) });
    expect(m).not.toBeNull();
    markers.push(m!);
    return m!;
  }

  async function impostor(env: { IMPOSTOR_ABSTRACT?: string; IMPOSTOR_PATH?: string }): Promise<void> {
    const child = spawn(process.execPath, ['-e', IMPOSTOR_SRC], { stdio: ['ignore', 'pipe', 'inherit'], env: { ...process.env, ...env } });
    children.push(child);
    await new Promise<void>((res, rej) => {
      child.stdout!.on('data', (d) => (String(d).includes('ready') ? res() : rej(new Error(String(d)))));
      child.on('exit', () => rej(new Error('impostor exited')));
    });
  }

  const unixTable = () => readFileSync('/proc/net/unix', 'utf8');

  // ── 1. the field case: one card, verdict preserved ────────────────────────

  itLinux('same session, interceptor armed: exactly one card (the interceptor\'s), verdict preserved', async () => {
    const hooks = registerPlugin();
    const id = newToolUseId();
    const result = await interceptorCall(hooks, id, SSH_READ);
    // The interceptor put up its card (card #1) — the verdict is "needs a human".
    expect(result?.requireApproval).toBeDefined();

    const r = runHookUnder('openclaw-claude', id, SSH_READ);
    // The hook raised no card and emitted no `ask` (which would re-enter
    // can_use_tool and card again); it did not allow either.
    expect(hookCards()).toBe(0);
    expect(r.decision).toBeUndefined();
    expect(r.stderr).toContain('the OpenClaw interceptor holds the card for this call');
    // Audit continues on the hook plane, recording who owns the card.
    const rows = hookAuditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: 'require_approval',
      outcome: 'asked',
      cardOwner: { plane: 'openclaw-interceptor', gatewayPid: process.pid, proof: 'direct-parent-socket' },
      hookName: 'PreToolUse',
    });
    expect(1 /* interceptor */ + hookCards()).toBe(1);

    // The verdict still rests on the human: deny on the one card blocks, and
    // the interceptor plane audits the answer.
    await result.requireApproval.onResolution('deny');
    expect(interceptorAuditRows().map((row) => row.outcome)).toEqual(['card_denied']);
  });

  itLinux('the interceptor\'s marker outlives the answer only by its linger', async () => {
    const hooks = registerPlugin();
    const id = newToolUseId();
    const result = await interceptorCall(hooks, id, SSH_READ);
    const name = cardOwnerSocketName(selfHolderIdentity()!, id, SSH_READ)!;
    expect(unixTable()).toContain(`@${name}`);
    await result.requireApproval.onResolution('allow-once');
    // Released after the linger, not torn down under a hook that is polling.
    expect(unixTable()).toContain(`@${name}`);
  });

  // ── 2. forged evidence: env, marker files, registry, sockets ─────────────

  itLinux('forged env claiming OpenClaw / an armed interceptor gives two cards', () => {
    const r = runHookUnder('openclaw-claude', newToolUseId(), SSH_READ, {
      waitMs: 300,
      env: {
        OPENCLAW_GATEWAY_PID: String(process.pid),
        OPENCLAW_SESSION_ID: 'agent:main:chat:628',
        OPENCLAW_INTERCEPTOR_ARMED: '1',
        SHIELDCORTEX_CARD_OWNER: 'openclaw-interceptor',
        SHIELDCORTEX_INTERCEPTOR_ARMED: '1',
        CLAUDE_CODE_ENTRYPOINT: 'sdk-ts',
      },
    });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
    expect(1 /* interceptor */ + hookCards()).toBe(2);
  });

  itLinux('forged marker / registry files give two cards', () => {
    const id = newToolUseId();
    const name = cardOwnerSocketName(selfHolderIdentity()!, id, SSH_READ)!;
    // Everything a same-user agent could write: a file named like the marker,
    // a registry claiming the interceptor is armed for this session, a file
    // named like the abstract socket.
    const forgeDir = mkdtempSync(join(tmpdir(), 'sc-628-forge-'));
    try {
      for (const dir of [join(home, '.shieldcortex', 'card-owner'), join(home, '.openclaw', 'state'), forgeDir]) {
        mkdirSync(dir, { recursive: true });
        writeFileSync(join(dir, name), JSON.stringify({ gatewayPid: process.pid, toolUseId: id, armed: true }));
        writeFileSync(join(dir, `@${name}`), '');
        writeFileSync(join(dir, 'card-owner.json'), JSON.stringify({ [id]: { owner: 'openclaw-interceptor', gatewayPid: process.pid } }));
      }
      const r = runHookUnder('openclaw-claude', id, SSH_READ, { waitMs: 300 });
      expect(r.decision).toBe('ask');
      expect(hookCards()).toBe(1);
    } finally {
      rmSync(forgeDir, { recursive: true, force: true });
    }
  });

  itLinux('a fake socket bound by another process (abstract name squatted) gives two cards', async () => {
    const id = newToolUseId();
    const name = cardOwnerSocketName(selfHolderIdentity()!, id, SSH_READ)!;
    await impostor({ IMPOSTOR_ABSTRACT: name });
    expect(unixTable()).toContain(`@${name}`);
    // The real interceptor cannot bind a squatted name; whatever it returns,
    // the listed socket is not in the gateway's fd table.
    const real = holdCardOwnerMarker({ toolCallId: id, params: SSH_READ });
    if (real) markers.push(real);
    const r = runHookUnder('openclaw-claude', id, SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  itLinux('a fake filesystem socket named like the marker gives two cards', async () => {
    const id = newToolUseId();
    const name = cardOwnerSocketName(selfHolderIdentity()!, id, SSH_READ)!;
    const dir = mkdtempSync(join(tmpdir(), 'sc-628-sock-'));
    try {
      await impostor({ IMPOSTOR_PATH: join(dir, `@${name}`) });
      const r = runHookUnder('openclaw-claude', id, SSH_READ, { waitMs: 300 });
      expect(r.decision).toBe('ask');
      expect(hookCards()).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // ── 3. sibling sessions ──────────────────────────────────────────────────

  itLinux('a sibling session\'s card under the same gateway neither suppresses nor satisfies this one', async () => {
    const hooks = registerPlugin();
    const sibling = await interceptorCall(hooks, newToolUseId(), SSH_READ, { sessionId: 'agent:sibling:chat:628' });
    expect(sibling?.requireApproval).toBeDefined();
    // Same command, same gateway, different call (tool_use_id).
    const r = runHookUnder('openclaw-claude', newToolUseId(), SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
    // And the sibling's approval is not this session's: the next identical
    // call is held again.
    await sibling.requireApproval.onResolution('allow-once');
    const again = runHookUnder('openclaw-claude', newToolUseId(), SSH_READ, { waitMs: 300 });
    expect(again.decision).toBe('ask');
    expect(hookCards()).toBe(2);
  });

  itLinux('the same tool_use_id with a different command is not proof', () => {
    const id = newToolUseId();
    hold(id, { command: 'cat ~/.ssh/known_hosts' });
    const r = runHookUnder('openclaw-claude', id, SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  itLinux('a claude the agent launches itself (not the gateway\'s child) never stands down', () => {
    // nested → fake-claude → hook: the marker is held by the worker, but the
    // hook's harness's parent is the nested launcher.
    const id = newToolUseId();
    hold(id, SSH_READ);
    const nested = join(home, 'nested-claude.mjs');
    writeFileSync(
      nested,
      [
        "import { spawnSync } from 'node:child_process';",
        "let input = '';",
        "process.stdin.on('data', (d) => { input += d; });",
        "process.stdin.on('end', () => {",
        `  const r = spawnSync(process.execPath, [${JSON.stringify(fakeClaude)}, ...${JSON.stringify(OPENCLAW_CLAUDE_FLAGS)}], { input, env: process.env, encoding: 'utf8' });`,
        '  process.stdout.write(r.stdout);',
        '});',
      ].join('\n'),
    );
    const r = spawnSync(process.execPath, [nested], {
      input: hookInput(id, SSH_READ),
      env: hookEnv({ SHIELDCORTEX_CARD_OWNER_WAIT_MS: '300' }),
      encoding: 'utf8',
      timeout: 30_000,
    });
    const relayed = JSON.parse(r.stdout || '{}') as { stdout?: string };
    expect(parseDecision(relayed.stdout ?? '')).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  // ── 4. PID reuse ─────────────────────────────────────────────────────────

  itLinux('PID reuse: a marker for the same pid but a different start time gives two cards', () => {
    const id = newToolUseId();
    const self = selfHolderIdentity()!;
    hold(id, SSH_READ, { pid: self.pid, startTime: String(BigInt(self.startTime) + 1n) });
    const r = runHookUnder('openclaw-claude', id, SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  // ── 5. interceptor disabled / unarmed / released ─────────────────────────

  itLinux('interceptor not armed (Action Guard off in the plugin) gives the hook\'s card', async () => {
    const hooks = registerPlugin({ interceptor: { actionGuard: { enabled: false } } });
    const id = newToolUseId();
    const result = await interceptorCall(hooks, id, SSH_READ);
    expect(result?.requireApproval).toBeUndefined();
    const r = runHookUnder('openclaw-claude', id, SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  itLinux('interceptor disabled in host config (no before_tool_call) gives the hook\'s card', () => {
    const hooks = registerPlugin({ interceptor: { enabled: false } });
    expect(hooks.before_tool_call).toBeUndefined();
    const r = runHookUnder('openclaw-claude', newToolUseId(), SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  itLinux('interceptor gone mid-session (marker closed) is not proof', () => {
    const id = newToolUseId();
    hold(id, SSH_READ).close();
    const r = runHookUnder('openclaw-claude', id, SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  itLinux('an unattended (automation) session gets no interceptor card and no marker → the hook cards', async () => {
    const hooks = registerPlugin();
    const id = newToolUseId();
    const result = await interceptorCall(hooks, id, SSH_READ, { sessionKey: 'agent:main:cron:628', sessionId: 'agent:main:cron:628' });
    expect(result?.requireApproval).toBeUndefined();
    expect(unixTable()).not.toContain(`@${cardOwnerSocketName(selfHolderIdentity()!, id, SSH_READ)}`);
    const r = runHookUnder('openclaw-claude', id, SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  itLinux.each([
    ['an older host that may not hold the call on the card', '2026.7.1'],
    ['a host that reports no version', null],
    ['a host whose version is junk', 'nightly'],
  ] as Array<[string, string | null]>)('%s: no marker, the hook cards', async (_label, hostVersion) => {
    const hooks = registerPlugin(undefined, hostVersion);
    const id = newToolUseId();
    const result = await interceptorCall(hooks, id, SSH_READ);
    expect(result?.requireApproval).toBeDefined();
    expect(unixTable()).not.toContain(`@${cardOwnerSocketName(selfHolderIdentity()!, id, SSH_READ)}`);
    const r = runHookUnder('openclaw-claude', id, SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  itLinux.each(['acceptEdits', 'auto', 'plan'])('permission mode %s never defers (Claude Code\'s own rules could act on an undecided call)', (mode) => {
    const id = newToolUseId();
    hold(id, SSH_READ);
    const r = runHookUnder('openclaw-claude', id, SSH_READ, { permissionMode: mode });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
    expect(hookAuditRows().some((row) => row.cardOwner)).toBe(false);
  });

  itLinux('documented bound: a wrapper the agent controls, as the direct parent of a claude it launched, can stand that claude\'s hook down', () => {
    // Pinned so the bound stays visible. This is the agent's own harness: the
    // wrapper already answers its prompts and could run the command with no
    // claude at all. It is not the gateway's claude-cli child, which the
    // agent cannot re-parent (see 'a claude the agent launches itself').
    const wrapper = join(home, 'agent-wrapper.mjs');
    const cardOwnerDist = pathToFileURL(join(REAL_DIST, 'card-owner.js')).href;
    writeFileSync(
      wrapper,
      [
        "import net from 'node:net';",
        "import { readFileSync } from 'node:fs';",
        "import { spawnSync } from 'node:child_process';",
        `import { cardOwnerSocketName } from ${JSON.stringify(cardOwnerDist)};`,
        "const stat = readFileSync('/proc/self/stat', 'utf8');",
        "const start = stat.slice(stat.lastIndexOf(')') + 2).trim().split(' ')[19];",
        "let input = '';",
        "process.stdin.on('data', (d) => { input += d; });",
        "process.stdin.on('end', () => {",
        '  const call = JSON.parse(input);',
        '  const name = cardOwnerSocketName({ pid: process.pid, startTime: start }, call.tool_use_id, call.tool_input);',
        '  const s = net.createServer((c) => c.destroy());',
        "  s.listen(String.fromCharCode(0) + name, () => {",
        `    const r = spawnSync(process.execPath, [${JSON.stringify(fakeClaude)}, ...${JSON.stringify(OPENCLAW_CLAUDE_FLAGS)}], { input, env: process.env, encoding: 'utf8' });`,
        '    process.stdout.write(r.stdout);',
        '    s.close();',
        '  });',
        '});',
      ].join('\n'),
    );
    const r = spawnSync(process.execPath, [wrapper], {
      input: hookInput(newToolUseId(), SSH_READ),
      env: hookEnv({ SHIELDCORTEX_CARD_OWNER_WAIT_MS: '300' }),
      encoding: 'utf8',
      timeout: 30_000,
    });
    const relayed = JSON.parse(r.stdout || '{}') as { stdout?: string };
    expect(parseDecision(relayed.stdout ?? '')).toBeUndefined();
    expect(hookCards()).toBe(0);
    // The row names the holder it proved, which is the wrapper, not this
    // test's "gateway".
    const row = hookAuditRows().find((x) => x.cardOwner);
    expect(row?.cardOwner.proof).toBe('direct-parent-socket');
    expect(row?.cardOwner.gatewayPid).not.toBe(process.pid);
  });

  itLinux('singleCard:false keeps both planes carding even with a valid proof', () => {
    writeConfig({ singleCard: false });
    const id = newToolUseId();
    hold(id, SSH_READ);
    const r = runHookUnder('openclaw-claude', id, SSH_READ);
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  // ── 6. block verdicts: strictest wins ────────────────────────────────────

  itLinux('a block on the hook plane still blocks, marker or not', () => {
    const id = newToolUseId();
    hold(id, CATASTROPHIC);
    const r = runHookUnder('openclaw-claude', id, CATASTROPHIC);
    expect(r.decision).toBe('deny');
    expect(hookAuditRows().some((row) => row.cardOwner)).toBe(false);
  });

  itLinux('a block on the interceptor plane blocks and leaves no marker to defer to', async () => {
    const hooks = registerPlugin();
    const id = newToolUseId();
    const result = await interceptorCall(hooks, id, CATASTROPHIC);
    expect(result).toMatchObject({ block: true });
    expect(unixTable()).not.toContain(`@${cardOwnerSocketName(selfHolderIdentity()!, id, CATASTROPHIC)}`);
    // The hook, finding no card to defer to, holds the call itself.
    const r = runHookUnder('openclaw-claude', id, CATASTROPHIC, { waitMs: 300 });
    expect(r.decision).toBe('deny');
  });

  itLinux('promptless sessions never defer (the hook denies as before)', () => {
    const id = newToolUseId();
    hold(id, SSH_READ);
    const r = runHookUnder('openclaw-claude', id, SSH_READ, { permissionMode: 'bypassPermissions' });
    expect(r.decision).toBe('deny');
    expect(hookAuditRows().some((row) => row.cardOwner)).toBe(false);
  });

  // ── 7. regressions: plain Claude Code, OpenClaw without claude-cli ──────

  it('plain Claude Code (not launched by OpenClaw) is unchanged and pays no wait, even with a marker', () => {
    const id = newToolUseId();
    if (linux) hold(id, SSH_READ);
    const r = runHookUnder('plain-claude', id, SSH_READ, { waitMs: 5_000 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
    expect(hookAuditRows().some((row) => row.cardOwner)).toBe(false);
    expect(r.elapsedMs).toBeLessThan(5_000);
  });

  it('a hook run directly (no harness flags) is unchanged', () => {
    const r = runHookUnder('direct', newToolUseId(), SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  it('a call with no tool_use_id is unchanged', () => {
    const r = runHookUnder('openclaw-claude', undefined, SSH_READ, { waitMs: 300 });
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  it('a dist without the card-owner module is unchanged (never zero cards)', () => {
    rmSync(join(distRoot, 'defence', 'iron-dome', 'card-owner.js'));
    const id = newToolUseId();
    if (linux) hold(id, SSH_READ);
    const r = runHookUnder('openclaw-claude', id, SSH_READ);
    expect(r.decision).toBe('ask');
    expect(hookCards()).toBe(1);
  });

  it('OpenClaw without claude-cli: the interceptor card is unchanged with or without a call id', async () => {
    const hooks = registerPlugin();
    const withoutId = await interceptorCall(hooks, undefined, SSH_READ);
    const withId = await interceptorCall(hooks, newToolUseId(), SSH_READ);
    for (const result of [withoutId, withId]) {
      expect(result.requireApproval).toMatchObject({
        timeoutMs: 600_000,
        timeoutBehavior: 'deny',
        allowedDecisions: ['allow-once', 'deny'],
      });
      expect(typeof result.requireApproval.onResolution).toBe('function');
    }
    const { onResolution: _a, ...a } = withoutId.requireApproval;
    const { onResolution: _b, ...b } = withId.requireApproval;
    expect(a).toEqual(b);
    await withoutId.requireApproval.onResolution('deny');
    await withId.requireApproval.onResolution('allow-once');
    expect(interceptorAuditRows().map((row) => row.outcome)).toEqual(['card_denied', 'approved_once']);
  });
});
