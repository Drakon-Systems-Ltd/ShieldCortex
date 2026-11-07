/**
 * #853 Plane A — held-action.ts in isolation: the hold window, the harness
 * timeout reading, the one-card dedupe store, the card, and the wait.
 *
 * The end-to-end hook behaviour is pinned in
 * src/__tests__/pre-tool-hook-held-853.test.ts.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  HOLD_DEDUPE_WINDOW_MS,
  HOLD_SECONDS_DEFAULT,
  HOLD_SECONDS_MAX,
  HOLD_SECONDS_MIN,
  abortWhenOrphaned,
  awaitHeldDecision,
  buildHeldCardParams,
  claimHold,
  heldRefusalReason,
  holdKey,
  holdWindowMs,
  normaliseHoldSeconds,
  preToolTimeoutsIn,
  readPreToolHookTimeout,
  requiredPreToolTimeoutSeconds,
  settingsFlagsFromArgv,
} from '../held-action.js';

const preTool = (timeout?: number, command = '/usr/bin/shieldcortex hook pre-tool') => ({
  hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command, ...(timeout === undefined ? {} : { timeout }) }] }] },
});

describe('hold window', () => {
  it('normaliseHoldSeconds defaults junk and clamps out-of-range values, never turns holds off', () => {
    expect(normaliseHoldSeconds(undefined)).toBe(HOLD_SECONDS_DEFAULT);
    expect(normaliseHoldSeconds('abc')).toBe(HOLD_SECONDS_DEFAULT);
    expect(normaliseHoldSeconds(NaN)).toBe(HOLD_SECONDS_DEFAULT);
    expect(normaliseHoldSeconds(0)).toBe(HOLD_SECONDS_MIN);
    expect(normaliseHoldSeconds(-5)).toBe(HOLD_SECONDS_MIN);
    expect(normaliseHoldSeconds(10_000)).toBe(HOLD_SECONDS_MAX);
    expect(normaliseHoldSeconds('90')).toBe(90);
    expect(normaliseHoldSeconds(90.9)).toBe(90);
  });

  it('the setup timeout is the hold plus margin plus start-up allowance', () => {
    expect(requiredPreToolTimeoutSeconds()).toBe(135);
    expect(requiredPreToolTimeoutSeconds(300)).toBe(315);
  });

  it('holds nothing without a known harness timeout', () => {
    expect(holdWindowMs({ holdSeconds: 120, hookTimeoutSeconds: null, elapsedMs: 0 })).toBe(0);
    expect(holdWindowMs({ holdSeconds: 120, hookTimeoutSeconds: Number.NaN, elapsedMs: 0 })).toBe(0);
  });

  it('ends 10 s before the harness kill, after the time already spent', () => {
    expect(holdWindowMs({ holdSeconds: 120, hookTimeoutSeconds: 135, elapsedMs: 0 })).toBe(120_000);
    expect(holdWindowMs({ holdSeconds: 120, hookTimeoutSeconds: 60, elapsedMs: 0 })).toBe(50_000);
    expect(holdWindowMs({ holdSeconds: 120, hookTimeoutSeconds: 60, elapsedMs: 4_000 })).toBe(46_000);
  });

  it('refuses to hold when what is left is under the minimum', () => {
    expect(holdWindowMs({ holdSeconds: 120, hookTimeoutSeconds: 10, elapsedMs: 0 })).toBe(0);
    expect(holdWindowMs({ holdSeconds: 120, hookTimeoutSeconds: 39, elapsedMs: 0 })).toBe(0);
    expect(holdWindowMs({ holdSeconds: 120, hookTimeoutSeconds: 45, elapsedMs: 6_000 })).toBe(0);
  });
});

describe('reading the harness timeout', () => {
  it('finds only ShieldCortex pre-tool entries, null for one without a timeout', () => {
    const settings = {
      hooks: {
        PreToolUse: [
          { hooks: [{ command: 'other-tool check', timeout: 1 }] },
          { hooks: [{ command: 'shieldcortex hook pre-tool', timeout: 135 }] },
          { hooks: [{ command: 'node /x/shieldcortex/scripts/pre-tool-hook.mjs' }] },
          { hooks: [{ command: 'shieldcortex hook prompt-recall', timeout: 2 }] },
        ],
      },
    };
    expect(preToolTimeoutsIn(settings)).toEqual([135, null]);
    expect(preToolTimeoutsIn(null)).toEqual([]);
    expect(preToolTimeoutsIn({ hooks: { PreToolUse: 'x' } })).toEqual([]);
  });

  it('parses --settings and --setting-sources in both forms', () => {
    expect(settingsFlagsFromArgv(['claude', '--settings', '/a.json', '--settings={"x":1}', '--setting-sources=user,local'])).toEqual({
      settings: ['/a.json', '{"x":1}'],
      sources: ['user', 'local'],
    });
    expect(settingsFlagsFromArgv(null)).toEqual({ settings: [], sources: null });
  });

  function reader(files: Record<string, unknown>) {
    return (p: string) => {
      if (!(p in files)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      const v = files[p];
      return typeof v === 'string' ? v : JSON.stringify(v);
    };
  }
  // Every reading below is for a proven Claude Code harness with no plugins
  // and no managed settings unless the test says otherwise.
  const CLAUDE = ['/usr/local/bin/claude'];
  const base = { home: '/h', managedPaths: [] as string[], pluginHookFiles: [] as string[] };

  it('takes the SMALLEST timeout across user, project, local and --settings', () => {
    const r = readPreToolHookTimeout({
      ...base,
      projectDir: '/p',
      parentArgv: ['claude', '--settings', JSON.stringify(preTool(90))],
      readFile: reader({
        '/h/.claude/settings.json': preTool(135),
        '/p/.claude/settings.json': preTool(200),
        '/p/.claude/settings.local.json': preTool(60),
      }),
    });
    expect(r.seconds).toBe(60);
    expect(r.sources.sort()).toEqual(['--settings', 'local', 'project', 'user']);
  });

  it('honours --setting-sources', () => {
    const r = readPreToolHookTimeout({
      ...base,
      projectDir: '/p',
      parentArgv: ['claude', '--setting-sources', 'user'],
      readFile: reader({ '/h/.claude/settings.json': preTool(135), '/p/.claude/settings.local.json': preTool(20) }),
    });
    expect(r.seconds).toBe(135);
  });

  it('managed settings always count, whatever --setting-sources says', () => {
    const r = readPreToolHookTimeout({
      ...base,
      parentArgv: ['claude', '--setting-sources', 'user'],
      managedPaths: ['/etc/m.json'],
      readFile: reader({ '/h/.claude/settings.json': preTool(135), '/etc/m.json': preTool(50) }),
    });
    expect(r.seconds).toBe(50);
    expect(r.sources).toContain('managed');
  });

  it('an entry without a timeout means the harness default applies: no hold', () => {
    const r = readPreToolHookTimeout({ ...base, parentArgv: CLAUDE, readFile: reader({ '/h/.claude/settings.json': preTool(undefined) }) });
    expect(r).toMatchObject({ seconds: null, reason: 'entry-without-timeout' });
  });

  it('no entry anywhere means no hold', () => {
    const r = readPreToolHookTimeout({ ...base, projectDir: '/p', parentArgv: CLAUDE, readFile: reader({}) });
    expect(r).toMatchObject({ seconds: null, reason: 'no-entry' });
  });

  // ── #853 review (CRITICAL): the budget must be PROVEN ──────────────────

  it.each([
    ['no argv at all (macOS, no /proc)', null],
    ['an empty argv', []],
    ['a process that is not Claude Code', ['/usr/bin/node', '/opt/other/runner.js', '--settings', '/x.json']],
  ])('%s: harness-unproven, even with a hold-sized timeout in settings', (_label, argv) => {
    const r = readPreToolHookTimeout({
      ...base,
      parentArgv: argv as string[] | null,
      readFile: reader({ '/h/.claude/settings.json': preTool(135) }),
    });
    expect(r).toMatchObject({ seconds: null, reason: 'harness-unproven' });
    expect(holdWindowMs({ holdSeconds: 120, hookTimeoutSeconds: r.seconds, elapsedMs: 0 })).toBe(0);
  });

  it('recognises native and npm-shim Claude Code command lines', () => {
    const files = reader({ '/h/.claude/settings.json': preTool(135) });
    for (const argv of [
      ['claude', '-p', 'x'],
      ['/home/u/.local/bin/claude'],
      ['node', '/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js'],
      ['/usr/bin/node', '/usr/local/bin/claude', '--print'],
    ]) {
      expect(readPreToolHookTimeout({ ...base, parentArgv: argv, readFile: files }).seconds).toBe(135);
    }
  });

  it('a --settings file that cannot be read is unproven, never skipped', () => {
    const r = readPreToolHookTimeout({
      ...base,
      parentArgv: ['claude', '--settings', '/missing.json'],
      readFile: reader({ '/h/.claude/settings.json': preTool(135) }),
    });
    expect(r).toMatchObject({ seconds: null, reason: 'settings-unreadable' });
  });

  it('a RELATIVE --settings path is unproven (relative to a cwd we cannot know)', () => {
    const r = readPreToolHookTimeout({
      ...base,
      parentArgv: ['claude', '--settings=conf/s.json'],
      readFile: reader({ '/h/.claude/settings.json': preTool(135), 'conf/s.json': preTool(20) }),
    });
    expect(r).toMatchObject({ seconds: null, reason: 'settings-unreadable' });
  });

  it('a settings file that exists but cannot be parsed is unproven, never skipped', () => {
    const r = readPreToolHookTimeout({
      ...base,
      projectDir: '/p',
      parentArgv: CLAUDE,
      readFile: reader({ '/h/.claude/settings.json': preTool(135), '/p/.claude/settings.local.json': '{not json' }),
    });
    expect(r).toMatchObject({ seconds: null, reason: 'settings-unreadable' });
  });

  it('a plugin hooks.json carrying a shorter timeout lowers the budget', () => {
    const r = readPreToolHookTimeout({
      ...base,
      parentArgv: CLAUDE,
      pluginHookFiles: ['/h/.claude/plugins/sc/hooks/hooks.json'],
      readFile: reader({ '/h/.claude/settings.json': preTool(135), '/h/.claude/plugins/sc/hooks/hooks.json': preTool(20) }),
    });
    expect(r.seconds).toBe(20);
    expect(r.sources).toContain('plugin');
  });

  it('plugin hooks.json files are found under ~/.claude/plugins and every --plugin-dir', () => {
    const root = mkdtempSync(join(tmpdir(), 'sc-hold-plugins-'));
    try {
      const home = join(root, 'home');
      mkdirSync(join(home, '.claude', 'plugins', 'cache', 'sc', 'hooks'), { recursive: true });
      writeFileSync(join(home, '.claude', 'plugins', 'cache', 'sc', 'hooks', 'hooks.json'), JSON.stringify(preTool(40)));
      const extra = join(root, 'extra');
      mkdirSync(join(extra, 'hooks'), { recursive: true });
      writeFileSync(join(extra, 'hooks', 'hooks.json'), JSON.stringify(preTool(25)));
      mkdirSync(join(home, '.claude'), { recursive: true });
      writeFileSync(join(home, '.claude', 'settings.json'), JSON.stringify(preTool(135)));
      const r = readPreToolHookTimeout({ home, managedPaths: [], parentArgv: ['claude', '--plugin-dir', extra] });
      expect(r.seconds).toBe(25);
      const noFlag = readPreToolHookTimeout({ home, managedPaths: [], parentArgv: ['claude'] });
      expect(noFlag.seconds).toBe(40);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('doctor mode (assumeNoArgvFlags) reads the files without a harness', () => {
    const r = readPreToolHookTimeout({ ...base, assumeNoArgvFlags: true, readFile: reader({ '/h/.claude/settings.json': preTool(135) }) });
    expect(r.seconds).toBe(135);
  });
});

describe('the dedupe store', () => {
  let home: string;
  beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'sc-hold-store-')); });
  afterEach(() => { rmSync(home, { recursive: true, force: true }); });

  const key = holdKey('a'.repeat(64), '/work');

  it('keys bind the call hash to the cwd', () => {
    expect(holdKey('a'.repeat(64), '/work')).not.toBe(holdKey('a'.repeat(64), '/other'));
    expect(holdKey('a'.repeat(64), '/work')).toMatch(/^[0-9a-f]{32}$/);
  });

  it('one open card per action identity while its holder lives', () => {
    const first = claimHold(key, { actionId: 'act-1', windowMs: 60_000, home });
    expect(first.ok).toBe(true);
    const second = claimHold(key, { actionId: 'act-2', windowMs: 60_000, home });
    expect(second).toMatchObject({ ok: false, reason: 'open', heldActionId: 'act-1' });
  });

  it('a denied or expired card refuses the same call for the dedupe window, then frees it', () => {
    for (const state of ['denied', 'expired'] as const) {
      const k = holdKey(state.padEnd(64, '0'), '/w');
      const first = claimHold(k, { actionId: `act-${state}`, windowMs: 60_000, home });
      if (!first.ok) throw new Error('claim failed');
      first.finish(state);
      const again = claimHold(k, { actionId: 'act-x', windowMs: 60_000, home });
      expect(again).toMatchObject({ ok: false, reason: `recently-${state}`, heldActionId: `act-${state}` });
      const later = claimHold(k, { actionId: 'act-y', windowMs: 60_000, home, now: Date.now() + HOLD_DEDUPE_WINDOW_MS + 1 });
      expect(later.ok).toBe(true);
    }
  });

  it('approved, cancelled and failed cards are not the owner saying no: the next call gets a card', () => {
    for (const state of ['approved', 'cancelled', 'card_failed'] as const) {
      const k = holdKey(state.padEnd(64, '1'), '/w');
      const first = claimHold(k, { actionId: 'a', windowMs: 60_000, home });
      if (!first.ok) throw new Error('claim failed');
      first.finish(state);
      expect(claimHold(k, { actionId: 'b', windowMs: 60_000, home }).ok).toBe(true);
    }
  });

  it('a stale open record (dead holder, or past its deadline) is taken over', () => {
    const dir = join(home, '.shieldcortex', 'holds');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${key}.json`), JSON.stringify({
      v: 1, actionId: 'ghost', state: 'open', pid: 2 ** 22 + 12345, startedAt: Date.now(), deadlineAt: Date.now() + 60_000,
    }));
    expect(claimHold(key, { actionId: 'live', windowMs: 60_000, home }).ok).toBe(true);

    const k2 = holdKey('b'.repeat(64), '/w');
    writeFileSync(join(dir, `${k2}.json`), JSON.stringify({
      v: 1, actionId: 'old', state: 'open', pid: process.pid, startedAt: 0, deadlineAt: Date.now() - 60_000,
    }));
    expect(claimHold(k2, { actionId: 'new', windowMs: 60_000, home }).ok).toBe(true);
  });

  it('the store never allows anything: a forged "approved" record only frees a new card', () => {
    const dir = join(home, '.shieldcortex', 'holds');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${key}.json`), JSON.stringify({ v: 1, actionId: 'forged', state: 'approved', pid: 1, startedAt: 0, deadlineAt: 0, endedAt: Date.now() }));
    const claim = claimHold(key, { actionId: 'real', windowMs: 60_000, home });
    expect(claim.ok).toBe(true);
    const rec = JSON.parse(readFileSync(join(dir, `${key}.json`), 'utf8'));
    expect(rec).toMatchObject({ actionId: 'real', state: 'open' });
  });

  it('a symlinked holds directory is store-unavailable, not followed', () => {
    const elsewhere = mkdtempSync(join(tmpdir(), 'sc-hold-elsewhere-'));
    try {
      mkdirSync(join(home, '.shieldcortex'), { recursive: true });
      symlinkSync(elsewhere, join(home, '.shieldcortex', 'holds'));
      expect(claimHold(key, { actionId: 'a', windowMs: 60_000, home })).toEqual({ ok: false, reason: 'store-unavailable' });
    } finally {
      rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  // ── #853 review (MEDIUM): two takers of one stale identity ─────────────

  function writeStale(k: string): void {
    const dir = join(home, '.shieldcortex', 'holds');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${k}.json`), JSON.stringify({
      v: 1, actionId: 'ghost', state: 'open', pid: 2 ** 22 + 4321, startedAt: 1, deadlineAt: 2,
    }));
  }

  it('while one taker holds the takeover lock, a second taker of the same stale record gets NO card', () => {
    writeStale(key);
    let second: ReturnType<typeof claimHold> | null = null;
    const first = claimHold(key, {
      actionId: 'first', windowMs: 60_000, home,
      beforeTakeover: () => { second = claimHold(key, { actionId: 'second', windowMs: 60_000, home, pid: process.pid }); },
    });
    expect(first.ok).toBe(true);
    expect(second).toMatchObject({ ok: false, reason: 'open' });
    const rec = JSON.parse(readFileSync(join(home, '.shieldcortex', 'holds', `${key}.json`), 'utf8'));
    expect(rec.actionId).toBe('first');
  });

  it('a taker whose stale record was replaced while it waited does not delete the fresh claim', () => {
    writeStale(key);
    const file = join(home, '.shieldcortex', 'holds', `${key}.json`);
    const result = claimHold(key, {
      actionId: 'late', windowMs: 60_000, home,
      // Another hook's fresh, live claim lands between our read and our lock.
      beforeTakeover: () => writeFileSync(file, JSON.stringify({
        v: 1, actionId: 'fresh', state: 'open', pid: process.pid, startedAt: Date.now(), deadlineAt: Date.now() + 60_000,
      })),
    });
    expect(result).toMatchObject({ ok: false, reason: 'open', heldActionId: 'fresh' });
    expect(JSON.parse(readFileSync(file, 'utf8')).actionId).toBe('fresh');
  });

  it('a takeover lock left by a dead taker is broken by age, not forever', () => {
    writeStale(key);
    const lock = join(home, '.shieldcortex', 'holds', `${key}.json.lock`);
    writeFileSync(lock, '');
    const old = new Date(Date.now() - 60_000);
    utimesSync(lock, old, old);
    expect(claimHold(key, { actionId: 'a', windowMs: 60_000, home }).ok).toBe(true);
  });

  it('many concurrent processes on one stale identity: exactly ONE card', async () => {
    const dist = join(process.cwd(), 'dist', 'defence', 'iron-dome', 'held-action.js');
    if (!existsSync(dist)) throw new Error('build first: dist/defence/iron-dome/held-action.js missing');
    writeStale(key);
    const script = [
      `import { claimHold } from ${JSON.stringify(pathToFileURL(dist).href)};`,
      `const r = claimHold(${JSON.stringify(key)}, { actionId: 'p' + process.pid, windowMs: 60000, home: ${JSON.stringify(home)} });`,
      'process.stdout.write(r.ok ? "OK" : "NO");',
      // Stay alive (as a real holder would) so the claim is not stale yet.
      'setTimeout(() => {}, 1500);',
    ].join('\n');
    const runs = Array.from({ length: 12 }, () => new Promise<string>((res) => {
      const c = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'ignore'] });
      let out = '';
      c.stdout.on('data', (d) => { out += String(d); });
      c.on('close', () => res(out));
    }));
    const outs = await Promise.all(runs);
    expect(outs.filter((o) => o === 'OK')).toHaveLength(1);
  }, 30_000);

  it('finish never overwrites a record another holder has since taken', () => {
    const first = claimHold(key, { actionId: 'one', windowMs: 60_000, home });
    if (!first.ok) throw new Error('claim failed');
    const file = join(home, '.shieldcortex', 'holds', `${key}.json`);
    writeFileSync(file, JSON.stringify({ v: 1, actionId: 'two', state: 'open', pid: process.pid, startedAt: Date.now(), deadlineAt: Date.now() + 60_000 }));
    first.finish('denied');
    expect(JSON.parse(readFileSync(file, 'utf8'))).toMatchObject({ actionId: 'two', state: 'open' });
  });
});

describe('the card', () => {
  const summary = { action: 'Load kernel module softdog (as administrator)', reason: 'privilege escalation', who: 'Claude Code on host-a, session abc' };

  it('offers Approve-once and Deny only, lives exactly as long as the hold, and says what Approve does', () => {
    const p = buildHeldCardParams({ tool: 'Bash', actionId: 'act-123', windowMs: 90_000, summary });
    expect(p.allowedDecisions).toEqual(['allow-once', 'deny']);
    expect(p.timeoutMs).toBe(90_000);
    expect(p.pluginId).toBe('shieldcortex');
    expect(String(p.title)).toContain('act-123');
    expect(String(p.title)).toMatch(/held, not run/);
    expect(String(p.title).length).toBeLessThanOrEqual(80);
    expect(String(p.description).length).toBeLessThanOrEqual(256);
    expect(String(p.description)).toMatch(/Approve runs it once now; deny or no answer: nothing runs/);
    expect(JSON.stringify(p)).not.toMatch(/retry/i);
  });

  it('a strange tool name is not echoed into the title', () => {
    const p = buildHeldCardParams({ tool: 'Bash\n$(rm -rf /)', actionId: 'a', windowMs: 60_000, summary });
    expect(String(p.title)).toMatch(/^ShieldCortex: tool is held/);
  });
});

describe('awaitHeldDecision', () => {
  type FakeChild = EventEmitter & {
    stdout: PassThrough; exitCode: number | null; signalCode: string | null; killed: string[]; kill: (s: string) => boolean;
  };
  function fakeSpawn(behave: (child: FakeChild) => void) {
    const calls: Array<{ bin: string; args: string[] }> = [];
    let last: FakeChild | null = null;
    const impl = ((bin: string, args: string[]) => {
      calls.push({ bin, args });
      const child = new EventEmitter() as FakeChild;
      child.stdout = new PassThrough();
      child.exitCode = null;
      child.signalCode = null;
      child.killed = [];
      child.kill = (s: string) => { child.killed.push(s); child.signalCode = s; return true; };
      last = child;
      setImmediate(() => behave(child));
      return child;
    }) as unknown as typeof import('node:child_process').spawn;
    return { impl, calls, child: () => last };
  }
  const answer = (out: string, code = 0) => (child: FakeChild) => {
    child.stdout.end(out);
    child.exitCode = code;
    child.emit('close', code);
  };
  const base = { openclawBin: '/bin/openclaw', params: { title: 't' }, windowMs: 5_000 };

  it.each([
    ['allow-once', 'approved'],
    ['deny', 'denied'],
    [null, 'expired'],
    ['timeout', 'expired'],
  ])('decision %p → %s', async (decision, kind) => {
    const f = fakeSpawn(answer(JSON.stringify({ decision })));
    await expect(awaitHeldDecision({ ...base, spawnImpl: f.impl })).resolves.toEqual({ kind });
  });

  it('asks the gateway once, on one connection that waits for the final answer', async () => {
    const f = fakeSpawn(answer(JSON.stringify({ decision: 'deny' })));
    await awaitHeldDecision({ ...base, spawnImpl: f.impl });
    expect(f.calls).toHaveLength(1);
    const args = f.calls[0].args;
    expect(args.slice(0, 3)).toEqual(['gateway', 'call', 'plugin.approval.request']);
    expect(args).toContain('--expect-final');
    expect(JSON.parse(args[args.indexOf('--params') + 1])).toEqual({ title: 't' });
  });

  it('allow-always was never offered and runs nothing', async () => {
    const f = fakeSpawn(answer(JSON.stringify({ decision: 'allow-always' })));
    await expect(awaitHeldDecision({ ...base, spawnImpl: f.impl })).resolves.toEqual({ kind: 'card_failed', reason: 'unrecognised-decision' });
  });

  it('a failed or garbled request runs nothing', async () => {
    const failed = fakeSpawn(answer('', 2));
    await expect(awaitHeldDecision({ ...base, spawnImpl: failed.impl })).resolves.toEqual({ kind: 'card_failed', reason: 'request-failed' });
    const garbled = fakeSpawn(answer('not json'));
    await expect(awaitHeldDecision({ ...base, spawnImpl: garbled.impl })).resolves.toEqual({ kind: 'card_failed', reason: 'unparseable-response' });
    const thrower = (() => { throw new Error('ENOENT'); }) as unknown as typeof import('node:child_process').spawn;
    await expect(awaitHeldDecision({ ...base, spawnImpl: thrower })).resolves.toEqual({ kind: 'card_failed', reason: 'spawn-failed' });
  });

  it('a gateway that never answers expires on OUR deadline and the request is killed', async () => {
    const f = fakeSpawn(() => { /* silence */ });
    const t0 = Date.now();
    await expect(awaitHeldDecision({ ...base, windowMs: 200, spawnImpl: f.impl })).resolves.toEqual({ kind: 'expired' });
    expect(Date.now() - t0).toBeLessThan(2_000);
    expect(f.child()?.killed).toEqual(['SIGKILL']);
  });

  it('abort cancels the hold and kills the request', async () => {
    const f = fakeSpawn(() => { /* silence */ });
    const ctl = new AbortController();
    const p = awaitHeldDecision({ ...base, spawnImpl: f.impl, signal: ctl.signal });
    setTimeout(() => ctl.abort(), 20);
    await expect(p).resolves.toEqual({ kind: 'cancelled' });
    expect(f.child()?.killed).toEqual(['SIGKILL']);
  });

  it('an already-aborted signal never raises a card', async () => {
    const f = fakeSpawn(() => { /* silence */ });
    const ctl = new AbortController();
    ctl.abort();
    await expect(awaitHeldDecision({ ...base, spawnImpl: f.impl, signal: ctl.signal })).resolves.toEqual({ kind: 'cancelled' });
    expect(f.calls).toHaveLength(0);
  });
});

describe('abortWhenOrphaned', () => {
  it('aborts once the parent pid changes', async () => {
    let ppid = 100;
    const ctl = new AbortController();
    const stop = abortWhenOrphaned(ctl, { intervalMs: 10, ppid: () => ppid });
    await new Promise((r) => setTimeout(r, 40));
    expect(ctl.signal.aborted).toBe(false);
    ppid = 1;
    await new Promise((r) => setTimeout(r, 40));
    expect(ctl.signal.aborted).toBe(true);
    stop();
  });
});

describe('agent copy', () => {
  it('every refusal says nothing ran, names the action id, and never offers a retry grant', () => {
    const kinds = ['denied', 'expired', 'card_failed', 'open', 'recently-denied', 'recently-expired', 'store-unavailable', 'no-budget'] as const;
    for (const k of kinds) {
      const text = heldRefusalReason(k, { actionId: 'act-9', windowMs: 120_000 });
      expect(text).toMatch(/Nothing ran\./);
      expect(text).toContain('act-9');
      expect(text).not.toMatch(/allow(s)? (one|ONE) retry|retry (it|this) (once|after)/i);
    }
    expect(heldRefusalReason('open', { actionId: 'new', heldActionId: 'old' })).toContain('actionId old');
    expect(heldRefusalReason('expired', { actionId: 'a', windowMs: 120_000 })).toMatch(/HELD for 2 min/);
  });

  it('#853 review: a CANCELLED hold never claims nothing ran — the outcome is unknown', () => {
    const text = heldRefusalReason('cancelled', { actionId: 'act-c' });
    expect(text).not.toMatch(/Nothing ran/i);
    expect(text).toMatch(/outcome is UNKNOWN/);
    expect(text).toMatch(/may have run/);
    expect(text).toContain('act-c');
    expect(text).not.toMatch(/allow(s)? (one|ONE) retry/i);
  });
});
