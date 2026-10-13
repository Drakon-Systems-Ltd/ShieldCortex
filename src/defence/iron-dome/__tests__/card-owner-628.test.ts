/**
 * #628 — the card-owner proof, unit level.
 *
 * The end-to-end suite (src/__tests__/pre-tool-hook-single-card-628.test.ts)
 * drives the real hook over the real /proc. This file pins the pieces: the
 * name derivation is identical in both build units, and each kernel fact the
 * proof reads is load-bearing — shown on a fake /proc tree where every fact
 * can be bent one at a time.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  awaitInterceptorResolution,
  CARD_OWNER_ANCHOR_FILENAME,
  cardOwnerSocketName,
  cardOwnerSurface,
  cardOwnerWaitMs,
  DEFAULT_CARD_OWNER_WAIT_MS,
  listeningAbstractSocketInodes,
  looksLikeOpenClawClaudeChild,
  MAX_CARD_OWNER_WAIT_MS,
  parseCardOwnerAnchor,
  parseCardOwnerReply,
  processHoldsSocketInode,
  proveInterceptorOwnsCard,
  readCardOwnerAnchor,
  readCardOwnerReply,
  readProcStat,
  verifyAnchoredLaunchChain,
  type CardOwnerAnchor,
} from '../card-owner.js';
import { defaultProtectedFsSeam, type ProtectedFsSeam } from '../protected-root.js';
import {
  cardOwnerReply,
  cardOwnerResolution,
  cardOwnerSocketName as pluginSocketName,
  cardOwnerSurface as pluginSurface,
  holdCardOwnerMarker,
  hostHoldsCallsOnCard,
  type CardOwnerMarker,
} from '../../../../plugins/openclaw/card-owner.js';

const ID = 'toolu_01AbCdEfGhIjKlMnOpQrStUv';

describe('#628 name derivation — hook and plugin agree byte for byte', () => {
  const holder = { pid: 4242, startTime: '987654' };
  it.each([
    [{ command: 'cat ~/.ssh/config' }],
    [{ command: 'cat ~/.ssh/config', description: 'x', timeout: 5 }],
    [{ file_path: '/home/u/a.txt', old_string: 'a', new_string: 'b' }],
    [{ file_path: '/home/u/a.txt', path: '/home/u/a.txt', edits: [{ oldText: 'a', newText: 'b' }] }],
    [{ notebook_path: '/home/u/n.ipynb' }],
    [{ url: 'https://example.com' }],
    [{}],
  ])('%j', (input) => {
    expect(pluginSurface(input)).toEqual(cardOwnerSurface(input));
    expect(pluginSocketName(holder, ID, input)).toBe(cardOwnerSocketName(holder, ID, input));
  });

  it('OpenClaw\'s added `path` beside claude-cli\'s `file_path` does not change the name', () => {
    const native = { file_path: '/home/u/a.txt', old_string: 'a', new_string: 'b' };
    const policy = { ...native, path: '/home/u/a.txt', edits: [{ oldText: 'a', newText: 'b' }] };
    expect(cardOwnerSocketName(holder, ID, policy)).toBe(cardOwnerSocketName(holder, ID, native));
  });

  it('every bound field changes the name', () => {
    const base = cardOwnerSocketName(holder, ID, { command: 'x' });
    expect(cardOwnerSocketName({ ...holder, pid: 4243 }, ID, { command: 'x' })).not.toBe(base);
    expect(cardOwnerSocketName({ ...holder, startTime: '987655' }, ID, { command: 'x' })).not.toBe(base);
    expect(cardOwnerSocketName(holder, `${ID}x`, { command: 'x' })).not.toBe(base);
    expect(cardOwnerSocketName(holder, ID, { command: 'y' })).not.toBe(base);
  });

  it.each([undefined, '', 'short', 'toolu_ has space', 'a'.repeat(129), 42])('no name without a usable tool_use_id (%p)', (id) => {
    expect(cardOwnerSocketName(holder, id, { command: 'x' })).toBeNull();
    expect(pluginSocketName(holder, id, { command: 'x' })).toBeNull();
  });
});

describe('#628 wait trigger and clamp', () => {
  it('only OpenClaw\'s stdio prompt transport triggers the wait', () => {
    expect(looksLikeOpenClawClaudeChild(['claude', '--permission-prompt-tool', 'stdio'])).toBe(true);
    expect(looksLikeOpenClawClaudeChild(['claude', '--permission-prompt-tool=stdio'])).toBe(true);
    expect(looksLikeOpenClawClaudeChild(['claude'])).toBe(false);
    expect(looksLikeOpenClawClaudeChild(['claude', '--permission-prompt-tool', 'mcp__x__y'])).toBe(false);
  });
  it('clamps the wait', () => {
    expect(cardOwnerWaitMs(undefined)).toBe(DEFAULT_CARD_OWNER_WAIT_MS);
    expect(cardOwnerWaitMs('junk')).toBe(DEFAULT_CARD_OWNER_WAIT_MS);
    expect(cardOwnerWaitMs('-5')).toBe(0);
    expect(cardOwnerWaitMs('999999')).toBe(MAX_CARD_OWNER_WAIT_MS);
    expect(MAX_CARD_OWNER_WAIT_MS).toBeLessThan(10_000); // inside the installed PreToolUse timeout
    expect(cardOwnerWaitMs('300')).toBe(300);
  });
});

// ── fake /proc ───────────────────────────────────────────────────────────────

const HARNESS = 5000;
const GATEWAY = 4000;

function statLine(pid: number, comm: string, ppid: number, start: string, state = 'S'): string {
  // fields 3..22: state ppid pgrp session tty tpgid flags minflt cminflt majflt
  // cmajflt utime stime cutime cstime priority nice threads itrealvalue starttime
  const rest = [state, String(ppid), '1', '1', '0', '-1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '20', '0', '1', '0', start, '0', '0'];
  return `${pid} (${comm}) ${rest.join(' ')}\n`;
}

const UNIX_HEADER = 'Num       RefCount Protocol Flags    Type St Inode Path\n';
const unixRow = (inode: string, path: string, flags = '00010000', st = '01') =>
  `0000000000000000: 00000002 00000000 ${flags} 0001 ${st} ${inode} ${path}\n`;

describe('#628 proof over a fake /proc — each kernel fact is load-bearing', () => {
  let root: string;
  const gwStart = '1000';
  const harnessStart = '2000';

  function writeProc(pid: number, comm: string, ppid: number, start: string, argv: string[] = [], state = 'S') {
    const dir = join(root, String(pid));
    mkdirSync(join(dir, 'fd'), { recursive: true });
    writeFileSync(join(dir, 'stat'), statLine(pid, comm, ppid, start, state));
    writeFileSync(join(dir, 'cmdline'), argv.join('\0') + '\0');
  }
  function holdFd(pid: number, fd: number, target: string) {
    symlinkSync(target, join(root, String(pid), 'fd', String(fd)));
  }
  function netUnix(rows: string) {
    mkdirSync(join(root, 'net'), { recursive: true });
    writeFileSync(join(root, 'net', 'unix'), UNIX_HEADER + rows);
  }
  const input = { command: 'cat ~/.ssh/config' };
  const name = () => cardOwnerSocketName({ pid: GATEWAY, startTime: gwStart }, ID, input)!;
  const prove = () => proveInterceptorOwnsCard({ harnessPid: HARNESS, toolUseId: ID, toolInput: input, procRoot: root, platform: 'linux' });

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'sc-628-proc-'));
    writeProc(GATEWAY, 'openclaw-gateway', 1, gwStart);
    writeProc(HARNESS, 'claude', GATEWAY, harnessStart, ['claude', '--permission-prompt-tool', 'stdio']);
    holdFd(GATEWAY, 3, 'socket:[777]');
    holdFd(GATEWAY, 4, '/home/u/.openclaw/state/openclaw.sqlite');
    netUnix(unixRow('777', `@${name()}`) + unixRow('778', '/run/user/1000/bus'));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it('the honest tree is proven', () => {
    expect(prove()).toMatchObject({ proven: true, holderPid: GATEWAY, holderStartTime: gwStart });
  });

  it('comm with spaces and parentheses does not shift the fields', () => {
    writeProc(GATEWAY, 'node (gw) x', 1, gwStart);
    expect(readProcStat(GATEWAY, root)).toEqual({ pid: GATEWAY, ppid: 1, startTime: gwStart });
    expect(prove().proven).toBe(true);
  });

  it('PID reuse: same pid, different start time → the name differs → not proven', () => {
    writeProc(GATEWAY, 'openclaw-gateway', 1, '1500');
    expect(prove()).toEqual({ proven: false, reason: 'no interceptor card for this call' });
  });

  it('a "parent" younger than the harness (a reused pid) is refused before any name is derived', () => {
    writeProc(GATEWAY, 'openclaw-gateway', 1, '3000');
    expect(prove()).toEqual({ proven: false, reason: 'parent younger than harness' });
  });

  it('the name listed but held by another process → not proven', () => {
    rmSync(join(root, String(GATEWAY), 'fd', '3'));
    writeProc(6000, 'impostor', 1, '1200');
    holdFd(6000, 3, 'socket:[777]');
    expect(prove()).toEqual({ proven: false, reason: 'card socket not held by the gateway parent' });
  });

  it('a socket that is not listening, or not a stream, is not the marker', () => {
    netUnix(unixRow('777', `@${name()}`, '00000000', '03'));
    expect(prove().proven).toBe(false);
    netUnix(`0000000000000000: 00000002 00000000 00010000 0002 01 777 @${name()}\n`);
    expect(prove().proven).toBe(false);
  });

  it('a filesystem socket whose path merely ends in the name is not the marker', () => {
    netUnix(unixRow('777', `/tmp/x/@${name()}`));
    expect(prove().proven).toBe(false);
  });

  it('the harness re-parented (gateway gone mid-call) → not proven', () => {
    writeProc(HARNESS, 'claude', 1, harnessStart);
    expect(prove()).toEqual({ proven: false, reason: 'harness has no gateway parent' });
  });

  it('a dead (zombie) gateway is not a holder', () => {
    writeProc(GATEWAY, 'openclaw-gateway', 1, gwStart, [], 'Z');
    expect(prove()).toEqual({ proven: false, reason: 'parent not readable' });
  });

  it('a grandparent holding the marker does not count: only the direct parent', () => {
    // agent-launched claude: harness → agent shell → real claude → gateway
    writeProc(5100, 'bash', HARNESS, '2100');
    writeProc(5200, 'claude', 5100, '2200', ['claude', '--permission-prompt-tool', 'stdio']);
    expect(proveInterceptorOwnsCard({ harnessPid: 5200, toolUseId: ID, toolInput: input, procRoot: root, platform: 'linux' }).proven).toBe(false);
  });

  it('a sibling call (different tool_use_id) is not proven by this marker', () => {
    expect(proveInterceptorOwnsCard({ harnessPid: HARNESS, toolUseId: `${ID}2`, toolInput: input, procRoot: root, platform: 'linux' }).proven).toBe(false);
  });

  it('not Linux, no /proc, or no tool_use_id → not proven', () => {
    expect(proveInterceptorOwnsCard({ harnessPid: HARNESS, toolUseId: ID, toolInput: input, procRoot: root, platform: 'darwin' }).proven).toBe(false);
    expect(proveInterceptorOwnsCard({ harnessPid: HARNESS, toolUseId: ID, toolInput: input, procRoot: join(root, 'nope'), platform: 'linux' }).proven).toBe(false);
    expect(proveInterceptorOwnsCard({ harnessPid: HARNESS, toolUseId: undefined, toolInput: input, procRoot: root, platform: 'linux' }).proven).toBe(false);
  });

  it('proof of the marker carries the inode it found (the resolution re-checks it)', () => {
    expect(prove()).toMatchObject({ proven: true, inode: '777', harnessStartTime: harnessStart });
  });
});

describe('#628 host floor — the marker is bound only where the host holds the call on the card', () => {
  it.each([
    ['2026.9.8', true], ['2026.10.1', true], ['v2026.10.1', true], [' 2026.10.1 ', true], ['2027.1.0', true],
    ['2026.9.7', false], ['2026.7.1', false], ['2025.12.31', false],
    // Whole-string validation (round-2 nit 2): junk suffixes and prereleases
    // are refused, including a prerelease of the floor itself.
    ['2026.9.8junk', false], ['2026.9.8-beta.0', false], ['2026.9.8+build.1', false], ['2026.10.1-beta.2', false],
    ['2026.9.8.1', false], ['x2026.9.8', false],
    ['', false], ['nightly', false], [null, false], [undefined, false], [20261001, false],
  ])('%p → %p', (version, ok) => {
    expect(hostHoldsCallsOnCard(version)).toBe(ok);
  });

  const itLinux = process.platform === 'linux' ? it : it.skip;
  itLinux('below the floor, or with no reported version, no marker is bound', () => {
    expect(holdCardOwnerMarker({ toolCallId: ID, params: {}, hostVersion: '2026.7.1' })).toBeNull();
    expect(holdCardOwnerMarker({ toolCallId: ID, params: {}, hostVersion: null })).toBeNull();
    const m = holdCardOwnerMarker({ toolCallId: `${ID}F`, params: {}, hostVersion: '2026.10.1' });
    expect(m).not.toBeNull();
    m!.close();
  });
});

describe('#628 the plugin marker on the real kernel', () => {
  const itLinux = process.platform === 'linux' ? it : it.skip;

  itLinux('a held marker is a listening abstract socket in this process\'s own fd table', () => {
    const m = holdCardOwnerMarker({ toolCallId: ID, params: { command: 'x' } })!;
    try {
      expect(m).not.toBeNull();
      const inodes = listeningAbstractSocketInodes(m.name);
      expect(inodes.size).toBe(1);
      expect(processHoldsSocketInode(process.pid, inodes)).toBe(true);
    } finally {
      m.close();
    }
    expect(listeningAbstractSocketInodes(m.name).size).toBe(0);
  });

  itLinux('no marker without a call id, or off Linux', () => {
    expect(holdCardOwnerMarker({ toolCallId: undefined, params: {} })).toBeNull();
    expect(holdCardOwnerMarker({ toolCallId: ID, params: {}, platform: 'darwin' })).toBeNull();
  });

  itLinux('resolve lingers, then closes', async () => {
    const m = holdCardOwnerMarker({ toolCallId: `${ID}L`, params: { command: 'x' }, lingerMs: 50 })!;
    m.resolve('allow-once');
    expect(listeningAbstractSocketInodes(m.name).size).toBe(1);
    await new Promise((r) => setTimeout(r, 200));
    expect(listeningAbstractSocketInodes(m.name).size).toBe(0);
  });

  itLinux('the hold is capped even if the host never answers', async () => {
    const m = holdCardOwnerMarker({ toolCallId: `${ID}C`, params: { command: 'x' }, maxHoldMs: 50 })!;
    expect(listeningAbstractSocketInodes(m.name).size).toBe(1);
    await new Promise((r) => setTimeout(r, 200));
    expect(listeningAbstractSocketInodes(m.name).size).toBe(0);
  });
});

// ── round 2, blocker 1: the card's RESOLUTION, not its existence ────────────

describe('#628 resolution channel — only an operator answer is adoptable', () => {
  it.each([
    ['allow-once', 'approved'], ['allow-always', 'approved'], ['deny', 'denied'],
    ['cancelled', 'unresolved'], ['timeout', 'unresolved'], ['allow-forever', 'unresolved'], [undefined, 'unresolved'],
  ])('host decision %p → %p', (decision, resolution) => {
    expect(cardOwnerResolution(decision)).toBe(resolution);
  });

  it('the gateway\'s line and the hook\'s parser agree, and the parser is strict', () => {
    for (const r of ['approved', 'denied', 'unresolved'] as const) {
      expect(parseCardOwnerReply(cardOwnerReply(ID, r).trimEnd(), ID)).toBe(r);
    }
    expect(parseCardOwnerReply(cardOwnerReply(ID, 'approved').trimEnd(), `${ID}2`)).toBeNull();
    expect(parseCardOwnerReply(JSON.stringify({ v: 2, toolUseId: ID, resolution: 'approved' }), ID)).toBeNull();
    expect(parseCardOwnerReply(JSON.stringify({ v: 1, toolUseId: ID, resolution: 'approved', extra: 1 }), ID)).toBeNull();
    expect(parseCardOwnerReply(JSON.stringify({ v: 1, toolUseId: ID, resolution: 'allow' }), ID)).toBeNull();
    expect(parseCardOwnerReply('approved', ID)).toBeNull();
    expect(parseCardOwnerReply('', ID)).toBeNull();
  });

  const itLinux = process.platform === 'linux' ? it : it.skip;
  const live: CardOwnerMarker[] = [];
  afterEach(() => { for (const m of live.splice(0)) m.close(); });
  const held = (suffix: string) => {
    const m = holdCardOwnerMarker({ toolCallId: `${ID}${suffix}`, params: { command: 'x' } })!;
    live.push(m);
    return m;
  };

  itLinux('a waiting reader gets the answer when the card is resolved', async () => {
    const m = held('W');
    const pending = readCardOwnerReply(m.name, 2_000);
    setTimeout(() => m.resolve('deny'), 100);
    expect(parseCardOwnerReply((await pending)!, `${ID}W`)).toBe('denied');
  });

  itLinux('a late reader still gets the answer during the linger', async () => {
    const m = held('Z');
    m.resolve('allow-once');
    expect(parseCardOwnerReply((await readCardOwnerReply(m.name, 2_000))!, `${ID}Z`)).toBe('approved');
  });

  itLinux('the first resolution wins', async () => {
    const m = held('F');
    m.resolve('cancelled');
    m.resolve('allow-once');
    expect(parseCardOwnerReply((await readCardOwnerReply(m.name, 2_000))!, `${ID}F`)).toBe('unresolved');
  });

  itLinux('closed with no resolution: the reader gets nothing', async () => {
    const m = held('C');
    const pending = readCardOwnerReply(m.name, 2_000);
    setTimeout(() => m.close(), 100);
    expect(await pending).toBeNull();
  });

  itLinux('no answer within the budget: nothing', async () => {
    const m = held('T');
    const started = Date.now();
    expect(await readCardOwnerReply(m.name, 200)).toBeNull();
    expect(Date.now() - started).toBeLessThan(1_500);
  });

  itLinux('no socket at all: nothing', async () => {
    expect(await readCardOwnerReply('shieldcortex-card-owner-v1-nobody-home', 500)).toBeNull();
  });
});

// ── round 2, blocker 2: the launch-chain anchor ─────────────────────────────

/** A seam that reports uid 0 and no group/other write for exactly the named
 *  paths, and the real host for everything else. */
function rootOwnedSeam(paths: Iterable<string>): ProtectedFsSeam {
  const root = new Set(paths);
  const base = defaultProtectedFsSeam();
  const mask = (st: ReturnType<ProtectedFsSeam['lstat']>, p: string) =>
    st && root.has(p) ? { ...st, uid: 0, gid: 0, mode: st.mode & ~0o022 } : st;
  return { ...base, lstat: (p) => mask(base.lstat(p), p), stat: (p) => mask(base.stat(p), p) };
}

function ancestors(p: string): string[] {
  const out = [p];
  while (dirname(out[out.length - 1]) !== out[out.length - 1]) out.push(dirname(out[out.length - 1]));
  return out;
}

describe('#628 anchor file — strict, root-owned, or nothing', () => {
  const good = { version: 1, gateway: { exe: '/usr/bin/node', entry: '/usr/lib/openclaw/openclaw.mjs', execArgv: [], env: {} } };
  it('a well-formed anchor parses', () => {
    expect(parseCardOwnerAnchor(good)).toEqual({ exe: '/usr/bin/node', entry: '/usr/lib/openclaw/openclaw.mjs', execArgv: [], env: {} });
    expect(parseCardOwnerAnchor({ version: 1, gateway: { exe: '/opt/openclaw/bin/openclaw' } })).toEqual({ exe: '/opt/openclaw/bin/openclaw', entry: null, execArgv: [], env: {} });
  });
  it.each([
    ['no version', { gateway: good.gateway }],
    ['another version', { ...good, version: 2 }],
    ['an unknown top-level key', { ...good, trust: 'all' }],
    ['an unknown gateway key', { version: 1, gateway: { ...good.gateway, pidFile: '/run/gw.pid' } }],
    ['a relative exe', { version: 1, gateway: { ...good.gateway, exe: 'node' } }],
    ['a relative entry', { version: 1, gateway: { ...good.gateway, entry: 'openclaw.mjs' } }],
    ['non-string flags', { version: 1, gateway: { ...good.gateway, execArgv: [1] } }],
    ['an env key that is not a loader variable', { version: 1, gateway: { ...good.gateway, env: { HOME: '/root' } } }],
    ['a non-object', 'gateway'],
  ])('%s is no anchor', (_label, raw) => {
    expect(parseCardOwnerAnchor(raw)).toBeNull();
  });

  let dir: string;
  beforeEach(() => { dir = realpathSync.native(mkdtempSync(join(tmpdir(), 'sc-628-anchor-'))); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('missing: no anchor (every default install)', () => {
    expect(readCardOwnerAnchor({ anchorPath: join(dir, CARD_OWNER_ANCHOR_FILENAME) })).toEqual({ ok: false, reason: 'no launch-chain anchor' });
  });
  it('written by the agent\'s own uid: no anchor', () => {
    const p = join(dir, CARD_OWNER_ANCHOR_FILENAME);
    writeFileSync(p, JSON.stringify(good));
    expect(readCardOwnerAnchor({ anchorPath: p })).toEqual({ ok: false, reason: 'anchor owned-by-agent' });
  });
  it('root-owned file in an agent-writable directory: no anchor', () => {
    const p = join(dir, CARD_OWNER_ANCHOR_FILENAME);
    writeFileSync(p, JSON.stringify(good));
    const seam = rootOwnedSeam(ancestors(p).filter((x) => x !== dir));
    expect(readCardOwnerAnchor({ anchorPath: p, fsSeam: seam })).toEqual({ ok: false, reason: 'anchor parent-owned-by-agent' });
  });
  it('root-owned and well-formed: an anchor', () => {
    const p = join(dir, CARD_OWNER_ANCHOR_FILENAME);
    writeFileSync(p, JSON.stringify(good));
    expect(readCardOwnerAnchor({ anchorPath: p, fsSeam: rootOwnedSeam(ancestors(p)) })).toMatchObject({ ok: true, path: p });
  });
  it('root-owned but malformed: no anchor', () => {
    const p = join(dir, CARD_OWNER_ANCHOR_FILENAME);
    writeFileSync(p, '{"version":1,');
    expect(readCardOwnerAnchor({ anchorPath: p, fsSeam: rootOwnedSeam(ancestors(p)) })).toEqual({ ok: false, reason: 'anchor malformed' });
  });
});

describe('#628 launch chain — root-owned images, and the parent IS the anchored gateway', () => {
  let proc: string;
  let fsRoot: string;
  let bin: string;
  const GW = 4000;
  const CL = 5000;
  const LAUNCHER = 4500;

  function file(rel: string): string {
    const p = join(fsRoot, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, '');
    return p;
  }
  function procEntry(pid: number, exe: string, argv: string[], env: Record<string, string> = {}, cwd = '/') {
    const d = join(proc, String(pid));
    mkdirSync(d, { recursive: true });
    symlinkSync(exe, join(d, 'exe'));
    symlinkSync(cwd, join(d, 'cwd'));
    writeFileSync(join(d, 'cmdline'), argv.join('\0') + '\0');
    writeFileSync(join(d, 'environ'), Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\0') + '\0');
  }

  let node: string;
  let gwEntry: string;
  let claudeEntry: string;
  let nativeClaude: string;
  let anchor: CardOwnerAnchor;
  let rootPaths: string[];

  beforeEach(() => {
    proc = mkdtempSync(join(tmpdir(), 'sc-628-lcp-'));
    fsRoot = realpathSync.native(mkdtempSync(join(tmpdir(), 'sc-628-lcf-')));
    bin = join(fsRoot, 'usr', 'bin');
    node = file('usr/bin/node');
    gwEntry = file('usr/lib/openclaw/openclaw.mjs');
    claudeEntry = file('usr/lib/claude/cli.js');
    nativeClaude = file('usr/lib/claude/bin/claude');
    file('usr/bin/sh');
    anchor = { exe: node, entry: gwEntry, execArgv: [], env: { NODE_OPTIONS: '--max-old-space-size=4096' } };
    rootPaths = [...new Set([node, gwEntry, claudeEntry, nativeClaude, join(bin, 'sh')].flatMap(ancestors))];
    procEntry(GW, node, [node, gwEntry, 'gateway'], { NODE_OPTIONS: '--max-old-space-size=4096' });
    procEntry(CL, node, ['claude', claudeEntry, '--permission-prompt-tool', 'stdio']);
  });
  afterEach(() => {
    rmSync(proc, { recursive: true, force: true });
    rmSync(fsRoot, { recursive: true, force: true });
  });

  const verify = (paths = rootPaths, a = anchor, gatewayPid = GW) =>
    verifyAnchoredLaunchChain({ harnessPid: CL, gatewayPid, anchor: a }, { procRoot: proc, fsSeam: rootOwnedSeam(paths) });

  it('root-owned chain, parent is the anchored gateway: verified', () => {
    expect(verify()).toEqual({ ok: true });
  });

  it('a native claude binary (no entry script) in a root-owned chain: verified', () => {
    rmSync(join(proc, String(CL)), { recursive: true });
    procEntry(CL, nativeClaude, ['claude', '--permission-prompt-tool', 'stdio']);
    expect(verify()).toEqual({ ok: true });
  });

  it('a relative entry is resolved against the process\'s cwd', () => {
    rmSync(join(proc, String(GW)), { recursive: true });
    procEntry(GW, node, [node, 'openclaw.mjs'], { NODE_OPTIONS: '--max-old-space-size=4096' }, dirname(gwEntry));
    expect(verify()).toEqual({ ok: true });
  });

  it('a user-writable claude entry script: refused', () => {
    expect(verify(rootPaths.filter((p) => p !== claudeEntry))).toEqual({ ok: false, reason: 'harness entry script owned-by-agent' });
  });

  it('a user-writable native claude binary: refused', () => {
    rmSync(join(proc, String(CL)), { recursive: true });
    procEntry(CL, nativeClaude, ['claude']);
    expect(verify(rootPaths.filter((p) => p !== nativeClaude))).toEqual({ ok: false, reason: 'harness executable owned-by-agent' });
  });

  it('a user-writable directory on claude\'s path: refused', () => {
    expect(verify(rootPaths.filter((p) => p !== dirname(claudeEntry)))).toEqual({ ok: false, reason: 'harness entry script parent-owned-by-agent' });
  });

  it('a user-writable gateway entry: refused', () => {
    expect(verify(rootPaths.filter((p) => p !== gwEntry))).toEqual({ ok: false, reason: 'gateway entry script owned-by-agent' });
  });

  it('a user-writable gateway executable: refused', () => {
    expect(verify(rootPaths.filter((p) => p !== node))).toEqual({ ok: false, reason: 'harness executable owned-by-agent' });
  });

  it('a forwarding launcher as the parent (root-owned or not) is not the anchored gateway', () => {
    const launcher = file('usr/lib/claude-shim/claude');
    procEntry(LAUNCHER, node, [node, launcher]);
    expect(verify([...rootPaths, ...ancestors(launcher)], anchor, LAUNCHER)).toEqual({ ok: false, reason: 'parent is not the anchored gateway' });
    expect(verify(rootPaths, anchor, LAUNCHER)).toEqual({ ok: false, reason: 'gateway entry script owned-by-agent' });
  });

  it('the anchored gateway image run with other interpreter flags (e.g. a preload): refused', () => {
    rmSync(join(proc, String(GW)), { recursive: true });
    procEntry(GW, node, [node, '--require', '/tmp/x.js', gwEntry], { NODE_OPTIONS: '--max-old-space-size=4096' });
    expect(verify()).toEqual({ ok: false, reason: 'gateway has no entry script' });
    expect(verify(rootPaths, { ...anchor, execArgv: ['--no-warnings'] })).toEqual({ ok: false, reason: 'gateway interpreter flags differ' });
  });

  it('a harness with interpreter flags before its entry: refused', () => {
    rmSync(join(proc, String(CL)), { recursive: true });
    procEntry(CL, node, [node, '--import', '/tmp/x.mjs', claudeEntry]);
    expect(verify()).toEqual({ ok: false, reason: 'harness has no entry script' });
  });

  it('a harness under a shell (a root-owned /bin/sh running a user-writable script): refused', () => {
    rmSync(join(proc, String(CL)), { recursive: true });
    procEntry(CL, join(bin, 'sh'), ['sh', '/home/u/.local/bin/claude']);
    expect(verify()).toEqual({ ok: false, reason: 'harness runs under an unsupported interpreter' });
  });

  it('a deleted (replaced) executable: refused', () => {
    rmSync(join(proc, String(CL)), { recursive: true });
    procEntry(CL, `${nativeClaude} (deleted)`, ['claude']);
    expect(verify()).toEqual({ ok: false, reason: 'harness executable replaced' });
  });

  it('loader variables: the gateway must match the anchor exactly; the harness may only inherit them', () => {
    rmSync(join(proc, String(GW)), { recursive: true });
    procEntry(GW, node, [node, gwEntry], {});
    expect(verify()).toEqual({ ok: false, reason: 'gateway NODE_OPTIONS differs from the anchor' });
    rmSync(join(proc, String(GW)), { recursive: true });
    procEntry(GW, node, [node, gwEntry], { NODE_OPTIONS: '--max-old-space-size=4096' });
    rmSync(join(proc, String(CL)), { recursive: true });
    procEntry(CL, node, [node, claudeEntry], { LD_PRELOAD: '/tmp/x.so' });
    expect(verify()).toEqual({ ok: false, reason: 'harness LD_PRELOAD differs from the anchor' });
    rmSync(join(proc, String(CL)), { recursive: true });
    procEntry(CL, node, [node, claudeEntry], { NODE_OPTIONS: '--max-old-space-size=4096' });
    expect(verify()).toEqual({ ok: true });
  });

  it('unreadable /proc state: refused', () => {
    rmSync(join(proc, String(GW), 'environ'));
    expect(verify()).toEqual({ ok: false, reason: 'gateway environment unreadable' });
  });
});

// ── the whole adoption, on a fake /proc and a real socket ───────────────────

describe('#628 awaitInterceptorResolution — adopt an operator answer, fall back on everything else', () => {
  const itLinux = process.platform === 'linux' ? it : it.skip;
  const GW = 4000;
  const CL = 5000;
  const gwStart = '1000';
  const clStart = '2000';
  const input = { command: 'cat ~/.ssh/config' };
  let proc: string;
  let fsRoot: string;
  let anchorPath: string;
  let seam: ProtectedFsSeam;
  let marker: CardOwnerMarker | null = null;
  let id: string;
  let n = 0;

  function writeUnix(inode: string) {
    const name = cardOwnerSocketName({ pid: GW, startTime: gwStart }, id, input)!;
    mkdirSync(join(proc, 'net'), { recursive: true });
    writeFileSync(join(proc, 'net', 'unix'), UNIX_HEADER + unixRow(inode, `@${name}`));
    rmSync(join(proc, String(GW), 'fd', '3'), { force: true });
    symlinkSync(`socket:[${inode}]`, join(proc, String(GW), 'fd', '3'));
  }

  beforeEach(() => {
    id = `${ID}R${n++}`;
    proc = mkdtempSync(join(tmpdir(), 'sc-628-arp-'));
    fsRoot = realpathSync.native(mkdtempSync(join(tmpdir(), 'sc-628-arf-')));
    const mk = (rel: string) => { const p = join(fsRoot, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, ''); return p; };
    const node = mk('usr/bin/node');
    const gwEntry = mk('usr/lib/openclaw/openclaw.mjs');
    const claudeEntry = mk('usr/lib/claude/cli.js');
    anchorPath = join(fsRoot, 'etc', 'shieldcortex', CARD_OWNER_ANCHOR_FILENAME);
    mkdirSync(dirname(anchorPath), { recursive: true });
    writeFileSync(anchorPath, JSON.stringify({ version: 1, gateway: { exe: node, entry: gwEntry } }));
    seam = rootOwnedSeam([node, gwEntry, claudeEntry, anchorPath].flatMap(ancestors));
    for (const [pid, comm, ppid, start, exe, argv] of [
      [GW, 'node', 1, gwStart, node, [node, gwEntry]],
      [CL, 'claude', GW, clStart, node, [node, claudeEntry, '--permission-prompt-tool', 'stdio']],
    ] as Array<[number, string, number, string, string, string[]]>) {
      const d = join(proc, String(pid));
      mkdirSync(join(d, 'fd'), { recursive: true });
      writeFileSync(join(d, 'stat'), statLine(pid, comm, ppid, start));
      writeFileSync(join(d, 'cmdline'), argv.join('\0') + '\0');
      writeFileSync(join(d, 'environ'), 'PATH=/usr/bin\0');
      symlinkSync(exe, join(d, 'exe'));
      symlinkSync('/', join(d, 'cwd'));
    }
    writeUnix('777');
    // The REAL socket the hook connects to, bound under the fake gateway's
    // identity so its name matches the fake /proc.
    marker = holdCardOwnerMarker({ toolCallId: id, params: input, holder: { pid: GW, startTime: gwStart } });
  });
  afterEach(() => {
    marker?.close();
    rmSync(proc, { recursive: true, force: true });
    rmSync(fsRoot, { recursive: true, force: true });
  });

  const adopt = (waitMs = 2_000, extra: Record<string, unknown> = {}) =>
    awaitInterceptorResolution({ harnessPid: CL, toolUseId: id, toolInput: input, procRoot: proc, platform: 'linux', fsSeam: seam, anchorPath, waitMs, ...extra });

  itLinux('operator approved: adopted as approved', async () => {
    setTimeout(() => marker!.resolve('allow-once'), 100);
    expect(await adopt()).toEqual({ kind: 'approved', holderPid: GW, holderStartTime: gwStart, socketName: marker!.name });
  });

  itLinux('operator denied: adopted as denied', async () => {
    marker!.resolve('deny');
    expect(await adopt()).toMatchObject({ kind: 'denied', holderPid: GW });
  });

  itLinux.each(['cancelled', 'timeout'])('%s: fallback (the hook cards)', async (decision) => {
    marker!.resolve(decision);
    expect(await adopt()).toEqual({ kind: 'fallback', reason: 'card not answered by the operator' });
  });

  itLinux('closed with no resolution: fallback', async () => {
    setTimeout(() => marker!.close(), 100);
    expect(await adopt()).toEqual({ kind: 'fallback', reason: 'no resolution from the gateway' });
  });

  itLinux('no answer within the budget: fallback at the budget', async () => {
    const started = Date.now();
    expect(await adopt(300)).toEqual({ kind: 'fallback', reason: 'no resolution from the gateway' });
    expect(Date.now() - started).toBeLessThan(1_500);
  });

  itLinux('the socket changed under the wait (another inode now holds the name): fallback', async () => {
    setTimeout(() => writeUnix('778'), 50);
    setTimeout(() => marker!.resolve('allow-once'), 150);
    expect(await adopt()).toEqual({ kind: 'fallback', reason: 'card socket changed during the wait' });
  });

  itLinux('no anchor: fallback at once, without waiting, even for an approved card', async () => {
    marker!.resolve('allow-once');
    const started = Date.now();
    expect(await adopt(5_000, { anchorPath: join(fsRoot, 'nope.json') })).toEqual({ kind: 'fallback', reason: 'no launch-chain anchor' });
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  itLinux('a harness not launched by OpenClaw: fallback at once', async () => {
    writeFileSync(join(proc, String(CL), 'cmdline'), 'claude\0');
    marker!.resolve('allow-once');
    expect(await adopt()).toEqual({ kind: 'fallback', reason: 'harness is not an OpenClaw claude-cli child' });
  });
});
