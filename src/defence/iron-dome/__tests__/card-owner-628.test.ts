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
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  awaitInterceptorCardOwner,
  cardOwnerSocketName,
  cardOwnerSurface,
  cardOwnerWaitMs,
  DEFAULT_CARD_OWNER_WAIT_MS,
  listeningAbstractSocketInodes,
  looksLikeOpenClawClaudeChild,
  processHoldsSocketInode,
  proveInterceptorOwnsCard,
  readProcStat,
} from '../card-owner.js';
import {
  cardOwnerSocketName as pluginSocketName,
  cardOwnerSurface as pluginSurface,
  holdCardOwnerMarker,
  hostHoldsCallsOnCard,
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
    expect(cardOwnerWaitMs('999999')).toBe(5_000);
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

  it('the wait is skipped (not proven at once) for a harness not launched by OpenClaw', async () => {
    writeProc(HARNESS, 'claude', GATEWAY, harnessStart, ['claude']);
    const started = Date.now();
    const proof = await awaitInterceptorCardOwner({ harnessPid: HARNESS, toolUseId: ID, toolInput: input, procRoot: root, platform: 'linux', waitMs: 2_000 });
    expect(proof).toEqual({ proven: false, reason: 'harness is not an OpenClaw claude-cli child' });
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it('the wait picks up a card that appears late', async () => {
    netUnix('');
    setTimeout(() => netUnix(unixRow('777', `@${name()}`)), 150);
    const proof = await awaitInterceptorCardOwner({ harnessPid: HARNESS, toolUseId: ID, toolInput: input, procRoot: root, platform: 'linux', waitMs: 2_000 });
    expect(proof.proven).toBe(true);
  });
});

describe('#628 host floor — the marker is bound only where the host holds the call on the card', () => {
  it.each([
    ['2026.9.8', true], ['2026.10.1', true], ['v2026.10.1', true], ['2026.10.1-beta.2', true], ['2027.1.0', true],
    ['2026.9.7', false], ['2026.7.1', false], ['2025.12.31', false],
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

  itLinux('release lingers, then closes', async () => {
    const m = holdCardOwnerMarker({ toolCallId: `${ID}L`, params: { command: 'x' }, lingerMs: 50 })!;
    m.release();
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
