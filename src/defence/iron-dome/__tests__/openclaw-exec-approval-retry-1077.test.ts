/**
 * #1077 ask 2 — an approval must match a retry of the same OpenClaw exec call.
 *
 * OpenClaw exec reaches the guard under two byte-exact names: `exec` (the
 * native contract, plugin plane) and `mcp__openclaw__exec` (Claude Code as
 * OpenClaw's CLI backend, through OpenClaw's MCP loopback bridge — the plane
 * that hashes calls for `approve` and `approve --denial`). Its input carries a
 * free-text label the model re-words every attempt, which used to mint a new
 * approval id per attempt. Only those two names drop label keys from the
 * approval hash; every other name, look-alikes included, keeps every field
 * bound. Expiry and one-shot semantics are unchanged.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  DEFAULT_APPROVAL_TTL_MS,
  approveRequest,
  consumeApproval,
  exactCallDigest,
  hashToolCall,
  recordPending,
} from '../action-approvals.js';
import { hasExactSpecialToolSchema } from '../tool-input-schema.js';
import { consumeRetryGrant, grantRetry, recordDenialFingerprint } from '../retry-control.js';

const NATIVE = ['mcp__openclaw__exec', 'exec'] as const;
const LOOKALIKES = [
  'mcp__evil__exec', 'mcp__other__exec', 'mcp__evil__Bash', 'mcp__openclaw__gateway_exec',
  'mcp__evil__openclaw__exec', 'MCP__OPENCLAW__EXEC', 'Exec', ' exec', 'mcp__openclaw__exec ',
];

const CALL = { command: "jq '.channels.telegram' ~/.openclaw/openclaw.json", workdir: '/home/u/clawd' };
const T0 = 1_800_000_000_000;

describe('#1077 — OpenClaw exec approval hash ignores the re-worded label', () => {
  describe.each(NATIVE)('%s', (tool) => {
    it('title / description / label do not move the hash', () => {
      const base = hashToolCall(tool, CALL);
      expect(hashToolCall(tool, { ...CALL, title: 'Read telegram config' })).toBe(base);
      expect(hashToolCall(tool, { ...CALL, title: 'Retry: read the Telegram section' })).toBe(base);
      expect(hashToolCall(tool, { ...CALL, description: 'Inspect channel config', label: 'telegram' })).toBe(base);
    });

    it('command, workdir and every execution field still move it', () => {
      const base = hashToolCall(tool, { ...CALL, title: 'a' });
      for (const changed of [
        { ...CALL, command: "jq '.channels' ~/.openclaw/openclaw.json" },
        { ...CALL, workdir: '/tmp' },
        { ...CALL, cwd: '/tmp' },
        { ...CALL, env: { LANG: 'C' } },
        { ...CALL, elevated: true },
        { ...CALL, host: 'node' },
        { ...CALL, background: true },
        { ...CALL, timeoutSeconds: 5 },
      ]) {
        expect(hashToolCall(tool, { ...changed, title: 'a' })).not.toBe(base);
      }
    });

    it('a label without a command string stays bound (argv-only or empty bag)', () => {
      expect(hashToolCall(tool, { argv: ['ls'], title: 'a' })).not.toBe(hashToolCall(tool, { argv: ['ls'], title: 'b' }));
      expect(hashToolCall(tool, { command: '', title: 'a' })).not.toBe(hashToolCall(tool, { command: '', title: 'b' }));
    });

    it('the tap digest stays byte-bound (unchanged)', () => {
      expect(exactCallDigest(tool, { ...CALL, title: 'a' })).not.toBe(exactCallDigest(tool, { ...CALL, title: 'b' }));
    });
  });

  it.each(LOOKALIKES)('look-alike %p keeps every field bound', (tool) => {
    expect(hashToolCall(tool, { ...CALL, title: 'a' })).not.toBe(hashToolCall(tool, { ...CALL, title: 'b' }));
    expect(hashToolCall(tool, { ...CALL, description: 'a' })).not.toBe(hashToolCall(tool, { ...CALL, description: 'b' }));
  });

  it('Bash is unchanged: `title` was never advisory there', () => {
    expect(hashToolCall('Bash', { command: 'ls', title: 'a' })).not.toBe(hashToolCall('Bash', { command: 'ls', title: 'b' }));
    expect(hashToolCall('Bash', { command: 'ls', description: 'a' })).toBe(hashToolCall('Bash', { command: 'ls', description: 'b' }));
  });

  it('the schema stance is intact: no MCP-fronted name gets the native exec contract', () => {
    expect(hasExactSpecialToolSchema('exec')).toBe(true);
    for (const tool of ['mcp__openclaw__exec', 'mcp__evil__exec', 'mcp__other__exec', 'mcp__evil__Bash']) {
      expect(hasExactSpecialToolSchema(tool)).toBe(false);
    }
  });
});

describe('#1077 — approve once, the retry with a new title passes (approval store)', () => {
  let home: string;
  beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'sc-1077-appr-')); });
  afterEach(() => { rmSync(home, { recursive: true, force: true }); });

  const approve = (tool: string, input: unknown, now = T0) => {
    const pending = recordPending({ tool, input, summary: `${tool}: x`, signals: ['disable-action-guard'] }, { home, now });
    expect(approveRequest(pending.hash, { home, now: now + 1_000 }).ok).toBe(true);
  };

  it.each(NATIVE)('%s: retry with a different title matches, once', (tool) => {
    approve(tool, { ...CALL, title: 'Read telegram config' });
    expect(consumeApproval(tool, { ...CALL, title: 'Retry: read the Telegram section' }, { home, now: T0 + 2_000 })).not.toBeNull();
    // One-shot: the next retry finds nothing.
    expect(consumeApproval(tool, { ...CALL, title: 'third try' }, { home, now: T0 + 3_000 })).toBeNull();
  });

  it.each(NATIVE)('%s: a different command or workdir does not match', (tool) => {
    approve(tool, { ...CALL, title: 'a' });
    expect(consumeApproval(tool, { ...CALL, command: 'cat ~/.openclaw/openclaw.json', title: 'a' }, { home, now: T0 + 2_000 })).toBeNull();
    expect(consumeApproval(tool, { ...CALL, workdir: '/tmp', title: 'a' }, { home, now: T0 + 2_000 })).toBeNull();
    // ...and the approval is not collaterally spent.
    expect(consumeApproval(tool, { ...CALL, title: 'b' }, { home, now: T0 + 2_000 })).not.toBeNull();
  });

  it.each(NATIVE)('%s: expiry is unchanged', (tool) => {
    approve(tool, { ...CALL, title: 'a' });
    expect(consumeApproval(tool, { ...CALL, title: 'b' }, { home, now: T0 + 1_000 + DEFAULT_APPROVAL_TTL_MS + 1 })).toBeNull();
  });

  it.each(LOOKALIKES)('%p: retry with a different title does NOT match', (tool) => {
    approve(tool, { ...CALL, title: 'a' });
    expect(consumeApproval(tool, { ...CALL, title: 'b' }, { home, now: T0 + 2_000 })).toBeNull();
  });

  it('an approval for the bridged name does not release the call under another name', () => {
    approve('mcp__openclaw__exec', { ...CALL, title: 'a' });
    for (const tool of ['exec', 'mcp__evil__exec', 'Bash']) {
      expect(consumeApproval(tool, { ...CALL, title: 'a' }, { home, now: T0 + 2_000 })).toBeNull();
    }
  });
});

describe('#1077 — `approve --denial` grant matches the headless retry (retry-control)', () => {
  let home: string;
  let cwd: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-1077-retry-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    cwd = mkdtempSync(join(tmpdir(), 'sc-1077-job-'));
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(cwd, { recursive: true, force: true });
  });

  const denyThenGrant = (tool: string, input: unknown) => {
    const hash = hashToolCall(tool, input);
    const rec = recordDenialFingerprint({
      hash, tool, actionId: 'act-1077000000000001', signals: ['disable-action-guard'],
      redactedSurface: `${tool}: [redacted action surface] fields=command`, cwd, sessionKey: 'sc-aaaaaaaaaaaaaaaa',
    }, { home, now: T0 });
    expect(rec.ok).toBe(true);
    expect(grantRetry({ hash, cwd }, { isInteractive: true }, { home, now: T0 + 1_000 }).ok).toBe(true);
  };
  const spend = (tool: string, input: unknown, now = T0 + 2_000) =>
    consumeRetryGrant({ hash: hashToolCall(tool, input), origin: { cwd, tool } }, { home, now });

  it('mcp__openclaw__exec: the retry under a new title spends the grant, once', () => {
    denyThenGrant('mcp__openclaw__exec', { ...CALL, title: 'Read telegram config' });
    expect(spend('mcp__openclaw__exec', { ...CALL, title: 'Retry: read the Telegram section' })).not.toBeNull();
    expect(spend('mcp__openclaw__exec', { ...CALL, title: 'again' }, T0 + 3_000)).toBeNull();
  });

  it('a different command does not spend it', () => {
    denyThenGrant('mcp__openclaw__exec', { ...CALL, title: 'a' });
    expect(spend('mcp__openclaw__exec', { ...CALL, command: 'cat ~/.openclaw/openclaw.json', title: 'a' })).toBeNull();
  });

  it.each(['mcp__evil__exec', 'mcp__other__exec', 'mcp__evil__Bash'])('%s: a new title does not spend it', (tool) => {
    denyThenGrant(tool, { ...CALL, title: 'a' });
    expect(spend(tool, { ...CALL, title: 'b' })).toBeNull();
  });
});
