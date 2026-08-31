import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterceptor, DEFAULT_CONFIG, createScriptSourceResolver } from '../interceptor.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';

/**
 * Issue #4 — the fs-backed half of the script-file fix.
 *
 * The guard core stays pure and asks the caller for an invoked script's source;
 * this is the resolver the interceptor injects, plus the end-to-end proof that
 * a dangerous command inside a real `.sh` on disk is now gated exactly as the
 * same command typed inline.
 *
 * Zeroth law: the resolver must never throw, never block and never let a
 * gateway call fail because of it.
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

function makeInterceptor(overrides: Record<string, unknown> = {}) {
  const config = { ...DEFAULT_CONFIG, ...overrides, actionGuard: { enabled: true, enforce: true, autoApprove: [], ...(overrides.actionGuard || {}) } } as any;
  return createInterceptor(config, okPipeline as any, { evaluateToolCall: evaluateToolCall as any });
}

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'sc-guard-4-'));
  writeFileSync(join(dir, 'danger.sh'), '#!/bin/bash\nsudo systemctl stop ssh\n');
  writeFileSync(join(dir, 'clean.sh'), '#!/bin/bash\necho hello\nnpm test\n');
  writeFileSync(join(dir, 'binary.bin'), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00, 0x01]));
  mkdirSync(join(dir, 'sub'));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('#4 — createScriptSourceResolver', () => {
  it('reads an absolute path', () => {
    expect(createScriptSourceResolver()(join(dir, 'clean.sh'))).toContain('echo hello');
  });

  it('resolves a relative path against the supplied cwd', () => {
    expect(createScriptSourceResolver(dir)('./clean.sh')).toContain('echo hello');
    expect(createScriptSourceResolver(dir)('clean.sh')).toContain('echo hello');
  });

  it('returns null for a missing file, a directory and a device', () => {
    const r = createScriptSourceResolver(dir);
    expect(r(join(dir, 'nope.sh'))).toBeNull();
    expect(r(join(dir, 'sub'))).toBeNull();
    expect(r('/dev/zero')).toBeNull();
    expect(r('/proc/self/cmdline')).toBeNull();
  });

  it('never throws on hostile input', () => {
    const r = createScriptSourceResolver(dir);
    for (const p of ['', '\0bad', '/', '~/', 'x'.repeat(5000)]) {
      expect(() => r(p)).not.toThrow();
    }
  });

  it('refuses a FIFO rather than blocking on it (zeroth law)', () => {
    // A `read` on a FIFO with no writer blocks forever — statSync-first means
    // it is never opened. Skipped where mkfifo is unavailable.
    const fifo = join(dir, 'pipe.fifo');
    try {
      execFileSync('mkfifo', [fifo]);
    } catch {
      return;
    }
    const t = Date.now();
    expect(createScriptSourceResolver(dir)(fifo)).toBeNull();
    expect(Date.now() - t).toBeLessThan(2000);
  });
});

describe('#4 — end-to-end: a dangerous script on disk is gated like the inline command', () => {
  it('denies an unattended `bash danger.sh` exactly as the inline sudo command', async () => {
    const i = makeInterceptor();
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: 'sudo systemctl stop ssh' } }),
    ).rejects.toThrow(/blocked|deny/i);
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: `bash ${join(dir, 'danger.sh')}` } }),
    ).rejects.toThrow(/blocked|deny/i);
  });

  it('resolves a relative script against the call cwd', async () => {
    const i = makeInterceptor();
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: 'bash ./danger.sh', cwd: dir } }),
    ).rejects.toThrow(/blocked|deny/i);
  });

  it('a clean script still passes with no prompt and no friction', async () => {
    const i = makeInterceptor();
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: `bash ${join(dir, 'clean.sh')}` }, cwd: dir }),
    ).resolves.toBeUndefined();
  });

  it('an unreadable script is allowed, not denied — the gap is recorded, not enforced', async () => {
    const entries: Array<Record<string, unknown>> = [];
    const i = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as any, okPipeline as any, {
      evaluateToolCall: evaluateToolCall as any,
      onAuditEntry: (e) => entries.push(e as unknown as Record<string, unknown>),
    });
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: `bash ${join(dir, 'ghost.sh')}` } }),
    ).resolves.toBeUndefined();
    const allow = entries.find((e) => e.action === 'allow');
    expect(allow).toBeDefined();
    expect(allow!.threats).toContain('opaque-script-invocation');
  });
});
