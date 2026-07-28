/**
 * #118 — one-shot exact-command approvals.
 *
 * Acceptance from the issue: blocked → approve → the SAME command passes once
 * → a second run is refused again. Plus the fixtures that keep it honest:
 * expiry, wrong hash, replay, and self-approval by a non-interactive caller.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync, readFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  hashToolCall,
  recordPending,
  approveRequest,
  consumeApproval,
  listApprovals,
  shortHash,
  DEFAULT_APPROVAL_TTL_MS,
} from '../action-approvals.js';
import { runApprove, isInteractive } from '../../../cli/approve.js';

const SUDO = { command: 'sudo modprobe softdog' };
const OTHER = { command: 'sudo rmmod softdog' };

describe('action approvals (#118)', () => {
  let home: string;
  const T0 = 1_800_000_000_000; // fixed clock — Date.now() is never used in tests

  const request = (input: unknown = SUDO, now = T0) =>
    recordPending(
      { tool: 'Bash', input, summary: `Bash: ${(input as { command: string }).command}`, signals: ['privilege-escalation'] },
      { home, now },
    );

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-approvals-'));
  });

  afterEach(() => {
    try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  describe('hashing', () => {
    it('is stable across calls and insensitive to whitespace noise', () => {
      expect(hashToolCall('Bash', { command: 'sudo  modprobe   softdog' }))
        .toBe(hashToolCall('Bash', { command: 'sudo modprobe softdog' }));
    });

    it('is key-order independent but content sensitive', () => {
      expect(hashToolCall('Bash', { a: '1', b: '2' })).toBe(hashToolCall('Bash', { b: '2', a: '1' }));
      expect(hashToolCall('Bash', SUDO)).not.toBe(hashToolCall('Bash', OTHER));
      expect(hashToolCall('Bash', SUDO)).not.toBe(hashToolCall('Write', SUDO));
    });
  });

  describe('the acceptance path', () => {
    it('refused → approved → passes ONCE → refused again', () => {
      const pending = request();
      // Nothing is approved yet, so the guard gets nothing to spend.
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();

      const outcome = approveRequest(shortHash(pending.hash), { home, now: T0 + 1000 });
      expect(outcome.ok).toBe(true);

      const spent = consumeApproval('Bash', SUDO, { home, now: T0 + 2000 });
      expect(spent).not.toBeNull();
      expect(spent!.hash).toBe(pending.hash);
      expect(spent!.consumedAt).toBe(T0 + 2000);

      // Single use: the very next identical call finds nothing.
      expect(consumeApproval('Bash', SUDO, { home, now: T0 + 2001 })).toBeNull();
    });

    it('approves by full hash as well as short prefix', () => {
      const pending = request();
      expect(approveRequest(pending.hash, { home, now: T0 }).ok).toBe(true);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).not.toBeNull();
    });
  });

  describe('an approval is bound to the exact call', () => {
    it('does not carry over to a different command', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      expect(consumeApproval('Bash', OTHER, { home, now: T0 })).toBeNull();
      // ...and the original approval is still intact, not collaterally spent.
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).not.toBeNull();
    });

    it('does not carry over to the same command on a different tool', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      expect(consumeApproval('Execute', SUDO, { home, now: T0 })).toBeNull();
    });
  });

  describe('expiry', () => {
    it('refuses an approval past its TTL', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      expect(consumeApproval('Bash', SUDO, { home, now: T0 + DEFAULT_APPROVAL_TTL_MS + 1 })).toBeNull();
    });

    it('honours a shorter operator-set TTL', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0, ttlMs: 60_000 });
      expect(consumeApproval('Bash', SUDO, { home, now: T0 + 59_000 })).not.toBeNull();

      const second = request(SUDO, T0 + 100_000);
      approveRequest(second.hash, { home, now: T0 + 100_000, ttlMs: 60_000 });
      expect(consumeApproval('Bash', SUDO, { home, now: T0 + 161_000 })).toBeNull();
    });

    it('does not let a repeated refusal extend a live approval', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      // The agent retries near the end of the window; the guard re-records.
      request(SUDO, T0 + DEFAULT_APPROVAL_TTL_MS - 1000);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 + DEFAULT_APPROVAL_TTL_MS + 1 })).toBeNull();
    });
  });

  describe('bad input', () => {
    it('reports not-found for an unknown hash', () => {
      request();
      expect(approveRequest('deadbeef', { home, now: T0 })).toEqual({ ok: false, reason: 'not-found' });
    });

    it('refuses to double-approve a live grant', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      expect(approveRequest(pending.hash, { home, now: T0 })).toEqual({ ok: false, reason: 'already-approved' });
    });

    it('refuses an ambiguous prefix rather than guessing', () => {
      request(SUDO);
      request(OTHER);
      // The empty prefix matches both records — must not approve either.
      expect(approveRequest('', { home, now: T0 })).toEqual({ ok: false, reason: 'not-found' });
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
      expect(consumeApproval('Bash', OTHER, { home, now: T0 })).toBeNull();
    });

    it('treats a corrupt store as empty, not as approval', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      const file = join(home, '.shieldcortex', 'approvals', 'approvals.json');
      rmSync(file);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
    });
  });

  describe('storage hygiene', () => {
    it('writes the store 0600 — it names commands the operator ran', () => {
      request();
      const file = join(home, '.shieldcortex', 'approvals', 'approvals.json');
      expect(existsSync(file)).toBe(true);
      expect(statSync(file).mode & 0o777).toBe(0o600);
    });

    it('does not accumulate duplicate records for a retried command', () => {
      request();
      request(SUDO, T0 + 5_000);
      request(SUDO, T0 + 10_000);
      expect(listApprovals({ home, now: T0 + 10_000 })).toHaveLength(1);
    });

    it('drops the consumed record from the file', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      consumeApproval('Bash', SUDO, { home, now: T0 });
      const file = join(home, '.shieldcortex', 'approvals', 'approvals.json');
      expect(JSON.parse(readFileSync(file, 'utf-8')).records).toEqual([]);
    });
  });

  describe('CLI gate — an agent cannot approve its own command', () => {
    const sink = () => {
      const lines: string[] = [];
      return { lines, write: (m: string) => { lines.push(m); } };
    };

    it('refuses to grant when stdio is not a TTY', () => {
      const pending = request();
      const out = sink();
      const code = runApprove([pending.hash], { home, now: T0, interactive: false, log: out.write, error: out.write });

      expect(code).toBe(1);
      expect(out.lines.join('\n')).toMatch(/interactive terminal/i);
      // Crucially, nothing was granted.
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
    });

    it('grants when a human is at the keyboard', () => {
      const pending = request();
      const out = sink();
      const code = runApprove([pending.hash], { home, now: T0, interactive: true, log: out.write, error: out.write });

      expect(code).toBe(0);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).not.toBeNull();
    });

    it('lists outstanding refusals without needing a TTY', () => {
      request();
      const out = sink();
      const code = runApprove([], { home, now: T0, interactive: false, log: out.write, error: out.write });

      expect(code).toBe(0);
      expect(out.lines.join('\n')).toContain('sudo modprobe softdog');
    });

    it('rejects a nonsense --ttl instead of silently defaulting', () => {
      const pending = request();
      const out = sink();
      const code = runApprove([pending.hash, '--ttl', 'soon'], { home, now: T0, interactive: true, log: out.write, error: out.write });

      expect(code).toBe(1);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
    });

    it('isInteractive requires BOTH stdin and stdout to be TTYs', () => {
      expect(isInteractive({ stdin: { isTTY: true }, stdout: { isTTY: true } })).toBe(true);
      expect(isInteractive({ stdin: { isTTY: true }, stdout: { isTTY: false } })).toBe(false);
      expect(isInteractive({ stdin: { isTTY: false }, stdout: { isTTY: true } })).toBe(false);
      expect(isInteractive({})).toBe(false);
    });
  });
});
