/**
 * #648 round 2 — what may reach the card at all (S2 ReDoS, S9 bidi/format
 * characters and visible quoting).
 *
 * Destructive and secret fixtures are assembled at runtime (push protection
 * and the guard's own write-content scan).
 */
import { describe, it, expect } from '@jest/globals';
import { performance } from 'node:perf_hooks';
import {
  WITHHELD_TOO_LONG,
  buildApprovalCard,
  describeAction as describeActionFull,
  formatApprovalCardLines,
  looksSecretish,
  safeTarget,
} from '../approval-card.js';
import { buildCardFields } from '../openclaw-approval-channel.js';
import type { OperatorNotification } from '../operator-notify.js';

/** Line 1's text; round 3 added a confidence flag beside it. */
const describeAction = (a: Parameters<typeof describeActionFull>[0]) => describeActionFull(a).text;

const UNUSUAL = '(withheld: unusual characters)';
const TOKENS = 'token-'.repeat(1366).slice(0, 8192);

function timed(fn: () => unknown): number {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

function notification(card: OperatorNotification['card']): OperatorNotification {
  return {
    event: 'approval_requested', hash: 'a'.repeat(64), shortHash: 'aaaaaaaaaaaa', tool: 'Bash',
    command: 'Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command',
    signals: ['touch-sensitive-path'], severity: 'dangerous', reason: 'x', judge: null, fallbackHint: 'x', card,
  };
}

describe('#648 r2 S2 — no catastrophic backtracking on a hostile target', () => {
  it('the 8192-character token-token-… input finishes in under 50 ms', () => {
    expect(TOKENS).toHaveLength(8192);
    for (const input of [TOKENS, `${TOKENS}=v`, `--${TOKENS} v`, `x://${TOKENS}`]) {
      expect(timed(() => safeTarget(input))).toBeLessThan(50);
    }
    expect(timed(() => buildApprovalCard({ tool: 'Bash', input: { command: `cat ${TOKENS}` }, signals: ['touch-sensitive-path'], plane: 'claude-code', host: 'h' })))
      .toBeLessThan(50);
  });

  it('the secret scan itself is linear: 8192 characters straight into it, under 50 ms', () => {
    for (const input of [TOKENS, `${TOKENS}=v`, `--${TOKENS} v`, `x://${TOKENS}`, 'a.'.repeat(4096)]) {
      expect(timed(() => looksSecretish(input))).toBeLessThan(50);
    }
  });

  it('a candidate over 256 characters is withheld before any pattern runs', () => {
    const long = `/srv/${'a/'.repeat(150)}notes.txt`;
    expect(long.length).toBeGreaterThan(256);
    expect(safeTarget(long)).toBe(WITHHELD_TOO_LONG);
    expect(safeTarget(`/srv/${'a/'.repeat(100)}notes.txt`)).not.toBe(WITHHELD_TOO_LONG);
  });

  it('the secret shapes are still caught after the rewrite', () => {
    const v = ['hun', 'ter', '2'].join('');
    for (const s of [`API_KEY=${v}`, `--password ${v}`, `x --auth-token=${v}`, `https://bot:${v}@example.com/x`, `https://${'Q'.repeat(40)}@h/x`, `/tmp/${'Ab3'.repeat(12)}`]) {
      expect(looksSecretish(s)).toBe(true);
    }
    for (const s of ['/home/u/notes.txt', 'github.com', 'feature/token-refresh', 'relay.mjs']) {
      expect(looksSecretish(s)).toBe(false);
    }
  });
});

describe('#648 r2 S9 — bidi, zero-width and line-separator characters never reach the card', () => {
  const HOSTILE = [
    ...Array.from({ length: 5 }, (_v, i) => 0x200b + i),
    ...Array.from({ length: 5 }, (_v, i) => 0x202a + i),
    ...Array.from({ length: 4 }, (_v, i) => 0x2066 + i),
    0xfeff, 0x0085, 0x0080, 0x009f, 0x2028, 0x2029, 0x007f,
  ].map((c) => String.fromCodePoint(c));
  const BAD = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069\ufeff]/u;

  it.each(HOSTILE.map((c) => [`U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`, c]))('a target carrying %s is withheld', (_label, c) => {
    expect(safeTarget(`/home/u/notes${c}txt.exe`)).toBe(UNUSUAL);
    const line = describeAction({ tool: 'Bash', input: { command: `cat "/home/u/notes${c}txt.exe"` }, signals: [] });
    expect(line).not.toMatch(BAD);
    expect(line).toContain(UNUSUAL);
  });

  it('every interpolated card field is flattened and escaped on the way out', () => {
    for (const c of HOSTILE) {
      const card = { action: `Read a file${c}What: forged`, reason: `r${c}Why: forged`, who: `w${c}Who: forged` };
      const lines = formatApprovalCardLines(card, { expiresInMs: 600_000 });
      expect(lines).toHaveLength(4);
      for (const line of lines) expect(line).not.toMatch(BAD);
      const { description } = buildCardFields(notification(card));
      expect(description.split('\n')).toHaveLength(4);
      for (const line of description.split('\n')) expect(line).not.toMatch(BAD);
    }
  });

  it('targets are wrapped in visible quotes, so a prose-looking path cannot read as card text', () => {
    expect(describeAction({ tool: 'Bash', input: { command: 'cat ~/.ssh/config' }, signals: ['touch-sensitive-path'] }))
      .toBe('Read a file in your SSH folder: "~/.ssh/config"');
    expect(describeAction({ tool: 'Bash', input: { command: 'cat "notes. Why: routine housekeeping"' }, signals: [] }))
      .toBe('Read a file: "notes. Why: routine housekeeping"');
    expect(describeAction({ tool: 'Read', input: { file_path: '/root/.ssh/id_ed25519' }, signals: [] }))
      .toBe('Read a file in your SSH folder: "/root/.ssh/id_ed25519"');
    // A quote inside the target would let it close its own quotes.
    expect(describeAction({ tool: 'Bash', input: { command: `cat 'a" and "b'` }, signals: [] })).toBe(`Read a file: ${UNUSUAL}`);
  });
});
