import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

import {
  EXPIRY_DIGEST_FOOTER,
  EXPIRY_DIGEST_MAX_CHARS,
  buildApprovalExpiryDigest,
  isApprovalTimeoutEntry,
  projectHostVersion,
} from '../expiry-digest.js';
import {
  APPROVAL_EXPIRY_DIGEST_REASON,
  buildActionGuardOutcomeNotification,
  formatActionGuardOutcomeNotification,
  projectActionGuardFields,
} from '../operator-notify.js';
import {
  EXPIRY_DIGEST_MAX_INDEX_BYTES,
  EXPIRY_DIGEST_MAX_LINE_BYTES,
  appendExpiryDigestRecord,
  readSessionGuardIndexBounded,
  recordActionGuardDegraded,
  type BoundedIndexRead,
} from '../session-guard.js';

/**
 * #673 — the reporting-only expiry digest: bounded evidence, recorded and
 * explicitly partial counts, closed-set privacy, a host-neutral complete
 * message, and content-free receipts every existing consumer ignores.
 */

const SALT = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const KEY = 'sc-0123456789abcdef';
const OTHER = 'sc-fedcba9876543210';
const NEUTRAL_RE = /Approval timed out\/unresolved; ShieldCortex granted nothing\. Whether this OpenClaw version \((?:\d{4}\.\d{1,2}\.\d{1,2}|unknown)\) blocked the call has not been verified by ShieldCortex\./g;
const AFFIRMATIVE = ['OpenClaw blocked this tool call', '(skipped)', 'was blocked', 'were blocked', 'was skipped', 'were skipped'];

function timeout(i: number, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    recordKind: 'guard',
    type: 'intercept',
    origin: 'openclaw-interceptor',
    action: 'require_approval',
    outcome: 'card_timeout',
    sessionKey: KEY,
    tool: 'Bash',
    severity: 'dangerous',
    threats: ['dangerous-shell'],
    heldAtTs: `2026-10-11T12:${String(i % 60).padStart(2, '0')}:00.000Z`,
    ts: `2026-10-11T12:${String(i % 60).padStart(2, '0')}:30.000Z`,
    nonce: i.toString(16).padStart(32, '0'),
    ...over,
  };
}

function whole(rows: Array<Record<string, unknown>>): BoundedIndexRead {
  return { rows, truncated: false, corrupt: 0, oversized: 0, unsafe: false };
}

/** (a) no affirmative phrase; (b) after removing the neutral clause and the
 *  fixed `why:` phrases, nothing matches /block/ or /skip/. */
function expectNoBlockedClaim(text: string, structured: string[] = []): void {
  for (const s of [text, ...structured]) {
    for (const phrase of AFFIRMATIVE) expect(s).not.toContain(phrase);
  }
  const stripped = text.replace(NEUTRAL_RE, '').replace(/— why: [^\n]*?\. (?=\n|$)/g, '— ');
  for (const s of [stripped, ...structured]) {
    expect(s).not.toMatch(/block/i);
    expect(s).not.toMatch(/skip/i);
  }
}

describe('#673 buildApprovalExpiryDigest — counts, budget and footer', () => {
  it('N=7 complete: 7 recorded, 7 entry lines, exact host-neutral footer', () => {
    const d = buildApprovalExpiryDigest(whole(Array.from({ length: 7 }, (_, i) => timeout(i))), { sessionKey: KEY });
    expect(d).toMatchObject({ observed: 7, rendered: 7, complete: true, alreadyDigested: false });
    expect(d.text.startsWith(`ShieldCortex — 7 recorded approval timeouts in OpenClaw session ${KEY} (report only)`)).toBe(true);
    expect(d.text.split('\n').filter((l) => l.startsWith('• '))).toHaveLength(7);
    expect(d.text.endsWith(EXPIRY_DIGEST_FOOTER)).toBe(true);
    expect(d.text).not.toContain('more recorded in this scan');
  });

  it('N=25 (pinned and unknown host): 10 lines, +15 more, ≤4000 chars, footer whole', () => {
    const cases: Array<{ hostVersion?: string; blockingHosts: ReadonlySet<string> }> = [
      { hostVersion: '2026.9.6', blockingHosts: new Set(['2026.9.6']) },
      { blockingHosts: new Set<string>() },
    ];
    for (const { hostVersion, blockingHosts } of cases) {
      const d = buildApprovalExpiryDigest(whole(Array.from({ length: 25 }, (_, i) => timeout(i))), {
        sessionKey: KEY, hostVersion, blockingHosts,
      });
      expect(d.observed).toBe(25);
      expect(d.rendered).toBe(10);
      expect(d.text).toContain('+15 more recorded in this scan');
      expect(d.text.length).toBeLessThanOrEqual(EXPIRY_DIGEST_MAX_CHARS);
      expect(d.text.endsWith(EXPIRY_DIGEST_FOOTER)).toBe(true);
    }
  });

  it('long entry lines are dropped whole into +K more; the footer is never cut', () => {
    // Every closed-set signal phrase on every row makes each line long.
    const many = ['secret-egress', 'data-exfiltration', 'credential-access', 'network-egress', 'dangerous-shell',
      'privilege-escalation', 'filesystem-destructive', 'persistence-risk', 'shell-injection', 'untrusted-script',
      'install-package', 'git-force-push', 'service-restart', 'recursive-force-delete', 'delete-root-or-home',
      'fork-bomb', 'format-filesystem', 'raw-disk-write', 'pipe-download-to-shell', 'modify-scheduler'];
    const d = buildApprovalExpiryDigest(whole(Array.from({ length: 25 }, (_, i) => timeout(i, { threats: many }))), { sessionKey: KEY });
    expect(d.text.length).toBeLessThanOrEqual(EXPIRY_DIGEST_MAX_CHARS);
    expect(d.text.endsWith(EXPIRY_DIGEST_FOOTER)).toBe(true);
    expect(d.text).toContain(`+${25 - d.rendered} more recorded in this scan`);
    for (const line of d.text.split('\n').filter((l) => l.startsWith('• '))) expect(line.endsWith('ShieldCortex.')).toBe(true);
  });

  it('a partial read (truncated, corrupt or oversized) says "at least N" and complete:false', () => {
    const cases = [
      { truncated: true, corrupt: 0, oversized: 0 },
      { truncated: false, corrupt: 1, oversized: 0 },
      { truncated: false, corrupt: 0, oversized: 1 },
    ];
    for (const bounds of cases) {
      const d = buildApprovalExpiryDigest({ rows: [timeout(1), timeout(2)], ...bounds }, { sessionKey: KEY });
      expect(d.complete).toBe(false);
      expect(d.text).toContain('at least 2 recorded approval timeouts');
      expect(d.text).toContain('the true total is unknown');
    }
  });

  it('a duplicate nonce counts once; nonce-less lines count per line; same-time distinct nonces count twice', () => {
    const same = timeout(1);
    const noNonceA = timeout(2, { nonce: undefined });
    const noNonceB = timeout(2, { nonce: undefined });
    const sameMsA = timeout(3, { nonce: 'a'.repeat(32) });
    const sameMsB = timeout(3, { nonce: 'b'.repeat(32) });
    const d = buildApprovalExpiryDigest(whole([same, { ...same }, noNonceA, noNonceB, sameMsA, sameMsB]), { sessionKey: KEY });
    expect(d.observed).toBe(5);
  });

  it('foreign session, hook origin and non-timeout outcomes are never entries', () => {
    const rows = [
      timeout(1, { sessionKey: OTHER }),
      timeout(2, { origin: 'claude-code-hook' }),
      timeout(3, { outcome: 'card_denied' }),
      timeout(4, { outcome: 'approved_once' }),
      timeout(5, { outcome: 'card_cancelled' }),
      timeout(6, { action: 'block' }),
    ];
    for (const r of rows) expect(isApprovalTimeoutEntry(r, KEY)).toBe(false);
    expect(buildApprovalExpiryDigest(whole(rows), { sessionKey: KEY })).toMatchObject({ observed: 0, text: '' });
  });

  it('a #260 summary is not a digest receipt; any digest row is', () => {
    const summary = { recordKind: 'summary', type: 'session_summary', origin: 'openclaw-session-end', sessionKey: KEY, outcome: 'action_guard_degraded' };
    expect(buildApprovalExpiryDigest(whole([summary, timeout(1)]), { sessionKey: KEY }).alreadyDigested).toBe(false);
    for (const phase of ['local_only', 'attempt', 'receipt']) {
      const digest = { recordKind: 'digest', type: 'expiry_digest', sessionKey: KEY, phase };
      expect(buildApprovalExpiryDigest(whole([timeout(1), digest]), { sessionKey: KEY }).alreadyDigested).toBe(true);
    }
  });
});

describe('#673 privacy — membership projection, never content', () => {
  it('secret markers in content fields and hostile metadata never reach the text', () => {
    const SECRET = 'SECRET_MARKER_673';
    const row = timeout(1, {
      preview: `curl -H 'Authorization: ${SECRET}'`,
      args: { command: SECRET },
      matches: [{ text: SECRET }],
      reason: SECRET,
      broker: { note: SECRET },
      actionKey: `ak-${SECRET}`,
      tool: `tool_${SECRET.toLowerCase()}`,
      threats: ['dangerous-shell', `sig-${SECRET.toLowerCase()}`],
      severity: `<${SECRET}>`,
      heldAtTs: `not-a-time ${SECRET}`,
      ts: '2026-13-45T99:99:99Z',
    });
    const d = buildApprovalExpiryDigest(whole([row]), { sessionKey: KEY, hostVersion: `2026.9.6; ${SECRET}` });
    expect(d.text).not.toContain(SECRET);
    expect(d.text).not.toContain(SECRET.toLowerCase());
    expect(d.text).toContain('• tool (medium) — why: ');
    expect(d.text).toContain('matched another safety rule');
    expect(d.text).toContain('OpenClaw version (unknown)');
    expect(d.text).not.toContain(String(row.nonce));
  });

  it('a shape-valid unknown signal id renders as the fixed phrase, not the id', () => {
    const d = buildApprovalExpiryDigest(whole([timeout(1, { threats: ['attacker-chosen-id'] })]), { sessionKey: KEY });
    expect(d.text).not.toContain('attacker-chosen-id');
    expect(d.text).toContain('why: matched another safety rule.');
  });

  it('projectActionGuardFields makes the same decisions as the outcome builder', () => {
    const input = { tool: 'evil_tool', signals: ['dangerous-shell', 'nope-x', 'dangerous-shell'], severity: 'catastrophic' };
    const n = buildActionGuardOutcomeNotification({
      event: 'action_guard_warning', outcome: 'warned', surface: 'x', reason: '', detectedAt: '2026-10-11T00:00:00.000Z', ...input,
    });
    expect(projectActionGuardFields({ ...input, event: 'action_guard_warning' })).toEqual({
      tool: n.tool, signals: n.signals, severity: n.severity,
    });
  });
});

describe('#673 host version — the complete message is honest on unknown hosts', () => {
  const rows = whole(Array.from({ length: 25 }, (_, i) => timeout(i)));

  it('uninspected, unknown and hostile versions: no blocked or skipped claim anywhere', () => {
    for (const hostVersion of ['2026.5.2', undefined, '2026.9.6</b>; rm -rf /']) {
      const d = buildApprovalExpiryDigest(rows, { sessionKey: KEY, hostVersion, blockingHosts: new Set(['2026.9.6']) });
      expect(d.text.endsWith(EXPIRY_DIGEST_FOOTER)).toBe(true);
      expectNoBlockedClaim(d.text, [APPROVAL_EXPIRY_DIGEST_REASON]);
    }
  });

  it('pinned version: the blocked clause appears only in entry lines', () => {
    const d = buildApprovalExpiryDigest(rows, { sessionKey: KEY, hostVersion: '2026.9.6', blockingHosts: new Set(['2026.9.6']) });
    const lines = d.text.split('\n');
    const entries = lines.filter((l) => l.startsWith('• '));
    expect(entries.every((l) => l.endsWith('OpenClaw blocked this tool call (skipped).'))).toBe(true);
    const rest = lines.filter((l) => !l.startsWith('• ')).join('\n');
    for (const phrase of AFFIRMATIVE) expect(rest).not.toContain(phrase);
    expect(rest).not.toMatch(/block|skip/i);
  });

  it('projects the version string to its released shape', () => {
    expect(projectHostVersion('2026.10.1')).toBe('2026.10.1');
    expect(projectHostVersion(' 2026.10.1 ')).toBe('2026.10.1');
    expect(projectHostVersion('2026.10.1-beta')).toBe('unknown');
    expect(projectHostVersion(42)).toBe('unknown');
  });
});

describe('#673 operator-notify — owned outcome and reason', () => {
  it('approval_expiry_digest survives and carries its own report-only reason', () => {
    const n = buildActionGuardOutcomeNotification({
      event: 'action_guard_warning', outcome: 'approval_expiry_digest', tool: 'tool', surface: 'redacted action surface',
      signals: [], severity: 'medium', reason: '', sessionId: KEY, detectedAt: '2026-10-11T00:00:00.000Z',
    });
    expect(n.outcome).toBe('approval_expiry_digest');
    expect(n.reason).toBe(APPROVAL_EXPIRY_DIGEST_REASON);
    expect(n.reason).not.toMatch(/advisory/i);
    const text = formatActionGuardOutcomeNotification({ ...n, digestText: 'DIGEST BODY' } as typeof n);
    expect(text).toBe('DIGEST BODY');
  });
});

describe('#673 bounded index reader and receipts', () => {
  const originalAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;
  let auditDir = '';
  const indexFile = (key = KEY) => join(auditDir, 'session-guard', `${key}.jsonl`);

  beforeEach(() => {
    auditDir = mkdtempSync(join(tmpdir(), 'sc-673-idx-'));
    process.env.SHIELDCORTEX_AUDIT_DIR = auditDir;
    mkdirSync(join(auditDir, 'session-guard'), { recursive: true });
  });

  afterEach(() => {
    if (originalAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
    else process.env.SHIELDCORTEX_AUDIT_DIR = originalAuditDir;
    rmSync(auditDir, { recursive: true, force: true });
  });

  it('rejects a key outside the sc- shape and a missing file reads empty', () => {
    expect(readSessionGuardIndexBounded('../etc/passwd').rows).toEqual([]);
    expect(readSessionGuardIndexBounded(KEY)).toMatchObject({ rows: [], truncated: false, unsafe: false });
  });

  it('reads only the tail of a file over 1 MiB and marks it truncated', () => {
    const pad = JSON.stringify({ recordKind: 'guard', origin: 'openclaw-interceptor', outcome: 'denied', sessionKey: KEY, pad: 'x'.repeat(1000) });
    const lines = Math.ceil((EXPIRY_DIGEST_MAX_INDEX_BYTES * 1.5) / pad.length);
    writeFileSync(indexFile(), `${Array.from({ length: lines }, () => pad).join('\n')}\n${JSON.stringify(timeout(1))}\n`);
    const read = readSessionGuardIndexBounded(KEY);
    expect(read.truncated).toBe(true);
    expect(read.corrupt).toBe(0);
    expect(read.rows.length).toBeLessThan(lines);
    expect(read.rows[read.rows.length - 1]).toMatchObject({ outcome: 'card_timeout' });
    expect(buildApprovalExpiryDigest(read, { sessionKey: KEY }).text).toContain('at least 1 recorded approval timeout');
  });

  it('skips oversized lines and counts corrupt ones', () => {
    const big = JSON.stringify({ ...timeout(9), pad: 'y'.repeat(EXPIRY_DIGEST_MAX_LINE_BYTES) });
    writeFileSync(indexFile(), `${big}\n{not json\n[1,2]\n${JSON.stringify(timeout(1))}\n`);
    const read = readSessionGuardIndexBounded(KEY);
    expect(read).toMatchObject({ oversized: 1, corrupt: 2, truncated: false });
    expect(read.rows).toHaveLength(1);
  });

  it('does not follow a symlink or read a directory at the index path', () => {
    const outside = join(auditDir, 'outside.jsonl');
    writeFileSync(outside, `${JSON.stringify(timeout(1))}\n`);
    symlinkSync(outside, indexFile());
    expect(readSessionGuardIndexBounded(KEY)).toMatchObject({ rows: [], unsafe: true });
    mkdirSync(indexFile(OTHER));
    expect(readSessionGuardIndexBounded(OTHER)).toMatchObject({ rows: [], unsafe: true });
  });

  it('appendExpiryDigestRecord writes only the closed field set, to the index and the realtime mirror', () => {
    const digestId = 'c'.repeat(32);
    // Extra fields a caller might try to smuggle are not copied.
    const smuggled = {
      digestId, phase: 'receipt' as const, observed: 3, rendered: 3, complete: true, transport: 'webhook' as const,
      status: 'delivered' as const, text: 'SECRET', url: 'https://x', error: 'boom',
    };
    expect(appendExpiryDigestRecord(KEY, smuggled)).toBe(true);
    const row = JSON.parse(readFileSync(indexFile(), 'utf8').trim());
    expect(Object.keys(row).sort()).toEqual(
      ['complete', 'digestId', 'observed', 'origin', 'phase', 'recordKind', 'rendered', 'sessionKey', 'status', 'transport', 'ts', 'type'].sort(),
    );
    expect(row).toMatchObject({ recordKind: 'digest', type: 'expiry_digest', origin: 'openclaw-session-end', status: 'delivered' });
    const mirror = readdirSync(auditDir).filter((f) => /^realtime-.*\.jsonl$/.test(f));
    expect(mirror).toHaveLength(1);
    expect(appendExpiryDigestRecord(KEY, { digestId: 'nothex', phase: 'attempt', observed: 1, rendered: 1, complete: true, transport: null })).toBe(false);
    expect(appendExpiryDigestRecord('sc-bad', { digestId, phase: 'attempt', observed: 1, rendered: 1, complete: true, transport: null })).toBe(false);
  });

  const receipt = {
    digestId: 'c'.repeat(32), phase: 'local_only' as const,
    observed: 1, rendered: 1, complete: true, transport: null,
  };
  const summary = {
    recordKind: 'summary', type: 'session_summary', origin: 'openclaw-session-end',
    sessionKey: KEY, outcome: 'action_guard_degraded',
  };
  const mirrorFile = () => join(auditDir, `realtime-${new Date().toISOString().slice(0, 10)}.jsonl`);
  const writerModule = new URL('../../../../dist/defence/iron-dome/session-guard.js', import.meta.url).href;

  it('B1 refuses a symlink index without touching its target or creating a mirror', () => {
    const outside = join(auditDir, 'outside.jsonl');
    const before = `${JSON.stringify(timeout(1))}\n`;
    writeFileSync(outside, before);
    symlinkSync(outside, indexFile());
    expect(appendExpiryDigestRecord(KEY, receipt)).toBe(false);
    expect(readFileSync(outside, 'utf8')).toBe(before);
    expect(existsSync(mirrorFile())).toBe(false);
  });

  it('B1 skips a symlink mirror without touching its target; the index remains usable', () => {
    const outside = join(auditDir, 'outside.jsonl');
    writeFileSync(outside, 'unchanged\n');
    symlinkSync(outside, mirrorFile());
    expect(appendExpiryDigestRecord(KEY, receipt)).toBe(true);
    expect(readFileSync(outside, 'utf8')).toBe('unchanged\n');
    expect(readSessionGuardIndexBounded(KEY).rows).toEqual([expect.objectContaining({ phase: 'local_only' })]);
  });

  it('B1 a FIFO mirror never blocks the writer (bounded child process)', () => {
    writeFileSync(indexFile(), `${JSON.stringify(timeout(1))}\n${JSON.stringify(summary)}\n`);
    const fifo = spawnSync('mkfifo', [mirrorFile()], { encoding: 'utf8', timeout: 3_000 });
    expect(fifo.error).toBeUndefined();
    expect(fifo.status).toBe(0);
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      const { appendExpiryDigestRecord } = await import(${JSON.stringify(writerModule)});
      process.stdout.write(JSON.stringify(appendExpiryDigestRecord(${JSON.stringify(KEY)}, ${JSON.stringify(receipt)})));
    `], { encoding: 'utf8', timeout: 3_000, env: { ...process.env, SHIELDCORTEX_AUDIT_DIR: auditDir } });
    expect(child.error).toBeUndefined();
    expect(child.status).toBe(0);
    expect(child.stdout).toBe('true');
    expect(readSessionGuardIndexBounded(KEY).rows).toContainEqual(expect.objectContaining({ phase: 'local_only' }));
  });

  it('B1 regular-file controls append to both sinks without overwriting existing bytes', () => {
    const before = `${JSON.stringify(summary)}\n`;
    writeFileSync(indexFile(), before);
    writeFileSync(mirrorFile(), before);
    expect(appendExpiryDigestRecord(KEY, receipt)).toBe(true);
    for (const file of [indexFile(), mirrorFile()]) {
      const text = readFileSync(file, 'utf8');
      expect(text.startsWith(before)).toBe(true);
      expect(text.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))).toEqual([
        summary, expect.objectContaining({ recordKind: 'digest', phase: 'local_only' }),
      ]);
    }
  });

  it.each([['torn fragment', '{'], ['valid object', JSON.stringify({ note: 'last row' })]])(
    'B2 establishes a readable marker after an unterminated %s and an existing summary', (_label, tail) => {
      writeFileSync(indexFile(), `${JSON.stringify(timeout(1))}\n${JSON.stringify(summary)}\n${tail}`);
      expect(appendExpiryDigestRecord(KEY, receipt)).toBe(true);
      const read = readSessionGuardIndexBounded(KEY);
      expect(read.rows).toContainEqual(summary);
      expect(read.rows).toContainEqual(expect.objectContaining({ recordKind: 'digest', phase: 'local_only' }));
      expect(read.corrupt).toBe(tail === '{' ? 1 : 0);
      if (tail !== '{') expect(read.rows).toContainEqual({ note: 'last row' });
      expect(buildApprovalExpiryDigest(read, { sessionKey: KEY }).alreadyDigested).toBe(true);
    },
  );

  it.each([['early EOF', true], ['short reads fill the window', false]])(
    'B3 %s preserves the parsed prefix and reports completeness honestly', (_label, earlyEof) => {
      const prefix = `${JSON.stringify(timeout(1))}\n`;
      writeFileSync(indexFile(), `${prefix}${JSON.stringify(timeout(2))}\n`);
      // Patch the real fs seam in an isolated process, not the reader result.
      // fstat sees the entire file; readSync supplies a prefix then EOF, or
      // successive short reads that eventually fill that exact window.
      const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
        import fs from 'node:fs';
        import { syncBuiltinESMExports } from 'node:module';
        const { readSessionGuardIndexBounded } = await import(${JSON.stringify(writerModule)});
        const realRead = fs.readSync;
        let calls = 0;
        fs.readSync = (fd, buffer, offset, length, position) => {
          calls++;
          if (${earlyEof} && calls > 1) return 0;
          return realRead(fd, buffer, offset, Math.min(length, ${Buffer.byteLength(prefix)}), position);
        };
        syncBuiltinESMExports();
        const read = readSessionGuardIndexBounded(${JSON.stringify(KEY)});
        process.stdout.write(JSON.stringify({ read, calls }));
      `], { encoding: 'utf8', timeout: 3_000, env: { ...process.env, SHIELDCORTEX_AUDIT_DIR: auditDir } });
      expect(child.error).toBeUndefined();
      expect(child.status).toBe(0);
      const { read, calls } = JSON.parse(child.stdout) as { read: BoundedIndexRead; calls: number };
      expect(calls).toBeGreaterThan(1);
      expect(read).toMatchObject({ truncated: earlyEof, corrupt: 0, oversized: 0, unsafe: false });
      expect(read.rows).toEqual(earlyEof ? [timeout(1)] : [timeout(1), timeout(2)]);
      const digest = buildApprovalExpiryDigest(read, { sessionKey: KEY });
      expect(digest.complete).toBe(!earlyEof);
      expect(digest.text).toContain(earlyEof ? 'at least 1 recorded approval timeout' : '2 recorded approval timeouts');
      if (!earlyEof) expect(digest.text).not.toContain('at least');
      expect(appendExpiryDigestRecord(KEY, { ...receipt, complete: digest.complete })).toBe(true);
      expect(readSessionGuardIndexBounded(KEY).rows).toContainEqual(expect.objectContaining({
        recordKind: 'digest', complete: !earlyEof,
      }));
    },
  );

  it('recordActionGuardDegraded ignores digest rows: they are neither a summary nor a guard', () => {
    const sessionId = 'agent:main:digest-ignored';
    const key = `sc-${createHmac('sha256', SALT).update(`action-guard-session:${sessionId}`).digest('hex').slice(0, 16)}`;
    for (const phase of ['local_only', 'attempt', 'receipt'] as const) {
      appendExpiryDigestRecord(key, { digestId: 'd'.repeat(32), phase, observed: 1, rendered: 1, complete: true, transport: phase === 'local_only' ? null : 'webhook', status: 'failed' });
    }
    // Digest rows alone: nothing to summarise.
    expect(recordActionGuardDegraded(sessionId, { salt: SALT })).toMatchObject({ recorded: false, count: 0 });
    // One real timeout: the summary counts it once and is not "existing".
    appendFileSync(indexFile(key), `${JSON.stringify(timeout(1, { sessionKey: key }))}\n`);
    expect(recordActionGuardDegraded(sessionId, { salt: SALT })).toMatchObject({ recorded: true, count: 1 });
    expect(recordActionGuardDegraded(sessionId, { salt: SALT })).toMatchObject({ existing: true });
  });
});

describe('#673 stop-hook ignores digest rows (causal)', () => {
  const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
  const STOP_HOOK = join(REPO, 'scripts', 'stop-hook.mjs');
  let home = '';

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-673-stop-'));
    const dir = join(home, '.shieldcortex');
    mkdirSync(join(dir, 'audit', 'session-guard'), { recursive: true });
    writeFileSync(join(dir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
    new Database(join(dir, 'memories.db')).close();
  });

  afterEach(() => { rmSync(home, { recursive: true, force: true }); });

  it('a session whose index holds only digest rows gets no degraded summary', () => {
    const session = 'digest-only-673';
    const key = `sc-${createHmac('sha256', SALT).update(`action-guard-session:${session}`).digest('hex').slice(0, 16)}`;
    const rows = ['local_only', 'attempt', 'receipt'].map((phase) => JSON.stringify({
      recordKind: 'digest', type: 'expiry_digest', origin: 'openclaw-session-end', sessionKey: key,
      digestId: 'e'.repeat(32), phase, observed: 2, rendered: 2, complete: true, transport: 'webhook', status: 'delivered',
      ts: new Date().toISOString(),
    }));
    writeFileSync(join(home, '.shieldcortex', 'audit', 'session-guard', `${key}.jsonl`), `${rows.join('\n')}\n`);
    const stop = spawnSync(process.execPath, [STOP_HOOK], {
      input: JSON.stringify({ session_id: session }),
      encoding: 'utf8',
      env: { ...process.env, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'), SHIELDCORTEX_SESSION_SALT: SALT },
    });
    expect(stop.status).toBe(0);
    const audit = join(home, '.shieldcortex', 'audit');
    const realtime = readdirSync(audit).filter((f) => /^realtime-.*\.jsonl$/.test(f));
    const all = realtime.flatMap((f) => readFileSync(join(audit, f), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)));
    expect(all.some((r) => r.type === 'session_summary' && r.sessionKey === key)).toBe(false);
    expect(existsSync(join(audit, 'session-guard', `${key}.jsonl`))).toBe(true);
  });
});
