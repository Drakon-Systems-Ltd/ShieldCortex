/**
 * #260 / #242 — session-guard reporting must work on the OpenClaw plane,
 * with the same session key formula the Claude Code hook uses.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createHmac } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  sessionKeyFor,
  appendSessionGuardIndex,
  recordActionGuardDegraded,
  GUARD_DEGRADED_OUTCOMES,
  isGuardIndexOrigin,
  isSummaryOrigin,
} from '../session-guard.js';

const SALT = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

function expectedKey(sessionId: string): string {
  return `sc-${createHmac('sha256', SALT).update(`action-guard-session:${sessionId}`).digest('hex').slice(0, 16)}`;
}

describe('#260 session key is identical to the Claude Code hook formula', () => {
  it('HMAC-SHA256 over action-guard-session:${id}, hex, 16, sc- prefix', () => {
    expect(sessionKeyFor('cron-job-42', { salt: SALT })).toBe(expectedKey('cron-job-42'));
    expect(sessionKeyFor('cron-job-42', { salt: SALT })).toMatch(/^sc-[a-f0-9]{16}$/);
  });

  it('rejects a raw session id as an index filename (silently dropped, not forged)', () => {
    expect(sessionKeyFor('', { salt: SALT })).toBeNull();
    expect(sessionKeyFor('   ', { salt: SALT })).toBeNull();
    expect(sessionKeyFor(undefined, { salt: SALT })).toBeNull();
  });
});

describe('#260 origins', () => {
  it('accepts both Claude and OpenClaw guard/summary origins', () => {
    expect(isGuardIndexOrigin('claude-code-hook')).toBe(true);
    expect(isGuardIndexOrigin('openclaw-interceptor')).toBe(true);
    expect(isGuardIndexOrigin(undefined)).toBe(false);
    expect(isSummaryOrigin('claude-code-stop-hook')).toBe(true);
    expect(isSummaryOrigin('openclaw-session-end')).toBe(true);
    expect(isSummaryOrigin('openclaw-interceptor')).toBe(false);
  });

  it('treats unattended deny outcomes as degraded', () => {
    expect(GUARD_DEGRADED_OUTCOMES.has('failure_denied')).toBe(true);
    expect(GUARD_DEGRADED_OUTCOMES.has('auto_denied')).toBe(true);
    expect(GUARD_DEGRADED_OUTCOMES.has('allowed')).toBe(false);
  });
});

describe('#260 index + summarise', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-260-'));
  });
  afterEach(() => {
    try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  it('indexes an OpenClaw unattended deny and emits action_guard_degraded at session end', () => {
    const sessionId = 'openclaw-cron-backup';
    const key = sessionKeyFor(sessionId, { salt: SALT })!;
    const written = appendSessionGuardIndex({
      home,
      entry: {
        type: 'intercept',
        origin: 'openclaw-interceptor',
        sessionKey: key,
        action: 'require_approval',
        outcome: 'failure_denied',
        tool: 'Bash',
        threats: ['secret-egress'],
        ts: '2026-08-11T01:30:28.897Z',
      },
    });
    expect(written).toBe(true);
    const indexFile = join(home, '.shieldcortex', 'audit', 'session-guard', `${key}.jsonl`);
    expect(existsSync(indexFile)).toBe(true);

    const result = recordActionGuardDegraded(sessionId, { home, salt: SALT, origin: 'openclaw-session-end' });
    expect(result.recorded).toBe(true);
    expect(result.count).toBe(1);
    expect(result.sessionKey).toBe(key);

    const auditDir = join(home, '.shieldcortex', 'audit');
    const files = readdirSync(auditDir).filter((f) => /^realtime-.*\.jsonl$/.test(f));
    expect(files.length).toBe(1);
    const rows = readFileSync(join(auditDir, files[0]), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summary = rows.find((r) => r.type === 'session_summary');
    expect(summary).toMatchObject({
      origin: 'openclaw-session-end',
      sessionKey: key,
      outcome: 'action_guard_degraded',
      guardOutcomeCount: 1,
    });
  });

  it('does not summarise twice', () => {
    const sessionId = 'once-only';
    const key = sessionKeyFor(sessionId, { salt: SALT })!;
    appendSessionGuardIndex({
      home,
      entry: {
        type: 'intercept',
        origin: 'openclaw-interceptor',
        sessionKey: key,
        outcome: 'failure_denied',
        ts: new Date().toISOString(),
      },
    });
    expect(recordActionGuardDegraded(sessionId, { home, salt: SALT }).recorded).toBe(true);
    const second = recordActionGuardDegraded(sessionId, { home, salt: SALT });
    expect(second.recorded).toBe(true);
    expect(second.existing).toBe(true);
    expect(second.count).toBe(0);
  });

  it('drops a row whose sessionKey is not the sc- form', () => {
    expect(appendSessionGuardIndex({
      home,
      entry: { origin: 'openclaw-interceptor', sessionKey: 'raw-session-id', outcome: 'failure_denied' },
    })).toBe(false);
    expect(existsSync(join(home, '.shieldcortex', 'audit', 'session-guard'))).toBe(false);
  });
});
