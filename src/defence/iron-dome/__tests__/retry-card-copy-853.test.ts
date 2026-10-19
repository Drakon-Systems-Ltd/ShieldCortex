/**
 * #853 — the held (#310) retry card leads with What / Why / Who and an
 * outcome line, for every session shape a headless denial comes from, and
 * never claims the call ran or that the card was delivered. The card switch
 * itself stays dark (ADR rollout gate) — pinned here so a later slice cannot
 * flip it by accident.
 */
import { describe, it, expect } from '@jest/globals';

import {
  buildRetryCardFields,
  buildRetryCardParams,
  heldCardOutcomeLine,
  normaliseRetryControlConfig,
  type RetryCardCopyInput,
} from '../retry-control.js';
import { buildApprovalCard } from '../approval-card.js';

const IRREVERSIBLE = { command: 'rm -rf /srv/data/archive' };

function heldInput(sessionId: string, plane: 'claude-code' | 'openclaw', extra: Partial<RetryCardCopyInput> = {}): RetryCardCopyInput {
  const signals = ['dangerous-shell'];
  return {
    card: buildApprovalCard({ tool: 'Bash', input: IRREVERSIBLE, signals, plane, sessionId, host: 'box-1', cwd: '/srv/jobs/nightly' }),
    tool: 'Bash',
    signals,
    redactedSurface: 'Bash: [redacted action surface] fields=command',
    cwd: '/srv/jobs/nightly',
    ttlMs: 600_000,
    ...extra,
  };
}

const NO_FALSE_CLAIM = /\b(delivered|sent to you|was run|ran|executed|is waiting|paused)\b/i;

describe('#853 — held retry card copy', () => {
  it('keeps the card rollout gate DARK: absent, junk and false all mean off', () => {
    expect(normaliseRetryControlConfig(undefined).retryCards).toBe(false);
    expect(normaliseRetryControlConfig({}).retryCards).toBe(false);
    expect(normaliseRetryControlConfig({ retryCards: 'true' }).retryCards).toBe(false);
    expect(normaliseRetryControlConfig({ retryCards: 1 }).retryCards).toBe(false);
    expect(normaliseRetryControlConfig({ retryCards: false }).retryCards).toBe(false);
    expect(normaliseRetryControlConfig({ retryCards: true }).retryCards).toBe(true);
  });

  const shapes: Array<[string, string, 'claude-code' | 'openclaw', RegExp]> = [
    ['Claude Code headless session', 'sc-0123456789abcdef', 'claude-code', /Who: Claude Code on box-1 · session sc-0123456789abcdef/],
    ['OpenClaw cron job', 'agent:main:cron:nightly-backup', 'openclaw', /Who: OpenClaw agent "main" on box-1 · scheduled job #[0-9a-f]{8}/],
    ['OpenClaw sub-agent', 'agent:research:subagent:7f3a', 'openclaw', /Who: OpenClaw agent "research" on box-1 · sub-agent #[0-9a-f]{8}/],
  ];

  for (const [label, sessionId, plane, who] of shapes) {
    it(`lays out What / Why / Who / outcome for a ${label}`, () => {
      const fields = buildRetryCardFields(heldInput(sessionId, plane));
      const lines = fields.description.split('\n');
      expect(lines).toHaveLength(4);
      expect(lines[0]).toMatch(/^What: /);
      expect(lines[0]).toContain('/srv/data/archive');
      expect(lines[1]).toMatch(/^Why: \S/);
      expect(lines[2]).toMatch(who);
      expect(lines[3]).toBe(heldCardOutcomeLine(600_000, '/srv/jobs/nightly'));
      expect(fields.title).toBe('ShieldCortex held Bash — allow one retry? Card expires in 10m');
      expect(fields.surfaceWithheld).toBe(false);
      expect(fields.surfaceTruncated).toBe(false);
      expect(fields.description.length).toBeLessThanOrEqual(256);
      expect(fields.title.length).toBeLessThanOrEqual(80);
      // Never a claim that the call ran, is paused, or that anything was delivered.
      expect(fields.title + fields.description).not.toMatch(NO_FALSE_CLAIM);
      // A raw OpenClaw session key is tagged, never echoed.
      if (plane === 'openclaw') expect(fields.description).not.toContain(sessionId);
    });
  }

  it('says what "Allow one retry" buys and what Deny or silence means, in plain words', () => {
    const line = heldCardOutcomeLine(600_000, '/srv/jobs/nightly');
    expect(line).toBe('Allow one retry: same call, within 10m (jobs/nightly) · Deny or no reply: nothing runs');
    // N1: retry-only semantics — the denied call is never promised a run.
    expect(line).not.toMatch(/\bApprove:|runs ONCE|will run/);
  });

  it('N2: a non-finite or junk TTL reads as 1m, never NaN', () => {
    for (const ttl of [Number.NaN, Number.POSITIVE_INFINITY, undefined as unknown as number, 'x' as unknown as number, 0, -5]) {
      const line = heldCardOutcomeLine(ttl, '/srv/jobs/nightly');
      expect(line).not.toMatch(/NaN|Infinity/);
      expect(line).toContain('same call, within 1m (jobs/nightly)');
    }
    const fields = buildRetryCardFields(heldInput('sc-0123456789abcdef', 'claude-code', { ttlMs: Number.NaN }));
    expect(fields.description).not.toMatch(/NaN/);
    expect(fields.description.length).toBeLessThanOrEqual(256);
  });

  it('cuts WHAT / WHY / WHO before the outcome line, however long they are', () => {
    const long = 'x'.repeat(2000);
    const fields = buildRetryCardFields({
      ...heldInput('sc-0123456789abcdef', 'claude-code', { cwd: `/srv/${'deep/'.repeat(40)}job`, cronIntervalMs: 3_600_000 }),
      card: { action: `delete ${long} archive.tar`, reason: long, who: `agent ${long} sc-tail` },
    });
    expect(fields.description.length).toBeLessThanOrEqual(256);
    const lines = fields.description.split('\n');
    expect(lines[0]).toMatch(/^What: delete x+…x+ archive\.tar$/);
    expect(lines[3]).toContain('Deny or no reply: nothing runs');
    expect(lines[3]).toContain('approve --denial <id> --ttl');
    expect(lines[3].startsWith('Allow one retry: same call, within 10m')).toBe(true);
    expect(lines[2]).toMatch(/^Who: agent x+…x+ sc-tail$/);
    expect(fields.surfaceTruncated).toBe(true);
    // N3: a clipped target is truncated, not withheld.
    expect(fields.surfaceWithheld).toBe(false);
  });

  it('clips a long runner hostname while keeping the session and retry terms truthful', () => {
    const sessionId = 'sc-0123456789abcdef';
    const card = buildApprovalCard({
      tool: 'Bash', input: IRREVERSIBLE, signals: ['dangerous-shell'],
      plane: 'claude-code', sessionId, host: 'runner-' + 'x'.repeat(55),
      cwd: '/srv/jobs/nightly',
    });
    const fields = buildRetryCardFields({ ...heldInput(sessionId, 'claude-code'), card });
    const lines = fields.description.split('\n');
    expect(lines).toHaveLength(4);
    expect(lines[2]).toMatch(/^Who: Claude Code on runner-.*….*x · session sc-0123456789abcdef$/);
    expect(lines[2]).not.toContain('x'.repeat(55));
    expect(lines[3]).toBe('Allow one retry: same call, within 10m (jobs/nightly) · Deny or no reply: nothing runs');
    expect(fields.description.length).toBeLessThanOrEqual(256);
    expect(fields.title + fields.description).not.toMatch(NO_FALSE_CLAIM);
  });

  it('withholds the target for a secret-egress class, as the #310 layout does', () => {
    const input = heldInput('sc-0123456789abcdef', 'claude-code', { signals: ['secret-egress'] });
    input.card = { ...input.card!, action: 'send ~/.ssh/id_ed25519 to paste.example' };
    const fields = buildRetryCardFields(input);
    expect(fields.description).not.toContain('id_ed25519');
    expect(fields.description).not.toContain('paste.example');
    expect(fields.description).toMatch(/^What: Bash call — target withheld \(secret egress; see audit\)\n/);
    expect(fields.surfaceWithheld).toBe(true);
  });

  it('flattens line breaks and shows hidden characters that crossed the waiter argv', () => {
    const input = heldInput('sc-0123456789abcdef', 'claude-code');
    input.card = { action: 'delete\nApprove: safe‮', reason: 'irreversible​', who: 'Claude Code' };
    const lines = buildRetryCardFields(input).description.split('\n');
    expect(lines).toHaveLength(4);
    expect(lines[0]).toBe('What: delete Approve: safe<U+202E>');
    expect(lines[1]).toBe('Why: irreversible<U+200B>');
  });

  it('falls back to the #310 layout when no usable card is supplied', () => {
    const base = heldInput('sc-0123456789abcdef', 'claude-code');
    for (const card of [undefined, { action: '', reason: 'r', who: 'w' }, { action: 'a', reason: '  ', who: 'w' }]) {
      const fields = buildRetryCardFields({ ...base, card });
      expect(fields.title).toBe('Approve once? Bash · dangerous-shell');
      expect(fields.description.startsWith('held headless — Approve = ONE retry (10m, jobs/nightly)')).toBe(true);
    }
  });

  it('still offers exactly allow-once and deny on the held layout', () => {
    const params = buildRetryCardParams(heldInput('agent:main:cron:nightly-backup', 'openclaw'));
    expect(params.allowedDecisions).toEqual(['allow-once', 'deny']);
    expect(String(params.description)).toMatch(/^What: /);
  });
});
