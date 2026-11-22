/**
 * #815 S2a — the version 2 (one-tap) card type and its builder, inert.
 * Nothing calls the builder yet, so the webhook still sends version 1.
 * Pinned: nonce on Approve only, digest and expiry on the card; the nonce in
 * no line a person reads and no command; no card (never a partial one) when
 * the denial is not retryable or a tap value is missing or malformed; each
 * notification field read once; pure builder; version 1 card unchanged.
 */
import { describe, it, expect, jest } from '@jest/globals';
import { WEBHOOK_CARD_VERSION, WEBHOOK_CARD_VERSION_2, buildDenialCardBlockV2, createWebhookNotifyChannel, type WebhookCardTap, type WebhookCardV2 } from '../webhook-notify-channel.js';
import { buildActionGuardOutcomeNotification, type ActionGuardOutcomeInput, type ActionGuardOutcomeNotification } from '../operator-notify.js';
import type { ApprovalCardSummary } from '../approval-card.js';
import type { TapMacFields } from '../approve-tap.js';

const ACTION_ID = 'act-0123456789abcdef';
const SESSION_ID = 'sc-fedcba9876543210';
const NONCE = '00112233445566778899aabbccddeeff';
const ARGS_HASH = 'ab'.repeat(32);
const EXP = 1_800_000_000_000;
const HEADLINE = '🛡️ ShieldCortex blocked an action: nobody was at a prompt to approve it';

const CARD: ApprovalCardSummary = {
  action: 'Read a file in your SSH folder',
  reason: 'touches a sensitive file (keys, passwords or credentials)',
  who: `Claude Code on jarvis · session ${SESSION_ID}`,
};

const DNP: ActionGuardOutcomeInput = {
  event: 'action_guard_denial',
  outcome: 'denied_no_prompt_surface',
  tool: 'Bash',
  surface: 'Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command',
  signals: ['touch-sensitive-path'],
  severity: 'dangerous',
  reason: '',
  actionId: ACTION_ID,
  sessionId: SESSION_ID,
  detectedAt: '2026-11-03T09:00:00.000Z',
};

const TAP: WebhookCardTap = { nonce: NONCE, argsHash: ARGS_HASH, exp: EXP };
const note = (over: Partial<ActionGuardOutcomeInput> = {}): ActionGuardOutcomeNotification =>
  buildActionGuardOutcomeNotification({ ...DNP, ...over });
const build = (n = note(), card = CARD, tap: unknown = TAP): WebhookCardV2 | undefined =>
  buildDenialCardBlockV2(n, card, tap as WebhookCardTap);

/** Everything version 1 and version 2 share for this denial. */
const SHARED = {
  kind: 'denial',
  headline: HEADLINE,
  what: CARD.action,
  why: CARD.reason,
  who: CARD.who,
  approveCommand: `shieldcortex approve --denial ${ACTION_ID}`,
  text: [
    HEADLINE,
    '',
    `What: ${CARD.action}`,
    `Why:  ${CARD.reason}`,
    `Who:  ${CARD.who}`,
    '',
    'The job was refused and did not do the work.',
    'To allow ONE retry, run in a terminal on that machine:',
    `  shieldcortex approve --denial ${ACTION_ID}`,
  ].join('\n'),
};

/** What the webhook itself sends today for a notification: the live path. */
async function sentCard(n: ActionGuardOutcomeNotification): Promise<Record<string, unknown> | undefined> {
  let body = '';
  const channel = createWebhookNotifyChannel({
    url: 'https://bridge.example.invalid/sc',
    fetchImpl: (async (_url: string, init: RequestInit) => {
      body = String(init.body);
      return { ok: true, status: 200 } as Response;
    }) as unknown as typeof fetch,
  });
  expect(await channel.send(n, { timeoutMs: 5_000 })).toEqual({ delivered: true });
  return (JSON.parse(body) as { card?: Record<string, unknown> }).card;
}

describe('#815 S2a — version 2 denial card (inert builder)', () => {
  it('builds the whole version 2 card beside version 1, which stays 1', () => {
    expect([WEBHOOK_CARD_VERSION, WEBHOOK_CARD_VERSION_2]).toEqual([1, 2]);
    expect(build()).toEqual({
      version: 2,
      ...SHARED,
      argsHash: ARGS_HASH,
      exp: EXP,
      actions: [
        { action: 'approve', label: 'Approve retry', actionId: ACTION_ID, nonce: NONCE },
        { action: 'deny', label: 'Deny', actionId: ACTION_ID },
      ],
    });
  });

  it('puts the nonce on Approve only; Deny carries no nonce, digest or expiry', () => {
    const [approve, deny] = build()!.actions;
    expect(Object.keys(approve).sort()).toEqual(['action', 'actionId', 'label', 'nonce']);
    expect(Object.keys(deny).sort()).toEqual(['action', 'actionId', 'label']);
    expect(JSON.stringify(deny)).not.toContain(NONCE);
    expect(JSON.stringify(build()).split(NONCE)).toHaveLength(2); // exactly once on the card
  });

  it('keeps the nonce out of every line a person reads and out of the command', () => {
    const card = build()!;
    for (const field of [card.text, card.headline, card.what, card.why, card.who, card.approveCommand]) {
      expect(field).not.toContain(NONCE);
    }
    expect(card.text).not.toContain(ARGS_HASH);
  });

  it('names the tap values as approve-tap.ts names them, so a MAC can be built from the card', () => {
    const c = build()!;
    const mac: TapMacFields = { actionId: c.actions[0].actionId, argsHash: c.argsHash, nonce: c.actions[0].nonce, exp: c.exp, approver: 'telegram:1' };
    expect(mac).toEqual({ actionId: ACTION_ID, argsHash: ARGS_HASH, nonce: NONCE, exp: EXP, approver: 'telegram:1' });
  });

  it('gives no card when the denial is not retryable', () => {
    expect(build(note({ outcome: 'auto_denied' }))).toBeUndefined();
    expect(build(note({ event: 'action_guard_warning' }))).toBeUndefined();
    expect(build({ ...note(), actionId: undefined })).toBeUndefined();
    expect(build({ ...note(), actionId: 'act-0123456789ABCDEF' })).toBeUndefined();
    expect(build({ ...note(), actionId: `${ACTION_ID}0` })).toBeUndefined();
    expect(buildDenialCardBlockV2(note(), undefined as unknown as ApprovalCardSummary, TAP)).toBeUndefined();
  });

  it.each<[string, unknown]>([
    ['no tap values', undefined],
    ['null tap values', null],
    ['tap values that are not an object', NONCE],
    ['a missing nonce', { argsHash: ARGS_HASH, exp: EXP }],
    ['a short nonce', { ...TAP, nonce: NONCE.slice(1) }],
    ['an upper-case nonce', { ...TAP, nonce: NONCE.toUpperCase() }],
    ['a nonce that is not a string', { ...TAP, nonce: 7 }],
    ['a missing digest', { nonce: NONCE, exp: EXP }],
    ['a short digest', { ...TAP, argsHash: ARGS_HASH.slice(2) }],
    ['a digest that is not hex', { ...TAP, argsHash: 'zz'.repeat(32) }],
    ['a missing expiry', { nonce: NONCE, argsHash: ARGS_HASH }],
    ['a zero expiry', { ...TAP, exp: 0 }],
    ['a negative expiry', { ...TAP, exp: -1 }],
    ['a fractional expiry', { ...TAP, exp: 1.5 }],
    ['an expiry that is a string', { ...TAP, exp: String(EXP) }],
    ['an expiry that is not a safe integer', { ...TAP, exp: Number.MAX_SAFE_INTEGER + 2 }],
  ])('gives no card, never a partial one, for %s', (_name, tap) => {
    expect(buildDenialCardBlockV2(note(), CARD, tap as WebhookCardTap)).toBeUndefined();
  });

  it.each<[string, string]>([
    ['at the start', NONCE + 'ab'.repeat(16)],
    ['in the middle', 'ab'.repeat(8) + NONCE + 'ab'.repeat(8)],
    ['at the end', 'ab'.repeat(16) + NONCE],
  ])('gives no card when a well-formed digest holds the whole nonce %s', (_name, argsHash) => {
    expect(argsHash).toMatch(/^[0-9a-f]{64}$/);
    expect(build(note(), CARD, { ...TAP, argsHash })).toBeUndefined();
  });

  it('still builds for a well-formed digest that does not hold the nonce, with the nonce once on the card', () => {
    const card = build(note(), CARD, { ...TAP, argsHash: 'cd'.repeat(32) })!;
    expect(card.argsHash).toBe('cd'.repeat(32));
    expect(JSON.stringify(card).split(NONCE)).toHaveLength(2);
  });

  it('never shows the nonce in a line a person reads, even when a line handed in contains it', () => {
    const card = build(note(), { ...CARD, who: `Claude Code on ${NONCE}` })!; // a card IS built: the line is withheld
    expect(`${card.who}\n${card.text}`).not.toContain(NONCE);
    expect(JSON.stringify(card).split(NONCE)).toHaveLength(2);
  });

  it('reads each notification field once, so a getter cannot have one action id checked and another returned', () => {
    const reads = { event: 0, outcome: 0, actionId: 0 };
    const n = Object.defineProperties({ ...note() }, {
      event: { enumerable: true, get: () => (reads.event++, 'action_guard_denial') },
      outcome: { enumerable: true, get: () => (reads.outcome++, 'denied_no_prompt_surface') },
      actionId: { enumerable: true, get: () => (reads.actionId++ < 2 ? ACTION_ID : '') }, // well-formed for two checks, then empty
    }) as ActionGuardOutcomeNotification;
    expect([build(n), reads]).toEqual([build(), { event: 1, outcome: 1, actionId: 1 }]);
    let late = 0; // an id that turns well-formed only after the first read is refused on that read
    const flip = Object.defineProperty({ ...note() }, 'actionId', { enumerable: true, get: () => (late++ ? ACTION_ID : '') });
    expect([build(flip), late]).toEqual([undefined, 1]);
  });

  it('is pure: no clock, no network, inputs untouched, same answer twice', () => {
    const now = jest.spyOn(Date, 'now');
    const net = jest.spyOn(globalThis, 'fetch');
    try {
      const n = Object.freeze(note());
      const card = Object.freeze({ ...CARD });
      const tap = Object.freeze({ ...TAP });
      const before = JSON.stringify([n, card, tap]);
      const first = buildDenialCardBlockV2(n, card, tap);
      const second = buildDenialCardBlockV2(n, card, tap);
      expect(first).toEqual(second);
      expect(JSON.stringify([n, card, tap])).toBe(before);
      expect(now).not.toHaveBeenCalled();
      expect(net).not.toHaveBeenCalled();
    } finally {
      now.mockRestore();
      net.mockRestore();
    }
  });

  it('leaves the version 1 card for the same input unchanged, and the webhook still sends version 1', async () => {
    const sent = await sentCard(buildActionGuardOutcomeNotification({ ...DNP, card: CARD }));
    expect(sent).toEqual({
      version: 1,
      ...SHARED,
      actions: [
        { action: 'approve', label: 'Approve retry', actionId: ACTION_ID },
        { action: 'deny', label: 'Deny', actionId: ACTION_ID },
      ],
    });
    expect(JSON.stringify(sent)).not.toMatch(/nonce|argsHash|"exp"/);
  });
});
