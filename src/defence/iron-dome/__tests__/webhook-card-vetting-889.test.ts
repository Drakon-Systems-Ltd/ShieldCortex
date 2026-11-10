/**
 * #889 phase 1, integration with the #815 webhook card.
 *
 * The webhook card's WHY is made of the guard's fixed phrases only
 * (`fixedTemplateReason`): anything else is sent as "matched another safety
 * rule". The package findings (#889) are free-form text on the interactive
 * card — a package name, a version, an OSV id — so none of it may reach the
 * webhook, and before this round none of it did: an OSV advisory, a fresh
 * version, an install hook and a lookup that could not finish all read as
 * one generic line, or as nothing at all (an `unchecked` lookup adds no
 * signal). The findings now travel to the template card as their KINDS, a
 * closed set mapped to fixed phrases in `SIGNAL_PHRASES`, so the phone sees
 * what kind of thing the check found and never what the command named.
 */
import { describe, it, expect } from '@jest/globals';
import { createWebhookNotifyChannel } from '../webhook-notify-channel.js';
import {
  buildActionGuardOutcomeNotification,
  requestOperatorApproval,
  type ActionGuardOutcomeInput,
  type AnyOperatorNotification,
} from '../operator-notify.js';
import {
  REASON_SEPARATOR,
  SIGNAL_CLASSES,
  SIGNAL_PHRASES,
  VETTING_CARD_SIGNALS,
  buildApprovalCard,
  buildTemplateApprovalCard,
  describeVettingKinds,
  fixedTemplateReason,
} from '../approval-card.js';

const ACTION_ID = 'act-0123456789abcdef';
const SESSION_ID = 'sc-fedcba9876543210';
const PHRASES: ReadonlySet<string> = new Set([...Object.values(SIGNAL_PHRASES), 'matched a safety rule']);
const OTHER_RULE = SIGNAL_PHRASES['redacted-signal'];

/** The free-form findings the interactive card shows. None may leave the box. */
const PKG = 'evil-pkg-889';
const VERSION = '1.0.3';
const OSV_ID = 'MAL-2026-18603';
const MAL_REASON = `OSV lists ${PKG}@${VERSION} as known malicious (${OSV_ID})`;
const UNCHECKED_REASON = 'unchecked: lookup failed';
const NEEDLES = [PKG, VERSION, OSV_ID, 'lookup failed', 'OSV lists', 'unchecked:'];

const INSTALL_INPUT = { tool: 'Bash', input: { command: `npm install ${PKG}@${VERSION}` }, plane: 'claude-code' as const, sessionId: SESSION_ID };

const DNP: ActionGuardOutcomeInput = {
  event: 'action_guard_denial',
  outcome: 'denied_no_prompt_surface',
  tool: 'Bash',
  surface: 'Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command',
  signals: ['local-package-install'],
  severity: 'dangerous',
  reason: '',
  correlationId: ACTION_ID,
  actionId: ACTION_ID,
  sessionId: SESSION_ID,
  origin: 'claude-code-hook',
  detectedAt: '2026-11-08T21:00:00.000Z',
};

async function post(n: AnyOperatorNotification): Promise<string> {
  let body = '';
  const channel = createWebhookNotifyChannel({
    url: 'https://bridge.example.invalid/sc',
    fetchImpl: (async (_url: string, init: RequestInit) => {
      body = String(init.body);
      return { ok: true, status: 200 } as Response;
    }) as unknown as typeof fetch,
  });
  const result = await channel.send(n, { timeoutMs: 5_000 });
  expect(result).toEqual({ delivered: true });
  return body;
}

async function holdBody(card: { action: string; reason: string; who: string }, signals: string[]): Promise<string> {
  let body = '';
  await requestOperatorApproval(
    {
      hash: 'c'.repeat(64),
      attemptId: 'a1b2c3d4e5f6a7b8',
      tool: 'Bash',
      command: 'Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command',
      signals,
      severity: 'dangerous',
      reason: 'Action Guard requires approval; inspect local audit for details.',
      sessionId: SESSION_ID,
      card,
    },
    {
      channel: createWebhookNotifyChannel({
        url: 'https://bridge.example.invalid/sc',
        fetchImpl: (async (_url: string, init: RequestInit) => {
          body = String(init.body);
          return { ok: true, status: 200 } as Response;
        }) as unknown as typeof fetch,
      }),
      timeoutMs: 5_000,
    },
  );
  return body;
}

const cardOf = (body: string) => (JSON.parse(body) as { card: Record<string, string> }).card;
const expectFixedWhy = (why: string) => {
  for (const part of why.split(REASON_SEPARATOR)) expect(PHRASES.has(part)).toBe(true);
};
const expectNoFindingText = (body: string) => {
  for (const needle of NEEDLES) expect(body).not.toContain(needle);
};

describe('#889 vetting reasons on the webhook card — the closed vocabulary', () => {
  it('every finding kind maps to a fixed phrase the webhook passes unchanged', () => {
    const kinds = ['malicious', 'advisory', 'new-version', 'install-hook', 'sdist-only', 'unchecked'];
    expect(Object.keys(VETTING_CARD_SIGNALS).sort()).toEqual([...kinds].sort());
    for (const kind of kinds) {
      const id = VETTING_CARD_SIGNALS[kind];
      expect(Object.hasOwn(SIGNAL_PHRASES, id)).toBe(true);
      expect(Object.hasOwn(SIGNAL_CLASSES, id)).toBe(true);
      expect(fixedTemplateReason(SIGNAL_PHRASES[id])).toBe(SIGNAL_PHRASES[id]);
    }
    expect(VETTING_CARD_SIGNALS.malicious).toBe('known-malicious-package');
    const all = describeVettingKinds(kinds);
    expect(all).toHaveLength(kinds.length);
    expect(fixedTemplateReason(all.join(REASON_SEPARATOR))).toBe(all.join(REASON_SEPARATOR));
  });

  it('a kind outside the set, or anything that is not a kind, renders nothing', () => {
    expect(describeVettingKinds(['bogus', `${PKG}; ${OSV_ID}`, '', 42 as unknown as string])).toEqual([]);
    expect(describeVettingKinds(undefined)).toEqual([]);
    expect(describeVettingKinds('malicious' as unknown as string[])).toEqual([]);
    expect(describeVettingKinds(['malicious', 'malicious', 'unchecked'])).toEqual([
      SIGNAL_PHRASES['known-malicious-package'],
      SIGNAL_PHRASES['package-check-unavailable'],
    ]);
  });
});

describe('#889 a MAL- hit on the webhook card', () => {
  const signals = ['local-package-install', 'package-vetting', 'known-malicious-package'];
  const card = buildTemplateApprovalCard({ ...INSTALL_INPUT, signals, extraReasons: [MAL_REASON], vettingKinds: ['malicious'] });

  it('the template card says the package is listed as malicious, once, and names nothing', () => {
    const parts = card.reason.split(REASON_SEPARATOR);
    expect(parts).toContain(SIGNAL_PHRASES['known-malicious-package']);
    expect(parts.filter((p) => p === SIGNAL_PHRASES['known-malicious-package'])).toHaveLength(1);
    expect(parts).not.toContain(OTHER_RULE);
    expectFixedWhy(card.reason);
    expectNoFindingText(JSON.stringify(card));
  });

  it('renders as the malicious reason on the headless denial card', async () => {
    const body = await post(buildActionGuardOutcomeNotification({ ...DNP, signals, card }));
    const got = cardOf(body);
    expect(got.why.split(REASON_SEPARATOR)).toContain(SIGNAL_PHRASES['known-malicious-package']);
    expectFixedWhy(got.why);
    expectNoFindingText(body);
  });

  it('renders as the malicious reason on the live-hold card', async () => {
    const body = await holdBody(card, signals);
    const got = cardOf(body);
    expect(got.why.split(REASON_SEPARATOR)).toContain(SIGNAL_PHRASES['known-malicious-package']);
    expectFixedWhy(got.why);
    expectNoFindingText(body);
  });
});

describe('#889 an unchecked lookup on the webhook card', () => {
  // An `unchecked` note adds no signal (a network blip must not change the
  // verdict), so without the kind the webhook card would say nothing about it.
  const signals = ['local-package-install'];
  const card = buildTemplateApprovalCard({ ...INSTALL_INPUT, signals, extraReasons: [UNCHECKED_REASON], vettingKinds: ['unchecked'] });

  it('the template card says the check could not finish, and nothing more', () => {
    expect(card.reason.split(REASON_SEPARATOR)).toEqual([
      SIGNAL_PHRASES['local-package-install'],
      SIGNAL_PHRASES['package-check-unavailable'],
    ]);
    expectNoFindingText(JSON.stringify(card));
  });

  it('renders as the package-check-unavailable reason on the headless denial card', async () => {
    const body = await post(buildActionGuardOutcomeNotification({ ...DNP, signals, card }));
    const got = cardOf(body);
    expect(got.why.split(REASON_SEPARATOR)).toContain(SIGNAL_PHRASES['package-check-unavailable']);
    expectFixedWhy(got.why);
    expectNoFindingText(body);
  });

  it('renders on the live-hold card too', async () => {
    const body = await holdBody(card, signals);
    expect(cardOf(body).why.split(REASON_SEPARATOR)).toContain(SIGNAL_PHRASES['package-check-unavailable']);
    expectNoFindingText(body);
  });
});

describe('#889 the other findings and the interactive card', () => {
  it('advisory, fresh version and install hooks each render as their own fixed phrase, in finding order', () => {
    const card = buildTemplateApprovalCard({
      ...INSTALL_INPUT,
      signals: ['local-package-install', 'package-vetting'],
      extraReasons: ['OSV: GHSA-xxxx-yyyy-zzzz affects this version', 'published 11 h ago', 'runs a postinstall script on install'],
      vettingKinds: ['new-version', 'install-hook', 'advisory'],
    });
    expect(card.reason.split(REASON_SEPARATOR)).toEqual([
      SIGNAL_PHRASES['local-package-install'],
      SIGNAL_PHRASES['package-vetting'],
      SIGNAL_PHRASES['package-advisory'],
      SIGNAL_PHRASES['package-install-hook'],
      SIGNAL_PHRASES['package-new-version'],
    ]);
    expect(JSON.stringify(card)).not.toMatch(/GHSA|11 h ago|postinstall/);
  });

  it('a template card with no kinds is exactly what it was before (#815 public contract)', () => {
    const signals = ['local-package-install', 'package-vetting'];
    const before = buildTemplateApprovalCard({ ...INSTALL_INPUT, signals });
    expect(buildTemplateApprovalCard({ ...INSTALL_INPUT, signals, extraReasons: [MAL_REASON] })).toEqual(before);
    expect(buildTemplateApprovalCard({ ...INSTALL_INPUT, signals, vettingKinds: [] })).toEqual(before);
  });

  it('the interactive card is unchanged: it still leads with the plain-English findings and ignores the kinds', () => {
    const signals = ['local-package-install', 'package-vetting', 'known-malicious-package'];
    const withKinds = buildApprovalCard({ ...INSTALL_INPUT, signals, extraReasons: [MAL_REASON], vettingKinds: ['malicious'] });
    const without = buildApprovalCard({ ...INSTALL_INPUT, signals, extraReasons: [MAL_REASON] });
    expect(withKinds).toEqual(without);
    expect(withKinds.reason.startsWith(MAL_REASON)).toBe(true);
  });
});
