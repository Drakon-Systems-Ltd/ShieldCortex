/**
 * #815 A — the readable card over the #143 webhook.
 *
 * The owner could not see a night of headless denials: when notify was wired
 * at all, what reached the chat was the values-free alert surface and nothing
 * a person could act on from a phone. The webhook now carries a versioned
 * `card` block — the #648 plain-English what/why/who, the exact approve
 * command, and (denials only) Approve/Deny choices bound to the action id.
 *
 * What these tests pin:
 *   - the payload contract a bridge (sc-notify-bridge) codes against;
 *   - every pre-#815 key is unchanged and keeps its place (the card is last);
 *   - nothing secret, no raw command and no hash/args ride on the card, and
 *     version 1 carries no nonce or any other credential;
 *   - the card is never offered where it would mislead (an advisory warning,
 *     a live-hold card on a denial, buttons with no action id behind them).
 */
import { describe, it, expect } from '@jest/globals';
import { createHmac } from 'node:crypto';
import { createWebhookNotifyChannel, WEBHOOK_CARD_VERSION } from '../webhook-notify-channel.js';
import {
  buildActionGuardOutcomeNotification,
  requestOperatorApproval,
  type ActionGuardOutcomeInput,
  type AnyOperatorNotification,
  type OperatorNotification,
} from '../operator-notify.js';
import {
  SIGNAL_PHRASES,
  WITHHELD_SECRET,
  buildApprovalCard,
  clipCardLine,
  describeSignals,
  type ApprovalCardSummary,
} from '../approval-card.js';
import { evaluateToolCall } from '../tool-action-guard.js';

const ACTION_ID = 'act-0123456789abcdef';
const SESSION_ID = 'sc-fedcba9876543210';

const CARD: ApprovalCardSummary = {
  action: 'Read a file in your SSH folder: "~/.ssh/config"',
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
  correlationId: ACTION_ID,
  actionId: ACTION_ID,
  sessionId: SESSION_ID,
  origin: 'claude-code-hook',
  detectedAt: '2026-11-03T09:00:00.000Z',
};

async function post(n: AnyOperatorNotification, secret?: string): Promise<{ body: string; headers: Record<string, string> }> {
  let captured: { body: string; headers: Record<string, string> } | null = null;
  const channel = createWebhookNotifyChannel({
    url: 'https://bridge.example.invalid/sc',
    secret,
    fetchImpl: (async (_url: string, init: RequestInit) => {
      captured = { body: String(init.body), headers: init.headers as Record<string, string> };
      return { ok: true, status: 200 } as Response;
    }) as unknown as typeof fetch,
  });
  const result = await channel.send(n, { timeoutMs: 5_000 });
  expect(result).toEqual({ delivered: true });
  return captured!;
}

async function payloadOf(n: AnyOperatorNotification): Promise<Record<string, unknown>> {
  return JSON.parse((await post(n)).body) as Record<string, unknown>;
}

/** The payload minus the clock, so two builds can be compared byte for byte. */
const stable = (p: Record<string, unknown>) => JSON.stringify({ ...p, ts: '<ts>' });

describe('#815 A — headless denial card (action_guard_denial / denied_no_prompt_surface)', () => {
  it('carries the versioned card: what/why/who, the exact approve command, and Approve/Deny bound to the action id', async () => {
    const body = await payloadOf(buildActionGuardOutcomeNotification({ ...DNP, card: CARD }));
    expect(WEBHOOK_CARD_VERSION).toBe(1);
    expect(body.card).toEqual({
      version: 1,
      kind: 'denial',
      headline: '🛡️ ShieldCortex blocked an action: nobody was at a prompt to approve it',
      what: CARD.action,
      why: CARD.reason,
      who: CARD.who,
      approveCommand: `shieldcortex approve --denial ${ACTION_ID}`,
      actions: [
        { action: 'approve', label: 'Approve retry', actionId: ACTION_ID },
        { action: 'deny', label: 'Deny', actionId: ACTION_ID },
      ],
      text: [
        '🛡️ ShieldCortex blocked an action: nobody was at a prompt to approve it',
        '',
        `What: ${CARD.action}`,
        `Why:  ${CARD.reason}`,
        `Who:  ${CARD.who}`,
        '',
        'The job was refused and did not do the work.',
        'To allow ONE retry, run in a terminal on that machine:',
        `  shieldcortex approve --denial ${ACTION_ID}`,
      ].join('\n'),
    });
  });

  it('each action carries exactly {action, label, actionId} — no nonce, hash, args or token in version 1', async () => {
    const body = await payloadOf(buildActionGuardOutcomeNotification({ ...DNP, card: CARD }));
    const card = body.card as { actions: Array<Record<string, unknown>> };
    for (const a of card.actions) expect(Object.keys(a).sort()).toEqual(['action', 'actionId', 'label']);
    expect(JSON.stringify(body.card)).not.toMatch(/nonce|hmac|token|secret|hash/i);
  });

  it('every pre-#815 key is byte-identical and keeps its order; the card is the last key', async () => {
    const without = await payloadOf(buildActionGuardOutcomeNotification(DNP));
    const withCard = await payloadOf(buildActionGuardOutcomeNotification({ ...DNP, card: CARD }));
    expect(Object.keys(withCard).at(-1)).toBe('card');
    const { card: _card, ...rest } = withCard;
    expect(stable(rest)).toBe(stable(without));
    // The values-free alert fields are untouched by the card.
    expect(rest.surface).toBe(DNP.surface);
    expect(rest.text).toBe(without.text);
  });

  it('the HMAC signature covers the card (it is part of the signed body)', async () => {
    const { body, headers } = await post(buildActionGuardOutcomeNotification({ ...DNP, card: CARD }), 'k'.repeat(32));
    expect(body).toContain('"card":');
    expect(headers['X-ShieldCortex-Signature']).toBe(createHmac('sha256', 'k'.repeat(32)).update(body).digest('hex'));
  });

  it('a non-headless denial is explained but offers no command and no choice', async () => {
    const body = await payloadOf(buildActionGuardOutcomeNotification({ ...DNP, outcome: 'auto_denied', card: CARD }));
    const card = body.card as Record<string, unknown>;
    expect(card.kind).toBe('denial');
    expect(card.headline).toBe('🛡️ ShieldCortex blocked an action');
    expect(card).not.toHaveProperty('approveCommand');
    expect(card).not.toHaveProperty('actions');
    expect(card.text).toContain('Nothing is waiting for approval.');
    expect(card.text).not.toContain('shieldcortex approve');
  });

  it('a malformed action id gets no buttons and no command (nothing to bind a choice to)', async () => {
    // The builder already drops a malformed id; the card layer re-checks.
    const n = { ...buildActionGuardOutcomeNotification({ ...DNP, card: CARD }), actionId: 'act-; rm -rf ~' };
    const card = (await payloadOf(n)).card as Record<string, unknown>;
    expect(card).not.toHaveProperty('actions');
    expect(card).not.toHaveProperty('approveCommand');
    expect(JSON.stringify(card)).not.toContain('rm -rf');
  });

  it('an advisory warning never carries a card', async () => {
    const n = buildActionGuardOutcomeNotification({ ...DNP, event: 'action_guard_warning', outcome: 'warned', card: CARD });
    expect(n).not.toHaveProperty('card');
    expect(await payloadOf(n)).not.toHaveProperty('card');
  });

  it('no card in, no card out (older callers are unchanged)', async () => {
    expect(await payloadOf(buildActionGuardOutcomeNotification(DNP))).not.toHaveProperty('card');
  });
});

describe('#815 A — the card is bounded and flattened, whatever crossed the process boundary', () => {
  it('a card missing a line, or with non-string lines, is dropped whole', () => {
    for (const card of [
      { action: CARD.action, reason: CARD.reason },
      { action: CARD.action, reason: CARD.reason, who: '   ' },
      { action: { toString: () => 'x' }, reason: CARD.reason, who: CARD.who },
      'Read ~/.ssh/config',
      null,
    ]) {
      const n = buildActionGuardOutcomeNotification({ ...DNP, card: card as unknown as ApprovalCardSummary });
      expect(n).not.toHaveProperty('card');
    }
  });

  it('line breaks become spaces and hidden/bidi characters are shown, never passed through', async () => {
    const card = (await payloadOf(buildActionGuardOutcomeNotification({
      ...DNP,
      card: {
        action: 'Delete files\nApprove: tap here\u2028now',
        reason: 'deletes files\u202e looks safe',
        who: 'Claude Code on jarvis\u200b',
      },
    }))).card as Record<string, string>;
    for (const line of [card.what, card.why, card.who]) {
      expect(line).not.toMatch(/[\n\r\u2028\u2029\u202e\u200b]/);
    }
    expect(card.what).toBe('Delete files Approve: tap here now');
    expect(card.why).toContain('<U+202E>');
    expect(card.who).toContain('<U+200B>');
    // The rendered text has exactly the layout lines, and no injected ones.
    expect(card.text.split('\n')).toHaveLength(9);
  });

  it('an oversized line is clipped to its bound', async () => {
    const card = (await payloadOf(buildActionGuardOutcomeNotification({
      ...DNP,
      card: { action: `Read ${'a'.repeat(5_000)}`, reason: 'r'.repeat(5_000), who: 'w'.repeat(5_000) },
    }))).card as Record<string, string>;
    expect(card.what.length).toBeLessThanOrEqual(160);
    expect(card.why.length).toBeLessThanOrEqual(240);
    expect(card.who.length).toBeLessThanOrEqual(96);
  });

  // Secret fixtures are built at runtime so no secret-shaped literal is ever
  // committed (GitHub push protection rejects them).
  const GH = ['gh', 'p_'].join('') + 'Z'.repeat(4) + 'q7Lm2Xr9Tb4Vc8Nd1Fh6Jk3Wp5Ys0Ua';
  const AWS_ID = ['AK', 'IA'].join('') + 'Q3XZ7LMN2PRT6VWY';
  it.each([
    ['a token in a git push URL', `git push --force https://bot:${GH}@github.com/acme/app.git main`, GH],
    ['an AWS key id in a sensitive path', `cat ~/.ssh/${AWS_ID}`, AWS_ID],
    ['a token in a pkill pattern', `pkill -f "relay --token=${GH}"`, GH],
  ])('a card built by the real #648 builder never carries the secret or the raw command: %s', async (_label, command, secret) => {
    const card = buildApprovalCard({
      tool: 'Bash',
      input: { command },
      signals: ['touch-sensitive-path'],
      plane: 'claude-code',
      sessionId: SESSION_ID,
    });
    const body = (await post(buildActionGuardOutcomeNotification({ ...DNP, card }))).body;
    expect(body).toContain('"card":');
    expect(body).not.toContain(secret);
    expect(body).not.toContain(secret.slice(0, 12));
    expect(body).not.toContain(secret.slice(-12));
    expect(body).not.toContain(command);
  });

  it('#815 A review B1: a credential-shaped git remote name, with the guard\'s own signals, is withheld from the card', async () => {
    // The guard's real signals (`git-force-push`), so the builder really
    // describes the push rather than going generic — the remote-name fallback
    // is reached, which is where the name skipped the redactor.
    const command = `git push --force ${AWS_ID} main`;
    const signals = evaluateToolCall('Bash', { command }).signals;
    expect(signals).toContain('git-force-push');
    const card = buildApprovalCard({ tool: 'Bash', input: { command }, signals, plane: 'claude-code', sessionId: SESSION_ID });
    expect(card.action).toBe(`Force-push to ${WITHHELD_SECRET} (branch "main") (git push --force)`);
    const body = (await post(buildActionGuardOutcomeNotification({ ...DNP, card }))).body;
    expect((JSON.parse(body) as { card: { what: string } }).card.what).toBe(card.action);
    for (const needle of [AWS_ID, AWS_ID.slice(0, 8), AWS_ID.slice(-8), command]) expect(body).not.toContain(needle);
  });
});

describe('#815 A — live hold card (approval_requested over the webhook)', () => {
  async function liveHoldBody(extra: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    let body: Record<string, unknown> | null = null;
    await requestOperatorApproval(
      {
        hash: 'c'.repeat(64),
        attemptId: 'a1b2c3d4e5f6a7b8',
        tool: 'Bash',
        command: 'Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command',
        signals: ['touch-sensitive-path'],
        severity: 'dangerous',
        reason: 'Action Guard requires approval; inspect local audit for details.',
        sessionId: SESSION_ID,
        card: CARD,
        ...extra,
      },
      {
        channel: createWebhookNotifyChannel({
          url: 'https://bridge.example.invalid/sc',
          fetchImpl: (async (_u: string, init: RequestInit) => {
            body = JSON.parse(String(init.body)) as Record<string, unknown>;
            return { ok: true, status: 200 } as Response;
          }) as unknown as typeof fetch,
        }),
      },
    );
    return body!;
  }

  it('carries what/why/who and the attempt-bound approve and deny commands, and no buttons (no action id on a hold)', async () => {
    const body = await liveHoldBody();
    expect(body.card).toEqual({
      version: 1,
      kind: 'approval',
      headline: '🛡️ ShieldCortex needs your approval',
      what: CARD.action,
      why: CARD.reason,
      who: CARD.who,
      approveCommand: 'shieldcortex approve cccccccccccc --attempt a1b2c3d4e5f6a7b8',
      denyCommand: 'shieldcortex deny cccccccccccc --attempt a1b2c3d4e5f6a7b8',
      text: [
        '🛡️ ShieldCortex needs your approval',
        '',
        `What: ${CARD.action}`,
        `Why:  ${CARD.reason}`,
        `Who:  ${CARD.who}`,
        '',
        'To allow it once, run in a terminal on that machine:',
        '  shieldcortex approve cccccccccccc --attempt a1b2c3d4e5f6a7b8',
        'To refuse it:',
        '  shieldcortex deny cccccccccccc --attempt a1b2c3d4e5f6a7b8',
      ].join('\n'),
    });
    // The card's commands agree with the top-level ones a pre-#815 receiver reads.
    expect((body.card as Record<string, unknown>).approveCommand).toBe(body.approveCommand);
    expect((body.card as Record<string, unknown>).denyCommand).toBe(body.denyCommand);
    expect(Object.keys(body).at(-1)).toBe('card');
    // The full hash stays where it always was, not on the card.
    expect(JSON.stringify(body.card)).not.toContain('c'.repeat(64));
  });

  it('a denial requested through the approval path never gets a live-hold card', async () => {
    const body = await liveHoldBody({ event: 'denied_no_prompt_surface', actionId: ACTION_ID });
    expect(body.event).toBe('denied_no_prompt_surface');
    expect(body).not.toHaveProperty('card');
    expect(body).not.toHaveProperty('denyCommand');
  });
});

// ── #815 A review B1 ────────────────────────────────────────────────────────
// The class: an approval-card field reaching the webhook without passing the
// credential redactor. The builder's remote-name fallback was one instance; a
// field from a future builder, or one that crossed a process boundary, would
// be another. So the webhook puts EVERY card line through the redactor itself,
// before the line is clipped and before anything is serialised. The cards
// below are hand-built so they test that egress gate on its own.

/** The raw body of a live hold (`approval_requested`) over the webhook. */
async function holdBody(card: ApprovalCardSummary): Promise<string> {
  let body = '';
  await requestOperatorApproval(
    {
      hash: 'c'.repeat(64),
      attemptId: 'a1b2c3d4e5f6a7b8',
      tool: 'Bash',
      command: 'Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command',
      signals: ['touch-sensitive-path'],
      severity: 'dangerous',
      reason: 'Action Guard requires approval; inspect local audit for details.',
      sessionId: SESSION_ID,
      card,
    },
    {
      channel: createWebhookNotifyChannel({
        url: 'https://bridge.example.invalid/sc',
        fetchImpl: (async (_u: string, init: RequestInit) => {
          body = String(init.body);
          return { ok: true, status: 200 } as Response;
        }) as unknown as typeof fetch,
      }),
    },
  );
  return body;
}

/** The same card over both webhook card paths: headless denial, then live hold. */
async function overBothPaths(card: ApprovalCardSummary): Promise<Array<{ path: string; body: string; card: Record<string, string> }>> {
  const denial = (await post(buildActionGuardOutcomeNotification({ ...DNP, card }))).body;
  const hold = await holdBody(card);
  return [['denial', denial], ['hold', hold]].map(([path, body]) => {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    expect(parsed).toHaveProperty('card');
    return { path, body, card: parsed.card as Record<string, string> };
  });
}

describe('#815 A review B1 — every card line passes the credential redactor at the webhook, before it is clipped', () => {
  const GH = ['gh', 'p_'].join('') + 'Z'.repeat(4) + 'q7Lm2Xr9Tb4Vc8Nd1Fh6Jk3Wp5Ys0Ua';
  const AWS_ID = ['AK', 'IA'].join('') + 'Q3XZ7LMN2PRT6VWY';
  const LINE_KEY = { action: 'what', reason: 'why', who: 'who' } as const;

  it.each([
    ['action', GH], ['action', AWS_ID],
    ['reason', GH], ['reason', AWS_ID],
    ['who', GH], ['who', AWS_ID],
  ] as const)('a secret in the card %s line is withheld whole on both paths (%#)', async (field, secret) => {
    const card: ApprovalCardSummary = { ...CARD, [field]: `Push the release to ${secret} now` };
    for (const got of await overBothPaths(card)) {
      expect(got.card[LINE_KEY[field]]).toBe(WITHHELD_SECRET);
      // The other two lines are untouched.
      for (const [f, k] of Object.entries(LINE_KEY)) if (f !== field) expect(got.card[k]).toBe(CARD[f as keyof ApprovalCardSummary]);
      for (const needle of [secret, secret.slice(0, 12), secret.slice(-12)]) expect(got.body).not.toContain(needle);
    }
  });

  it('a secret the clip would cut in half is still withheld whole: the gate runs before the clip', async () => {
    const action = `${'Read a file in the build folder '.repeat(2)}${GH} ${'and then the release folder '.repeat(3)}`.trim();
    // Precondition: clipping alone would have shown the secret's head.
    expect(clipCardLine(action, 160)).toContain(GH.slice(0, 12));
    for (const got of await overBothPaths({ ...CARD, action })) {
      expect(got.card.what).toBe(WITHHELD_SECRET);
      expect(got.card.text).toContain(`What: ${WITHHELD_SECRET}`);
      expect(got.body).not.toContain(GH.slice(0, 12));
    }
  });

  it('a secret split by a hidden or control character is seen whole', async () => {
    for (const split of ['​', '⁠', '\u0007']) {
      const action = `Read a file: "${AWS_ID.slice(0, 4)}${split}${AWS_ID.slice(4)}"`;
      for (const got of await overBothPaths({ ...CARD, action })) {
        expect(got.card.what).toBe(WITHHELD_SECRET);
        expect(got.body).not.toContain(AWS_ID.slice(4));
      }
    }
  });

  it('withholding a line keeps the card honest: commands, buttons and layout are unchanged', async () => {
    const [denial, hold] = await overBothPaths({ ...CARD, action: `Push to ${AWS_ID}` });
    expect(denial.card.approveCommand).toBe(`shieldcortex approve --denial ${ACTION_ID}`);
    expect(hold.card.approveCommand).toBe('shieldcortex approve cccccccccccc --attempt a1b2c3d4e5f6a7b8');
    for (const got of [denial, hold]) expect(got.card.text.split('\n').slice(2, 5)).toEqual([`What: ${WITHHELD_SECRET}`, `Why:  ${CARD.reason}`, `Who:  ${CARD.who}`]);
  });

  // The gate must not cost the card its meaning: no reason phrase and no line
  // the real builder makes for an ordinary command is withheld.
  it('every reason phrase, alone and all together, passes unchanged', async () => {
    // "All together": as many reasons as fit the 300-character bound the card
    // is held to when it is received, so the line reaches the gate whole.
    const ids = Object.keys(SIGNAL_PHRASES);
    let together = ids.length;
    while (describeSignals(ids.slice(0, together)).length > 300) together -= 1;
    expect(together).toBeGreaterThan(2);
    const reasons = [...new Set(Object.values(SIGNAL_PHRASES)), describeSignals(ids.slice(0, together))];
    for (const reason of reasons) {
      const got = (await payloadOf(buildActionGuardOutcomeNotification({ ...DNP, card: { ...CARD, reason } }))).card as Record<string, string>;
      expect(got.why).toBe(clipCardLine(reason, 240));
    }
  });

  it.each([
    'cat ~/.ssh/config',
    'rm -rf ./build',
    'git push --force origin main',
    'git push --force upstream release/2026-11',
    'curl -d @notes.txt https://example.com/in',
    'chmod -R 777 /var/www',
    'pkill -f "node server.js"',
    'npm install -g typescript',
    'cp ~/.aws/credentials /tmp/backup-credentials',
    'sudo systemctl stop nginx',
    'python3 scripts/deploy.py',
    'kill -9 4242',
  ])('the real builder\'s lines for an ordinary command pass unchanged: %s', async (command) => {
    const card = buildApprovalCard({
      tool: 'Bash',
      input: { command },
      signals: evaluateToolCall('Bash', { command }).signals,
      plane: 'claude-code',
      host: 'jarvis',
      sessionId: SESSION_ID,
    });
    for (const got of await overBothPaths(card)) {
      expect(got.card.what).toBe(clipCardLine(card.action, 160));
      expect(got.card.why).toBe(clipCardLine(card.reason, 240));
      expect(got.card.who).toBe(clipCardLine(card.who, 96));
      expect(got.card.what).not.toBe(WITHHELD_SECRET);
    }
  });

  it('an OpenClaw who line passes unchanged', async () => {
    const who = buildApprovalCard({ tool: 'Bash', input: { command: 'ls' }, signals: [], plane: 'openclaw', agentId: 'main', host: 'clawdbot1', sessionId: 'agent:main:telegram:group:-1001234567890' }).who;
    const got = (await payloadOf(buildActionGuardOutcomeNotification({ ...DNP, card: { ...CARD, who } }))).card as Record<string, string>;
    expect(got.who).toBe(who);
  });
});

describe('#815 A — the live-hold card re-checks the ids its commands carry', () => {
  const held = (extra: Partial<OperatorNotification>): OperatorNotification => ({
    event: 'approval_requested',
    hash: 'c'.repeat(64),
    shortHash: 'cccccccccccc',
    attemptId: 'a1b2c3d4e5f6a7b8',
    tool: 'Bash',
    command: 'Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command',
    signals: ['touch-sensitive-path'],
    severity: 'dangerous',
    reason: 'r',
    judge: null,
    fallbackHint: '',
    card: CARD,
    ...extra,
  });

  it('well-formed ids: the card is built', async () => {
    expect(await payloadOf(held({}))).toHaveProperty('card');
    expect(await payloadOf(held({ attemptId: undefined }))).toHaveProperty('card');
  });

  it('a hand-built notification whose hash or attempt id is not the expected hex gets no card', async () => {
    for (const extra of [
      { shortHash: 'ccc; rm -rf ~' },
      { shortHash: 'c'.repeat(64) },
      { attemptId: 'a1b2c3d4 && curl x' },
      { attemptId: 'a1b2' },
    ]) {
      const body = await payloadOf(held(extra));
      expect(body).not.toHaveProperty('card');
      // Every pre-#815 key is still sent.
      expect(body).toHaveProperty('approveCommand');
      expect(body).toHaveProperty('denyCommand');
    }
  });
});

describe('#815 A — a line of trailing markers keeps them, and stays inside the bound set when the card was received', () => {
  it('the overrun clipCardLine allows for its markers is capped by the 300-character line bound', async () => {
    const action = `Delete files${' and 9 more'.repeat(26)}`;
    expect(action.length).toBeLessThanOrEqual(300);
    const got = (await payloadOf(buildActionGuardOutcomeNotification({ ...DNP, card: { ...CARD, action } }))).card as Record<string, string>;
    expect(got.what.endsWith(' and 9 more')).toBe(true);
    expect(got.what.length).toBeLessThanOrEqual(300);
    // A longer line is cut at the bound first, and then clipped to its own.
    const long = (await payloadOf(buildActionGuardOutcomeNotification({ ...DNP, card: { ...CARD, action: `Delete files${' and 9 more'.repeat(80)}` } }))).card as Record<string, string>;
    expect(long.what.length).toBeLessThanOrEqual(160);
  });
});
