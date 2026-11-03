/**
 * ShieldCortex — the webhook operator-notify channel (#143).
 *
 * The generic "configured channel" of the resolution order in
 * operator-notify.ts. It does not know about Telegram, WhatsApp, ntfy, or any
 * specific bridge — it POSTs the structured notification to a URL the
 * operator configured (notify-config.ts, already validated to `http:`/
 * `https:` before it ever reaches here) and reads only the HTTP status as
 * delivery confirmation.
 *
 * Two things distinguish this from `src/events/webhooks.ts` (the existing
 * memory-event dispatcher):
 *   1. It is NOT fire-and-forget. An approval notification that silently
 *      vanished into a DNS failure would be worse than no notification at
 *      all — the operator would believe they had opted in to being reached
 *      and would not be. So this awaits the response and reports failure.
 *   2. The response is read for ONE bit only: 2xx or not. The operator's
 *      actual decision never arrives on this response — see operator-notify.ts's
 *      module doc. A compromised or careless endpoint that echoes back
 *      `{"approved":true}` gets nothing from this channel for it; the human's
 *      answer only ever counts when it lands on the #118 approval store.
 *
 * #815 A: a held call or a headless denial can also carry a versioned `card`
 * block — the #648 plain-English what/why/who, the exact approve command, and
 * (denials only) the Approve/Deny choices bound to the action id. Version 1
 * has no tap path; see `WEBHOOK_CARD_VERSION`.
 */
import { createHmac } from 'node:crypto';
import { clipCardLine, type ApprovalCardSummary } from './approval-card.js';
import type {
  ActionGuardOutcomeNotification,
  AnyOperatorNotification,
  ConversationThreatNotification,
  NotifyChannel,
  OperatorNotification,
} from './operator-notify.js';
import {
  formatOperatorNotification,
  isActionGuardOutcomeNotification,
  isConversationThreatNotification,
} from './operator-notify.js';

export interface WebhookNotifyChannelOptions {
  /** Already validated by notify-config.ts's `normaliseWebhookUrl` — this
   *  module does not re-validate the scheme, but does not trust it blindly
   *  either: fetch itself will reject a genuinely malformed URL. */
  url: string;
  /** Optional HMAC signing key, mirroring events/webhooks.ts's pattern — lets
   *  the receiving endpoint verify the POST actually came from this install. */
  secret?: string;
  /** Injected for tests; defaults to the global fetch. */
  fetchImpl?: typeof fetch;
}

/** The event as a header/body value. Anything that is not exactly one of the
 *  two non-approval events reads as `approval_requested` — a receiver routing
 *  on this header must never see a value this module invented, and an older
 *  caller with no `event` at all keeps getting the header it has always got. */
function eventOf(n: AnyOperatorNotification): string {
  if (n.event === 'maintenance_fail') return 'maintenance_fail';
  if (n.event === 'mcp_tool_change') return 'mcp_tool_change';
  if (n.event === 'agent_config_change') return 'agent_config_change';
  if (n.event === 'denied_no_prompt_surface') return 'denied_no_prompt_surface';
  if (n.event === 'conversation_threat') return 'conversation_threat';
  if (n.event === 'action_guard_denial') return 'action_guard_denial';
  if (n.event === 'action_guard_warning') return 'action_guard_warning';
  return 'approval_requested';
}

/**
 * The #225 conversation-alert body. Structurally incapable of carrying an
 * approve/deny affordance: there is no hash on the notification to build one
 * from, and this function does not invent one. A receiver that draws buttons
 * from `approveCommand`/`denyCommand` therefore draws none for this event,
 * rather than drawing a pair bound to `undefined`.
 */
function buildConversationPayload(n: ConversationThreatNotification): Record<string, unknown> {
  return {
    event: 'conversation_threat',
    outcome: n.outcome,
    posture: n.posture,
    summary: n.summary,
    reason: n.reason,
    ...(n.sessionId ? { sessionId: n.sessionId } : {}),
    ...(n.model ? { model: n.model } : {}),
    ...(n.host ? { host: n.host } : {}),
    detectedAt: n.detectedAt,
    text: formatOperatorNotification(n),
    ts: new Date().toISOString(),
  };
}

// ── #815 A: the readable card, for a bridge that relays to a chat ──────────

/**
 * Version of the `card` block. A receiver (sc-notify-bridge) must check it
 * before drawing anything from the block.
 *
 *   1 — this shape. `actions` name the choices and the action they belong to
 *       (`{ action, label, actionId }`) and NOTHING else: no hash, no args, no
 *       token. There is no tap path in version 1 — a button drawn from it can
 *       do nothing, so a version-1 receiver shows `approveCommand` instead of
 *       a button that pretends to approve.
 *   2 — reserved for #815 B (one-tap approve): each `actions[]` entry gains a
 *       single-use, expiring `nonce`. Nothing in version 1 is a credential.
 */
export const WEBHOOK_CARD_VERSION = 1 as const;

export interface WebhookCardAction {
  action: 'approve' | 'deny';
  label: string;
  /** The #310 action id (`act-` + 16 hex). The only identity a button carries. */
  actionId: string;
}

export interface WebhookCard {
  version: typeof WEBHOOK_CARD_VERSION;
  /** 'approval' — the call is HELD and a human answer decides it.
   *  'denial'   — the call is already refused; approving authorises a RETRY. */
  kind: 'approval' | 'denial';
  headline: string;
  /** Plain-English WHAT, built on the box with every target redactor-passed. */
  what: string;
  why: string;
  who: string;
  /** The exact command that allows it, when there is one. */
  approveCommand?: string;
  /** Live holds only — on a denial there is nothing left to refuse. */
  denyCommand?: string;
  /** Present only when an action id exists to bind a choice to. */
  actions?: WebhookCardAction[];
  /** The card as plain text, for a receiver that renders text only. */
  text: string;
}

/** Per-line bounds. A chat message is not a document, and a line that crossed
 *  a process boundary is re-flattened (line breaks and hidden characters) by
 *  `clipCardLine` before it is sent anywhere. */
const CARD_WHAT_MAX = 160;
const CARD_WHY_MAX = 240;
const CARD_WHO_MAX = 96;
const ACTION_ID_SHAPE = /^act-[a-f0-9]{16}$/;

function cardLines(card: ApprovalCardSummary): { what: string; why: string; who: string } {
  return {
    what: clipCardLine(card.action, CARD_WHAT_MAX),
    why: clipCardLine(card.reason, CARD_WHY_MAX),
    who: clipCardLine(card.who, CARD_WHO_MAX),
  };
}

function cardText(headline: string, lines: { what: string; why: string; who: string }, tail: string[]): string {
  return [headline, '', `What: ${lines.what}`, `Why:  ${lines.why}`, `Who:  ${lines.who}`, '', ...tail].join('\n');
}

/** The card for a HELD call (approval_requested over the webhook). There is no
 *  action id on a live hold, so it carries the commands and no `actions`. */
function buildApprovalCardBlock(n: OperatorNotification, card: ApprovalCardSummary): WebhookCard {
  const lines = cardLines(card);
  const attemptArg = n.attemptId ? ` --attempt ${n.attemptId}` : '';
  const approveCommand = `shieldcortex approve ${n.shortHash}${attemptArg}`;
  const denyCommand = `shieldcortex deny ${n.shortHash}${attemptArg}`;
  const headline = '🛡️ ShieldCortex needs your approval';
  return {
    version: WEBHOOK_CARD_VERSION,
    kind: 'approval',
    headline,
    ...lines,
    approveCommand,
    denyCommand,
    text: cardText(headline, lines, [
      'To allow it once, run in a terminal on that machine:',
      `  ${approveCommand}`,
      'To refuse it:',
      `  ${denyCommand}`,
    ]),
  };
}

/** The card for a refused call. Only a headless denial
 *  (`denied_no_prompt_surface`) has a retry to authorise; any other denial is
 *  explained but offers no command and no choice. */
function buildDenialCardBlock(n: ActionGuardOutcomeNotification, card: ApprovalCardSummary): WebhookCard {
  const lines = cardLines(card);
  const actionId = typeof n.actionId === 'string' && ACTION_ID_SHAPE.test(n.actionId) ? n.actionId : undefined;
  const retryable = n.outcome === 'denied_no_prompt_surface' && actionId !== undefined;
  const headline = n.outcome === 'denied_no_prompt_surface'
    ? '🛡️ ShieldCortex blocked an action: nobody was at a prompt to approve it'
    : '🛡️ ShieldCortex blocked an action';
  if (!retryable) {
    return {
      version: WEBHOOK_CARD_VERSION,
      kind: 'denial',
      headline,
      ...lines,
      text: cardText(headline, lines, ['The call was refused. Nothing is waiting for approval.']),
    };
  }
  const approveCommand = `shieldcortex approve --denial ${actionId}`;
  return {
    version: WEBHOOK_CARD_VERSION,
    kind: 'denial',
    headline,
    ...lines,
    approveCommand,
    actions: [
      { action: 'approve', label: 'Approve retry', actionId },
      { action: 'deny', label: 'Deny', actionId },
    ],
    text: cardText(headline, lines, [
      'The job was refused and did not do the work.',
      'To allow ONE retry, run in a terminal on that machine:',
      `  ${approveCommand}`,
    ]),
  };
}

function buildPayload(n: AnyOperatorNotification): Record<string, unknown> {
  if (n.event === 'maintenance_fail') return { event: n.event, checks: n.checks, text: formatOperatorNotification(n), ts: new Date().toISOString() };
  if (n.event === 'mcp_tool_change') return { event: n.event, kind: n.kind, server: n.server, tools: n.tools, toolCount: n.toolCount, ...(n.reason ? { reason: n.reason } : {}), text: formatOperatorNotification(n), ts: new Date().toISOString() };
  if (n.event === 'agent_config_change') return { event: n.event, file: n.file, changes: n.changes, changeCount: n.changeCount, ...(n.severity ? { severity: n.severity } : {}), text: formatOperatorNotification(n), ts: new Date().toISOString() };
  if (isConversationThreatNotification(n)) return buildConversationPayload(n);
  if (isActionGuardOutcomeNotification(n)) return buildActionGuardPayload(n);
  return buildApprovalPayload(n);
}

function buildActionGuardPayload(n: ActionGuardOutcomeNotification): Record<string, unknown> {
  return {
    event: eventOf(n),
    outcome: n.outcome,
    tool: n.tool,
    surface: n.surface,
    signals: n.signals,
    severity: n.severity,
    reason: n.reason,
    ...(n.correlationId ? { correlationId: n.correlationId } : {}),
    ...(n.actionId ? { actionId: n.actionId } : {}),
    ...(n.sessionId ? { sessionId: n.sessionId } : {}),
    ...(n.origin ? { origin: n.origin } : {}),
    detectedAt: n.detectedAt,
    text: formatOperatorNotification(n),
    ts: new Date().toISOString(),
    // Last, so every pre-#815 key keeps its place for an existing receiver.
    ...(n.event === 'action_guard_denial' && n.card ? { card: buildDenialCardBlock(n, n.card) } : {}),
  };
}

function buildApprovalPayload(n: OperatorNotification): Record<string, unknown> {
  const event = eventOf(n);
  const denied = event === 'denied_no_prompt_surface';
  const payload: Record<string, unknown> = {
    // First field on purpose: a receiver that renders these into a chat has to
    // know whether it is drawing a question or an incident report BEFORE it
    // draws anything, and drawing Approve/Deny buttons on a dead request is
    // how an operator is trained to ignore the live ones.
    event,
    hash: n.hash,
    shortHash: n.shortHash,
    ...(n.attemptId ? { attemptId: n.attemptId } : {}),
    tool: n.tool,
    command: n.command,
    signals: n.signals,
    severity: n.severity,
    reason: n.reason,
    judge: n.judge,
    text: formatOperatorNotification(n),
    approveCommand: denied
      ? `shieldcortex approve --denial ${n.actionId ?? '<actionId>'}`
      : `shieldcortex approve ${n.shortHash}${n.attemptId ? ` --attempt ${n.attemptId}` : ''}`,
    ts: new Date().toISOString(),
  };
  // Present only where they mean something: `denyCommand` on a live hold (on a
  // denial there is nothing left to deny), the denial context on a denial.
  // `denied_no_prompt_surface` is a NEW event, so no existing receiver can be
  // relying on the shape of its body — the `approval_requested` body is
  // unchanged but for the added `event` key.
  // #509 r5 (finding 5): bound to the attempt exactly like `approveCommand`,
  // so a replayed deny from an earlier payload cannot remove a newer request.
  if (!denied) payload.denyCommand = `shieldcortex deny ${n.shortHash}${n.attemptId ? ` --attempt ${n.attemptId}` : ''}`;
  if (denied && n.deniedReason) payload.deniedReason = n.deniedReason;
  if (n.sessionId) payload.sessionId = n.sessionId;
  if (n.cwd) payload.cwd = n.cwd;
  // #815 A: the readable card for a live hold. `buildNotification` attaches a
  // card only to 'approval_requested'; the check is repeated so a hand-built
  // denial can never be given a live-hold card with a deny command on it.
  if (!denied && n.card) payload.card = buildApprovalCardBlock(n, n.card);
  return payload;
}

/**
 * Build a `NotifyChannel` that delivers by POSTing to a fixed URL.
 *
 * Every failure mode — network error, non-2xx, an abort on timeout — resolves
 * to `{ delivered: false, reason }` rather than throwing, so a caller using
 * this as one candidate in `requestOperatorApproval`'s resolution order can
 * fall through to the next channel (or to null, and the unchanged
 * hash-in-terminal fallback) without a try/catch of its own.
 */
export function createWebhookNotifyChannel(opts: WebhookNotifyChannelOptions): NotifyChannel {
  const fetchImpl = opts.fetchImpl ?? fetch;

  return {
    name: 'webhook',
    async send(notification, { timeoutMs }) {
      const payload = buildPayload(notification);
      const body = JSON.stringify(payload);

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        // Derived, not hardcoded: a receiver that filters or routes on this
        // header (page me for a denial, queue an approval) is the whole point
        // of having a header at all.
        'X-ShieldCortex-Event': eventOf(notification),
      };
      // #369 — receivers routing "is anything actually pending?" need the
      // outcome without parsing the body. Only outcome-bearing alerts have one.
      if (isActionGuardOutcomeNotification(notification)) {
        headers['X-ShieldCortex-Outcome'] = notification.outcome;
      }
      if (opts.secret) {
        headers['X-ShieldCortex-Signature'] = createHmac('sha256', opts.secret).update(body).digest('hex');
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetchImpl(opts.url, {
          method: 'POST',
          headers,
          body,
          signal: controller.signal,
        });
        // The status is the ENTIRE signal read from the response. The body
        // (if any) is never parsed here — see module doc.
        if (!res.ok) {
          return { delivered: false, reason: `webhook responded ${res.status}` };
        }
        return { delivered: true };
      } catch (err) {
        return { delivered: false, reason: err instanceof Error ? err.message : String(err) };
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
