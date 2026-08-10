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
 */
import { createHmac } from 'node:crypto';
import type { NotifyChannel, OperatorNotification } from './operator-notify.js';
import { formatOperatorNotification } from './operator-notify.js';

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

/** The event as a header/body value. Anything that is not exactly the denial
 *  reads as `approval_requested` — a receiver routing on this header must
 *  never see a value this module invented, and an older caller with no `event`
 *  at all keeps getting the header it has always got. */
function eventOf(n: OperatorNotification): string {
  return n.event === 'denied_no_prompt_surface' ? 'denied_no_prompt_surface' : 'approval_requested';
}

function buildPayload(n: OperatorNotification): Record<string, unknown> {
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
    tool: n.tool,
    command: n.command,
    signals: n.signals,
    severity: n.severity,
    reason: n.reason,
    judge: n.judge,
    text: formatOperatorNotification(n),
    approveCommand: `shieldcortex approve ${n.shortHash}`,
    ts: new Date().toISOString(),
  };
  // Present only where they mean something: `denyCommand` on a live hold (on a
  // denial there is nothing left to deny), the denial context on a denial.
  // `denied_no_prompt_surface` is a NEW event, so no existing receiver can be
  // relying on the shape of its body — the `approval_requested` body is
  // unchanged but for the added `event` key.
  if (!denied) payload.denyCommand = `shieldcortex deny ${n.shortHash}`;
  if (denied && n.deniedReason) payload.deniedReason = n.deniedReason;
  if (n.sessionId) payload.sessionId = n.sessionId;
  if (n.cwd) payload.cwd = n.cwd;
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
