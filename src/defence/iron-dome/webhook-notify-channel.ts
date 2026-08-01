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

function buildPayload(n: OperatorNotification): Record<string, unknown> {
  return {
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
    denyCommand: `shieldcortex deny ${n.shortHash}`,
    ts: new Date().toISOString(),
  };
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
        'X-ShieldCortex-Event': 'approval_requested',
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
