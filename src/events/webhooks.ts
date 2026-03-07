/**
 * Webhook dispatcher — sends POST notifications on memory events.
 * Config stored in ~/.shieldcortex/config.json under "webhooks" key.
 */

import { readRawConfig } from '../cloud/config.js';
import { createHmac } from 'crypto';

export interface WebhookConfig {
  url: string;
  events: string[];  // ['memory_created', 'memory_quarantined', 'contradiction_detected', 'consolidation_complete']
  secret?: string;   // optional HMAC signing key
  enabled: boolean;
}

/**
 * Load webhook configurations from ~/.shieldcortex/config.json.
 * Returns an empty array if missing or malformed.
 */
export function loadWebhooks(): WebhookConfig[] {
  try {
    const raw = readRawConfig();
    if (!Array.isArray(raw.webhooks)) return [];
    return (raw.webhooks as WebhookConfig[]).filter(
      (w) => w && typeof w.url === 'string' && Array.isArray(w.events) && typeof w.enabled === 'boolean'
    );
  } catch {
    return [];
  }
}

/**
 * Dispatch a webhook event to all matching, enabled webhooks.
 * Fire-and-forget — never throws, never blocks.
 */
export async function dispatchWebhook(event: string, payload: Record<string, unknown>): Promise<void> {
  try {
    const webhooks = loadWebhooks();
    const matching = webhooks.filter((w) => w.enabled && w.events.includes(event));
    if (matching.length === 0) return;

    const body = JSON.stringify({ event, payload, timestamp: new Date().toISOString() });
    const timestamp = new Date().toISOString();

    for (const webhook of matching) {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-ShieldCortex-Event': event,
        'X-ShieldCortex-Timestamp': timestamp,
      };

      if (webhook.secret) {
        const signature = createHmac('sha256', webhook.secret).update(body).digest('hex');
        headers['X-ShieldCortex-Signature'] = signature;
      }

      // Fire-and-forget with 5-second timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      fetch(webhook.url, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal,
      })
        .catch(() => {})
        .finally(() => clearTimeout(timeoutId));
    }
  } catch {
    // Never throw — all errors are silently caught
  }
}
