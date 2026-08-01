/**
 * ShieldCortex — operator-notify configuration (#143).
 *
 * `operator-notify.ts` is the transport; this is the only thing allowed to
 * decide whether it runs at all, and against what URL. Same discipline as
 * broker-config.ts, which this deliberately mirrors: a config file lives on
 * disk, and on a box the agent has already been talked into misusing, "on
 * disk" means "reachable" — so this is written the way a parser for hostile
 * input is written: allowlist the fields, bound the numbers, and treat
 * anything unrecognised as absent rather than as intent.
 *
 * The rule that matters most (#143 acceptance criterion 7):
 *
 *   **Default OFF. Nothing changes for an operator who has not opted in.**
 *
 * `enabled` is false unless the config says exactly `true`, and a `webhookUrl`
 * is only ever accepted if it parses as `http:`/`https:` — anything else
 * (a `javascript:`/`file:`/`data:` scheme, or plain junk) is dropped, which
 * degrades to "no configured channel" rather than a spoofed one.
 */

export interface NotifyConfig {
  /** Master switch. FALSE by default — the whole transport is opt-in. */
  enabled: boolean;
  /** Per-channel delivery deadline. */
  timeoutMs: number;
  /** The configured channel's target, when the transport is a webhook.
   *  Absent = no configured channel (the TUI tier and the hash fallback are
   *  the only things left). See webhook-notify-channel.ts. */
  webhookUrl?: string;
}

const TIMEOUT_MIN_MS = 500;
const TIMEOUT_MAX_MS = 60_000;
const WEBHOOK_URL_MAX_LENGTH = 2_048;

export const DEFAULT_NOTIFY_CONFIG: NotifyConfig = {
  enabled: false,
  timeoutMs: 10_000,
};

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** A finite number inside [min, max], or undefined — no clamping, matching
 *  broker-config.ts's `boundedNumber`: a value we do not understand is not
 *  silently reinterpreted as the nearest one we do. */
function boundedNumber(v: unknown, min: number, max: number): number | undefined {
  if (typeof v !== 'number' || !Number.isFinite(v)) return undefined;
  if (v < min || v > max) return undefined;
  return v;
}

/**
 * A webhook URL, or undefined. Only `http:`/`https:` are accepted — every
 * other scheme (`javascript:`, `file:`, `data:`, or anything malformed) is a
 * potential local-file-read or script-execution vector if it were ever
 * handed to something less careful than `fetch`, so it is refused here
 * rather than trusted downstream. Length-bounded for the same reason
 * broker-config.ts bounds a model name: an unbounded string from disk has no
 * business becoming an unbounded network call.
 */
export function normaliseWebhookUrl(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const trimmed = v.trim();
  if (!trimmed || trimmed.length > WEBHOOK_URL_MAX_LENGTH) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return undefined;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return undefined;
  return trimmed;
}

/**
 * Turn whatever was on disk into a config the notify transport can be
 * trusted with. Total: every input, including junk, yields a valid
 * NotifyConfig — never throws, never passes an unrecognised key through.
 */
export function normaliseNotifyConfig(raw: unknown): NotifyConfig {
  if (!isPlainObject(raw)) return { ...DEFAULT_NOTIFY_CONFIG };

  const cfg: NotifyConfig = {
    // Strict true, matching broker-config.ts's `enabled` — not truthy. A
    // stray "true" string or a 1 must not arm the transport.
    enabled: raw.enabled === true,
    timeoutMs: boundedNumber(raw.timeoutMs, TIMEOUT_MIN_MS, TIMEOUT_MAX_MS) ?? DEFAULT_NOTIFY_CONFIG.timeoutMs,
  };

  const webhookUrl = normaliseWebhookUrl(raw.webhookUrl);
  if (webhookUrl !== undefined) cfg.webhookUrl = webhookUrl;

  return cfg;
}
