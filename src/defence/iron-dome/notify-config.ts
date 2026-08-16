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

import {
  DEFAULT_DNP_DIGEST_WINDOW_MS,
  normaliseDnpDigestWindowMs,
} from './dnp-digest.js';

export interface NotifyConfig {
  /** Master switch. FALSE by default — the whole transport is opt-in. */
  enabled: boolean;
  /** Per-channel delivery deadline. */
  timeoutMs: number;
  /** The configured channel's target, when the transport is a webhook.
   *  Absent = no configured channel (the TUI tier and the hash fallback are
   *  the only things left). See webhook-notify-channel.ts. */
  webhookUrl?: string;
  /** HMAC-SHA256 signing key for the webhook body (`X-ShieldCortex-Signature`,
   *  see webhook-notify-channel.ts). Without it this install can only ever
   *  send UNAUTHENTICATED POSTs, and any receiver worth pointing at — one that
   *  can page a human or re-run a job — has to reject unsigned requests.
   *
   *  This is the one field in this file that is a credential: it is never
   *  logged, never put in an error message, and never written to an audit row.
   *  Nothing here formats it, and nothing downstream may either. */
  webhookSecret?: string;
  /** Deliver via a native OpenClaw plugin-approval card — Approve/Deny
   *  buttons on whatever channel the operator's gateway already reaches
   *  (Telegram, WhatsApp, Discord…). Strict `true` only, same as `enabled`:
   *  this arms a channel that can put taps within reach of a phone, so a
   *  truthy-but-not-true value must read as "not opted in".
   *  See openclaw-approval-channel.ts. */
  openclaw: boolean;
  /**
   * #331 — host-local DNP digest window (ms).
   * - default 15m
   * - `0` disables digest (every DNP notifies, legacy volume)
   * - only finite values in [60s, 24h] accepted; junk → default
   * Payload / permission_mode never appear here and never mute.
   */
  dnpDigestWindowMs: number;
}

const TIMEOUT_MIN_MS = 500;
const TIMEOUT_MAX_MS = 60_000;
const WEBHOOK_URL_MAX_LENGTH = 2_048;
/** An HMAC key is a key, not a document. Generous enough for any real
 *  generator (a 512-bit hex key is 128 chars), small enough that a config file
 *  that has accidentally swallowed a file's contents is rejected rather than
 *  hashed. */
const WEBHOOK_SECRET_MAX_LENGTH = 512;

export const DEFAULT_NOTIFY_CONFIG: NotifyConfig = {
  enabled: false,
  timeoutMs: 10_000,
  openclaw: false,
  dnpDigestWindowMs: DEFAULT_DNP_DIGEST_WINDOW_MS,
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
 * The webhook signing key, or undefined. Same "unusable reads as absent"
 * discipline as every other field here — a non-string, an empty string, or
 * something too long to be a key is dropped, which degrades to today's
 * unsigned POST rather than to a crash or to a signature computed over
 * `[object Object]`.
 *
 * Trimmed deliberately: config files acquire trailing newlines, and the
 * receiver's copy of the secret is invariably the trimmed literal, so trimming
 * turns an invisible whitespace mismatch into a working signature rather than
 * a 401 nobody can explain.
 *
 * NOTE for anyone editing this: no branch of this function may put the value
 * into a thrown error, a log line, or a return value other than the secret
 * itself. It is the only credential in this config.
 */
export function normaliseWebhookSecret(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const trimmed = v.trim();
  if (!trimmed || trimmed.length > WEBHOOK_SECRET_MAX_LENGTH) return undefined;
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
    // Strict true for the same reason as `enabled`: this arms a channel that
    // raises native gateway approval cards. Junk degrades to "not opted in".
    openclaw: raw.openclaw === true,
    // #331 — volume window. Explicit 0 disables. Junk → default 15m.
    // Never derived from permission_mode or any payload field.
    dnpDigestWindowMs: normaliseDnpDigestWindowMs(raw.dnpDigestWindowMs),
  };

  const webhookUrl = normaliseWebhookUrl(raw.webhookUrl);
  if (webhookUrl !== undefined) cfg.webhookUrl = webhookUrl;

  // Kept independent of `webhookUrl`: a secret configured without a URL is
  // harmless (nothing signs anything), and dropping it here would make a
  // later URL fix silently produce unsigned POSTs.
  const webhookSecret = normaliseWebhookSecret(raw.webhookSecret);
  if (webhookSecret !== undefined) cfg.webhookSecret = webhookSecret;

  return cfg;
}
