/**
 * ShieldCortex — the "nothing ran" follow-up for a held Plane A card (#853).
 *
 * When a held retry card ends without an Approve (it expired, the operator
 * denied it, or its transport failed), the owner is told so, once, with no
 * buttons. The detached #310 waiter is the only process alive at that moment,
 * so it is the one that sends.
 *
 * Where it goes, honestly:
 *   - the configured DENIAL sink (`actionGuard.notify.webhookUrl`), the same
 *     sink every headless denial already uses. The body is an action-guard
 *     outcome alert, which structurally carries no approve/deny command, so a
 *     receiver that draws buttons from those fields draws none;
 *   - otherwise it is QUEUED in the retry store and rides the next operator
 *     notify (`drainHeldFollowUps` in the hook), because this codebase has no
 *     verified no-button send path on the OpenClaw gateway that drew the card
 *     (the same gap `loadNotify` in the hook documents for `denialChannel`).
 *
 * It never throws and never touches a grant, a claim or a suppression.
 */
import { closeSync, constants, existsSync, fstatSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

import { normaliseNotifyConfig } from './notify-config.js';
import { buildActionGuardOutcomeNotification, type ActionGuardOutcomeNotification } from './operator-notify.js';
import { heldFollowUpLine, queueHeldFollowUp, type ExpiredGrantNotice, type HeldFollowUp } from './retry-control.js';
import { createWebhookNotifyChannel } from './webhook-notify-channel.js';

/** The outcome each follow-up kind is reported under (denials.jsonl, webhook). */
export const HELD_FOLLOW_UP_OUTCOMES: Readonly<Record<HeldFollowUp['kind'], string>> = Object.freeze({
  expired: 'retry_card_expired',
  denied: 'retry_denied',
  failed: 'retry_card_failed',
  grant_failed: 'retry_grant_failed',
});

const FOLLOW_UP_TIMEOUT_MS = 5_000;

export type HeldFollowUpStatus = 'delivered' | 'queued' | 'dropped';

export interface HeldFollowUpOptions {
  home?: string;
  /** Defaults to SHIELDCORTEX_CONFIG_DIR, else `<home>/.shieldcortex` — the
   *  same resolution the hook uses (#501), so both read ONE config file. */
  configDir?: string;
  fetchImpl?: typeof fetch;
  now?: number;
}

function configDirFor(opts: HeldFollowUpOptions): string {
  if (opts.configDir) return opts.configDir;
  if (opts.home === undefined) {
    const override = process.env.SHIELDCORTEX_CONFIG_DIR?.trim();
    if (override) return override;
  }
  return join(opts.home ?? homedir(), '.shieldcortex');
}

/** `actionGuard.notify`, with the deprecated `interceptor.actionGuard` alias
 *  filling the gap exactly as the hook's flatten does (#209). */
function readNotifyBlock(configDir: string): unknown {
  try {
    const file = join(configDir, 'config.json');
    if (!existsSync(file)) return null;
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    const isBlock = (v: unknown): v is Record<string, unknown> =>
      !!v && typeof v === 'object' && !Array.isArray(v);
    const top = isBlock(parsed.actionGuard) ? parsed.actionGuard : null;
    const interceptor = isBlock(parsed.interceptor) ? parsed.interceptor : null;
    const alias = interceptor && isBlock(interceptor.actionGuard) ? interceptor.actionGuard : null;
    return top?.notify ?? alias?.notify ?? null;
  } catch {
    return null;
  }
}

/** The no-button alert body. `digestText` is what text renderers print. */
export function buildHeldFollowUpNotification(
  item: HeldFollowUp,
): ActionGuardOutcomeNotification & { digestText: string } {
  const n = buildActionGuardOutcomeNotification({
    event: 'action_guard_denial',
    outcome: HELD_FOLLOW_UP_OUTCOMES[item.kind],
    tool: item.tool,
    surface: '',
    signals: [],
    severity: 'unknown',
    // Rebuilt by the builder from the outcome; never free text from here.
    reason: '',
    ...(item.actionId ? { actionId: item.actionId } : {}),
    origin: 'claude-code-hook',
    detectedAt: new Date(item.at).toISOString(),
  });
  return { ...n, digestText: heldFollowUpLine(item) };
}

/**
 * Deliver now on the denial sink, or queue for the next notify. The returned
 * status is what the waiter writes on its denials.jsonl row.
 */
export async function deliverHeldFollowUp(
  item: HeldFollowUp,
  opts: HeldFollowUpOptions = {},
): Promise<HeldFollowUpStatus> {
  try {
    const notify = normaliseNotifyConfig(readNotifyBlock(configDirFor(opts)));
    if (notify.enabled && notify.webhookUrl) {
      const channel = createWebhookNotifyChannel({
        url: notify.webhookUrl,
        secret: notify.webhookSecret,
        ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
      });
      const sent = await channel.send(buildHeldFollowUpNotification(item), {
        timeoutMs: FOLLOW_UP_TIMEOUT_MS,
      });
      if (sent?.delivered) return 'delivered';
    }
  } catch {
    /* fall through to the queue */
  }
  return queueHeldFollowUp(item, { home: opts.home }) ? 'queued' : 'dropped';
}

/**
 * The operator-visible half of the ack. `denials.jsonl` is the file operators
 * already open after a headless denial, so a retry outcome belongs on the same
 * line-oriented record — no new sink, no new route, nothing to configure.
 * Never carries the nonce, the hash, or the command.
 */
export function appendRetryOutcomeRow(
  row: Record<string, unknown>,
  opts: { home?: string } = {},
): boolean {
  const file = join(opts.home ?? homedir(), '.shieldcortex', 'denials.jsonl');
  let fd: number | undefined;
  try {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    fd = openSync(
      file,
      constants.O_CREAT | constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink > 1) return false;
    writeFileSync(fd, `${JSON.stringify({ ...row, detectedAt: new Date().toISOString() })}\n`);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
  }
}

/**
 * #853 — one `retry_grant_expired_unspent` row per grant the sweeper removed:
 * the operator allowed ONE retry and nothing used it (for a one-shot worker,
 * the launcher never re-ran it). The sweep deletes the grant, and its notice
 * only rides a send that may not happen, so this row is the durable record.
 * Returns how many rows were written; never throws.
 */
export function recordUnspentGrantExpiries(
  expired: ExpiredGrantNotice[],
  opts: { home?: string } = {},
): number {
  let written = 0;
  for (const g of Array.isArray(expired) ? expired : []) {
    try {
      const minutes = Math.max(1, Math.round(Number(g.ttlMs) / 60_000) || 1);
      const ok = appendRetryOutcomeRow(
        {
          event: 'action_guard_denial',
          outcome: 'retry_grant_expired_unspent',
          origin: 'claude-code-hook',
          tool: String(g.tool || 'tool').slice(0, 64),
          reason: `the operator allowed ONE retry (${minutes}m) and nothing retried the call before it expired; nothing ran`,
          ...(typeof g.actionId === 'string' && /^act-[0-9a-f]{16}$/.test(g.actionId) ? { actionId: g.actionId } : {}),
        },
        opts,
      );
      if (ok) written += 1;
    } catch {
      /* a row that cannot be written never changes a decision */
    }
  }
  return written;
}
