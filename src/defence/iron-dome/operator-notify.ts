/**
 * ShieldCortex — channel-agnostic operator-notification transport (#143).
 *
 * Design: docs/design/2026-07-31-ai-approval-broker.md, acceptance criterion 1.
 *
 * The missing half of the approval broker. Everything else in this feature —
 * the decision core (approval-broker.ts), the judge (approval-judge.ts), the
 * one-shot store (action-approvals.ts, #118) — already existed. What did not
 * exist was a way to REACH the operator when the guard holds: 433 real stops
 * on the Jarvis box in July all dead-ended on the Claude Code hook path,
 * because it had no channel at all, only a hash printed somewhere nobody was
 * watching.
 *
 * This module is deliberately small and does exactly one thing: try a
 * sequence of channels (TUI if attended, then a configured channel) and
 * report which one — if any — successfully handed a human-readable
 * notification to a transport that can carry it to the operator.
 *
 * The one invariant every export here exists to protect:
 *
 *   **Delivering a notification is not consent.**
 *
 * `requestOperatorApproval` can never return an approval, a denial, or
 * anything that looks like one — its result type is `{ deliveredVia, attempts
 * }` and nothing else, by construction (see the adversarial tests in
 * __tests__/operator-notify.test.ts, which prove a channel cannot smuggle an
 * "approved" field through it). The human's actual answer always arrives
 * later, out of band, through `approveRequest` / `denyRequest` in
 * action-approvals.ts, keyed to the SAME hash this notification carries. This
 * module does not import that store at all — not "does not call it", does
 * not import it — so it is structurally incapable of granting anything, not
 * merely disciplined about not doing so.
 *
 * Consequences that follow from that one property:
 *   - A channel that throws, hangs past its deadline, or returns a malformed
 *     result is indistinguishable from one that was never configured: all of
 *     them fall through to the next channel, and ultimately to `null`.
 *   - `null` is not a failure state for this module — it is the honest
 *     answer whenever no channel is configured (issue #143 requirement 7:
 *     default off, nothing changes for an operator who has not opted in) or
 *     every configured channel failed. The caller's existing hash-in-terminal
 *     fallback (#118's `shieldcortex approve <hash>`) is NEVER removed and
 *     is not this module's concern — it is the floor beneath this module,
 *     not a rung of it.
 */

/** What the judge (approval-judge.ts) found, carried for display only. This
 *  module never re-derives a decision from it — see the module doc above. */
export interface NotificationJudgeSummary {
  assessment: string;
  confidence: number;
  inContext: boolean;
  injectionSuspected: boolean;
  rationale?: string;
}

/**
 * The full notification content. Every field the operator needs to resist
 * social engineering is here: the exact command, what tripped, the tier, the
 * judge's own read if one ran, and a fallback hint bound to the SAME hash a
 * reply must act on (design doc requirement: "readable enough that you can't
 * be tricked into tapping yes on something you didn't initiate").
 */
export interface OperatorNotification {
  /** Full sha256 from action-approvals.ts's hashToolCall. The one thing every
   *  reply — tap, webhook, or terminal — must be bound to. */
  hash: string;
  shortHash: string;
  tool: string;
  /** The exact command/target the guard flagged — never a paraphrase. */
  command: string;
  /** Signals from the guard verdict — "what tripped". */
  signals: string[];
  /** Guard tier (dangerous/sensitive/...). Catastrophic never reaches here —
   *  it hard-blocks before any approval flow exists (approval-broker.ts). */
  severity: string;
  reason: string;
  /** The broker's judge verdict, when the broker ran one. Null means no
   *  judge ran — rendered explicitly, never silently omitted, so "no AI
   *  looked at this" is as visible as a verdict would be. */
  judge: NotificationJudgeSummary | null;
  /** The `shieldcortex approve <hash>` / `shieldcortex deny <hash>` text.
   *  ALWAYS present — this is the floor (#118) and is never conditional on
   *  whether a channel is configured or expected to succeed. */
  fallbackHint: string;
}

export type ChannelSendResult =
  | { delivered: true }
  | { delivered: false; reason: string };

/**
 * A channel is anything that can hand a notification to a human and report
 * whether the HANDOFF succeeded — never anything that reports the human's
 * decision. Structurally typed and narrow on purpose (mirrors
 * `ModelInvoker` in approval-judge.ts and `BrokerInvokerContext` in
 * broker-invoker.ts): a narrow seam is one a fake can honestly satisfy in
 * tests, and one a real transport (a TUI, a webhook, an OpenClaw gateway
 * message call) can implement without dragging its client library into the
 * guard core. See webhook-notify-channel.ts and
 * plugins/openclaw/gateway-notify-channel.ts for concrete implementations —
 * NOTHING channel-specific (no Telegram client, no fetch call) lives here.
 */
export interface NotifyChannel {
  name: string;
  send(notification: OperatorNotification, opts: { timeoutMs: number }): Promise<ChannelSendResult>;
}

export interface RequestOperatorApprovalInput {
  hash: string;
  tool: string;
  command: string;
  signals: string[];
  severity: string;
  reason: string;
  judge?: NotificationJudgeSummary | null;
}

export interface RequestOperatorApprovalDeps {
  /** Tried FIRST, and only when `attended` is true. In practice this tier is
   *  usually satisfied by the host's own synchronous UI (Claude Code's ask
   *  dialog, OpenClaw's `context.requireApproval` card) rather than a channel
   *  built against this interface — so callers on those surfaces typically
   *  leave this unset and rely on their own existing prompt, using this
   *  module only for the tiers below it. It exists so a surface WITHOUT one
   *  of those (a bespoke TUI) has somewhere to plug in. */
  tui?: NotifyChannel;
  attended?: boolean;
  /** The configured channel — webhook, gateway message call, whatever the
   *  operator set up. Absent means "not opted in" (#143 requirement 7:
   *  default off) and this tier is skipped entirely, not attempted-and-failed. */
  channel?: NotifyChannel;
  /** Per-channel delivery deadline. A hanging transport must not hang the
   *  guard — same instinct as cli-invoker.ts's hard kill deadline. */
  timeoutMs?: number;
  /** Test/observability seam — fired after each attempt, success or failure. */
  onAttempt?: (channel: string, result: ChannelSendResult) => void;
}

export interface RequestOperatorApprovalResult {
  /** Which channel delivered, or null if none did (including "none configured").
   *  This is the ONLY outcome field. There is deliberately no field here that
   *  could be mistaken for, or repurposed into, an approval — see module doc. */
  deliveredVia: string | null;
  attempts: Array<{ channel: string; result: ChannelSendResult }>;
}

const DEFAULT_TIMEOUT_MS = 10_000;
/** A notification is a short alert, not a document. Bounding the rendered
 *  command keeps a single pathological tool call from producing a
 *  multi-megabyte push notification or webhook payload. */
const MAX_COMMAND_CHARS = 2_000;

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max)}… [truncated ${text.length - max} chars]`;
}

/** Build the notification content once, so every channel in the resolution
 *  order sees byte-identical fields — no channel gets a "friendlier" or
 *  differently-scoped version of what tripped. */
function buildNotification(input: RequestOperatorApprovalInput): OperatorNotification {
  const shortHash = input.hash.slice(0, 12);
  return {
    hash: input.hash,
    shortHash,
    tool: input.tool,
    command: truncate(input.command, MAX_COMMAND_CHARS),
    signals: [...input.signals],
    severity: input.severity,
    reason: input.reason,
    judge: input.judge ?? null,
    fallbackHint: `shieldcortex approve ${shortHash}   |   shieldcortex deny ${shortHash}`,
  };
}

/** Human-readable rendering, used by channels that send plain text (webhook
 *  bodies, gateway chat messages). Channels are free to build their own
 *  richer presentation (inline buttons, etc.) from the structured
 *  `OperatorNotification` instead — this is the lowest common denominator. */
export function formatOperatorNotification(n: OperatorNotification): string {
  const lines = [
    '🛡️ ShieldCortex — approval needed',
    '',
    `Tool:      ${n.tool}`,
    `Command:   ${n.command}`,
    `Tripped:   ${n.signals.join(', ') || 'none'}`,
    `Tier:      ${n.severity}`,
    `Reason:    ${n.reason}`,
    '',
  ];
  if (n.judge) {
    lines.push(
      `AI judge:  ${n.judge.assessment} (confidence ${n.judge.confidence})` +
        `${n.judge.inContext ? '' : ', out of context'}` +
        `${n.judge.injectionSuspected ? ', INJECTION SUSPECTED' : ''}`,
    );
    if (n.judge.rationale) lines.push(`  "${n.judge.rationale}"`);
  } else {
    lines.push('AI judge:  no judge ran — this verdict is rules-only');
  }
  lines.push('');
  lines.push(`[Approve]  shieldcortex approve ${n.shortHash}`);
  lines.push(`[Deny]     shieldcortex deny ${n.shortHash}`);
  return truncate(lines.join('\n'), 4_000);
}

/**
 * Race one channel against a deadline, and normalise EVERY failure mode
 * (throw, timeout, malformed result) to the same `{ delivered: false }`
 * shape. There is no path through this function that turns a broken channel
 * into a delivered one.
 */
async function tryChannel(
  channel: NotifyChannel,
  notification: OperatorNotification,
  timeoutMs: number,
): Promise<ChannelSendResult> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      channel.send(notification, { timeoutMs }),
      new Promise<ChannelSendResult>((resolve) => {
        timer = setTimeout(() => resolve({ delivered: false, reason: `timed out after ${timeoutMs}ms` }), timeoutMs);
      }),
    ]);
    if (!result || typeof result !== 'object' || typeof (result as { delivered?: unknown }).delivered !== 'boolean') {
      return { delivered: false, reason: 'channel returned a malformed result' };
    }
    if (result.delivered !== true) {
      const reason = (result as { reason?: unknown }).reason;
      return { delivered: false, reason: typeof reason === 'string' ? reason : 'channel reported delivery failure' };
    }
    // Narrow to exactly the shape this module promises callers — a hostile or
    // careless channel returning extra fields (`approved: true`, `decision:
    // 'approve'`) does not leak past this point.
    return { delivered: true };
  } catch (err) {
    return { delivered: false, reason: err instanceof Error ? err.message : String(err) };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Try to reach the operator: TUI first (only if `attended`), then the
 * configured channel. Returns which one delivered, or null.
 *
 * This function does not record a pending approval, does not consume one,
 * and does not decide approve/deny — see the module doc. Callers keep doing
 * exactly what they did before #143 (record the pending hash, offer the
 * terminal fallback); this is purely an additional, best-effort ping layered
 * in front of that unchanged floor.
 */
export async function requestOperatorApproval(
  input: RequestOperatorApprovalInput,
  deps: RequestOperatorApprovalDeps,
): Promise<RequestOperatorApprovalResult> {
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const notification = buildNotification(input);
  const attempts: RequestOperatorApprovalResult['attempts'] = [];

  const candidates: NotifyChannel[] = [];
  if (deps.attended && deps.tui) candidates.push(deps.tui);
  if (deps.channel) candidates.push(deps.channel);

  for (const ch of candidates) {
    const result = await tryChannel(ch, notification, timeoutMs);
    attempts.push({ channel: ch.name, result });
    deps.onAttempt?.(ch.name, result);
    if (result.delivered) return { deliveredVia: ch.name, attempts };
  }

  return { deliveredVia: null, attempts };
}
