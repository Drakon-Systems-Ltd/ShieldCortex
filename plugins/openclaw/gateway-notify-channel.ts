/**
 * ShieldCortex — the OpenClaw gateway operator-notify channel (#143).
 *
 * Design: docs/design/2026-07-31-ai-approval-broker.md, acceptance criterion 6:
 * "On OpenClaw the transport should use the gateway's own message capability."
 *
 * Same shape and same reasoning as broker-invoker.ts's `createGatewayInvoker`:
 * the gateway does not expose a message-sending seam to plugins by any fixed
 * contract today, so this defines the narrowest one that could satisfy the
 * design and fails closed when it is absent —
 *
 *   no `context.notifyOperator` → no invoker → `createGatewayNotifyChannel`
 *   returns null → `requestOperatorApproval`'s resolution order (see
 *   operator-notify.ts) simply has one fewer candidate and falls through to
 *   whatever else is configured, ultimately to the unchanged
 *   hash-in-terminal fallback.
 *
 * Which is exactly today's behaviour on every gateway build shipping now:
 * nothing regresses, and wiring this up costs nothing on a host that hasn't
 * implemented the seam yet.
 *
 * What this file deliberately does NOT contain: any client for Telegram,
 * WhatsApp, or any other chat platform. That lives entirely on the gateway
 * side of `notifyOperator`, wherever the host chooses to implement it — this
 * plugin only ever hands over structured data and a rendered text fallback,
 * mirroring the "no Telegram client hard-coded into the guard core"
 * requirement from the design doc.
 *
 * Types are declared/rendered LOCALLY rather than imported from
 * `shieldcortex/defence/iron-dome/operator-notify.js` — same reason
 * `ToolGuardVerdictLike` is structural in interceptor.ts (see that file's
 * header): this module is built by tsconfig.openclaw-plugin.json, whose
 * `rootDir` is `plugins/openclaw`, and a cross-boundary import fails that
 * build (TS6059). `NotifyChannelLike`/`OperatorNotificationLike` mirror
 * `operator-notify.ts`'s real shapes structurally, and the real
 * `requestOperatorApproval` accepts anything satisfying `NotifyChannel`
 * regardless of which module declared the type.
 */

/** Mirrors `NotificationJudgeSummary` in operator-notify.ts, display-only. */
export interface JudgeSummaryLike {
  assessment: string;
  confidence: number;
  inContext: boolean;
  injectionSuspected: boolean;
  rationale?: string;
}

/** Mirrors `OperatorNotification` in operator-notify.ts. */
export interface OperatorNotificationLike {
  hash: string;
  shortHash: string;
  tool: string;
  command: string;
  signals: string[];
  severity: string;
  reason: string;
  judge: JudgeSummaryLike | null;
  fallbackHint: string;
}

export type ChannelSendResultLike = { delivered: true } | { delivered: false; reason: string };

/** Mirrors `NotifyChannel` in operator-notify.ts. */
export interface NotifyChannelLike {
  name: string;
  send(notification: OperatorNotificationLike, opts: { timeoutMs: number }): Promise<ChannelSendResultLike>;
}

/** What the gateway seam is handed — trusted-or-bounded fields only, same
 *  discipline as `GatewayCompletionRequest` in broker-invoker.ts. */
export interface GatewayOperatorMessage {
  text: string;
  hash: string;
  shortHash: string;
  tool: string;
  command: string;
  signals: string[];
  severity: string;
  approveCommand: string;
  denyCommand: string;
}

/** The optional seam. Structural, so any gateway shape that fits can supply it. */
export interface GatewayNotifyContext {
  notifyOperator?: (message: GatewayOperatorMessage) => Promise<unknown>;
}

/**
 * Local, minimal text rendering — deliberately duplicated rather than
 * imported (see the module header). Kept in sync BY HAND with
 * `formatOperatorNotification` in operator-notify.ts, whose own test suite
 * pins the fields that must appear (exact command, tripped signals, tier,
 * judge verdict, both affordances on the same hash); this local copy is
 * pinned by this file's own tests below the same way.
 */
function renderText(n: OperatorNotificationLike): string {
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
  return lines.join('\n').slice(0, 4_000);
}

function buildMessage(n: OperatorNotificationLike): GatewayOperatorMessage {
  return {
    text: renderText(n),
    hash: n.hash,
    shortHash: n.shortHash,
    tool: n.tool,
    command: n.command,
    signals: n.signals,
    severity: n.severity,
    approveCommand: `shieldcortex approve ${n.shortHash}`,
    denyCommand: `shieldcortex deny ${n.shortHash}`,
  };
}

/**
 * Read the seam's ack as narrowly as `coerceCompletion` reads a completion in
 * broker-invoker.ts: a resolved call with no explicit `{ delivered: false }`
 * is treated as accepted (some hosts will not have a richer ack shape at
 * all), but an EXPLICIT `delivered: false` is honoured, and nothing beyond
 * the boolean is ever read — a hostile or careless host echoing back
 * `approved: true` gets nothing from this for it.
 */
function coerceAck(raw: unknown): ChannelSendResultLike {
  if (raw && typeof raw === 'object' && (raw as { delivered?: unknown }).delivered === false) {
    const reason = (raw as { reason?: unknown }).reason;
    return { delivered: false, reason: typeof reason === 'string' ? reason : 'gateway reported delivery failure' };
  }
  return { delivered: true };
}

/**
 * Build a notify channel from the gateway's own message seam, or null when
 * the gateway does not offer one. Null is not an error state — see the
 * module doc.
 */
export function createGatewayNotifyChannel(context: GatewayNotifyContext): NotifyChannelLike | null {
  if (!context || typeof context !== 'object') return null;
  const notifyOperator = context.notifyOperator;
  if (typeof notifyOperator !== 'function') return null;

  return {
    name: 'gateway',
    async send(notification): Promise<ChannelSendResultLike> {
      try {
        const raw = await notifyOperator(buildMessage(notification));
        return coerceAck(raw);
      } catch (err) {
        return { delivered: false, reason: err instanceof Error ? err.message : String(err) };
      }
    },
  };
}
