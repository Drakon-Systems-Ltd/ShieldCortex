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

/**
 * What actually happened to the held call, from the operator's point of view.
 *
 * The distinction is not cosmetic. On a promptless box — `bypassPermissions`,
 * which is how every unattended agent and cron on this fleet runs — the hook
 * cannot raise a prompt, so the guard DENIES rather than leaving an
 * unanswerable ask (#139). Before this discriminator existed, both outcomes
 * were notified with the same "approval needed" wording, so the operator was
 * asked to approve something that had already been refused and handed back to
 * the agent seconds earlier. Measured cost of that on this fleet: 41 gated
 * actions hard-denied in one week with nobody told a job had died.
 *
 *   'approval_requested'      — the call is HELD, a human answer still decides it.
 *   'denied_no_prompt_surface' — the call is DEAD. Nothing is waiting on the
 *                                operator; this is an incident report, and the
 *                                only forward path is authorising a RETRY.
 *   'conversation_threat'      — the conversation firewall saw something on the
 *                                INPUT path (#225). There is no held tool call,
 *                                no approval hash, and nothing for the operator
 *                                to approve — see ConversationThreatNotification.
 */
export type OperatorNotificationEvent =
  | 'approval_requested'
  | 'denied_no_prompt_surface'
  | 'conversation_threat';

export type ActionGuardOutcomeEvent = 'action_guard_denial' | 'action_guard_warning';

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
  /** Which of the two outcomes this is. Required, because a notification whose
   *  wording does not match what happened is worse than none: the operator
   *  learns that these messages are approximately true and stops reading them.
   *  Every pre-existing construction site supplies 'approval_requested', which
   *  is exactly what they all meant before the discriminator existed.
   *
   *  'conversation_threat' is deliberately NOT assignable here: that event has
   *  no hash, tool or command, so it gets its own type
   *  (`ConversationThreatNotification`) rather than this one with holes in it.
   *  Excluding it also makes the two a real discriminated union. */
  event: Exclude<OperatorNotificationEvent, 'conversation_threat'>;
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
  /** WHY no prompt could be raised, verbatim from the hook's
   *  `noPromptSurfaceReason` (e.g. `bypassPermissions mode shows no prompt`).
   *  Only set on 'denied_no_prompt_surface' — on the approval path there is
   *  nothing to explain, the ask went out. */
  deniedReason?: string;
  /** Which job this was. An alert that says "something was blocked somewhere"
   *  is unactionable: the operator's next move is always to go look at the job
   *  that died, and these two fields are the only handle on it this hook has
   *  (`session_id` / `cwd` off the harness payload). Carried on both events —
   *  useful on an ask, load-bearing on a denial. */
  sessionId?: string;
  cwd?: string;
  /** The `shieldcortex approve <hash>` / `shieldcortex deny <hash>` text.
   *  ALWAYS present — this is the floor (#118) and is never conditional on
   *  whether a channel is configured or expected to succeed. On a denial it
   *  carries the approve half only: the call is already refused, so "deny" is
   *  an affordance with nothing behind it. */
  fallbackHint: string;
}

/**
 * What the conversation firewall did about what it saw (#225).
 *
 *   'blocked'     — posture `enforce` and a dirty verdict: the run did NOT go
 *                   to the model.
 *   'observed'    — a dirty verdict under posture `observe`: the run PROCEEDED.
 *                   Saying "blocked" here would be the same lie #143's event
 *                   discriminator exists to prevent.
 *   'unavailable' — the scanner could not be run at all. The turn proceeded
 *                   UNSCANNED, which is neither clean nor protected and must
 *                   never be rendered as either.
 */
export type ConversationThreatOutcome = 'blocked' | 'observed' | 'unavailable';

/**
 * A conversation-firewall detection, on its way to a human (#225).
 *
 * Deliberately NOT an `OperatorNotification`. There is no held call behind it,
 * so there is no `hash`, no `tool`, no `command` and no approve/deny pair — and
 * because those fields do not exist on this type, no channel can render an
 * Approve button bound to `undefined`, which is exactly what the first cut of
 * this feature did by casting an ad-hoc `{kind, ...}` object through
 * `NotifyChannel.send`. A notification the operator can tap and change nothing
 * is how they learn to ignore the ones that matter.
 *
 * What it carries is bounded and derived: a risk SUMMARY from the scanner, the
 * posture, the outcome, and enough identity to find the session. It never
 * carries the prompt — the input that tripped a prompt-injection detector is
 * hostile text by assumption, and forwarding it onto a chat surface would
 * relay the attack to the operator's phone.
 */
export interface ConversationThreatNotification {
  event: 'conversation_threat';
  outcome: ConversationThreatOutcome;
  /** The configured posture at the moment of the decision (off/observe/enforce). */
  posture: string;
  /** Scanner verdict summary, e.g. `HIGH (2 detections)`. Never prompt text. */
  summary: string;
  /** One-line operator-facing explanation, built by the caller. */
  reason: string;
  /** Which conversation, so the operator can go and look. */
  sessionId?: string;
  /** Model the run would have gone to, when the host names it. */
  model?: string;
  /** Which box. A fleet alert with no host is unactionable. */
  host?: string;
  detectedAt: string;
}

/**
 * A terminal Action Guard outcome alert (#242/#243).
 *
 * This is deliberately NOT an `OperatorNotification`: there is no pending
 * approval handle, no hash that can authorise the already-refused call, and the
 * command surface is redacted/allowlisted by the caller before construction.
 * Denied commands are enriched for secret/data-egress content by construction;
 * forwarding them verbatim would turn the alert channel into a leak path.
 */
export interface ActionGuardOutcomeNotification {
  event: ActionGuardOutcomeEvent;
  outcome: string;
  tool: string;
  /** Redacted/allowlisted description only — never the raw command body. */
  surface: string;
  signals: string[];
  severity: string;
  reason: string;
  /** Stable non-secret correlation key, e.g. a local digest; never a raw session id. */
  correlationId?: string;
  detectedAt: string;
}

/** Every shape a channel can be handed. */
export type AnyOperatorNotification = OperatorNotification | ConversationThreatNotification | ActionGuardOutcomeNotification;

export function isActionGuardOutcomeNotification(
  n: AnyOperatorNotification,
): n is ActionGuardOutcomeNotification {
  return n.event === 'action_guard_denial' || n.event === 'action_guard_warning';
}

export function isConversationThreatNotification(
  n: AnyOperatorNotification,
): n is ConversationThreatNotification {
  return (n as { event?: unknown })?.event === 'conversation_threat';
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
  send(notification: AnyOperatorNotification, opts: { timeoutMs: number }): Promise<ChannelSendResult>;
}

export interface RequestOperatorApprovalInput {
  hash: string;
  tool: string;
  command: string;
  signals: string[];
  severity: string;
  reason: string;
  judge?: NotificationJudgeSummary | null;
  /** Defaults to 'approval_requested' — so a caller written before the
   *  discriminator existed keeps producing byte-identical notifications.
   *  A conversation-firewall alert is not requested through here: it has no
   *  hash to bind a reply to. Use `buildConversationThreatNotification` +
   *  `deliverOperatorNotification`. */
  event?: Exclude<OperatorNotificationEvent, 'conversation_threat'>;
  /** Only meaningful with event: 'denied_no_prompt_surface'; ignored otherwise
   *  rather than rendered, so a caller cannot accidentally tell the operator an
   *  action was blocked when it is merely held. */
  deniedReason?: string;
  sessionId?: string;
  cwd?: string;
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
/** Session id, cwd and the denial reason all arrive from the harness's own
 *  JSON payload, which this module does not control. Same instinct as
 *  MAX_COMMAND_CHARS: bound anything that crosses in from outside before it
 *  becomes a push notification. */
const MAX_CONTEXT_CHARS = 500;

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max)}… [truncated ${text.length - max} chars]`;
}

/** A bounded, non-empty string, or undefined — a field we cannot render
 *  honestly is omitted rather than shown as "undefined". */
function optionalText(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const trimmed = v.trim();
  if (!trimmed) return undefined;
  return truncate(trimmed, MAX_CONTEXT_CHARS);
}

/** Build the notification content once, so every channel in the resolution
 *  order sees byte-identical fields — no channel gets a "friendlier" or
 *  differently-scoped version of what tripped. */
function buildNotification(input: RequestOperatorApprovalInput): OperatorNotification {
  const shortHash = input.hash.slice(0, 12);
  const denied = input.event === 'denied_no_prompt_surface';
  const notification: OperatorNotification = {
    event: denied ? 'denied_no_prompt_surface' : 'approval_requested',
    hash: input.hash,
    shortHash,
    tool: input.tool,
    command: truncate(input.command, MAX_COMMAND_CHARS),
    signals: [...input.signals],
    severity: input.severity,
    reason: input.reason,
    judge: input.judge ?? null,
    // On a denial the deny half is dropped: the guard already said no, and an
    // affordance that does nothing is how an operator learns to ignore the
    // ones that do.
    fallbackHint: denied
      ? `shieldcortex approve ${shortHash}   (authorises a RETRY — the blocked call is already gone)`
      : `shieldcortex approve ${shortHash}   |   shieldcortex deny ${shortHash}`,
  };
  // Only set on the event they belong to, so an absent field is unambiguous
  // rather than "maybe the caller forgot".
  if (denied) {
    const deniedReason = optionalText(input.deniedReason);
    if (deniedReason) notification.deniedReason = deniedReason;
  }
  const sessionId = optionalText(input.sessionId);
  if (sessionId) notification.sessionId = sessionId;
  const cwd = optionalText(input.cwd);
  if (cwd) notification.cwd = cwd;
  return notification;
}

/** The bounded fields a caller may supply for a conversation-firewall alert.
 *  Everything here is truncated and type-checked before it becomes a payload:
 *  the caller is the OpenClaw plugin, running inside a gateway whose input is
 *  by definition untrusted on this path. */
export interface ConversationThreatInput {
  outcome: ConversationThreatOutcome;
  posture: string;
  summary: string;
  reason: string;
  sessionId?: string;
  model?: string;
  host?: string;
  /** ISO timestamp; supplied by the caller so a test can pin it. */
  detectedAt: string;
}

export interface ActionGuardOutcomeInput {
  event: ActionGuardOutcomeEvent;
  outcome: string;
  tool: string;
  surface: string;
  signals: string[];
  severity: string;
  reason: string;
  /** Stable non-secret correlation key, e.g. a local digest; never a raw session id. */
  correlationId?: string;
  /** ISO timestamp; supplied by the caller so a test can pin it. */
  detectedAt: string;
}

const SAFE_ACTION_GUARD_TOOLS = new Set([
  'Bash', 'Edit', 'MultiEdit', 'Write', 'Read', 'Glob', 'Grep', 'LS', 'Task',
  'TodoWrite', 'WebFetch', 'WebSearch', 'NotebookEdit', 'Workflow',
]);
const SAFE_ACTION_GUARD_SIGNALS = new Set([
  'secret-egress', 'approval-required', 'fallback-scan', 'privilege-escalation',
  'filesystem-destructive', 'destructive-filesystem', 'dangerous-shell',
  'command-exec', 'network-egress', 'credential-access', 'data-exfiltration',
  'untrusted-script', 'reviewed-script', 'shell-injection', 'persistence-risk',
]);
const SAFE_ACTION_GUARD_OUTCOMES = new Set([
  'auto_denied', 'denied_no_prompt_surface', 'failure_denied', 'warned', 'failure_allowed',
]);
const SAFE_ACTION_GUARD_SEVERITIES = new Set(['critical', 'dangerous', 'high', 'medium', 'low', 'benign', 'unknown']);

function safeActionGuardTool(v: unknown): string {
  return SAFE_ACTION_GUARD_TOOLS.has(String(v ?? '')) ? String(v) : 'tool';
}

function safeActionGuardOutcome(v: unknown): string {
  const outcome = String(v ?? '');
  return SAFE_ACTION_GUARD_OUTCOMES.has(outcome) ? outcome : 'guard_outcome';
}

function safeActionGuardSeverity(v: unknown, event: ActionGuardOutcomeEvent): string {
  const severity = String(v ?? '');
  if (SAFE_ACTION_GUARD_SEVERITIES.has(severity)) return severity;
  return event === 'action_guard_denial' ? 'high' : 'medium';
}

function safeActionGuardSignals(signals: unknown): string[] {
  if (!Array.isArray(signals)) return [];
  const out: string[] = [];
  let redacted = false;
  for (const raw of signals) {
    const signal = String(raw ?? '').trim();
    if (SAFE_ACTION_GUARD_SIGNALS.has(signal)) out.push(signal);
    else if (signal) redacted = true;
  }
  if (redacted) out.push('redacted-signal');
  return out.filter((signal, index) => out.indexOf(signal) === index).slice(0, 25);
}

function safeActionGuardReason(event: ActionGuardOutcomeEvent, outcome: string): string {
  if (event === 'action_guard_warning') {
    return outcome === 'failure_allowed'
      ? 'Action Guard was unavailable or advisory-only and the tool call was not blocked; inspect local audit for details.'
      : 'Action Guard warning in advisory mode; inspect local audit for details.';
  }
  if (outcome === 'denied_no_prompt_surface') {
    return 'Action Guard required approval but this session has no prompt surface; the tool call was denied.';
  }
  if (outcome === 'failure_denied') {
    return 'Action Guard was unavailable and fallback policy denied the tool call; inspect local audit for details.';
  }
  return 'Action Guard denied the tool call; inspect local audit for details.';
}

function safeActionGuardCorrelationId(v: unknown): string | undefined {
  const text = String(v ?? '').trim();
  return /^sc-[a-f0-9]{16}$/.test(text) ? text : undefined;
}

function safeDetectedAt(v: unknown): string {
  const text = String(v ?? '').trim();
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(text)
    ? text
    : '1970-01-01T00:00:00.000Z';
}

export function buildActionGuardOutcomeNotification(
  input: ActionGuardOutcomeInput,
): ActionGuardOutcomeNotification {
  const event: ActionGuardOutcomeEvent = input.event === 'action_guard_warning' ? 'action_guard_warning' : 'action_guard_denial';
  const outcome = safeActionGuardOutcome(input.outcome);
  const n: ActionGuardOutcomeNotification = {
    event,
    outcome,
    tool: safeActionGuardTool(input.tool),
    surface: 'redacted action surface',
    signals: safeActionGuardSignals(input.signals),
    severity: safeActionGuardSeverity(input.severity, event),
    reason: safeActionGuardReason(event, outcome),
    detectedAt: safeDetectedAt(input.detectedAt),
  };
  const correlationId = safeActionGuardCorrelationId(input.correlationId);
  if (correlationId) n.correlationId = correlationId;
  return n;
}

/**
 * Build a conversation-threat notification (#225). The single construction
 * point, mirroring `buildNotification` for the approval path: every channel
 * then sees byte-identical, bounded fields, and no caller can smuggle prompt
 * text through by putting it in a field this builder does not truncate.
 */
export function buildConversationThreatNotification(
  input: ConversationThreatInput,
): ConversationThreatNotification {
  const n: ConversationThreatNotification = {
    event: 'conversation_threat',
    outcome: input.outcome,
    posture: truncate(String(input.posture ?? 'unknown'), 32),
    summary: truncate(String(input.summary ?? 'unspecified'), MAX_CONTEXT_CHARS),
    reason: truncate(String(input.reason ?? ''), MAX_CONTEXT_CHARS),
    detectedAt: input.detectedAt,
  };
  const sessionId = optionalText(input.sessionId);
  if (sessionId) n.sessionId = sessionId;
  const model = optionalText(input.model);
  if (model) n.model = model;
  const host = optionalText(input.host);
  if (host) n.host = host;
  return n;
}

/**
 * Render a conversation-firewall alert (#225).
 *
 * Three properties this rendering must keep, all of them learned the expensive
 * way in #143: it names WHAT HAPPENED to the turn before anything else (an
 * "observed" alert that reads like a block teaches operators the alerts are
 * approximately true); it offers NO approve/deny affordance, because there is
 * nothing to approve; and it never prints the offending text.
 */
export function formatConversationThreatNotification(n: ConversationThreatNotification): string {
  const headline =
    n.outcome === 'blocked'
      ? '🛡️ ShieldCortex — conversation BLOCKED: this turn did NOT reach the model'
      : n.outcome === 'unavailable'
        ? '🛡️ ShieldCortex — conversation NOT SCANNED: the scanner was unavailable, the turn ran unscanned'
        : '🛡️ ShieldCortex — conversation threat detected: the turn RAN (observe posture, nothing was blocked)';
  const lines = [headline, ''];
  lines.push(
    `Verdict:   ${n.summary}`,
    `Posture:   ${n.posture}`,
    `Outcome:   ${n.outcome}`,
    `Detail:    ${n.reason}`,
  );
  if (n.sessionId) lines.push(`Session:   ${n.sessionId}`);
  if (n.model) lines.push(`Model:     ${n.model}`);
  if (n.host) lines.push(`Host:      ${n.host}`);
  lines.push(`At:        ${n.detectedAt}`);
  lines.push('');
  // No [Approve]/[Deny]: there is no held call and no hash. What an operator
  // can actually do is change the posture or go and read the session.
  lines.push(
    n.outcome === 'observed'
      ? 'Nothing was blocked. To make this posture stop the turn, set interceptor.conversation.posture=enforce.'
      : n.outcome === 'unavailable'
        ? 'The turn was NOT scanned. Check the ShieldCortex install on this host — this is an unprotected turn, not a clean one.'
        : 'The turn was refused before it reached the model. No action is pending.',
  );
  lines.push('The prompt itself is deliberately NOT included in this alert.');
  return truncate(lines.join('\n'), 4_000);
}

export function formatActionGuardOutcomeNotification(n: ActionGuardOutcomeNotification): string {
  const denied = n.event === 'action_guard_denial';
  const lines = [
    denied
      ? '🛡️ ShieldCortex — Action Guard BLOCKED a tool call'
      : '🛡️ ShieldCortex — Action Guard warning: advisory-mode tool call ran',
    '',
    `Tool:      ${n.tool}`,
    `Surface:   ${n.surface}`,
    `Tripped:   ${n.signals.join(', ') || 'none'}`,
    `Tier:      ${n.severity}`,
    `Outcome:   ${n.outcome}`,
    `Reason:    ${n.reason}`,
  ];
  if (n.correlationId) lines.push(`Correlation: ${n.correlationId}`);
  lines.push(`At:        ${n.detectedAt}`);
  lines.push('');
  lines.push(
    denied
      ? 'The call was already refused. No approval is pending; inspect the local audit row/session before authorising any retry.'
      : 'The call was allowed only because actionGuard.enforce=false. Treat this as a degraded-protection signal, not a clean pass.',
  );
  lines.push('The raw command is deliberately NOT included in this alert.');
  return truncate(lines.join('\n'), 4_000);
}

/** Human-readable rendering, used by channels that send plain text (webhook
 *  bodies, gateway chat messages). Channels are free to build their own
 *  richer presentation (inline buttons, etc.) from the structured
 *  `OperatorNotification` instead — this is the lowest common denominator. */
export function formatOperatorNotification(n: AnyOperatorNotification): string {
  // #242/#243 terminal guard alerts have no hash and no command. They are not
  // approval requests; the operator gets a redacted incident report and enough
  // session identity to find the real row locally.
  if (isActionGuardOutcomeNotification(n)) return formatActionGuardOutcomeNotification(n);
  // #225 alerts have no hash, no tool and no command — they get their own
  // rendering rather than an approval layout with empty fields in it.
  if (isConversationThreatNotification(n)) return formatConversationThreatNotification(n);
  // A stale caller (an older dist, a plugin built before the discriminator)
  // can hand over an object with no `event` at all. Anything that is not
  // EXACTLY the denial reads as the approval wording — the same value every
  // pre-#143-denial caller meant — so an unknown value degrades to today's
  // text rather than to a false "this was blocked".
  const denied = n.event === 'denied_no_prompt_surface';
  const lines = denied
    ? ['🛡️ ShieldCortex — BLOCKED: this action did NOT run', '']
    : ['🛡️ ShieldCortex — approval needed', ''];
  lines.push(
    `Tool:      ${n.tool}`,
    `Command:   ${n.command}`,
    `Tripped:   ${n.signals.join(', ') || 'none'}`,
    `Tier:      ${n.severity}`,
    `Reason:    ${n.reason}`,
  );
  if (denied) {
    // WHICH JOB DIED. Without this the alert is a fact about the fleet rather
    // than something an operator can act on — the incident this fixes was
    // found by reading audit jsonl by hand precisely because the alert (when
    // it arrived at all) never named the session or the working directory.
    lines.push(`Blocked:   ${n.deniedReason ?? 'no prompt surface in this session'}`);
    if (n.sessionId) lines.push(`Session:   ${n.sessionId}`);
    if (n.cwd) lines.push(`Cwd:       ${n.cwd}`);
  }
  lines.push('');
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
  if (denied) {
    // No Approve/Deny pair: there is nothing left to deny, and the approve
    // command means something different here — it authorises the NEXT attempt,
    // which is the only thing that can still happen.
    lines.push('The agent has already been refused; this job did not do the work.');
    lines.push('To authorise a RETRY, run in YOUR terminal:');
    lines.push(`  shieldcortex approve ${n.shortHash}`);
  } else {
    lines.push(`[Approve]  shieldcortex approve ${n.shortHash}`);
    lines.push(`[Deny]     shieldcortex deny ${n.shortHash}`);
  }
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
  notification: AnyOperatorNotification,
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
 * Despite the name, this also carries the `denied_no_prompt_surface` event
 * (see `OperatorNotificationEvent`) — the transport, the resolution order and
 * the deadline are identical whether the news is "a human must decide this" or
 * "a job just died and nobody was told", and duplicating all of that to change
 * one string would be the more dangerous change. The name is kept because
 * every caller, every channel and the #118 store already speak it.
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
  const notification = buildNotification(input);

  const candidates: NotifyChannel[] = [];
  if (deps.attended && deps.tui) candidates.push(deps.tui);
  if (deps.channel) candidates.push(deps.channel);

  return deliverOperatorNotification(notification, {
    channels: candidates,
    timeoutMs: deps.timeoutMs,
    onAttempt: deps.onAttempt,
  });
}

export interface DeliverNotificationDeps {
  /** Tried in order; the first delivery wins. An empty list is the honest
   *  "nothing configured" case and returns `deliveredVia: null` without
   *  pretending an attempt was made. */
  channels: NotifyChannel[];
  timeoutMs?: number;
  onAttempt?: (channel: string, result: ChannelSendResult) => void;
}

/**
 * Hand an already-built notification to the first channel that will take it
 * (#225 uses this directly; `requestOperatorApproval` is now a thin wrapper
 * that builds the approval-shaped notification and calls straight through).
 *
 * ONE delivery core, deliberately: the #225 conversation sink must not grow a
 * second transport with its own timeout handling and its own idea of what
 * "delivered" means. Every guarantee `tryChannel` makes — bounded deadline,
 * every failure mode normalised, nothing but the boolean read back from a
 * channel — therefore holds for conversation alerts too, unchanged.
 */
export async function deliverOperatorNotification(
  notification: AnyOperatorNotification,
  deps: DeliverNotificationDeps,
): Promise<RequestOperatorApprovalResult> {
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const attempts: RequestOperatorApprovalResult['attempts'] = [];

  for (const ch of deps.channels ?? []) {
    if (!ch || typeof ch.send !== 'function') continue;
    const result = await tryChannel(ch, notification, timeoutMs);
    attempts.push({ channel: ch.name, result });
    deps.onAttempt?.(ch.name, result);
    if (result.delivered) return { deliveredVia: ch.name, attempts };
  }

  return { deliveredVia: null, attempts };
}
