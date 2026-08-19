#!/usr/bin/env node
/**
 * ShieldCortex — Action Guard Hook (PreToolUse)
 *
 * P1/WS1 carry-over: the dangerous-tier enforce-by-default semantics the
 * OpenClaw plugin ships (plugins/openclaw/interceptor.ts runActionGuard) applied
 * to Claude Code via the native PreToolUse permission protocol.
 *
 * Verdict → Claude Code decision mapping:
 *   - catastrophic (`block`)        → permissionDecision "deny". ALWAYS — the
 *     hard-block tier ignores `actionGuard.enforce:false`, mirroring the plugin.
 *   - dangerous (`require_approval`) → permissionDecision "ask" (Claude Code's
 *     own confirm dialog) when the session can actually show one, else "deny"
 *     (see prompt-surface rule below). `actionGuard.enforce:false` opts down to
 *     a stderr warning with NO decision.
 *   - autoApprove match              → NO decision. The guard defers to Claude
 *     Code's own permission system rather than emitting "allow": ShieldCortex
 *     narrows or stays neutral, it never WIDENS what the user's settings allow.
 *   - benign / read-only / pure-print → no output at all.
 *
 * Prompt-surface rule: "ask" is only meaningful where Claude Code will actually
 * raise a prompt. In `bypassPermissions` and `dontAsk` the harness shows no
 * prompt, and when `permission_mode` is absent or unrecognised we cannot tell.
 * Harnesses have not treated an unanswerable "ask" consistently — a Claude Code
 * build 144 versions behind was observed discarding it and executing the command
 * (aiquant, 2026-07-30), while current builds block. "deny" is the one verdict
 * every version honours, so whenever approval is required and no prompt surface
 * can be confirmed, the hook denies instead of asking. Same guard verdict, an
 * outcome that does not depend on the harness version. The audit row records
 * `permissionMode` and outcome `denied_no_prompt_surface` so this is
 * distinguishable from a catastrophic auto-deny in forensics.
 *
 * Failure posture (WS2): a guard that cannot load or evaluate no longer fails
 * OPEN unconditionally. A small, dependency-free FALLBACK_CATASTROPHIC scan
 * (duplicated inline, not imported from dist — it must survive the exact
 * failure it guards against) runs against the same command/path/url surface.
 * If it recognises one of the handful of unambiguous, essentially-never-benign
 * catastrophic shapes (rm -rf /, a raw-disk dd/mkfs/wipefs, a fork bomb,
 * curl|bash), the call is denied — fail CLOSED for the catastrophic tier even
 * with a broken/missing guard. Anything the fallback does NOT recognise still
 * fails OPEN with a stderr note, exactly as before: turning every tool call
 * into a denial whenever the guard is merely unavailable (e.g. a stale dist
 * after an upgrade) would itself break unattended agents/cron — the outcome
 * ShieldCortex exists to prevent. See plugins/openclaw/interceptor.ts for the
 * mirrored fallback on the OpenClaw runtime surface.
 *
 * The hook always exits 0 — denial travels in hookSpecificOutput JSON, never
 * exit codes, so a crash can't masquerade as a verdict.
 */

import { closeSync, constants, existsSync, fstatSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'fs';
import { mkdirSecure } from './lib/state-perms.mjs';
import { basename, dirname, join, resolve, sep } from 'path';
import { homedir, tmpdir } from 'os';
import { spawn } from 'child_process';
import { fileURLToPath, pathToFileURL } from 'url';
import { createHash, createHmac, randomBytes } from 'crypto';

const here = dirname(fileURLToPath(import.meta.url));

// ==================== CONFIG ====================

const DEFAULT_ACTION_GUARD = { enabled: true, enforce: true, autoApprove: [], auditAllows: true };

/** #224 binding module, loaded once in main. Null when dist predates it. */
let bindingMod = null;

function loadActionGuardConfig() {
  try {
    const configPath = join(homedir(), '.shieldcortex', 'config.json');
    if (!existsSync(configPath)) return { ...DEFAULT_ACTION_GUARD };
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    // #209: single source of truth. Top-level `actionGuard` governs every
    // surface; `interceptor.actionGuard` is a deprecated alias that fills
    // per-key gaps so pre-#209 configs keep their posture. On a conflicting
    // key the top-level value wins and the conflict is reported on stderr —
    // honoured silently, a wrong alias would recreate the split-brain this
    // fix exists to kill. Mirrored in plugins/openclaw/index.ts
    // (normaliseConfig) and src/cli/doctor.ts (checkActionGuard); the three
    // build units cannot share an import, so keep them in step by hand.
    const isBlock = (v) => v && typeof v === 'object' && !Array.isArray(v);
    const top = isBlock(config?.actionGuard) ? config.actionGuard : null;
    const alias = isBlock(config?.interceptor?.actionGuard) ? config.interceptor.actionGuard : null;
    if (top && alias) {
      const conflicts = Object.keys(alias).filter(
        (k) => k in top && JSON.stringify(top[k]) !== JSON.stringify(alias[k]),
      );
      if (conflicts.length > 0) {
        process.stderr.write(
          `[ShieldCortex] deprecated interceptor.actionGuard conflicts with actionGuard on: ${conflicts.join(', ')} — ` +
          `top-level actionGuard wins; run \`shieldcortex doctor --fix-action-guard\` to migrate\n`,
        );
      }
    }
    const raw = top || alias ? { ...(alias ?? {}), ...(top ?? {}) } : null;
    if (!raw) return { ...DEFAULT_ACTION_GUARD };
    return {
      enabled: raw.enabled !== false,
      enforce: raw.enforce !== false,
      autoApprove: Array.isArray(raw.autoApprove) ? raw.autoApprove.filter((a) => typeof a === 'string') : [],
      auditAllows: raw.auditAllows !== false,
      // #143, passed through RAW. normaliseBrokerConfig in dist is the single
      // place that knows which values would loosen an invariant; re-implementing
      // half of it here is how the two halves end up disagreeing. Absent or
      // not-exactly-enabled means the broker never runs.
      broker: raw.broker && typeof raw.broker === 'object' && !Array.isArray(raw.broker) ? raw.broker : null,
      // #143 notify transport — same discipline: passed through RAW, validated
      // only by normaliseNotifyConfig in dist. Absent or not-exactly-enabled
      // means no channel is ever attempted (the existing hash-in-terminal
      // refusal is the whole of this hook's behaviour, as before #143).
      notify: raw.notify && typeof raw.notify === 'object' && !Array.isArray(raw.notify) ? raw.notify : null,
      // #189 reviewed-script allowlist — same discipline again: RAW array,
      // shape-validated only by normaliseReviewedScripts in dist. Absent or
      // malformed means no exemption ever fires, which is where the guard
      // started — the allowlist can only fail closed.
      reviewedScripts: Array.isArray(raw.reviewedScripts) ? raw.reviewedScripts : null,
      // #310 operator retry control — RAW again, validated only by
      // normaliseRetryControlConfig in dist. `retryCards` must be exactly
      // true to arm anything; absent or junk means this hook behaves exactly
      // as it did before #310 (DNP terminal, no fingerprint, no card).
      retry: {
        retryCards: raw.retryCards,
        retryGrantTtlMs: raw.retryGrantTtlMs,
        denySuppressionMs: raw.denySuppressionMs,
      },
    };
  } catch {
    // Unreadable config → guard on with defaults. Enforce-by-default means a
    // corrupt config file must not silently disable the guard.
    return { ...DEFAULT_ACTION_GUARD };
  }
}

// ==================== PROMPT SURFACE ====================
// Whether an "ask" verdict can actually reach a human in this session. See the
// prompt-surface rule in the header comment for why an unanswerable ask is
// downgraded to a deny rather than emitted anyway.

/** Modes Claude Code documents as raising a permission prompt for a hook "ask". */
const PROMPTING_PERMISSION_MODES = new Set(['default', 'manual', 'acceptEdits', 'plan', 'auto']);

/** Modes Claude Code documents as showing no prompt — an "ask" has nowhere to go. */
const PROMPTLESS_PERMISSION_MODES = new Set(['bypassPermissions', 'dontAsk']);

/**
 * Why this session cannot answer an "ask", or null when it can.
 * Unknown/absent modes count as unconfirmable: a harness that does not tell us
 * whether it can prompt cannot be trusted to honour a prompt.
 */
function noPromptSurfaceReason(permissionMode) {
  if (typeof permissionMode !== 'string' || permissionMode.length === 0) {
    return 'session reported no permission_mode';
  }
  if (PROMPTLESS_PERMISSION_MODES.has(permissionMode)) return `${permissionMode} mode shows no prompt`;
  if (PROMPTING_PERMISSION_MODES.has(permissionMode)) return null;
  return 'unrecognised permission_mode';
}

// ==================== GUARD (lazy dist import) ====================

/**
 * Load the built tool-action-guard from dist. Returns null when the dist build
 * is missing/incomplete → the caller fails OPEN (see failure posture above).
 * SHIELDCORTEX_DIST_ROOT is a test seam, mirroring recall-defence.mjs.
 */
async function loadGuard() {
  const distRoot = process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist');
  try {
    const mod = await import(
      pathToFileURL(resolve(distRoot, 'defence', 'iron-dome', 'tool-action-guard.js')).href
    );
    return typeof mod.evaluateToolCall === 'function' ? mod : null;
  } catch {
    return null;
  }
}

/**
 * The invoked-script source resolver (#160).
 *
 * Without this, `evaluateToolCall` cannot fold a script's CONTENTS into the
 * scan, so a payload written in one call and executed by path in the next is
 * allowed here while the OpenClaw plugin surface — which always passed a
 * resolver — folds it and blocks. Same guard, same input, opposite verdict,
 * and this is the surface that gates every Bash call in a Claude Code session.
 *
 * Optional by construction: if the module is missing the hook behaves exactly
 * as it did before, degrading to `opaque-script-invocation` rather than
 * failing on a partial dist.
 */
async function loadScriptResolver() {
  const distRoot = process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist');
  try {
    const mod = await import(
      pathToFileURL(resolve(distRoot, 'defence', 'iron-dome', 'script-source-resolver.js')).href
    );
    return typeof mod.createScriptSourceResolver === 'function'
      ? mod.createScriptSourceResolver(process.cwd())
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Load the reviewed-script allowlist check (#189). Optional exactly like the
 * resolver above, and meaningless without it: an exemption only exists where
 * a fold would have happened. Missing module, empty config, malformed
 * entries — all degrade to "no exemptions", never to an error.
 */
async function loadReviewedScriptCheck(rawEntries) {
  if (!Array.isArray(rawEntries) || rawEntries.length === 0) return undefined;
  const distRoot = process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist');
  try {
    const mod = await import(
      pathToFileURL(resolve(distRoot, 'defence', 'iron-dome', 'reviewed-scripts.js')).href
    );
    return typeof mod.createReviewedScriptCheck === 'function'
      ? mod.createReviewedScriptCheck(rawEntries, process.cwd())
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Load the one-shot approval store (#118). Optional by design: when the dist
 * module is missing the guard behaves exactly as it did before approvals
 * existed — refuse and say so — rather than failing open.
 */
async function loadApprovals() {
  const distRoot = process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist');
  try {
    const mod = await import(
      pathToFileURL(resolve(distRoot, 'defence', 'iron-dome', 'action-approvals.js')).href
    );
    return typeof mod.consumeApproval === 'function' && typeof mod.recordPending === 'function'
      ? mod
      : null;
  } catch {
    return null;
  }
}

/**
 * Load the #310 retry-control plane. Returns null unless
 * `actionGuard.retryCards` is exactly true AND the dist module is present and
 * complete — the same discipline as loadBroker/loadNotify, for the same
 * reason: a half-assembled trust surface must degrade to "not configured",
 * never to a crash and never to a changed decision.
 *
 * Null is the normal answer. The feature ships dark (ADR rollout gate).
 */
async function loadRetryControl(rawRetry, digestWindowMs) {
  if (!rawRetry || rawRetry.retryCards !== true) return null;
  const distRoot = process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist');
  try {
    const mod = await import(
      pathToFileURL(resolve(distRoot, 'defence', 'iron-dome', 'retry-control.js')).href
    );
    const required = [
      'normaliseRetryControlConfig', 'recordDenialFingerprint', 'claimCardLaunch',
      'releaseCardLaunch', 'consumeRetryGrant', 'hashToolCall', 'canonicaliseCwd',
      'buildRetryCardParams', 'pruneRetryControl', 'drainLostActionIds',
      'formatBudgetExhaustedNotice', 'formatUnspentExpiryNotice',
    ];
    if (required.some((fn) => typeof mod[fn] !== 'function')) return null;
    const config = mod.normaliseRetryControlConfig(rawRetry, { digestWindowMs });
    if (!config?.retryCards) return null;
    return { config, mod };
  } catch {
    return null;
  }
}

/** #224 — optional: stamp binding fields. Missing dist degrades to unbound. */
async function loadBinding() {
  const distRoot = process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist');
  try {
    const mod = await import(
      pathToFileURL(resolve(distRoot, 'defence', 'iron-dome', 'enforcement-binding.js')).href
    );
    return typeof mod.attachEnforcementBinding === 'function' ? mod : null;
  } catch {
    return null;
  }
}

/**
 * Load the session action lease (#227). Null when the dist build predates it —
 * an old install simply has no lease plane, which the freeze CLI's capability
 * report states rather than hides. State unreadability is NOT handled here:
 * the store itself fails closed (verdict 'unknown') for scoped actions.
 */
async function loadLease() {
  const distRoot = process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist');
  try {
    const mod = await import(
      pathToFileURL(resolve(distRoot, 'defence', 'iron-dome', 'session-lease-store.js')).href
    );
    return typeof mod.evaluateToolCallLease === 'function' ? mod : null;
  } catch {
    return null;
  }
}

/**
 * Load the AI-assisted approval broker (#143). Returns null when the broker is
 * not switched on, or when the dist build predates it.
 *
 * Null is the normal answer and a safe one: no broker means this hook behaves
 * exactly as it did before #143 — every dangerous-tier call is refused with the
 * `shieldcortex approve <hash>` fallback. All four pieces are required
 * together; a decision core without its config normaliser would be a policy
 * consuming unvalidated input, which is the one shape this must never take.
 */
async function loadBroker(rawBrokerConfig) {
  if (!rawBrokerConfig || rawBrokerConfig.enabled !== true) return null;
  const distRoot = process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist');
  const load = async (file) => {
    try {
      return await import(pathToFileURL(resolve(distRoot, 'defence', 'iron-dome', file)).href);
    } catch {
      return null;
    }
  };
  try {
    const [core, judge, config, cli] = await Promise.all([
      load('approval-broker.js'), load('approval-judge.js'), load('broker-config.js'), load('cli-invoker.js'),
    ]);
    if (typeof core?.brokerDecision !== 'function') return null;
    if (typeof judge?.runJudge !== 'function') return null;
    if (typeof config?.normaliseBrokerConfig !== 'function') return null;
    if (typeof cli?.createCliInvoker !== 'function') return null;

    const normalised = config.normaliseBrokerConfig(rawBrokerConfig);
    if (!normalised?.enabled) return null;
    return {
      config: normalised,
      brokerDecision: core.brokerDecision,
      runJudge: judge.runJudge,
      // #143 residual. Optional on purpose: a dist build from before the
      // residual has runJudge and nothing else, and the pass below falls back
      // to it. A missing detail function costs an audit field, never a gate.
      runJudgeDetailed: typeof judge.runJudgeDetailed === 'function' ? judge.runJudgeDetailed : null,
      createCliInvoker: cli.createCliInvoker,
    };
  } catch {
    // A broker that cannot be assembled is a broker that does not run. The
    // operator still gets asked, which is where this hook started.
    return null;
  }
}

/**
 * Load the operator-notify transport (#143). Returns null when notify is not
 * switched on, or when the dist build predates it — mirrors `loadBroker`
 * exactly, for the same reason: this hook is one process per tool call and
 * has no persistent state, so every load is from scratch, and every failure
 * to assemble the transport must degrade to "no channel", never to a crash
 * or a changed decision.
 *
 * This is INDEPENDENT of the AI broker (#143's judge layer): a hold reaches
 * the operator whether or not a judge ran, because the gap this closes —
 * "the operator never even heard about the request" — exists regardless of
 * whether an AI looked at it first.
 */
async function loadNotify(rawNotifyConfig) {
  if (!rawNotifyConfig || rawNotifyConfig.enabled !== true) return null;
  const distRoot = process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist');
  const load = async (file) => {
    try {
      return await import(pathToFileURL(resolve(distRoot, 'defence', 'iron-dome', file)).href);
    } catch {
      return null;
    }
  };
  try {
    const [notifyConfigMod, notifyMod, webhookMod, openclawMod, digestMod] = await Promise.all([
      load('notify-config.js'), load('operator-notify.js'), load('webhook-notify-channel.js'),
      load('openclaw-approval-channel.js'), load('dnp-digest.js'),
    ]);
    if (typeof notifyConfigMod?.normaliseNotifyConfig !== 'function') return null;
    if (typeof notifyMod?.requestOperatorApproval !== 'function') return null;
    if (typeof webhookMod?.createWebhookNotifyChannel !== 'function') return null;

    const normalised = notifyConfigMod.normaliseNotifyConfig(rawNotifyConfig);
    if (!normalised?.enabled) return null;

    // Channel precedence: the native OpenClaw approval card (#143's real
    // destination — Approve/Deny buttons on the operator's own channel) when
    // opted in AND buildable, else the webhook. One channel per hold: the
    // card and a webhook ping racing each other would give two surfaces the
    // same one-shot hash and make the store's "already-approved" refusals
    // look like faults. A configured webhook remains the fallback for a box
    // where the openclaw binary or the dist module has gone missing.
    let channel = null;
    let openclawBin = null;
    if (
      normalised.openclaw === true &&
      typeof openclawMod?.createOpenClawApprovalChannel === 'function' &&
      typeof openclawMod?.resolveOpenClawBinaryLite === 'function'
    ) {
      openclawBin = openclawMod.resolveOpenClawBinaryLite();
      if (openclawBin) {
        channel = openclawMod.createOpenClawApprovalChannel({
          openclawBin,
          waiterEntry: resolve(distRoot, 'defence', 'iron-dome', 'openclaw-approval-waiter.js'),
        });
      }
    }
    // The webhook, when configured. It serves two roles and is still built at
    // most once: the primary channel where no card channel exists, and — for
    // `denied_no_prompt_surface` — the ONLY channel, because the card channel
    // is interactive-only and correctly refuses an event with no live decision
    // behind it (see openclaw-approval-channel.ts). Still one channel per
    // hold: `pingOperator` picks exactly one, never both.
    const webhookChannel = normalised.webhookUrl
      ? webhookMod.createWebhookNotifyChannel({
          url: normalised.webhookUrl,
          // Signs the body so the receiver can reject spoofed POSTs. Passed
          // straight through and never logged — see notify-config.ts.
          secret: normalised.webhookSecret,
        })
      : null;
    if (!channel) channel = webhookChannel;
    // Neither channel buildable (absent/rejected webhookUrl, no openclaw
    // opt-in or no binary) means no configured channel exists yet. Degrading
    // to null here, rather than constructing a channel that would never
    // deliver, keeps this indistinguishable from "not configured" downstream.
    if (!channel) return null;

    return {
      config: normalised,
      requestOperatorApproval: notifyMod.requestOperatorApproval,
      deliverOperatorNotification: typeof notifyMod.deliverOperatorNotification === 'function'
        ? notifyMod.deliverOperatorNotification
        : null,
      buildActionGuardOutcomeNotification: typeof notifyMod.buildActionGuardOutcomeNotification === 'function'
        ? notifyMod.buildActionGuardOutcomeNotification
        : null,
      formatDnpDigestText: typeof digestMod?.formatDnpDigestText === 'function'
        ? digestMod.formatDnpDigestText
        : null,
      /** Where a denial goes when the primary channel cannot carry one. Null
       *  means an openclaw-only install: the denial reaches no channel, which
       *  is the honest outcome until a non-interactive gateway send path
       *  exists to point it at. The terminal-hash floor is unchanged. */
      denialChannel: webhookChannel,
      /** #310 — the retry card is raised by our OWN waiter, not by this
       *  channel (whose send() correctly refuses a DNP: there is no live
       *  decision behind one). What the card path needs from here is the
       *  resolved binary and the operator's opt-in, nothing else. */
      openclawBin,
      // `timeoutMs` is NOT a constructor option — the channel's `send()` is
      // handed the deadline per-call (see `pingOperator`, and
      // operator-notify.ts's `tryChannel`), so one channel object is timeout-
      // agnostic and every caller (this hook, the OpenClaw plugin) supplies
      // its own budget.
      channel,
    };
  } catch {
    // A transport that cannot be assembled is a transport that does not run.
    // The operator still gets the unchanged hash-in-terminal refusal.
    return null;
  }
}

/**
 * Best-effort ping through the configured channel. NEVER throws, NEVER
 * blocks longer than the transport's own bounded timeout (see
 * operator-notify.ts and webhook-notify-channel.ts, both of which enforce
 * their own deadlines independent of this caller), and its result is used
 * for nothing but a stderr breadcrumb — the hook's actual decision (the
 * 'ask'/'deny' + hash fallback) is decided before and after this call
 * identically.
 *
 * `noPromptSurface` is the ONLY thing that makes this call know which branch
 * `emitApprovalRequired` is about to take. It is the same pure function
 * evaluated on the same `permissionMode` a few lines later — recomputing a
 * pure string is cheaper and far less fragile than restructuring the refusal
 * path around the notification, and it means the notify layer cannot alter
 * the verdict even by accident: the decision is still derived, independently,
 * from the permission mode alone.
 *
 * When it is non-null the held call has ALREADY been refused by the time this
 * message lands, so the operator is told a job died — not asked a question
 * nothing is waiting on (#143).
 */
function approvalSurfaceUnsafe(value) {
  let text = '';
  try { text = JSON.stringify(value); } catch { text = String(value ?? ''); }
  if (!text) return false;
  if (/[\u0000-\u001f\u007f]/.test(text)) return true;
  if (/https?:\/\//i.test(text)) return true;
  if (/ignore\.previous\.instructions/i.test(text)) return true;
  if (/DO_NOT_PERSIST|SECRET|TOKEN|PASSWORD/i.test(text)) return true;
  if (/\b(?:bearer|authorization|password|passwd|token|api[_-]?key)\b\s*[:=]/i.test(text)) return true;
  if (/\b(?:gh[pousr]_|github_pat_|sk-|xox[baprs]-|ya29\.|eyJ)[A-Za-z0-9_.-]{6,}/i.test(text)) return true;
  if (/[A-Za-z0-9_-]{40,}/.test(text)) return true;
  return false;
}

function safeApprovalCommand(toolName, toolInput) {
  return redactedActionSurface(toolName, toolInput);
}

function safeApprovalVerdict(verdict) {
  const event = 'action_guard_warning';
  return {
    severity: safeSeverity(verdict?.severity, event),
    decision: safeDecision(verdict?.decision, event),
    signals: safeSignalList(verdict?.signals),
    reason: 'Action Guard requires approval; inspect local audit for details.',
  };
}

function safeDiagnosticApprovalReason(reason) {
  const raw = String(reason ?? '');
  const hashHint = raw.match(/shieldcortex approve [0-9a-f]{12}/)?.[0];
  const degraded = /degraded|unavailable|could not scan|guard runtime/i.test(raw);
  const lead = degraded
    ? 'Action Guard is degraded/unavailable and requires approval; inspect local audit for details.'
    : 'Action Guard requires approval; inspect local audit for details.';
  return `${lead}${hashHint ? ` To allow this exact command once, run in YOUR terminal: ${hashHint}` : ''}`;
}

async function pingOperator(notify, { toolName, toolInput, verdict, hash, noPromptSurface, sessionKey }) {
  if (!notify) return null;
  const denied = typeof noPromptSurface === 'string' && noPromptSurface.length > 0;
  // A denial cannot go to an interactive Approve/Deny card — there is nothing
  // left to decide — so it takes the plain-message channel or no channel at
  // all. `deliveredVia: null` is a normal outcome here, exactly as it is when
  // nothing is configured.
  const channel = denied ? notify.denialChannel : notify.channel;
  if (!channel) return null;
  try {
    const displayVerdict = safeApprovalVerdict(verdict);
    const safeSessionId = notificationContext(sessionKey).sessionId;
    const result = await notify.requestOperatorApproval(
      {
        hash,
        tool: safeToolName(toolName),
        command: safeApprovalCommand(toolName, toolInput),
        signals: displayVerdict.signals,
        severity: displayVerdict.severity,
        reason: displayVerdict.reason,
        event: denied ? 'denied_no_prompt_surface' : 'approval_requested',
        deniedReason: denied ? noPromptSurface : undefined,
        sessionId: safeSessionId,
        cwd: undefined,
      },
      { channel, timeoutMs: notify.config.timeoutMs },
    );
    if (result?.deliveredVia) {
      const via = safeNotifyLabel(result.deliveredVia) ?? 'redacted-channel';
      console.error(
        denied
          ? `[shieldcortex] operator-notify: reported the DENIAL of ${safeToolName(toolName)} via ${via} (${hash.slice(0, 12)}).`
          : `[shieldcortex] approval broker: pinged the operator via ${via} (${hash.slice(0, 12)}).`,
      );
    }
    return result ?? null;
  } catch (err) {
    // A notify transport that throws must not change the guard's outcome —
    // it already recorded/is about to record the pending hash regardless.
    console.error('[shieldcortex] ⚠️ operator-notify error — falling back to the terminal hash only.');
    return { deliveredVia: null, attempts: [{ channel: 'operator-notify', result: { delivered: false, reason: safeDiagnosticReason(err?.message ?? err) } }] };
  }
}

const SAFE_TOOL_NAMES = new Set([
  'Bash', 'Edit', 'MultiEdit', 'Write', 'Read', 'Glob', 'Grep', 'LS', 'Task',
  'TodoWrite', 'WebFetch', 'WebSearch', 'NotebookEdit', 'Workflow',
]);
const SAFE_SIGNALS = new Set([
  // Generic / legacy summary names kept for older rows and broker payloads.
  'secret-egress', 'approval-required', 'fallback-scan', 'privilege-escalation',
  'filesystem-destructive', 'destructive-filesystem', 'dangerous-shell',
  'command-exec', 'network-egress', 'credential-access', 'data-exfiltration',
  'untrusted-script', 'reviewed-script', 'shell-injection', 'persistence-risk',
  'install-package', 'git-force-push', 'local-package-install', 'move-or-copy', 'file-delete', 'service-restart', 'exec-like',
  // #284 Face 1 — real Action Guard signal names must survive the local
  // denials.jsonl / operator-notify path. Previously almost every live
  // catastrophic signal collapsed to "redacted-signal".
  'recursive-force-delete', 'delete-root-or-home', 'fork-bomb', 'format-filesystem',
  'raw-disk-write', 'redirect-to-block-device', 'disk-partition-tool',
  'pipe-download-to-shell', 'pipe-download-stdin-exec', 'pipe-download-module-exec',
  'recursive-perms-on-root', 'shred-device', 'git-delete-branch',
  'stop-process-or-service', 'modify-network-firewall', 'install-package-global',
  'modify-scheduler', 'truncate-to-zero', 'wipe-history-or-logs',
  'touch-sensitive-path', 'touch-approval-store', 'touch-decisions-ledger',
  'dd-overwrite', 'recursive-perms-system-dir', 'registry-code-exec',
  'decode-pipe-to-shell', 'change-permissions', 'git-mutate',
  'recursive-find-delete', 'external-egress', 'oversized-command',
  'opaque-script-invocation', 'opaque-script', 'secret-egress-fold',
  'force-push', 'force-push-invocation',
]);
const MAX_SESSION_SALT_RECOVERY_ATTEMPTS = 256;
const GUARD_DEGRADED_OUTCOMES = new Set(['auto_denied', 'denied_no_prompt_surface', 'failure_denied', 'warned', 'failure_allowed']);
const SAFE_BROKER_OUTCOMES = new Set(['harden', 'pre_clear', 'hold', 'unavailable', 'not_brokerable']);
const SAFE_JUDGE_ASSESSMENTS = new Set(['approve', 'deny', 'hold', 'uncertain', 'in_context', 'out_of_context', 'benign', 'unavailable']);
/** #143 residual — why a judge is 'unavailable'. Allowlisted, like every other
 *  string this hook copies into an audit row that leaves the process. */
const SAFE_JUDGE_UNAVAILABLE_REASONS = new Set(['timeout', 'unreachable', 'parse', 'thrown', 'disabled']);

function readExistingSessionSalt(file) {
  try {
    const st = lstatSync(file);
    if (!st.isFile() || st.isSymbolicLink()) return null;
    const salt = readFileSync(file, 'utf8').trim();
    return /^[a-f0-9]{64}$/i.test(salt) ? salt.toLowerCase() : null;
  } catch {
    return null;
  }
}



function fdPathForDescriptor(fd) {
  if (existsSync('/proc/self/fd')) return `/proc/self/fd/${fd}`;
  return null;
}

function withAnchoredDirectory(dir, fn) {
  if (!ensureDirectoryNoSymlink(dir)) return false;
  let dirFd;
  try {
    dirFd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    if (!ensureDirectoryNoSymlink(dir)) return false;
    const fdPath = fdPathForDescriptor(dirFd);
    if (!fdPath) return fn(dir);
    return fn(fdPath);
  } catch {
    return false;
  } finally {
    if (dirFd !== undefined) {
      try { closeSync(dirFd); } catch { /* ignore */ }
    }
  }
}

function publishFileAtomically(file, contents) {
  const dir = dirname(file);
  const tmpName = `${basename(file)}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`;
  const finalName = basename(file);
  return withAnchoredDirectory(dir, (dirPath) => {
    const tmp = `${dirPath}/${tmpName}`;
    const final = `${dirPath}/${finalName}`;
    try {
      writeFileSync(tmp, contents, { flag: 'wx', mode: 0o600 });
      linkSync(tmp, final);
      return true;
    } catch {
      return false;
    } finally {
      try { unlinkSync(tmp); } catch { /* ignore */ }
    }
  });
}

function legacySessionSaltFiles(primary) {
  return [primary, `${primary}.recovered`, `${primary}.recovered2`, `${primary}.recovered3`];
}

function discoveredSessionSaltFiles(primary) {
  try {
    const dir = dirname(primary);
    const entries = [];
    for (const name of readdirSync(dir)) {
      const match = name.match(/^action-guard-session-salt\.recovered(\d+)$/);
      if (!match) continue;
      const slot = Number(match[1]);
      if (!Number.isInteger(slot) || String(slot) !== match[1]) continue;
      if (slot < 4 || slot >= 4 + MAX_SESSION_SALT_RECOVERY_ATTEMPTS) continue;
      entries.push({ slot, file: join(dir, name) });
    }
    entries.sort((a, b) => a.slot - b.slot);
    return entries.map((entry) => entry.file);
  } catch {
    return [];
  }
}

function sessionKeySalt() {
  const fromEnv = process.env.SHIELDCORTEX_SESSION_SALT;
  if (typeof fromEnv === 'string' && /^[a-f0-9]{64}$/i.test(fromEnv)) return fromEnv.toLowerCase();
  try {
    const dir = join(homedir(), '.shieldcortex');
    const primary = join(dir, 'action-guard-session-salt');
    if (!ensureDirectoryNoSymlink(dir)) return undefined;
    const readableFiles = [...legacySessionSaltFiles(primary), ...discoveredSessionSaltFiles(primary)];
    for (const file of readableFiles) {
      const existing = readExistingSessionSalt(file);
      if (existing) return existing;
    }
    const salt = randomBytes(32).toString('hex');
    for (const file of legacySessionSaltFiles(primary)) {
      if (publishFileAtomically(file, `${salt}\n`)) return salt;
      const raced = readExistingSessionSalt(file);
      if (raced) return raced;
    }
    for (let i = 4; i < 4 + MAX_SESSION_SALT_RECOVERY_ATTEMPTS; i += 1) {
      const file = `${primary}.recovered${i}`;
      const existing = readExistingSessionSalt(file);
      if (existing) return existing;
      if (publishFileAtomically(file, `${salt}\n`)) return salt;
      const raced = readExistingSessionSalt(file);
      if (raced) return raced;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

function sessionKeyFor(value) {
  if (typeof value !== 'string' || !value.trim()) return undefined;
  const salt = sessionKeySalt();
  if (!salt) return undefined;
  return `sc-${createHmac('sha256', salt).update(`action-guard-session:${value}`).digest('hex').slice(0, 16)}`;
}

function hookSessionExtras(hookData, permissionMode) {
  const extra = {};
  const rawSessionId = typeof hookData?.session_id === 'string' ? hookData.session_id : hookData?.sessionId;
  const sessionKey = sessionKeyFor(rawSessionId);
  if (sessionKey) extra.sessionKey = sessionKey;
  const safeMode = safePermissionMode(permissionMode);
  if (safeMode) extra.permissionMode = safeMode;
  return extra;
}

function safeToolName(value) {
  return SAFE_TOOL_NAMES.has(value) ? value : 'tool';
}

function safeSignalList(signals) {
  if (!Array.isArray(signals)) return [];
  const out = [];
  let redacted = false;
  for (const raw of signals) {
    const signal = String(raw ?? '').trim();
    if (SAFE_SIGNALS.has(signal)) out.push(signal);
    else if (signal) redacted = true;
  }
  if (redacted) out.push('redacted-signal');
  return [...new Set(out)].slice(0, 25);
}

function looksCredentialishNotifyLabel(text) {
  const value = String(text ?? '').trim();
  if (!value) return false;
  if (/^[A-Za-z]+:\S+/.test(value)) return true;
  if (/^(gh[pousr]_|github_pat_|sk-|xox[baprs]-|ya29\.|eyJ)/i.test(value)) return true;
  if (/bearer[-_:]?[a-z0-9]{8,}/i.test(value)) return true;
  if (/[A-Za-z0-9_-]{28,}/.test(value)) return true;
  return false;
}

function safeNotifyLabel(value) {
  const text = String(value ?? '').trim();
  if (!/^[a-z0-9_.:-]{1,80}$/i.test(text)) return null;
  return looksCredentialishNotifyLabel(text) ? null : text;
}

function safePermissionMode(value) {
  return ['default', 'manual', 'acceptEdits', 'plan', 'auto', 'dontAsk', 'bypassPermissions'].includes(value)
    ? value
    : null;
}

function mintActionId() {
  // #284 Face 3 — action-scoped id, distinct from the session key.
  return `act-${randomBytes(8).toString('hex')}`;
}

function notificationContext(sessionKey, actionId) {
  const out = {};
  if (/^sc-[a-f0-9]{16}$/.test(String(sessionKey ?? ''))) {
    out.sessionId = sessionKey;
  }
  if (typeof actionId === 'string' && /^act-[a-f0-9]{16}$/.test(actionId)) {
    out.actionId = actionId;
    out.correlationId = actionId;
  }
  return out;
}

function safeBrokerAudit(audit) {
  if (!audit || typeof audit !== 'object') return undefined;
  const out = {};
  const outcome = String(audit.outcome ?? '');
  if (SAFE_BROKER_OUTCOMES.has(outcome)) out.outcome = outcome;
  const judgeAssessment = String(audit.judgeAssessment ?? '');
  if (SAFE_JUDGE_ASSESSMENTS.has(judgeAssessment)) out.judgeAssessment = judgeAssessment;
  if (typeof audit.judgeConfidence === 'number' && Number.isFinite(audit.judgeConfidence)) {
    out.judgeConfidence = Math.max(0, Math.min(1, audit.judgeConfidence));
  } else if (audit.judgeConfidence === null) {
    out.judgeConfidence = null;
  }
  if (typeof audit.injectionSuspected === 'boolean') out.injectionSuspected = audit.injectionSuspected;
  if (typeof audit.inContext === 'boolean') out.inContext = audit.inContext;
  // #143 residual. A boolean and one allowlisted word — the same treatment
  // every other field here gets, because "it came from our own core" is not a
  // property this function is allowed to assume.
  if (typeof audit.judgeTimedOut === 'boolean') out.judgeTimedOut = audit.judgeTimedOut;
  const unavailableReason = String(audit.judgeUnavailableReason ?? '');
  if (SAFE_JUDGE_UNAVAILABLE_REASONS.has(unavailableReason)) out.judgeUnavailableReason = unavailableReason;
  const signals = safeSignalList(audit.signals);
  if (signals.length > 0) out.signals = signals;
  return Object.keys(out).length > 0 ? out : undefined;
}

function redactedActionSurface(toolName, toolInput) {
  const keys = ['command', 'script', 'file_path', 'path', 'url', 'pattern'];
  const present = keys.filter((k) => toolInput?.[k] !== undefined && toolInput?.[k] !== null);
  const suffix = present.length > 0 ? ` fields=${present.join(',')}` : ' no command field';
  // #284 Face 1 — denials.jsonl / notify carry a redacted surface only.
  // Do not claim the raw command lives in realtime-*.jsonl; that pointer was a lie.
  return `${safeToolName(toolName)}: [redacted action surface; command not persisted to notify or denials.jsonl preview]${suffix}`;
}

function redactedAuditArgs(toolName, toolInput) {
  return { surface: redactedActionSurface(toolName, toolInput) };
}

function safeSeverity(value, event) {
  if (value === 'catastrophic') return 'critical';
  if (['critical', 'dangerous', 'high', 'medium', 'low', 'benign', 'unknown'].includes(value)) return value;
  return event === 'action_guard_denial' ? 'high' : 'medium';
}

function safeDecision(value, event) {
  if (['block', 'require_approval', 'allow'].includes(value)) return value;
  return event === 'action_guard_warning' ? 'require_approval' : 'block';
}

function terminalOutcomeAuditVerdict(verdict, outcome, event) {
  return {
    severity: safeSeverity(verdict?.severity, event),
    decision: safeDecision(verdict?.decision, event),
    signals: safeSignalList(verdict?.signals),
    reason: safeGuardOutcomeReason(verdict, outcome, event),
  };
}


function safeAllowAuditVerdict(verdict, outcome = 'allowed') {
  return {
    severity: safeSeverity(verdict?.severity, 'action_guard_warning'),
    decision: safeDecision(verdict?.decision, 'action_guard_warning'),
    signals: safeSignalList(verdict?.signals),
    reason: outcome === 'approved'
      ? 'Action Guard approval path was satisfied; inspect local audit for details.'
      : 'Action Guard scanned and allowed this tool call; inspect local audit for details.',
  };
}

function writeTerminalOutcomeAudit(toolName, verdict, toolInput, action, outcome, event, extra = {}) {
  const actionId = extra.actionId || mintActionId();
  // #284: do NOT pass raw toolInput as intentArgs on the deny path. Binding would
  // mint actionKey from the full command and put it on the durable audit row —
  // the same leak denials.jsonl is carefully redacting. Terminal outcomes are
  // already refused; reconciliation uses actionId, not a replayable actionKey.
  writeAuditEntry(
    safeToolName(toolName),
    terminalOutcomeAuditVerdict(verdict, outcome, event),
    redactedAuditArgs(toolName, toolInput),
    action,
    outcome,
    {
      ...extra,
      actionId,
      origin: extra.origin || 'claude-code-hook',
    },
  );
  return actionId;
}

function safeDiagnosticReason(reason) {
  const text = String(reason ?? 'delivery failed').toLowerCase();
  if (text.includes('timed out') || text.includes('timeout')) return 'delivery timed out';
  if (text.includes('malformed')) return 'channel returned malformed result';
  if (text.includes('responded')) return 'channel returned non-success status';
  if (text.includes('missing dist')) return 'guard runtime unavailable: missing dist build';
  if (text.includes('evaluation error')) return 'guard runtime unavailable: evaluation error';
  if (text.includes('unavailable')) return 'guard runtime unavailable';
  return 'delivery failed';
}

function safeGuardOutcomeReason(verdict, outcome, event) {
  if (event === 'action_guard_warning') {
    return outcome === 'failure_allowed'
      ? 'Action Guard was unavailable and advisory mode allowed a dangerous tool call; inspect local audit for details.'
      : 'Action Guard warning in advisory mode; inspect local audit for details.';
  }
  if (outcome === 'denied_no_prompt_surface') {
    return 'Action Guard required approval but this session has no prompt surface; the tool call was denied.';
  }
  if (String(verdict?.reason ?? '').toLowerCase().includes('guard unavailable')) {
    return 'Action Guard was unavailable and fallback policy denied the tool call; inspect local audit for details.';
  }
  return 'Action Guard denied the tool call; inspect local audit for details.';
}

function terminalDecisionReason(verdict, outcome, event) {
  const signals = safeSignalList(verdict?.signals);
  const suffix = signals.length > 0 ? ` [${signals.join(', ')}]` : '';
  const nextStep = outcome === 'denied_no_prompt_surface'
    ? ' Configure actionGuard.autoApprove for this exact safe pattern or set actionGuard.enforce:false to downgrade dangerous-tier calls to warnings.'
    : '';
  const severity = safeSeverity(verdict?.severity, event);
  const severityPrefix = severity === 'critical' ? 'Catastrophic-tier. ' : '';
  return `ShieldCortex Action Guard: ${severityPrefix}${safeGuardOutcomeReason(verdict, outcome, event)}${nextStep}${suffix}`;
}

function buildLocalGuardOutcome({ toolName, toolInput, verdict, outcome, event, sessionKey, actionId, notify }) {
  const id = actionId || mintActionId();
  const context = notificationContext(sessionKey, id);
  const row = {
    event,
    outcome,
    // #284 Face 2 — origin on every denial row (especially auto_deny/critical).
    origin: 'claude-code-hook',
    tool: safeToolName(toolName),
    surface: redactedActionSurface(toolName, toolInput),
    signals: safeSignalList(verdict.signals),
    severity: verdict.severity === 'catastrophic' ? 'critical' : String(verdict.severity ?? 'unknown'),
    reason: safeGuardOutcomeReason(verdict, outcome, event),
    ...(context.sessionId ? { sessionId: context.sessionId } : {}),
    ...(context.actionId ? { actionId: context.actionId } : {}),
    ...(context.correlationId ? { correlationId: context.correlationId } : {}),
    detectedAt: new Date().toISOString(),
  };
  if (notify && typeof notify === 'object') {
    row.notify = notify;
  }
  return row;
}

function recordLocalGuardOutcome(outcome) {
  const file = join(homedir(), '.shieldcortex', 'denials.jsonl');
  if (appendFileNoFollow(file, JSON.stringify(outcome) + '\n')) {
    console.error(`[shieldcortex] action-guard outcome recorded locally: ~/.shieldcortex/denials.jsonl (${outcome.event}/${outcome.outcome}).`);
    return true;
  }
  console.error('[shieldcortex] ⚠️ local action-guard outcome sink UNWRITABLE (~/.shieldcortex/denials.jsonl).');
  return false;
}

function classifyNotifyStatus(notifyMod, result) {
  // #284 Face 4 — distinguish not_configured / no_channel / delivered / error.
  // #331 — coalesced is a successful volume decision, not a delivery failure.
  // #310 — nor is suppressed: the operator DENIED this action, and windowed
  // silence is what they asked for. Recorded distinctly so "we chose not to
  // page" is never mistaken for "we tried and failed".
  if (result?.suppressed === true) {
    return {
      status: 'suppressed',
      deliveredVia: null,
      ...(typeof result.suppressedUntilMs === 'number' ? { suppressedUntilMs: result.suppressedUntilMs } : {}),
    };
  }
  if (result?.coalesced === true) {
    return {
      status: 'coalesced',
      deliveredVia: null,
      digestCount: typeof result.digestCount === 'number' ? result.digestCount : undefined,
    };
  }
  if (!notifyMod) {
    return { status: 'not_configured', deliveredVia: null };
  }
  if (
    !notifyMod.denialChannel ||
    typeof notifyMod.deliverOperatorNotification !== 'function' ||
    typeof notifyMod.buildActionGuardOutcomeNotification !== 'function'
  ) {
    return { status: 'no_channel', deliveredVia: null };
  }
  if (result?.deliveredVia) {
    return {
      status: 'delivered',
      deliveredVia: safeNotifyLabel(result.deliveredVia) ?? 'redacted-channel',
    };
  }
  const attemptReason = Array.isArray(result?.attempts)
    ? result.attempts.map((a) => a?.result?.reason).find(Boolean)
    : null;
  return {
    status: 'error',
    deliveredVia: null,
    error: safeDiagnosticReason(attemptReason ?? 'delivery failed'),
  };
}

/**
 * #310 — raise ONE operator retry card for a denial that already happened.
 *
 * Claim first (which debits the card budget in the same locked write as the
 * nonce it mints), then launch the waiter that owns the card end-to-end. A
 * launch that fails releases the slot, so a box where the waiter cannot start
 * does not silently burn the window's budget.
 *
 * The claimNonce reaches the waiter on an INHERITED FD (fd 3), pointing at an
 * already-unlinked 0600 temp file — so it is not in `/proc/<pid>/cmdline` for
 * every other local process to read. R3 rule 4's argv fallback lives in the
 * waiter's own parser and is deliberately not used from here.
 */
async function raiseRetryCard(retry, notify, ctx) {
  const openclawBin = notify?.openclawBin;
  if (!openclawBin) return { raised: false, reason: 'no-openclaw-card-channel' };

  const claim = retry.mod.claimCardLaunch(
    { id: ctx.id, actionId: ctx.actionId },
    {
      home: homedir(),
      windowStartMs: ctx.windowStartMs,
      windowMs: ctx.windowMs,
      actionId: ctx.actionId,
    },
  );
  if (!claim.ok) return { raised: false, reason: claim.reason, lostActionIds: claim.lostActionIds };

  const distRoot = process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist');
  const waiterEntry = resolve(distRoot, 'defence', 'iron-dome', 'dnp-retry-waiter.js');
  const receiptDir = join(tmpdir(), 'shieldcortex-retry-receipts');
  const token = randomBytes(8).toString('hex');
  const receiptPath = join(receiptDir, `${token}.json`);
  const noncePath = join(receiptDir, `${token}.nonce`);

  let nonceFd;
  try {
    mkdirSync(receiptDir, { recursive: true, mode: 0o700 });
    writeFileSync(noncePath, claim.nonce, { mode: 0o600, flag: 'wx' });
    nonceFd = openSync(noncePath, 'r');
    // Unlinked immediately: the fd is the only remaining handle to it, and
    // that handle dies with the waiter.
    unlinkSync(noncePath);

    // `cronIntervalMs` is deliberately NOT passed: PreToolUse carries no cronId
    // and no schedule (design B3), so this hook does not know the interval and
    // will not guess one. The builder supports the caveat for a caller that
    // does; until such a caller exists, the card stays silent about it rather
    // than printing a number nobody measured.
    const params = retry.mod.buildRetryCardParams({
      tool: ctx.tool,
      signals: ctx.signals,
      redactedSurface: ctx.redactedSurface,
      cwd: ctx.cwd,
      ttlMs: retry.config.retryGrantTtlMs,
    });
    const child = spawn(
      process.execPath,
      [
        waiterEntry,
        '--params-b64', Buffer.from(JSON.stringify(params), 'utf8').toString('base64'),
        '--fingerprint', claim.id,
        ...(ctx.actionId ? ['--action-id', ctx.actionId] : []),
        '--openclaw-bin', openclawBin,
        '--receipt', receiptPath,
        '--nonce-fd', '3',
        '--ttl-ms', String(retry.config.retryGrantTtlMs),
        '--suppress-ms', String(retry.config.denySuppressionMs),
      ],
      { detached: true, stdio: ['ignore', 'ignore', 'ignore', nonceFd] },
    );
    child.unref();
    return { raised: true, id: claim.id };
  } catch (err) {
    try { retry.mod.releaseCardLaunch({ id: claim.id }, { home: homedir() }); } catch { /* self-heals at claim expiry */ }
    try { unlinkSync(noncePath); } catch { /* already gone */ }
    return { raised: false, reason: `waiter failed to start: ${safeDiagnosticReason(err?.message ?? err)}` };
  } finally {
    if (nonceFd !== undefined) {
      try { closeSync(nonceFd); } catch { /* ignore */ }
    }
  }
}

/**
 * The card budget window START, which IS the digest window start (R3 rule 7) —
 * read in this same handler so the two can never drift into independent
 * first-event windows. When the digest is switched off entirely
 * (`dnpDigestWindowMs: 0`) there is no shared window to read, so the budget
 * falls back to a fixed epoch-aligned bucket: deterministic across the
 * one-process-per-tool-call hooks, which is the property that matters.
 */
function retryBudgetWindow(digestDecision) {
  if (digestDecision?.state && typeof digestDecision.state.windowStartMs === 'number') {
    return {
      windowStartMs: digestDecision.state.windowStartMs,
      windowMs: digestDecision.state.windowMs,
    };
  }
  const windowMs = 15 * 60 * 1000;
  const nowMs = Date.now();
  return { windowStartMs: Math.floor(nowMs / windowMs) * windowMs, windowMs };
}

async function alertGuardOutcome(notifyOrPromise, { toolName, toolInput, verdict, outcome, event, sessionKey, actionId, retryCtx }) {
  const id = actionId || mintActionId();
  // #284 dual-review blocker (SOL): write the denial row FIRST with notify pending,
  // then attempt delivery and append/update status. A hang/crash during notify must
  // not drop the forensics row that operators open first (denials.jsonl).
  const pendingRow = buildLocalGuardOutcome({
    toolName, toolInput, verdict, outcome, event, sessionKey, actionId: id,
    notify: { status: 'pending', deliveredVia: null },
  });
  recordLocalGuardOutcome(pendingRow);

  let notify = null;
  try {
    notify = typeof notifyOrPromise?.then === 'function' ? await notifyOrPromise : notifyOrPromise;
  } catch {
    notify = null;
  }

  let deliveryResult = null;

  // ── #310 retry control, step 1: FINGERPRINT, then SUPPRESSION ─────────
  // The order is binding (design B2): suppression check → digest/budget
  // accounting → card. A suppressed event still writes its fingerprint and
  // its denials.jsonl rows — audit truth is never what gets muted — but it
  // never opens the siren window and never burns card budget.
  let retry = null;
  let retryStep = null;
  if (outcome === 'denied_no_prompt_surface' && retryCtx?.rawConfig) {
    retry = await loadRetryControl(retryCtx.rawConfig, notify?.config?.dnpDigestWindowMs);
    if (retry) {
      try {
        retryStep = retry.mod.recordDenialFingerprint(
          {
            hash: retry.mod.hashToolCall(toolName, toolInput),
            tool: safeToolName(toolName),
            actionId: id,
            signals: safeSignalList(verdict?.signals),
            redactedSurface: redactedActionSurface(toolName, toolInput),
            // From the HARNESS payload, never from tool input (design B3).
            cwd: retryCtx.cwd,
            sessionKey,
          },
          { home: homedir() },
        );
      } catch {
        // A retry plane that cannot record must never change the denial the
        // guard already made, and must never widen anything.
        retryStep = null;
      }
    }
  }
  const retrySuppressed = retryStep?.suppressed === true;

  // #331 — DNP volume control. Always record forensics; outbound notify is
  // at most once per host window. Payload never decides mute.
  let digestDecision = null;
  if (outcome === 'denied_no_prompt_surface' && notify && !retrySuppressed) {
    try {
      const dig = await import(
        pathToFileURL(resolve(process.env.SHIELDCORTEX_DIST_ROOT ?? resolve(here, '..', 'dist'), 'defence', 'iron-dome', 'dnp-digest.js')).href
      );
      if (typeof dig.recordDnpDigestEvent === 'function') {
        const context = notificationContext(sessionKey, id);
        digestDecision = dig.recordDnpDigestEvent(
          {
            actionId: id,
            sessionId: context.sessionId,
            tool: safeToolName(toolName),
            signals: safeSignalList(verdict?.signals),
            severity: String(verdict?.severity ?? 'unknown'),
          },
          {
            home: homedir(),
            windowMs: notify.config?.dnpDigestWindowMs,
          },
        );
      }
    } catch {
      digestDecision = null;
    }
  }

  // ── #310 step 3: the CARD ─────────────────────────────────────────────
  // Only for an event that survived the suppression check, and only once the
  // digest window whose START it shares has been read (R3 rule 7).
  let retryCard = null;
  if (retry && retryStep?.ok && !retrySuppressed) {
    try {
      retryCard = await raiseRetryCard(retry, notify, {
        id: retryStep.id,
        actionId: id,
        tool: safeToolName(toolName),
        signals: safeSignalList(verdict?.signals),
        redactedSurface: redactedActionSurface(toolName, toolInput),
        cwd: retryStep.row?.originScope?.cwd,
        ...retryBudgetWindow(digestDecision),
      });
    } catch {
      retryCard = { raised: false, reason: 'card path error' };
    }
    if (retryCard?.raised) {
      console.error(
        `[shieldcortex] #310 retry card raised for ${safeToolName(toolName)} (${id}) — a tap authorises ONE scoped retry, nothing more.`,
      );
    }
  }

  if (retrySuppressed) {
    // The operator already said no to this exact action. Windowed silence is
    // what they asked for; the forensics rows above are unaffected.
    deliveryResult = {
      deliveredVia: null,
      suppressed: true,
      suppressedUntilMs: retryStep?.suppressedUntilMs,
      attempts: [],
    };
    console.error(
      `[shieldcortex] #310 retry control: silenced by your own Deny until ${new Date(retryStep?.suppressedUntilMs ?? Date.now()).toISOString()} — denial recorded, operator not paged.`,
    );
  } else if (digestDecision?.action === 'coalesce') {
    deliveryResult = {
      deliveredVia: null,
      coalesced: true,
      digestCount: digestDecision.summary?.count,
      attempts: [],
    };
  } else if (
    notify?.denialChannel &&
    typeof notify.deliverOperatorNotification === 'function' &&
    typeof notify.buildActionGuardOutcomeNotification === 'function'
  ) {
    try {
      let notification = notify.buildActionGuardOutcomeNotification(pendingRow);
      // Enrich first-of-window DNP with digest text when builder supports it.
      if (
        digestDecision?.action === 'notify' &&
        digestDecision.summary &&
        typeof notify.formatDnpDigestText === 'function'
      ) {
        notification = {
          ...notification,
          digestText: notify.formatDnpDigestText(digestDecision.summary),
          digestCount: digestDecision.summary.count,
        };
      } else if (digestDecision?.action === 'notify' && digestDecision.summary) {
        // Inline fallback so older dist still gets a rolled-up reason line.
        notification = {
          ...notification,
          reason: `${notification.reason} [digest: ${digestDecision.summary.count} DNP in window]`,
        };
      }
      // #310 — the operator copy for the two things they cannot see from a
      // denial row: denials that got no card because the window budget was
      // spent, and grants that expired without ever being used. Both are
      // DRAINED here, on the path that actually sends: an id claimed and then
      // not delivered is an id the operator never hears about.
      if (retry) {
        const notices = [];
        try {
          const lost = [
            ...(retryCard && !retryCard.raised && retryCard.reason === 'budget-exhausted'
              ? retryCard.lostActionIds ?? []
              : []),
            ...retry.mod.drainLostActionIds({ home: homedir() }),
          ];
          const uniqueLost = [...new Set(lost.filter(Boolean))];
          if (uniqueLost.length > 0) notices.push(retry.mod.formatBudgetExhaustedNotice(uniqueLost));
          const swept = retry.mod.pruneRetryControl({ home: homedir() });
          if (swept.expired.length > 0) notices.push(retry.mod.formatUnspentExpiryNotice(swept.expired));
        } catch {
          // A notice that cannot be built is a notice that is not sent — the
          // denial row and the decision are untouched either way.
        }
        if (notices.length > 0) {
          const block = notices.join('\n\n');
          notification = typeof notification.digestText === 'string' && notification.digestText
            ? { ...notification, digestText: `${notification.digestText}\n\n${block}` }
            : { ...notification, reason: `${notification.reason} [#310: ${block.replace(/\s+/g, ' ')}]` };
        }
      }
      deliveryResult = await notify.deliverOperatorNotification(notification, {
        channels: [notify.denialChannel],
        timeoutMs: notify.config?.timeoutMs,
      }) ?? null;
      if (deliveryResult?.deliveredVia) {
        const via = safeNotifyLabel(deliveryResult.deliveredVia) ?? 'redacted-channel';
        console.error(`[shieldcortex] operator-notify: reported ${outcome} for ${safeToolName(toolName)} via ${via}.`);
      }
    } catch (err) {
      console.error('[shieldcortex] ⚠️ operator-notify error — guard outcome unchanged.');
      deliveryResult = {
        deliveredVia: null,
        attempts: [{ channel: 'operator-notify', result: { delivered: false, reason: safeDiagnosticReason(err?.message ?? err) } }],
      };
    }
  }

  const notifyStatus = classifyNotifyStatus(notify, deliveryResult);
  // Append a second denials.jsonl line with final notify status (same actionId)
  // so operators can see both "denied" and "were they told" without losing the
  // first row if delivery hangs.
  const finalRow = buildLocalGuardOutcome({
    toolName, toolInput, verdict, outcome, event, sessionKey, actionId: id,
    notify: notifyStatus,
  });
  recordLocalGuardOutcome(finalRow);

  return {
    deliveredVia: deliveryResult?.deliveredVia ?? null,
    attempts: deliveryResult?.attempts ?? [],
    notify: notifyStatus,
    actionId: id,
  };
}


function notificationAudit(result) {
  if (!result) return {};
  return {
    notify: {
      deliveredVia: safeNotifyLabel(result.deliveredVia),
      attempts: Array.isArray(result.attempts)
        ? result.attempts.map((a) => ({
            channel: safeNotifyLabel(a.channel) ?? 'redacted-channel',
            delivered: a.result?.delivered === true,
            reason: a.result?.delivered === true ? undefined : safeDiagnosticReason(a.result?.reason),
          }))
        : [],
    },
  };
}

function recordNotifyAudit(toolName, verdict, toolInput, baseExtra, result) {
  // #284 Face 4 — always record notify status when the deny path ran alert.
  if (!result) {
    writeAuditEntry(
      safeToolName(toolName),
      {
        severity: safeSeverity(verdict?.severity, 'action_guard_warning'),
        decision: safeDecision(verdict?.decision, 'action_guard_warning'),
        signals: safeSignalList(verdict?.signals),
      },
      { notification: 'redacted' },
      'notify',
      'notify_not_configured',
      { ...baseExtra, notify: { status: 'not_configured', deliveredVia: null } },
    );
    return;
  }
  const status = result.notify?.status
    ?? (result.deliveredVia ? 'delivered' : 'error');
  const outcome =
    status === 'delivered' ? 'notified'
      : status === 'not_configured' ? 'notify_not_configured'
        : status === 'no_channel' ? 'notify_no_channel'
          : status === 'suppressed' ? 'notify_suppressed'
            : 'notify_failed';
  writeAuditEntry(
    safeToolName(toolName),
    {
      severity: safeSeverity(verdict?.severity, 'action_guard_warning'),
      decision: safeDecision(verdict?.decision, 'action_guard_warning'),
      signals: safeSignalList(verdict?.signals),
    },
    { notification: 'redacted' },
    'notify',
    outcome,
    {
      ...baseExtra,
      ...(result.actionId ? { actionId: result.actionId } : {}),
      notify: result.notify ?? notificationAudit(result).notify,
      ...notificationAudit(result),
    },
  );
}

/**
 * One broker pass. Returns a decision, or null to mean "carry on as before".
 *
 * NOTE — the judge gets NO sessionSummary here, and that is deliberate. This
 * hook is one process per tool call: it has no session state, and the only
 * session-shaped thing within reach is the agent's own transcript, which is
 * exactly what the judge must never read. With no context the judge is told to
 * answer inContext:false, so on this surface the broker can HARDEN but will not
 * pre-clear. That is the fail-closed half of the feature, which is the half
 * worth having first.
 */
async function runBrokerPass(broker, toolName, toolInput, verdict) {
  try {
    const invoke = broker.createCliInvoker({
      model: broker.config.model,
      timeoutMs: broker.config.judgeTimeoutMs,
    });
    const request = {
      tool: toolName,
      toolInput,
      verdict: {
        severity: verdict.severity,
        action: verdict.action,
        reason: verdict.reason,
        signals: verdict.signals,
      },
    };
    const opts = { timeoutMs: broker.config.judgeTimeoutMs };

    // #143 residual — "the judge never answered" and "the judge said hold" were
    // the same null, so a judge timing out on every call looked like a cautious
    // one. The detail is metadata: `result` is still null on every failure, and
    // null still holds for a human.
    let judgeResult = null;
    let judgeMeta;
    if (broker.runJudgeDetailed) {
      const detailed = await broker.runJudgeDetailed(request, invoke, opts);
      judgeResult = detailed?.result ?? null;
      judgeMeta = {
        timedOut: detailed?.timedOut === true,
        error: typeof detailed?.error === 'string' ? detailed.error : null,
      };
    } else {
      judgeResult = await broker.runJudge(request, invoke, opts);
    }

    const decision = broker.brokerDecision({
      tool: toolName,
      toolInput,
      verdict,
      judge: judgeResult,
      ...(judgeMeta ? { judgeMeta } : {}),
      policy: {
        allowPreClear: broker.config.allowPreClear,
        preClearConfidence: broker.config.preClearConfidence,
      },
    });
    return decision && typeof decision.outcome === 'string' ? decision : null;
  } catch (err) {
    console.error(`[shieldcortex] ⚠️ approval broker error: ${err?.message ?? err} — refusing as usual`);
    return null;
  }
}

/**
 * Surfaces the operator is shown. `script` is the only expansion in #241:
 * it is the explicitly reviewed non-exec command field for Workflow. Do not
 * mirror extractCommand's broad detection heuristic here — arbitrary `code`
 * or `input` fields may contain issue bodies or other sensitive payloads, and
 * notification transport needs a separate redaction design before exporting
 * them. Keep the established command/target fields otherwise unchanged.
 */
const DESCRIBE_KEYS = [
  'command', 'file_path', 'path', 'url', 'pattern',
];

/**
 * One-line description of a refused call, for the operator's approve list and
 * for the notification's `command` field.
 *
 * INVARIANT: the operator must be shown the SAME surface the guard judged and
 * the hash covers. A tool that carries its command under `script` (Workflow),
 * `code` or `input` used to render as a bare tool name, so both
 * `shieldcortex approve --list` and the notification said only "Workflow"
 * while the hash being approved covered a force-push. That is the one thing a
 * notification may never do (operator-notify.ts: "the exact command/target the
 * guard flagged — never a paraphrase").
 *
 * DISPLAY ONLY: this never feeds `hashToolCall`, so widening what is shown
 * cannot widen what an approval releases. Bounding lives downstream —
 * `recordPending` caps the stored summary, `buildNotification` caps `command`.
 */
function describeToolCall(toolName, toolInput) {
  const input = toolInput ?? {};
  const keys = String(toolName).trim().toLowerCase() === 'workflow'
    ? ['command', 'script', ...DESCRIBE_KEYS.slice(1)]
    : DESCRIBE_KEYS;
  let surface = '';
  for (const key of keys) {
    const value = input[key];
    if (value === undefined || value === null) continue;
    surface = typeof value === 'string' ? value : JSON.stringify(value);
    if (surface) break;
  }
  return surface ? `${toolName}: ${surface}` : toolName;
}

// ==================== FALLBACK (guard load/eval failure — WS2) ====================
// Deliberately DUPLICATED from tool-action-guard.ts's CATASTROPHIC list, not
// imported — it must keep working when the dist build is the thing that's
// broken. Narrow by design: only the unambiguous, essentially-never-benign
// catastrophic shapes, so a broken/stale guard still fails closed on
// "rm -rf /"-class commands without turning every tool call into a denial
// whenever the guard is merely unavailable. Anything not recognised here
// still falls through to the pre-existing fail-open behaviour below.
const FALLBACK_CATASTROPHIC_PATTERNS = [
  /\brm\b[^|;&\n]*?(?:(?<![\w.\/-])-\w*r\w*f\w*|(?<![\w.\/-])-\w*f\w*r\w*|(?=[^|;&\n]*--recursive)(?=[^|;&\n]*--force))/i,
  /\brm\b[^|;&\n]*\s(?:-\w+\s+)*(?:\/|~|\$HOME|\/\*|\*|\.\/\*)(?:\s|$)/i,
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&?\s*\}\s*;\s*:/,
  /\bmkfs(\.\w+)?\b/i,
  /\bdd\b[^|;&\n]*\bof=\/dev\/(sd|nvme|hd|disk|mmcblk|vd)/i,
  /\b(fdisk|parted|sgdisk|wipefs|blkdiscard)\b/i,
  // Leading `[^\n|]*` (not `[^\n]*`, issue #92 must-fix 1: ReDoS) + `env <assign>
  // <interp>` admitted (issue #92 must-fix 3) — mirrors tool-action-guard.ts's
  // pipe-download-to-shell pattern exactly; kept in sync there.
  /\b(?:curl|wget|fetch)\b[^\n|]*\|(?:[^\n|]*\|)*\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:env\s+)?(?:\w+=\S*\s+)*(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?!(?:\s+-[a-z]+)*\s+-[cem]\b)/i,
  // Stdin-executing python MODULES defeat the -m exemption above (issue #86.1) —
  // mirrors tool-action-guard.ts's pipe-download-module-exec; kept in sync there.
  /\b(?:curl|wget|fetch)\b[^|\n]*\|[^\n]*\bpython\d?\b[^\n]*\s-m\s*(?:code|pty|pdb)(?![\w.])/i,
  /\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s\/(?:\s|$)/i,
];

// WS2 dangerous-tier fallback (issue #59). Ported from — and kept in sync with
// — tool-action-guard.ts's DANGEROUS list and plugins/openclaw/interceptor.ts.
// Used ONLY when the real guard can't scan: a recognised-dangerous shape is
// gated to Claude Code's permission dialog (ask; headless blocks) instead of
// the pre-#59 fail-OPEN. Mirrors the real (already-narrowed) patterns so a
// benign op during an outage — `crontab -l`, `npm ls -g`, `git status` — still
// passes.
const FALLBACK_DANGEROUS_PATTERNS = [
  { re: /\brm\b|\bunlink\b|\brmdir\b|(?:(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?|\bxargs\s+(?:-{1,2}\S+\s+)*|-exec\s+)shred\b/i, signal: 'file-delete' },
  { re: /\bsudo\b|\bdoas\b|\bsu\s/i, signal: 'privilege-escalation' },
  { re: /\bgit\b[^|\n]*\bpush\b[^|\n]*(--force\b|-f\b|\+)/i, signal: 'git-force-push' },
  { re: /\bgit\b[^|\n]*\b(branch\s+-D|push\b[^|\n]*--delete|push\b[^|\n]*\s:)/i, signal: 'git-delete-branch' },
  { re: /\b(systemctl|service)\b[^|\n]*\b(stop|disable|mask)\b|\b(kill|pkill|killall)\b/i, signal: 'stop-process-or-service' },
  { re: /\b(iptables|ufw|nft|netplan|firewall-cmd)\b/i, signal: 'modify-network-firewall' },
  { re: /\b(?:apt|apt-get|yum|dnf|brew|pip|pip3|gem|cargo)\b[^|\n]*\b(?:install|add)\b/i, signal: 'install-package' },
  { re: /\b(?:npm|yarn|pnpm|bun)\b(?=[^|;&\n]*(?:\s['"]?-g\b['"]?|--global(?![\w-])|\bglobal\s+add\b))(?=[^|;&\n]*\s(?:install|add)(?=\s|$|[|;&\n]))|\b(?:npm|pnpm|bun)\s+(?:i(?:n(?:s(?:t(?:a(?:ll?)?)?)?)?)?|isnt(?:all)?)\b[^|;&\n]*(?:\s['"]?-g\b['"]?|--global(?![\w-]))/i, signal: 'install-package-global' },
  { re: /(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:(?:env|nohup|time|stdbuf|nice)\b(?:\s+(?:-{1,2}\S+|\w+=\S*|\d+))*\s+)*(?:sudo\s+)?(?:crontab\b(?!\s+-l\b)|at\b(?!\s+-l\b)(?!\s*$))|\/etc\/cron|\bsystemd-run\b[^|;&\n]*--on-(?:calendar|active|boot|startup|unit-active|unit-inactive)\b/i, signal: 'modify-scheduler' },
  { re: /\bdd\b[^|;&\n]*\bof=/i, signal: 'dd-overwrite' },
  { re: /\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s\/(?:etc|usr|var|home|bin|sbin|boot|lib|lib64|opt|root)(?:\/\*?)?(?:\s|$)/i, signal: 'recursive-perms-system-dir' },
  { re: /\btruncate\b[^|;&\n]*(?:-s\s*0\b|--size(?:=|\s+)0\b)/i, signal: 'truncate-to-zero' },
  { re: /\bhistory\s+-c\b|\.bash_history|truncate\b[^|\n]*\.log/i, signal: 'wipe-history-or-logs' },
  { re: /\/etc\/(passwd|shadow|sudoers)|~\/\.ssh|id_rsa|\.aws\/credentials|\.env\b/i, signal: 'touch-sensitive-path' },
  // Guard's own approval store (#118): agent-side writes here mint approvals.
  { re: /\.shieldcortex[\\/]+approvals\b/i, signal: 'touch-approval-store' },
  // Session-lease ledger + store (#227): a freeze an agent can edit is not a freeze.
  { re: /\.shieldcortex[\\/]+(?:DECISIONS\.md|leases)\b/i, signal: 'touch-decisions-ledger' },
  { re: /(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?uvx\b/i, signal: 'registry-code-exec' },
  { re: /(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:pnpm|yarn)\b[^|;&\n]*\bdlx\b/i, signal: 'registry-code-exec' },
  { re: /\b(?:base64|openssl|xxd|cat|http)\b[^\n|]*\|(?:[^\n|]*\|)*\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?:\s+-)?\s*(?:[;&|\n]|$)/i, signal: 'decode-pipe-to-shell' },
];

/** Same command/path/url field set tool-action-guard.ts extracts — narrow, not the whole args object. */
const FALLBACK_SURFACE_KEYS = [
  'command', 'cmd', 'script', 'code', 'input', 'shell', 'run',
  'path', 'file_path', 'filePath', 'file', 'target', 'destination', 'dir', 'directory',
  'url', 'uri', 'endpoint', 'href', 'host', 'to',
];

// Outage-only blunt scanner: cap the scanned surface to bound worst-case regex
// time (some ported guard patterns are O(n²) on crafted token runs). 4 KB is
// far beyond a real shell command; dangerous shapes appear early. Kept in sync
// with plugins/openclaw/interceptor.ts (FALLBACK_SCAN_CAP).
const FALLBACK_SCAN_CAP = 4096;

function fallbackExecSurface(toolInput) {
  const parts = [];
  for (const k of FALLBACK_SURFACE_KEYS) {
    const v = toolInput?.[k];
    if (typeof v === 'string' && v.length > 0) parts.push(v);
  }
  return parts.join('   ').slice(0, FALLBACK_SCAN_CAP);
}

function fallbackCatastrophicMatch(toolInput) {
  const text = fallbackExecSurface(toolInput);
  if (!text) return false;
  return FALLBACK_CATASTROPHIC_PATTERNS.some((re) => re.test(text));
}

/** First matching dangerous signal for the WS2 fallback, or null (issue #59). */
function fallbackDangerousMatch(toolInput) {
  const text = fallbackExecSurface(toolInput);
  if (!text) return null;
  for (const { re, signal } of FALLBACK_DANGEROUS_PATTERNS) {
    if (re.test(text)) return signal;
  }
  return null;
}

// ==================== AUDIT (local JSONL) ====================
// Same file the OpenClaw plugin appends to (~/.shieldcortex/audit/realtime-*.jsonl)
// so `shieldcortex` audit tooling reads one unified stream; `origin`
// disambiguates which surface produced the entry.

function summariseToolArgs(args) {
  const parts = [];
  for (const [k, val] of Object.entries(args ?? {})) {
    if (typeof val === 'string') parts.push(`${k}=${val.slice(0, 80)}`);
    else if (typeof val === 'number' || typeof val === 'boolean') parts.push(`${k}=${val}`);
  }
  return parts.join(' ').slice(0, 160);
}



function ensureDirectoryNoSymlink(dir) {
  const root = resolve(homedir());
  const target = resolve(dir);
  if (target !== root && !target.startsWith(`${root}${sep}`)) return false;
  let current = root;
  const rest = target.slice(root.length).split(sep).filter(Boolean);
  for (const part of rest) {
    current = join(current, part);
    try {
      const st = lstatSync(current);
      if (!st.isDirectory() || st.isSymbolicLink()) return false;
    } catch {
      try {
        mkdirSecure(current);
        const st = lstatSync(current);
        if (!st.isDirectory() || st.isSymbolicLink()) return false;
      } catch {
        return false;
      }
    }
  }
  return true;
}

function testOnlyPauseAppendOpen() {
  const ms = Number(process.env.SHIELDCORTEX_TEST_APPEND_OPEN_DELAY_MS ?? 0);
  if (!Number.isFinite(ms) || ms <= 0) return;
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(ms, 1000));
  } catch { /* ignore */ }
}

function testOnlyPausePostAppendValidation() {
  const ms = Number(process.env.SHIELDCORTEX_TEST_POST_APPEND_VALIDATION_DELAY_MS ?? 0);
  if (!Number.isFinite(ms) || ms <= 0) return;
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(ms, 1000));
  } catch { /* ignore */ }
}

function fdMatchesExpectedPath(fd, file) {
  try {
    const actual = fstatSync(fd);
    const expected = lstatSync(file);
    return expected.isFile()
      && !expected.isSymbolicLink()
      && actual.dev === expected.dev
      && actual.ino === expected.ino;
  } catch {
    return false;
  }
}

function cleanLogToken(value, max = 120) {
  return String(value ?? 'unknown').replace(/[\u0000-\u001f\u007f]/g, '?').slice(0, max);
}

function noteAuditSinkFailure(detail) {
  console.error(
    `[shieldcortex] ⚠️ audit sink UNWRITABLE (~/.shieldcortex/audit): ${cleanLogToken(detail, 160)} — this audit entry was DROPPED.`,
  );
}

function appendFileNoFollow(file, line) {
  let fd;
  try {
    if (!ensureDirectoryNoSymlink(dirname(file))) return false;
    testOnlyPauseAppendOpen();
    if (!ensureDirectoryNoSymlink(dirname(file))) return false;
    testOnlyPausePostAppendValidation();
    if (!ensureDirectoryNoSymlink(dirname(file))) return false;
    fd = openSync(file, constants.O_CREAT | constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink > 1 || !fdMatchesExpectedPath(fd, file)) return false;
    writeFileSync(fd, line);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
  }
}

function appendSessionGuardIndex(auditDir, entry) {
  if (!/^sc-[a-f0-9]{16}$/.test(String(entry.sessionKey ?? ''))) return;
  if (!GUARD_DEGRADED_OUTCOMES.has(String(entry.outcome ?? ''))) return;
  try {
    const dir = join(auditDir, 'session-guard');
    if (!ensureDirectoryNoSymlink(auditDir)) return;
    if (!ensureDirectoryNoSymlink(dir)) return;
    appendFileNoFollow(join(dir, `${entry.sessionKey}.jsonl`), JSON.stringify({ recordKind: 'guard', ...entry }) + '\n');
  } catch {
    // The primary audit row remains the canonical fallback; never alter the hook decision.
  }
}

// `extra` carries whatever the call site needs on the row: #139's
// permissionMode, #143's broker verdict. One slot rather than one parameter per
// feature — the two landed independently and each had added its own.
function writeAuditEntry(toolName, verdict, args, action, outcome, extra = {}) {
  try {
    const auditDir = join(homedir(), '.shieldcortex', 'audit');
    if (!ensureDirectoryNoSymlink(auditDir)) {
      noteAuditSinkFailure('audit directory is unsafe or outside the state tree');
      return;
    }
    const date = new Date().toISOString().slice(0, 10);
    let entry = {
      type: 'intercept',
      origin: 'claude-code-hook',
      tool: toolName,
      severity: verdict.severity === 'catastrophic' || verdict.severity === 'critical' ? 'critical' : verdict.decision === 'allow' ? 'low' : 'high',
      firewallResult: 'ACTION_GUARD',
      threats: safeSignalList(verdict.signals),
      anomalyScore: verdict.decision === 'block' ? 1 : verdict.decision === 'allow' ? 0.1 : 0.6,
      trustScore: 0,
      sensitivityLevel: 'INTERNAL',
      fragmentationScore: null,
      pipelineDurationMs: 0,
      preview: `${toolName} :: ${summariseToolArgs(args)}`.slice(0, 200),
      auditEventId: randomBytes(16).toString('hex'),
      ts: new Date().toISOString(),
      action,
      outcome,
      // #192: the durable record keeps the evidence (rule → matched span), not
      // just the rule names — a folded-source denial is diagnosable from the
      // row alone. Absent when no pattern produced a span; secret-egress never
      // contributes one (the span would be the secret).
      ...(verdict.matches && verdict.matches.length > 0 ? { matches: verdict.matches } : {}),
      // #189: when the reviewed-script allowlist exempted a file from folding,
      // the row says so — an allow that leaned on review must be tellable
      // apart from an allow that scanned everything.
      ...(verdict.reviewedScripts && verdict.reviewedScripts.length > 0
        ? { reviewedScripts: verdict.reviewedScripts }
        : {}),
      // #143's broker verdict arrives through here as `{ broker: … }`, so
      // "was a model consulted, and what did it say?" stays answerable from the
      // audit stream alone — same field and shape the OpenClaw plugin emits.
      // #139 adds `permissionMode` + its outcome the same way.
      ...extra,
    };
    delete entry.intentArgs;
    if (bindingMod?.attachEnforcementBinding) {
      try {
        const intentArgs = extra.intentArgs && typeof extra.intentArgs === 'object' ? extra.intentArgs : args;
        entry = bindingMod.attachEnforcementBinding(entry, {
          plane: 'action_guard',
          hookName: 'PreToolUse',
          pluginId: 'claude-code-hook',
          tool: toolName,
          args: intentArgs && typeof intentArgs === 'object' ? intentArgs : {},
        });
      } catch { /* write the unbound row rather than drop the event */ }
    }
    if (!appendFileNoFollow(join(auditDir, `realtime-${date}.jsonl`), JSON.stringify(entry) + '\n')) {
      noteAuditSinkFailure(`append failed for realtime-${date}.jsonl`);
      return;
    }
    appendSessionGuardIndex(auditDir, entry);
  } catch (err) {
    // Best-effort — never block on audit failure, but never silent either
    // (issue #95). This hook is one process per tool call, so a per-failure
    // stderr note IS the once-per-process warning; kept in sync with the
    // plugin interceptor's noteAuditSinkFailure.
    noteAuditSinkFailure(err?.message ?? err);
  }
}

// ==================== DECISION OUTPUT ====================

function emitDecision(permissionDecision, reason) {
  console.log(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision,
        permissionDecisionReason: reason,
      },
    }),
  );
}

/**
 * Emit the dangerous-tier outcome: "ask" where Claude Code will raise a prompt,
 * "deny" where it will not (see the prompt-surface rule in the header).
 *
 * The guard's verdict is `require_approval` either way — only the outcome
 * differs — so `action` is unchanged and the distinction lives in `outcome`
 * plus the recorded `permissionMode`.
 */
async function emitApprovalRequired(toolName, auditVerdict, toolInput, permissionMode, action, reason, brokerAudit, notify = null, baseExtra = {}, retryCtx = null) {
  // `brokerAudit` rides along so a brokered call keeps its judge verdict on the
  // row whichever way this goes (#143 + #139): "was a model consulted, and did
  // the harness even have a prompt surface?" must both be answerable from one
  // audit line.
  const safeBroker = safeBrokerAudit(brokerAudit);
  const broker = safeBroker ? { broker: safeBroker } : {};
  const noPromptSurface = noPromptSurfaceReason(permissionMode);
  if (!noPromptSurface) {
    const displayVerdict = safeApprovalVerdict(auditVerdict);
    writeAuditEntry(
      safeToolName(toolName),
      displayVerdict,
      redactedAuditArgs(toolName, toolInput),
      action,
      'asked',
      { ...baseExtra, intentArgs: toolInput, ...(safePermissionMode(permissionMode) ? { permissionMode: safePermissionMode(permissionMode) } : {}), ...broker },
    );
    emitDecision('ask', safeDiagnosticApprovalReason(reason));
    return;
  }
  const actionId = writeTerminalOutcomeAudit(toolName, { ...auditVerdict, reason }, toolInput, action, 'denied_no_prompt_surface', 'action_guard_denial', {
    ...baseExtra,
    ...(safePermissionMode(permissionMode) ? { permissionMode: safePermissionMode(permissionMode) } : {}),
    noPromptSurfaceReason: noPromptSurface,
    ...broker,
  });
  const notified = await alertGuardOutcome(notify, {
    toolName,
    toolInput,
    verdict: { ...auditVerdict, reason },
    outcome: 'denied_no_prompt_surface',
    event: 'action_guard_denial',
    sessionKey: baseExtra.sessionKey,
    actionId,
    // #310. Null on every caller but the real dangerous-tier path: a DEGRADED
    // guard (handleDegradedGuard) mints no retry affordance, because a scan
    // that could not run is not a verdict an operator should be offered a
    // one-tap retry of.
    retryCtx,
  });
  recordNotifyAudit(toolName, { ...auditVerdict, reason }, toolInput, { ...baseExtra, actionId }, notified);
  console.error(
    `[shieldcortex] action-guard DENIED ${safeToolName(toolName)}: approval required, but ${noPromptSurface} — denying rather than raising a prompt nothing will answer.`,
  );
  emitDecision('deny', terminalDecisionReason({ ...auditVerdict, reason }, 'denied_no_prompt_surface', 'action_guard_denial'));
}

/**
 * WS2 fail-closed path (issue #59): when the real guard cannot load or
 * evaluate, run the dependency-free fallback scan. Three tiers, so no
 * dangerous op is ever silently allowed on a scan failure — and every
 * could-not-scan decision leaves a `gate_degraded` audit row so forensics can
 * tell "scanned & allowed" from "could not scan":
 *   1. catastrophic → deny, always.
 *   2. dangerous    → gate to Claude Code's permission dialog (ask; headless
 *                     runs cannot answer → blocked). enforce:false → advisory.
 *   3. no match     → benign/unknown: fail OPEN (a degraded guard must not
 *                     wedge normal work) but leave a visible breadcrumb.
 * ALWAYS terminates the process — the caller need do nothing after.
 */
async function handleDegradedGuard(toolName, toolInput, cfg, failureNote, permissionMode, notify, baseExtra = {}) {
  const failureSummary = safeDiagnosticReason(failureNote);
  // 1. Catastrophic — hard deny, always.
  if (fallbackCatastrophicMatch(toolInput)) {
    const fallbackVerdict = { severity: 'catastrophic', decision: 'block', signals: ['fallback-scan'], reason: `Guard unavailable: ${failureSummary}; fallback catastrophic scan matched` };
    const actionId = writeTerminalOutcomeAudit(
      toolName,
      fallbackVerdict,
      toolInput, 'auto_deny', 'auto_denied', 'action_guard_denial', baseExtra,
    );
    const notified = await alertGuardOutcome(notify, {
      toolName,
      toolInput,
      verdict: fallbackVerdict,
      outcome: 'auto_denied',
      event: 'action_guard_denial',
      sessionKey: baseExtra.sessionKey,
      actionId,
    });
    recordNotifyAudit(toolName, fallbackVerdict, toolInput, { ...baseExtra, actionId }, notified);
    console.error(`[shieldcortex] ⚠️ action-guard UNAVAILABLE (${failureSummary}) and fallback scan matched a catastrophic pattern — DENYING ${safeToolName(toolName)} (fail-closed, WS2)`);
    emitDecision('deny', terminalDecisionReason(fallbackVerdict, 'auto_denied', 'action_guard_denial'));
    process.exit(0);
  }

  // 2. Dangerous — gate to the permission dialog; enforce:false opts to advisory.
  const dangerousSignal = fallbackDangerousMatch(toolInput);
  if (dangerousSignal) {
    if (!cfg.enforce) {
      const fallbackWarnVerdict = { severity: 'dangerous', decision: 'require_approval', signals: ['fallback-scan', dangerousSignal], reason: `Guard unavailable: ${failureSummary}; enforce:false advisory` };
      const actionId = writeTerminalOutcomeAudit(
        toolName,
        fallbackWarnVerdict,
        toolInput, 'gate_degraded', 'failure_allowed', 'action_guard_warning', baseExtra,
      );
      const notified = await alertGuardOutcome(notify, {
        toolName,
        toolInput,
        verdict: fallbackWarnVerdict,
        outcome: 'failure_allowed',
        event: 'action_guard_warning',
        sessionKey: baseExtra.sessionKey,
        actionId,
      });
      recordNotifyAudit(toolName, fallbackWarnVerdict, toolInput, { ...baseExtra, actionId }, notified);
      console.error(`[shieldcortex] ⚠️ action-guard unavailable (${failureSummary}) — advisory (enforce:false), allowing dangerous ${safeToolName(toolName)} [${safeSignalList([dangerousSignal]).join(', ')}]`);
      process.exit(0);
    }
    console.error(`[shieldcortex] ⚠️ action-guard UNAVAILABLE (${failureSummary}) — gating DANGEROUS ${safeToolName(toolName)} [${safeSignalList([dangerousSignal]).join(', ')}] (fail-closed)`);
    await emitApprovalRequired(
      toolName,
      { severity: 'dangerous', decision: 'require_approval', signals: ['fallback-scan', dangerousSignal] },
      toolInput,
      permissionMode,
      'gate_degraded',
      `ShieldCortex Action Guard: guard could not scan (${failureSummary}); dangerous operation [${dangerousSignal}] gated — approve only if you trust it`,
      undefined,
      notify,
      baseExtra,
    );
    process.exit(0);
  }

  // 3. No match — benign/unknown. Fail open, but never silently.
  const fallbackOpenVerdict = { severity: 'benign', decision: 'allow', signals: ['fallback-scan'], reason: `Guard unavailable: ${failureSummary}; fallback matched nothing` };
  const actionId = writeTerminalOutcomeAudit(
    toolName,
    fallbackOpenVerdict,
    toolInput, 'gate_degraded', 'failure_allowed', 'action_guard_warning', baseExtra,
  );
  const notified = await alertGuardOutcome(notify, {
    toolName,
    toolInput,
    verdict: fallbackOpenVerdict,
    outcome: 'failure_allowed',
    event: 'action_guard_warning',
    sessionKey: baseExtra.sessionKey,
    actionId,
  });
  recordNotifyAudit(toolName, fallbackOpenVerdict, toolInput, { ...baseExtra, actionId }, notified);
  console.error(`[shieldcortex] action-guard unavailable (${failureSummary}) — allowing ${safeToolName(toolName)} (fallback matched nothing; fail-open)`);
  process.exit(0);
}

// ==================== MAIN ====================

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('readable', () => {
  let chunk;
  while ((chunk = process.stdin.read()) !== null) input += chunk;
});

process.stdin.on('end', async () => {
  try {
    bindingMod = await loadBinding();
    const cfg = loadActionGuardConfig();
    if (!cfg.enabled) process.exit(0);

    let hookData;
    try {
      hookData = JSON.parse(input || '{}');
    } catch {
      process.exit(0); // Malformed payload — nothing to evaluate.
    }
    const toolName = typeof hookData.tool_name === 'string' ? hookData.tool_name : '';
    const toolInput =
      hookData.tool_input && typeof hookData.tool_input === 'object' ? hookData.tool_input : {};
    // Absent on harnesses that don't report it — noPromptSurfaceReason() treats
    // that as "cannot confirm a prompt surface", not as "prompting is fine".
    const permissionMode = hookData.permission_mode;
    if (!toolName) process.exit(0);
    const baseExtra = hookSessionExtras(hookData, permissionMode);
    let notifyPromise;
    const getNotify = () => {
      if (!notifyPromise) notifyPromise = loadNotify(cfg.notify).catch(() => null);
      return notifyPromise;
    };

    // Session action lease (#227) — EARLY, before the guard even loads. A
    // freeze is a HARD control and must bind regardless of the guard's own
    // state: if it ran only after a successful guard evaluation, a missing/
    // stale `dist` (an upgrade window) would let a frozen action through the
    // degraded fallback, which does not know the freeze. So it runs here,
    // before loadGuard, before every approval affordance. Unscoped calls (the
    // overwhelming majority) return null without touching disk. A THROW or a
    // missing module is treated as no-lease — a broken lease layer must never
    // become a new way to deny everything — while state UNreadability fails
    // closed to 'unknown' inside the store itself.
    const leaseSelf = baseExtra.sessionKey || `ppid:${process.ppid}`;
    let leaseGate = null;
    try {
      const lease = await loadLease();
      if (lease) {
        leaseGate = lease.evaluateToolCallLease(toolName, toolInput, { self: leaseSelf });
        if (leaseGate && leaseGate.ledgerChanged) {
          console.error(
            `[shieldcortex] DECISIONS.md changed since last read (${String(leaseGate.ledgerChanged.fromHash).slice(0, 12)} → ${String(leaseGate.ledgerChanged.toHash).slice(0, 12)}) — tamper evidence, review the ledger`,
          );
        }
        if (leaseGate && leaseGate.decision.verdict !== 'allow') {
          writeAuditEntry(safeToolName(toolName), {
            decision: 'block', severity: 'dangerous', family: 'exec',
            action: `session-lease:${leaseGate.scope}`, reason: leaseGate.decision.reason,
            signals: ['session-lease', leaseGate.decision.verdict],
          }, redactedAuditArgs(toolName, toolInput), 'auto_deny', 'auto_denied', baseExtra);
          console.error(`[shieldcortex] action-guard SESSION-LEASE refused ${safeToolName(toolName)} [${leaseGate.scope}/${leaseGate.decision.verdict}]`);
          emitDecision('deny', `ShieldCortex Action Guard: ${leaseGate.decision.reason}`);
          process.exit(0);
        }
      }
    } catch {
      leaseGate = null;
    }

    const guard = await loadGuard();
    bindingMod = await loadBinding();
    if (!guard) {
      await handleDegradedGuard(toolName, toolInput, cfg, 'missing dist build', permissionMode, await getNotify(), baseExtra); // always exits
      return;
    }

    const resolveScriptSource = await loadScriptResolver();
    // #189: the allowlist check only rides along when a resolver exists —
    // without a resolver nothing folds, so there is nothing to exempt.
    const isReviewedScript = resolveScriptSource
      ? await loadReviewedScriptCheck(cfg.reviewedScripts)
      : undefined;
    let verdict;
    try {
      // 4th arg, not the 3rd — the 3rd is the IronDome config. Passing the
      // options object into the config slot type-checks in .mjs and silently
      // does nothing, which is the same shape of defect as the gap this fixes.
      verdict = guard.evaluateToolCall(
        toolName,
        toolInput,
        undefined,
        resolveScriptSource
          ? (isReviewedScript ? { resolveScriptSource, isReviewedScript } : { resolveScriptSource })
          : undefined,
      );
    } catch (err) {
      await handleDegradedGuard(toolName, toolInput, cfg, `evaluation error: ${err?.message ?? err}`, permissionMode, await getNotify(), baseExtra); // always exits
      return;
    }

    if (verdict.decision === 'allow') {
      // Issue #95: audit RECOGNISED allows (severity above benign) so forensics
      // can tell "scanned & allowed" from "never scanned". Benign allows stay
      // unaudited — volume discipline, mirrored with the plugin interceptor.
      if (verdict.severity !== 'benign' && cfg.auditAllows !== false) {
        writeAuditEntry(safeToolName(toolName), safeAllowAuditVerdict(verdict, 'allowed'), redactedAuditArgs(toolName, toolInput), 'allow', 'allowed', baseExtra);
      }
      process.exit(0);
    }

    // Catastrophic — hard deny, always enforced while the guard is enabled.
    if (verdict.decision === 'block') {
      // #227: the action is refused, so release any lease this call minted
      // early — a blocked action must not leave a hold on that scope. (A
      // frozen scope was already refused above and acquired nothing.)
      if (leaseGate?.acquired) {
        try { (await loadLease())?.releaseToolCallLease(toolName, toolInput, { self: leaseSelf }); } catch { /* self-heals at TTL */ }
      }
      const actionId = writeTerminalOutcomeAudit(toolName, verdict, toolInput, 'auto_deny', 'auto_denied', 'action_guard_denial', baseExtra);
      const notified = await alertGuardOutcome(getNotify(), {
        toolName,
        toolInput,
        verdict,
        outcome: 'auto_denied',
        event: 'action_guard_denial',
        sessionKey: baseExtra.sessionKey,
        actionId,
      });
      recordNotifyAudit(toolName, verdict, toolInput, { ...baseExtra, actionId }, notified);
      console.error(
        `[shieldcortex] action-guard BLOCKED ${safeToolName(toolName)}: ${safeGuardOutcomeReason(verdict, 'auto_denied', 'action_guard_denial')} [${safeSignalList(verdict.signals).join(', ')}]`,
      );
      emitDecision('deny', terminalDecisionReason(verdict, 'auto_denied', 'action_guard_denial'));
      process.exit(0);
    }

    // require_approval — the dangerous tier.
    // Per-operator autoApprove allowlist (family / action / signal match, same
    // matching as the plugin). Never applies to catastrophic — that returned above.
    const autoApprove = cfg.autoApprove ?? [];
    if (autoApprove.length > 0) {
      const hay = [verdict.family, verdict.action, ...verdict.signals].map((s) => String(s).toLowerCase());
      const matched = autoApprove.some((a) => {
        const n = a.toLowerCase();
        return hay.some((h) => h === n || h.includes(n));
      });
      if (matched) {
        writeAuditEntry(safeToolName(toolName), safeAllowAuditVerdict(verdict, 'approved'), redactedAuditArgs(toolName, toolInput), 'require_approval', 'approved', baseExtra);
        process.exit(0); // Defer to Claude Code's own permission system.
      }
    }

    if (!cfg.enforce) {
      const actionId = writeTerminalOutcomeAudit(toolName, verdict, toolInput, 'warn', 'warned', 'action_guard_warning', baseExtra);
      const notified = await alertGuardOutcome(getNotify(), {
        toolName,
        toolInput,
        verdict,
        outcome: 'warned',
        event: 'action_guard_warning',
        sessionKey: baseExtra.sessionKey,
        actionId,
      });
      recordNotifyAudit(toolName, verdict, toolInput, { ...baseExtra, actionId }, notified);
      console.error(`[shieldcortex] ⚠️ Action Guard: ${safeToolName(toolName)} — ${safeGuardOutcomeReason(verdict, 'warned', 'action_guard_warning')}`);
      process.exit(0); // Advisory: warn, emit no decision.
    }

    // #310 operator retry control, loaded once for both halves: the consume
    // just below, and the fingerprint/card on the DNP path further down. Null
    // — the normal answer — unless `actionGuard.retryCards` is exactly true
    // and the dist module is complete, in which case this hook behaves
    // exactly as it did before #310.
    const retryPlane = await loadRetryControl(cfg.retry);
    const retryOriginCwd = retryPlane ? retryPlane.mod.canonicaliseCwd(hookData.cwd) : undefined;
    const retryCtx = retryPlane ? { rawConfig: cfg.retry, cwd: retryOriginCwd } : null;

    // One-shot exact-command approval (#118). An operator who ran
    // `shieldcortex approve <hash>` in a terminal gets exactly one pass for
    // exactly this call; the approval is spent here. Everything else falls
    // through to the normal refusal, which now carries the hash to approve.
    const approvals = await loadApprovals();
    if (approvals) {
      try {
        const spent = approvals.consumeApproval(toolName, toolInput);
        if (spent) {
          writeAuditEntry(safeToolName(toolName), safeAllowAuditVerdict(verdict, 'approved'), redactedAuditArgs(toolName, toolInput), 'require_approval', 'approved', baseExtra);
          console.error(
            `[shieldcortex] action-guard: consumed operator approval ${spent.hash.slice(0, 12)} for ${safeToolName(toolName)} (single use).`,
          );
          process.exit(0); // Defer to the harness's own permission system.
        }
      } catch {
        // An unusable approvals store must never widen OR wedge the guard —
        // fall through to the broker and then to the standard refusal below.
      }
    }

    // ── #310 retry grant consume ──────────────────────────────────────────
    // The other half of operator retry control: this call may be the RETRY of
    // something that was denied on this promptless box, for which a human has
    // since authorised exactly one pass — by tapping a card the gateway
    // authenticated, or by typing `shieldcortex approve --denial <actionId>`.
    //
    // Placed here, beside #118 and before the broker, for the same reason
    // #118 is: an operator who has already spoken is not overruled by an AI.
    // Placed AFTER the catastrophic branch (which returned long ago) because
    // no retry path may ever exist for that tier.
    //
    // The origin is computed HERE, from this hook's own context — the harness
    // payload's cwd (realpath-canonicalised) and the tool name — and never
    // from tool input, which the agent controls.
    if (retryPlane) {
      try {
        const spentRetry = retryPlane.mod.consumeRetryGrant(
          {
            hash: retryPlane.mod.hashToolCall(toolName, toolInput),
            origin: { cwd: retryOriginCwd, tool: toolName },
          },
          { home: homedir() },
        );
        if (spentRetry) {
          writeAuditEntry(
            safeToolName(toolName),
            safeAllowAuditVerdict(verdict, 'approved'),
            redactedAuditArgs(toolName, toolInput),
            'require_approval',
            'approved',
            { ...baseExtra, grantKind: 'retry', ...(spentRetry.actionId ? { actionId: spentRetry.actionId } : {}) },
          );
          console.error(
            `[shieldcortex] action-guard: consumed operator RETRY grant for ${safeToolName(toolName)} (#310, single use, scoped to this directory).`,
          );
          process.exit(0); // Defer to the harness's own permission system.
        }
      } catch {
        // Same discipline as #118 above: never widen, never wedge.
      }
    }

    // ── AI-assisted approval broker (#143) ────────────────────────────────
    // Runs AFTER the one-shot approval is consumed, deliberately: an operator
    // who typed `shieldcortex approve <hash>` in their own terminal has already
    // spoken, and the AI never overrules the human. It runs BEFORE the pending
    // record is written, so a call the judge hardens is not simultaneously
    // offered up for approval.
    const broker = await loadBroker(cfg.broker);
    const brokered = broker ? await runBrokerPass(broker, toolName, toolInput, verdict) : null;

    if (brokered?.outcome === 'harden') {
      const brokerAudit = safeBrokerAudit(brokered.audit);
      const actionId = writeTerminalOutcomeAudit(toolName, { ...verdict, reason: brokered.reason ?? verdict.reason }, toolInput, 'require_approval', 'auto_denied', 'action_guard_denial', { ...baseExtra, ...(brokerAudit ? { broker: brokerAudit } : {}) });
      const notified = await alertGuardOutcome(getNotify(), {
        toolName,
        toolInput,
        verdict: { ...verdict, reason: brokered.reason ?? verdict.reason },
        outcome: 'auto_denied',
        event: 'action_guard_denial',
        sessionKey: baseExtra.sessionKey,
        actionId,
      });
      recordNotifyAudit(toolName, { ...verdict, reason: brokered.reason ?? verdict.reason }, toolInput, { ...baseExtra, actionId, ...(brokerAudit ? { broker: brokerAudit } : {}) }, notified);
      console.error(`[shieldcortex] approval broker HARDENED ${safeToolName(toolName)} to a denial: ${safeDiagnosticReason(brokered.reason)}`);
      // No approve-hash offered. Hardening exists precisely for the case where
      // the request is trying to talk somebody into saying yes.
      emitDecision('deny', `ShieldCortex approval broker: injection-risk review hardened this request to a denial. [${safeSignalList(verdict.signals).join(', ')}]`);
      process.exit(0);
    }

    if (brokered?.outcome === 'pre_clear') {
      const brokerAudit = safeBrokerAudit(brokered.audit);
      writeAuditEntry(safeToolName(toolName), safeAllowAuditVerdict(verdict, 'approved'), redactedAuditArgs(toolName, toolInput), 'require_approval', 'approved', { ...baseExtra, ...(brokerAudit ? { broker: brokerAudit } : {}) });
      console.error(`[shieldcortex] approval broker PRE-CLEARED ${safeToolName(toolName)}: ${safeDiagnosticReason(brokered.reason)} [${safeSignalList(verdict.signals).join(', ')}]`);
      // No decision emitted — the guard defers to Claude Code's own permission
      // system rather than answering "allow". ShieldCortex narrows or stays
      // neutral; it never WIDENS what the user's own settings permit.
      process.exit(0);
    }

    const noPromptSurfaceForHold = noPromptSurfaceReason(permissionMode);

    // hold / not_brokerable / no broker at all → the pre-#143 refusal, intact
    // only when something can actually hold. Promptless denials are terminal:
    // no pending approval, no retry hash, no operator affordance.
    if (approvals && !noPromptSurfaceForHold) {
      try {
        approvals.recordPending({
          tool: toolName,
          input: toolInput,
          summary: describeToolCall(toolName, toolInput),
          signals: verdict.signals,
        });
      } catch {
        // As above: never widen, never wedge.
      }
    }

    const displayVerdict = safeApprovalVerdict(verdict);
    let message = `ShieldCortex Action Guard: ${displayVerdict.reason} [${displayVerdict.signals.join(', ')}]`;
    if (approvals && !noPromptSurfaceForHold) {
      let fullHash;
      try {
        fullHash = approvals.hashToolCall(toolName, toolInput);
        message += ` — to allow this exact command once, run in YOUR terminal: shieldcortex approve ${fullHash.slice(0, 12)}`;
      } catch {
        // Hash is a nicety; never let it break the refusal path.
      }

      // ── operator-notify transport (#143) ─────────────────────────────────
      // The 433 real stops this issue was filed about all dead-ended right
      // here: a hold with nothing but a hash in a transcript nobody was
      // watching. If the operator configured a channel, ping it now — a
      // best-effort ADDITION to the unchanged refusal above, never a
      // replacement for it (`emitApprovalRequired` below still emits the
      // identical decision whether or not this delivers, times out, or errors).
      //
      // The notification must say which of the two things actually happens
      // next, so it is told the prompt-surface verdict up front: on a
      // promptless box this is not "approve this?" but "this was BLOCKED and
      // did not run". `emitApprovalRequired` re-derives the same value from
      // the same permissionMode below and remains the sole owner of the
      // decision — nothing here can change it.
      if (fullHash) {
        const result = await pingOperator(await getNotify(), {
          toolName,
          toolInput,
          verdict,
          hash: fullHash,
          noPromptSurface: null,
          // Which job died. Absent on a harness that does not report them —
          // rendered only when present, never as "undefined".
          sessionKey: baseExtra.sessionKey,
        });
        recordNotifyAudit(toolName, verdict, toolInput, baseExtra, result);
      }
    }
    // #139: ask ONLY where a prompt can actually be raised. Under
    // bypassPermissions, Claude Code 2.1.76 converts a hook `ask` into `allow`
    // and executes — the guard looks like it fired, the audit row agrees, and
    // the command still ran. `deny` is the one verdict every version honours
    // unconditionally, so an unconfirmable prompt surface is treated as
    // promptless rather than as fine.
    //
    // Placed at the END of the chain on purpose: the one-shot approval (#118)
    // and the broker (#143) both get their say first, so an operator who
    // already approved, or a call the judge hardened, is unaffected by this.
    await emitApprovalRequired(
      toolName,
      verdict,
      toolInput,
      permissionMode,
      'require_approval',
      message,
      brokered?.audit,
      await getNotify(),
      baseExtra,
      retryCtx,
    );
    process.exit(0);
  } catch (error) {
    console.error(`[shieldcortex] action-guard hook error: ${error?.message ?? error}`);
    process.exit(0);
  }
});
