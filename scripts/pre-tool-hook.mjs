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

import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { homedir } from 'os';
import { fileURLToPath, pathToFileURL } from 'url';

const here = dirname(fileURLToPath(import.meta.url));

// ==================== CONFIG ====================

const DEFAULT_ACTION_GUARD = { enabled: true, enforce: true, autoApprove: [], auditAllows: true };

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
  return `unrecognised permission_mode "${permissionMode}"`;
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
    const [notifyConfigMod, notifyMod, webhookMod, openclawMod] = await Promise.all([
      load('notify-config.js'), load('operator-notify.js'), load('webhook-notify-channel.js'),
      load('openclaw-approval-channel.js'),
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
    if (
      normalised.openclaw === true &&
      typeof openclawMod?.createOpenClawApprovalChannel === 'function' &&
      typeof openclawMod?.resolveOpenClawBinaryLite === 'function'
    ) {
      const openclawBin = openclawMod.resolveOpenClawBinaryLite();
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
      /** Where a denial goes when the primary channel cannot carry one. Null
       *  means an openclaw-only install: the denial reaches no channel, which
       *  is the honest outcome until a non-interactive gateway send path
       *  exists to point it at. The terminal-hash floor is unchanged. */
      denialChannel: webhookChannel,
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
async function pingOperator(notify, { toolName, toolInput, verdict, hash, noPromptSurface, sessionId, cwd }) {
  if (!notify) return;
  const denied = typeof noPromptSurface === 'string' && noPromptSurface.length > 0;
  // A denial cannot go to an interactive Approve/Deny card — there is nothing
  // left to decide — so it takes the plain-message channel or no channel at
  // all. `deliveredVia: null` is a normal outcome here, exactly as it is when
  // nothing is configured.
  const channel = denied ? notify.denialChannel : notify.channel;
  if (!channel) return;
  try {
    const result = await notify.requestOperatorApproval(
      {
        hash,
        tool: toolName,
        command: describeToolCall(toolName, toolInput),
        signals: verdict.signals,
        severity: verdict.severity,
        reason: verdict.reason,
        event: denied ? 'denied_no_prompt_surface' : 'approval_requested',
        deniedReason: denied ? noPromptSurface : undefined,
        // Which job. Straight off the harness payload, bounded and validated
        // by buildNotification in operator-notify.ts.
        sessionId,
        cwd,
      },
      { channel, timeoutMs: notify.config.timeoutMs },
    );
    if (result?.deliveredVia) {
      console.error(
        denied
          ? `[shieldcortex] operator-notify: reported the DENIAL of ${toolName} via ${result.deliveredVia} (${hash.slice(0, 12)}).`
          : `[shieldcortex] approval broker: pinged the operator via ${result.deliveredVia} (${hash.slice(0, 12)}).`,
      );
    }
  } catch (err) {
    // A notify transport that throws must not change the guard's outcome —
    // it already recorded/is about to record the pending hash regardless.
    console.error(`[shieldcortex] ⚠️ operator-notify error: ${err?.message ?? err} — falling back to the terminal hash only.`);
  }
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
    const judgeResult = await broker.runJudge(
      {
        tool: toolName,
        toolInput,
        verdict: {
          severity: verdict.severity,
          action: verdict.action,
          reason: verdict.reason,
          signals: verdict.signals,
        },
      },
      invoke,
      { timeoutMs: broker.config.judgeTimeoutMs },
    );
    const decision = broker.brokerDecision({
      tool: toolName,
      toolInput,
      verdict,
      judge: judgeResult,
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

// `extra` carries whatever the call site needs on the row: #139's
// permissionMode, #143's broker verdict. One slot rather than one parameter per
// feature — the two landed independently and each had added its own.
function writeAuditEntry(toolName, verdict, args, action, outcome, extra = {}) {
  try {
    const auditDir = join(homedir(), '.shieldcortex', 'audit');
    mkdirSync(auditDir, { recursive: true });
    const date = new Date().toISOString().slice(0, 10);
    const entry = {
      type: 'intercept',
      origin: 'claude-code-hook',
      tool: toolName,
      severity: verdict.severity === 'catastrophic' ? 'critical' : verdict.decision === 'allow' ? 'low' : 'high',
      firewallResult: 'ACTION_GUARD',
      threats: verdict.signals,
      anomalyScore: verdict.decision === 'block' ? 1 : verdict.decision === 'allow' ? 0.1 : 0.6,
      trustScore: 0,
      sensitivityLevel: 'INTERNAL',
      fragmentationScore: null,
      pipelineDurationMs: 0,
      preview: `${toolName} :: ${summariseToolArgs(args)}`.slice(0, 200),
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
    appendFileSync(join(auditDir, `realtime-${date}.jsonl`), JSON.stringify(entry) + '\n');
  } catch (err) {
    // Best-effort — never block on audit failure, but never silent either
    // (issue #95). This hook is one process per tool call, so a per-failure
    // stderr note IS the once-per-process warning; kept in sync with the
    // plugin interceptor's noteAuditSinkFailure.
    console.error(
      `[shieldcortex] ⚠️ audit sink UNWRITABLE (~/.shieldcortex/audit): ${err?.message ?? err} — this audit entry was DROPPED.`,
    );
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
function emitApprovalRequired(toolName, auditVerdict, toolInput, permissionMode, action, reason, brokerAudit) {
  // `brokerAudit` rides along so a brokered call keeps its judge verdict on the
  // row whichever way this goes (#143 + #139): "was a model consulted, and did
  // the harness even have a prompt surface?" must both be answerable from one
  // audit line.
  const broker = brokerAudit ? { broker: brokerAudit } : {};
  const noPromptSurface = noPromptSurfaceReason(permissionMode);
  if (!noPromptSurface) {
    writeAuditEntry(toolName, auditVerdict, toolInput, action, 'asked', { permissionMode, ...broker });
    emitDecision('ask', reason);
    return;
  }
  writeAuditEntry(toolName, auditVerdict, toolInput, action, 'denied_no_prompt_surface', {
    permissionMode: typeof permissionMode === 'string' ? permissionMode : null,
    noPromptSurfaceReason: noPromptSurface,
    ...broker,
  });
  console.error(
    `[shieldcortex] action-guard DENIED ${toolName}: approval required, but ${noPromptSurface} — denying rather than raising a prompt nothing will answer.`,
  );
  emitDecision(
    'deny',
    `${reason} — this needs approval, but ${noPromptSurface}, so it is denied rather than left to an unanswerable prompt. Run it yourself, add an actionGuard.autoApprove entry for it, or set actionGuard.enforce:false to downgrade the dangerous tier to warnings.`,
  );
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
function handleDegradedGuard(toolName, toolInput, cfg, failureNote, permissionMode) {
  // 1. Catastrophic — hard deny, always.
  if (fallbackCatastrophicMatch(toolInput)) {
    writeAuditEntry(
      toolName,
      { severity: 'catastrophic', decision: 'block', signals: ['fallback-scan'] },
      toolInput, 'auto_deny', 'auto_denied',
    );
    console.error(`[shieldcortex] ⚠️ action-guard UNAVAILABLE (${failureNote}) and fallback scan matched a catastrophic pattern — DENYING ${toolName} (fail-closed, WS2)`);
    emitDecision('deny', `ShieldCortex Action Guard: ${failureNote}, fallback catastrophic scan matched — denying to fail closed`);
    process.exit(0);
  }

  // 2. Dangerous — gate to the permission dialog; enforce:false opts to advisory.
  const dangerousSignal = fallbackDangerousMatch(toolInput);
  if (dangerousSignal) {
    if (!cfg.enforce) {
      writeAuditEntry(
        toolName,
        { severity: 'dangerous', decision: 'require_approval', signals: ['fallback-scan', dangerousSignal] },
        toolInput, 'gate_degraded', 'failure_allowed',
      );
      console.error(`[shieldcortex] ⚠️ action-guard unavailable (${failureNote}) — advisory (enforce:false), allowing dangerous ${toolName} [${dangerousSignal}]`);
      process.exit(0);
    }
    console.error(`[shieldcortex] ⚠️ action-guard UNAVAILABLE (${failureNote}) — gating DANGEROUS ${toolName} [${dangerousSignal}] (fail-closed)`);
    emitApprovalRequired(
      toolName,
      { severity: 'dangerous', decision: 'require_approval', signals: ['fallback-scan', dangerousSignal] },
      toolInput,
      permissionMode,
      'gate_degraded',
      `ShieldCortex Action Guard: guard could not scan (${failureNote}); dangerous operation [${dangerousSignal}] gated — approve only if you trust it`,
    );
    process.exit(0);
  }

  // 3. No match — benign/unknown. Fail open, but never silently.
  writeAuditEntry(
    toolName,
    { severity: 'benign', decision: 'allow', signals: ['fallback-scan'] },
    toolInput, 'gate_degraded', 'failure_allowed',
  );
  console.error(`[shieldcortex] action-guard unavailable (${failureNote}) — allowing ${toolName} (fallback matched nothing; fail-open)`);
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

    const guard = await loadGuard();
    if (!guard) {
      handleDegradedGuard(toolName, toolInput, cfg, 'missing dist build', permissionMode); // always exits
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
      handleDegradedGuard(toolName, toolInput, cfg, `evaluation error: ${err?.message ?? err}`, permissionMode); // always exits
      return;
    }

    if (verdict.decision === 'allow') {
      // Issue #95: audit RECOGNISED allows (severity above benign) so forensics
      // can tell "scanned & allowed" from "never scanned". Benign allows stay
      // unaudited — volume discipline, mirrored with the plugin interceptor.
      if (verdict.severity !== 'benign' && cfg.auditAllows !== false) {
        writeAuditEntry(toolName, verdict, toolInput, 'allow', 'allowed');
      }
      process.exit(0);
    }

    // Catastrophic — hard deny, always enforced while the guard is enabled.
    if (verdict.decision === 'block') {
      writeAuditEntry(toolName, verdict, toolInput, 'auto_deny', 'auto_denied');
      console.error(
        `[shieldcortex] action-guard BLOCKED ${toolName}: ${verdict.reason} [${verdict.signals.join(', ')}]`,
      );
      emitDecision('deny', `ShieldCortex Action Guard: ${verdict.reason} [${verdict.signals.join(', ')}]`);
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
        writeAuditEntry(toolName, verdict, toolInput, 'require_approval', 'approved');
        process.exit(0); // Defer to Claude Code's own permission system.
      }
    }

    if (!cfg.enforce) {
      writeAuditEntry(toolName, verdict, toolInput, 'warn', 'warned');
      console.error(`[shieldcortex] ⚠️ Action Guard: ${toolName} — ${verdict.reason}`);
      process.exit(0); // Advisory: warn, emit no decision.
    }

    // One-shot exact-command approval (#118). An operator who ran
    // `shieldcortex approve <hash>` in a terminal gets exactly one pass for
    // exactly this call; the approval is spent here. Everything else falls
    // through to the normal refusal, which now carries the hash to approve.
    const approvals = await loadApprovals();
    if (approvals) {
      try {
        const spent = approvals.consumeApproval(toolName, toolInput);
        if (spent) {
          writeAuditEntry(toolName, verdict, toolInput, 'require_approval', 'approved');
          console.error(
            `[shieldcortex] action-guard: consumed operator approval ${spent.hash.slice(0, 12)} for ${toolName} (single use).`,
          );
          process.exit(0); // Defer to the harness's own permission system.
        }
      } catch {
        // An unusable approvals store must never widen OR wedge the guard —
        // fall through to the broker and then to the standard refusal below.
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
      writeAuditEntry(toolName, verdict, toolInput, 'require_approval', 'auto_denied', { broker: brokered.audit });
      console.error(`[shieldcortex] approval broker HARDENED ${toolName} to a denial: ${brokered.reason}`);
      // No approve-hash offered. Hardening exists precisely for the case where
      // the request is trying to talk somebody into saying yes.
      emitDecision('deny', `ShieldCortex approval broker: ${brokered.reason}`);
      process.exit(0);
    }

    if (brokered?.outcome === 'pre_clear') {
      writeAuditEntry(toolName, verdict, toolInput, 'require_approval', 'approved', { broker: brokered.audit });
      console.error(`[shieldcortex] approval broker PRE-CLEARED ${toolName}: ${brokered.reason} [${verdict.signals.join(', ')}]`);
      // No decision emitted — the guard defers to Claude Code's own permission
      // system rather than answering "allow". ShieldCortex narrows or stays
      // neutral; it never WIDENS what the user's own settings permit.
      process.exit(0);
    }

    // hold / not_brokerable / no broker at all → the pre-#143 refusal, intact.
    if (approvals) {
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

    let message = `ShieldCortex Action Guard: ${verdict.reason} [${verdict.signals.join(', ')}]`;
    if (approvals) {
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
        const notify = await loadNotify(cfg.notify);
        await pingOperator(notify, {
          toolName,
          toolInput,
          verdict,
          hash: fullHash,
          noPromptSurface: noPromptSurfaceReason(permissionMode),
          // Which job died. Absent on a harness that does not report them —
          // rendered only when present, never as "undefined".
          sessionId: typeof hookData.session_id === 'string' ? hookData.session_id : undefined,
          cwd: typeof hookData.cwd === 'string' ? hookData.cwd : undefined,
        });
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
    emitApprovalRequired(
      toolName,
      verdict,
      toolInput,
      permissionMode,
      'require_approval',
      message,
      brokered?.audit,
    );
    process.exit(0);
  } catch (error) {
    console.error(`[shieldcortex] action-guard hook error: ${error?.message ?? error}`);
    process.exit(0);
  }
});
