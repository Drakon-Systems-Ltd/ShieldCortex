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
 *     own confirm dialog) by default. `actionGuard.enforce:false` opts down to
 *     a stderr warning with NO decision. In headless runs ("claude --print")
 *     "ask" cannot prompt, so the call fails — the same fail-closed unattended
 *     posture as the plugin's no-approver deny path.
 *   - autoApprove match              → NO decision. The guard defers to Claude
 *     Code's own permission system rather than emitting "allow": ShieldCortex
 *     narrows or stays neutral, it never WIDENS what the user's settings allow.
 *   - benign / read-only / pure-print → no output at all.
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

const DEFAULT_ACTION_GUARD = { enabled: true, enforce: true, autoApprove: [] };

function loadActionGuardConfig() {
  try {
    const configPath = join(homedir(), '.shieldcortex', 'config.json');
    if (!existsSync(configPath)) return { ...DEFAULT_ACTION_GUARD };
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    const raw = config?.actionGuard;
    if (!raw || typeof raw !== 'object') return { ...DEFAULT_ACTION_GUARD };
    return {
      enabled: raw.enabled !== false,
      enforce: raw.enforce !== false,
      autoApprove: Array.isArray(raw.autoApprove) ? raw.autoApprove.filter((a) => typeof a === 'string') : [],
    };
  } catch {
    // Unreadable config → guard on with defaults. Enforce-by-default means a
    // corrupt config file must not silently disable the guard.
    return { ...DEFAULT_ACTION_GUARD };
  }
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

// ==================== FALLBACK (guard load/eval failure — WS2) ====================
// Deliberately DUPLICATED from tool-action-guard.ts's CATASTROPHIC list, not
// imported — it must keep working when the dist build is the thing that's
// broken. Narrow by design: only the unambiguous, essentially-never-benign
// catastrophic shapes, so a broken/stale guard still fails closed on
// "rm -rf /"-class commands without turning every tool call into a denial
// whenever the guard is merely unavailable. Anything not recognised here
// still falls through to the pre-existing fail-open behaviour below.
const FALLBACK_CATASTROPHIC_PATTERNS = [
  /\brm\b[^|;&\n]*?(?:-\w*r\w*f\w*|-\w*f\w*r\w*|(?=[^|;&\n]*--recursive)(?=[^|;&\n]*--force))/i,
  /\brm\b[^|;&\n]*\s(?:-\w+\s+)*(?:\/|~|\$HOME|\/\*|\*|\.\/\*)(?:\s|$)/i,
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&?\s*\}\s*;\s*:/,
  /\bmkfs(\.\w+)?\b/i,
  /\bdd\b[^|;&\n]*\bof=\/dev\/(sd|nvme|hd|disk|mmcblk|vd)/i,
  /\b(fdisk|parted|sgdisk|wipefs|blkdiscard)\b/i,
  // Leading `[^\n|]*` (not `[^\n]*`, issue #92 must-fix 1: ReDoS) + `env <assign>
  // <interp>` admitted (issue #92 must-fix 3) — mirrors tool-action-guard.ts's
  // pipe-download-to-shell pattern exactly; kept in sync there.
  /\b(?:curl|wget|fetch)\b[^\n|]*\|(?:[^\n|]*\|)*\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:env\s+)?(?:\w+=\S*\s+)*(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?!(?:\s+-[a-z]+)*\s+-[cem]\b)/i,
  /\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s\/(?:\s|$)/i,
];

/** Same command/path/url field set tool-action-guard.ts extracts — narrow, not the whole args object. */
const FALLBACK_SURFACE_KEYS = [
  'command', 'cmd', 'script', 'code', 'input', 'shell', 'run',
  'path', 'file_path', 'filePath', 'file', 'target', 'destination', 'dir', 'directory',
  'url', 'uri', 'endpoint', 'href', 'host', 'to',
];

function fallbackExecSurface(toolInput) {
  const parts = [];
  for (const k of FALLBACK_SURFACE_KEYS) {
    const v = toolInput?.[k];
    if (typeof v === 'string' && v.length > 0) parts.push(v);
  }
  return parts.join('   ');
}

function fallbackCatastrophicMatch(toolInput) {
  const text = fallbackExecSurface(toolInput);
  if (!text) return false;
  return FALLBACK_CATASTROPHIC_PATTERNS.some((re) => re.test(text));
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

function writeAuditEntry(toolName, verdict, args, action, outcome) {
  try {
    const auditDir = join(homedir(), '.shieldcortex', 'audit');
    mkdirSync(auditDir, { recursive: true });
    const date = new Date().toISOString().slice(0, 10);
    const entry = {
      type: 'intercept',
      origin: 'claude-code-hook',
      tool: toolName,
      severity: verdict.severity === 'catastrophic' ? 'critical' : 'high',
      firewallResult: 'ACTION_GUARD',
      threats: verdict.signals,
      anomalyScore: verdict.decision === 'block' ? 1 : 0.6,
      trustScore: 0,
      sensitivityLevel: 'INTERNAL',
      fragmentationScore: null,
      pipelineDurationMs: 0,
      preview: `${toolName} :: ${summariseToolArgs(args)}`.slice(0, 200),
      ts: new Date().toISOString(),
      action,
      outcome,
    };
    appendFileSync(join(auditDir, `realtime-${date}.jsonl`), JSON.stringify(entry) + '\n');
  } catch {
    // Best-effort — never block on audit failure.
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
 * WS2 fail-closed path: when the real guard cannot load or evaluate, run the
 * narrow fallback scan and deny a catastrophic-looking command instead of
 * silently allowing it. Exits the process (denying) when the fallback
 * matches; otherwise returns so the caller falls through to its existing
 * fail-OPEN logging — the fallback recognising nothing is not evidence the
 * command is safe, only that it isn't one of the handful of unambiguous shapes.
 */
function denyIfFallbackCatastrophic(toolName, toolInput, failureNote) {
  if (!fallbackCatastrophicMatch(toolInput)) return;
  writeAuditEntry(
    toolName,
    { severity: 'catastrophic', decision: 'block', signals: ['fallback-scan'] },
    toolInput,
    'auto_deny',
    'auto_denied',
  );
  console.error(
    `[shieldcortex] ⚠️ action-guard UNAVAILABLE (${failureNote}) and fallback scan matched a catastrophic pattern — DENYING ${toolName} (fail-closed, WS2)`,
  );
  emitDecision(
    'deny',
    `ShieldCortex Action Guard: ${failureNote}, fallback catastrophic scan matched — denying to fail closed`,
  );
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
    if (!toolName) process.exit(0);

    const guard = await loadGuard();
    if (!guard) {
      denyIfFallbackCatastrophic(toolName, toolInput, 'missing dist build');
      console.error('[shieldcortex] action-guard unavailable (missing dist build) — allowing tool call');
      process.exit(0);
    }

    let verdict;
    try {
      verdict = guard.evaluateToolCall(toolName, toolInput);
    } catch (err) {
      denyIfFallbackCatastrophic(toolName, toolInput, `evaluation error: ${err?.message ?? err}`);
      console.error(`[shieldcortex] ⚠️ action-guard error (allowing ${toolName}): ${err?.message ?? err}`);
      process.exit(0);
    }

    if (verdict.decision === 'allow') process.exit(0);

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

    writeAuditEntry(toolName, verdict, toolInput, 'require_approval', 'asked');
    emitDecision('ask', `ShieldCortex Action Guard: ${verdict.reason} [${verdict.signals.join(', ')}]`);
    process.exit(0);
  } catch (error) {
    console.error(`[shieldcortex] action-guard hook error: ${error?.message ?? error}`);
    process.exit(0);
  }
});
