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
 * Failure posture (v1): a guard that cannot load or evaluate fails OPEN with a
 * stderr note, matching the plugin ("a guard error must never break the
 * agent"). WS2 (fail-closed) revisits this across both surfaces.
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
      console.error('[shieldcortex] action-guard unavailable (missing dist build) — allowing tool call');
      process.exit(0);
    }

    let verdict;
    try {
      verdict = guard.evaluateToolCall(toolName, toolInput);
    } catch (err) {
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
