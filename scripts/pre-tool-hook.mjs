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

const DEFAULT_ACTION_GUARD = { enabled: true, enforce: true, autoApprove: [], auditAllows: true };

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
      auditAllows: raw.auditAllows !== false,
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

/** One-line description of a refused call, for the operator's approve list. */
function describeToolCall(toolName, toolInput) {
  const input = toolInput ?? {};
  const surface =
    input.command ?? input.file_path ?? input.path ?? input.url ?? input.pattern ?? '';
  const text = typeof surface === 'string' ? surface : JSON.stringify(surface);
  return text ? `${toolName}: ${text}` : toolName;
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

function writeAuditEntry(toolName, verdict, args, action, outcome) {
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
function handleDegradedGuard(toolName, toolInput, cfg, failureNote) {
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
    writeAuditEntry(
      toolName,
      { severity: 'dangerous', decision: 'require_approval', signals: ['fallback-scan', dangerousSignal] },
      toolInput, 'gate_degraded', 'asked',
    );
    console.error(`[shieldcortex] ⚠️ action-guard UNAVAILABLE (${failureNote}) — gating DANGEROUS ${toolName} [${dangerousSignal}] to the permission dialog (fail-closed; headless runs block)`);
    emitDecision('ask', `ShieldCortex Action Guard: guard could not scan (${failureNote}); dangerous operation [${dangerousSignal}] gated — approve only if you trust it`);
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
    if (!toolName) process.exit(0);

    const guard = await loadGuard();
    if (!guard) {
      handleDegradedGuard(toolName, toolInput, cfg, 'missing dist build'); // always exits
      return;
    }

    let verdict;
    try {
      verdict = guard.evaluateToolCall(toolName, toolInput);
    } catch (err) {
      handleDegradedGuard(toolName, toolInput, cfg, `evaluation error: ${err?.message ?? err}`); // always exits
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
        approvals.recordPending({
          tool: toolName,
          input: toolInput,
          summary: describeToolCall(toolName, toolInput),
          signals: verdict.signals,
        });
      } catch {
        // An unusable approvals store must never widen OR wedge the guard —
        // fall through to the standard refusal below.
      }
    }

    writeAuditEntry(toolName, verdict, toolInput, 'require_approval', 'asked');
    let message = `ShieldCortex Action Guard: ${verdict.reason} [${verdict.signals.join(', ')}]`;
    if (approvals) {
      try {
        const hash = approvals.hashToolCall(toolName, toolInput).slice(0, 12);
        message += ` — to allow this exact command once, run in YOUR terminal: shieldcortex approve ${hash}`;
      } catch {
        // Hash is a nicety; never let it break the refusal path.
      }
    }
    emitDecision('ask', message);
    process.exit(0);
  } catch (error) {
    console.error(`[shieldcortex] action-guard hook error: ${error?.message ?? error}`);
    process.exit(0);
  }
});
