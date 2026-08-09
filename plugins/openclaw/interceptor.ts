import { createHash } from 'node:crypto';
import { mkdirSync, appendFileSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { join, isAbsolute, resolve as resolvePath } from 'node:path';
import { homedir } from 'node:os';
import { createGatewayInvoker, type BrokerInvokerContext, type ModelInvokerLike } from './broker-invoker.js';

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type InterceptAction = 'log' | 'warn' | 'require_approval';
export type FailureAction = 'allow' | 'deny';

/**
 * Action Guard config — gates what the agent DOES (shell/file/network/git),
 * not just what it remembers. Catastrophic operations (rm -rf /, fork bombs,
 * disk wipes, secret exfil) are always blocked when `enabled`.
 *
 * Recognised-dangerous ops (`rm <path>`, `sudo`, force-push, external egress,
 * touching secret paths) are ENFORCED by default (P1/WS1): with an approver in
 * the loop they prompt; unattended (no approver) they fail closed on the failure
 * policy. `enforce:false` opts back down to warn-and-allow (advisory).
 *
 * `autoApprove` is the per-agent escape hatch: a dangerous op whose family,
 * action, or signal matches an entry passes without gating — so enforce-by-default
 * does not break unattended agents doing legitimate dangerous work. It NEVER
 * relaxes catastrophic ops (those hard-block regardless).
 */
export interface ActionGuardConfig {
  enabled: boolean;
  enforce: boolean;
  autoApprove?: string[];
  /** Audit recognised (severity 'sensitive'+) allow-decisions. Default true (issue #95).
   *  Benign allows are never audited — on a busy agent every `ls` would drown the stream. */
  auditAllows?: boolean;
  /** RAW approval-broker config (#143), passed through untouched. It is
   *  normalised by `normaliseBrokerConfig` in the main package before it reaches
   *  the broker — this plugin never interprets it, so a hostile value cannot be
   *  laundered by travelling through here. Absent/disabled = today's behaviour. */
  broker?: Record<string, unknown>;
  /** RAW reviewed-script allowlist (#189), same passthrough discipline: shape
   *  validation lives in `normaliseReviewedScripts` in the main package (and in
   *  this plugin's duplicated `createReviewedScriptCheck` — see the build-
   *  boundary note at that function). Absent/malformed = nothing is exempt. */
  reviewedScripts?: unknown[];
}

/** Structural shape of a Tool Action Guard verdict (kept local to avoid a
 * compile-time dependency on the main package across the plugin build boundary;
 * the real `evaluateToolCall` from `shieldcortex/defence` is compatible). */
export interface ToolGuardVerdictLike {
  decision: 'allow' | 'require_approval' | 'block';
  severity: 'benign' | 'sensitive' | 'dangerous' | 'catastrophic' | string;
  family: string;
  action: string;
  reason: string;
  signals: string[];
  /** Rule → matched-span evidence behind `signals` (issue #192). */
  matches?: Array<{ signal: string; span: string }>;
  /** Files the reviewed-script allowlist exempted from folding (#189). */
  reviewedScripts?: string[];
}
/** Optional 4th-parameter seam on the real evaluator (issue #4): the guard core
 *  stays pure/synchronous and asks the CALLER to resolve an invoked script's
 *  source, so `bash deploy.sh` is scanned by the same rules as the inline
 *  command. Structurally typed, like ToolGuardVerdictLike above. */
export interface ToolGuardEvaluatorOptions {
  resolveScriptSource?: (scriptPath: string) => string | null;
  /** #189: answers whether a human pinned this exact path + content as
   *  reviewed. An evaluator that predates the seam simply ignores it. */
  isReviewedScript?: (scriptPath: string, source: string) => boolean;
}
export type ToolGuardEvaluator = (
  toolName: string,
  args: Record<string, unknown>,
  config?: unknown,
  options?: ToolGuardEvaluatorOptions,
) => ToolGuardVerdictLike;

// ── Approval broker (#143) ──────────────────────────────────────────────────
// Structurally typed, like ToolGuardVerdictLike above: the real implementations
// live in `shieldcortex/defence` (approval-broker.ts, approval-judge.ts,
// broker-config.ts) and are injected at runtime, because this plugin is built
// across a package boundary and must keep working when the main package is a
// different version — or absent. No injection = no broker = today's behaviour.

export interface JudgeResultLike {
  assessment: 'benign' | 'uncertain' | 'malicious';
  confidence: number;
  inContext: boolean;
  injectionSuspected: boolean;
  rationale?: string;
}

export interface BrokerAuditLike {
  outcome: string;
  tool: string;
  action: string;
  severity: string;
  signals: string[];
  judgeAssessment: string;
  judgeConfidence: number | null;
  injectionSuspected: boolean;
  inContext: boolean | null;
  reason: string;
}

export interface BrokerDecisionLike {
  outcome: 'not_brokerable' | 'harden' | 'hold' | 'pre_clear';
  reason: string;
  canAutoApproveOnTimeout: boolean;
  audit: BrokerAuditLike;
}

export interface BrokerConfigLike {
  enabled: boolean;
  allowPreClear: boolean;
  preClearConfidence: number;
  judgeTimeoutMs: number;
  approvalTimeoutMs: { sensitive: number; dangerous: number };
  model?: string;
}

/** Everything the interceptor needs to run a broker pass, injected as one unit
 *  so a half-wired broker (a decision core with no judge, say) cannot exist. */
export interface BrokerRuntime {
  /** ALREADY normalised by `normaliseBrokerConfig`. The interceptor does not
   *  sanitise config; it consumes a config that was sanitised at the boundary. */
  config: BrokerConfigLike;
  runJudge: (
    req: {
      tool: string;
      toolInput: unknown;
      verdict: { severity: string; action: string; reason: string; signals: string[] };
      sessionSummary?: string;
    },
    invoke: ModelInvokerLike,
    opts?: { timeoutMs?: number },
  ) => Promise<JudgeResultLike | null>;
  brokerDecision: (input: {
    tool: string;
    toolInput: unknown;
    verdict: ToolGuardVerdictLike;
    judge: JudgeResultLike | null;
    policy?: { allowPreClear: boolean; preClearConfidence: number };
  }) => BrokerDecisionLike;
  timeoutOutcome: (decision: BrokerDecisionLike) => 'approve' | 'deny';
  approvalTimeoutMs?: (config: BrokerConfigLike, severity: string) => number;
}

export interface InterceptorConfig {
  enabled: boolean;
  severityActions: Record<Severity, InterceptAction>;
  failurePolicy: Record<Severity, FailureAction>;
  actionGuard?: ActionGuardConfig;
  logger?: { info: (msg: string) => void; warn: (msg: string) => void };
}

export interface ToolCallContext {
  toolName: string;
  arguments: Record<string, unknown>;
  requireApproval?: (message: string) => Promise<boolean>;
  /** Optional one-shot completion through the gateway's OWN model pool (#143).
   *  ShieldCortex supplies no credentials of its own; when a gateway build does
   *  not offer this, the broker has no judge and holds for the operator —
   *  exactly today's behaviour. See broker-invoker.ts. */
  invokeModel?: BrokerInvokerContext['invokeModel'];
  /** Working directory the tool call runs in, when the gateway supplies one —
   *  used to resolve a relative script path (issue #4). Falls back to the
   *  call's own `cwd` argument, then `process.cwd()`. */
  cwd?: string;
}

export interface InterceptAuditEntry {
  type: 'intercept';
  tool: string;
  severity: Severity;
  firewallResult: string;
  threats: string[];
  anomalyScore: number;
  trustScore: number;                 // from the pipeline result's trust score
  sensitivityLevel: string;           // from the pipeline result's sensitivity level
  fragmentationScore: number | null;  // from the pipeline result's fragmentation score, or null
  pipelineDurationMs: number;         // wall-clock ms around the runDefencePipeline call
  action: InterceptAction | 'auto_deny' | 'rate_limit' | 'allow' | 'gate_degraded';
  outcome: 'approved' | 'denied' | 'auto_denied' | 'logged' | 'warned' | 'failure_allowed' | 'failure_denied' | 'allowed';
  preview: string;
  ts: string;
  /** The approval broker's record for this call (#143). Present on exactly the
   *  calls the broker judged, so "was a model consulted, and what did it say?"
   *  is answerable from the audit stream alone. Absent = the broker never ran. */
  broker?: BrokerAuditLike;
  /** Rule → matched-span evidence behind `threats` (issue #192). Absent when
   *  no pattern produced a span. `secret-egress` never contributes one — the
   *  span would be the secret. */
  matches?: Array<{ signal: string; span: string }>;
  /** Files the reviewed-script allowlist exempted from folding (#189). */
  reviewedScripts?: string[];
}

const WATCHED_TOOLS = ['remember', 'mcp__memory__remember'] as const;

const CONTENT_FIELDS: Record<string, string[]> = {
  remember: ['content', 'title'],
  mcp__memory__remember: ['content', 'title'],
};

// Defaults relaxed in v4.11.0: critical/high no longer block the tool call with
// a synchronous approval prompt. The defence pipeline still runs and
// `failurePolicy` still denies on critical/high, so the block is preserved —
// what changes is the user-facing approval gate. Opt back in with
// `severityActions: { high: 'require_approval', critical: 'require_approval' }`.
const DEFAULT_CONFIG: InterceptorConfig = {
  enabled: true,
  severityActions: {
    low: 'log',
    medium: 'log',
    high: 'warn',
    critical: 'log',
  },
  failurePolicy: {
    low: 'allow',
    medium: 'allow',
    high: 'deny',
    critical: 'deny',
  },
  // Action Guard on by default: catastrophic ops are blocked out of the box;
  // recognised-dangerous ops are ENFORCED by default (P1/WS1) — attended → prompt,
  // unattended → fail closed on failurePolicy. Populate `autoApprove` per agent to
  // pre-approve the dangerous ops it legitimately needs unattended; set
  // `enforce:false` to opt back down to warn-and-allow.
  actionGuard: {
    enabled: true,
    enforce: true,
    autoApprove: [],
    auditAllows: true,
  },
};

export { WATCHED_TOOLS, CONTENT_FIELDS, DEFAULT_CONFIG };

export function extractContent(toolName: string, args: Record<string, unknown>): { title: string; content: string } {
  const fields = CONTENT_FIELDS[toolName];
  if (!fields) return { title: '', content: '' };
  const title = typeof args.title === 'string' ? args.title : '';
  const content = typeof args.content === 'string' ? args.content : '';
  return { title, content };
}

interface FirewallResult {
  result: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  anomalyScore: number;
}

export function mapSeverity(firewall: FirewallResult): Severity {
  if (firewall.result === 'BLOCK') return 'critical';
  if (firewall.result === 'QUARANTINE') return 'high';
  if (firewall.result === 'ALLOW' && firewall.anomalyScore >= 0.3) return 'medium';
  return 'low';
}

// --- Deny Cache ---

// Exact replica of normalizeMemoryText() from index.ts (lines 426-434).
// Must produce identical output for SHA-256 hash consistency.
function normaliseContent(text: string): string {
  return String(text || '')
    .toLowerCase()
    .replace(/[`"'\\]/g, ' ')
    .replace(/https?:\/\/\S+/g, ' ')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function hashContent(text: string): string {
  return createHash('sha256').update(normaliseContent(text)).digest('hex');
}

interface DenyCacheEntry {
  hash: string;
  ts: number;
}

const TWO_HOURS_MS = 2 * 60 * 60 * 1000;

export class DenyCache {
  private cache = new Map<string, DenyCacheEntry[]>();
  private maxPerTool: number;
  private ttlMs: number;

  constructor(maxPerTool = 200, ttlMs = TWO_HOURS_MS) {
    this.maxPerTool = maxPerTool;
    this.ttlMs = ttlMs;
  }

  isDenied(tool: string, content: string): boolean {
    const entries = this.cache.get(tool);
    if (!entries) return false;
    const hash = hashContent(content);
    const now = Date.now();
    return entries.some(e => e.hash === hash && (now - e.ts) < this.ttlMs);
  }

  addDenial(tool: string, content: string): void {
    const hash = hashContent(content);
    const now = Date.now();
    if (!this.cache.has(tool)) {
      this.cache.set(tool, []);
    }
    const entries = this.cache.get(tool)!;
    const live = entries.filter(e => (now - e.ts) < this.ttlMs);
    if (live.some(e => e.hash === hash)) return;
    live.push({ hash, ts: now });
    while (live.length > this.maxPerTool) {
      live.shift();
    }
    this.cache.set(tool, live);
  }

  reset(): void {
    this.cache.clear();
  }
}

// --- Rate Limiter ---

export class RateLimiter {
  private timestamps: number[] = [];
  private maxPerWindow: number;
  private windowMs: number;

  constructor(maxPerWindow = 5, windowMs = 60_000) {
    this.maxPerWindow = maxPerWindow;
    this.windowMs = windowMs;
  }

  shouldAllow(): boolean {
    const now = Date.now();
    this.timestamps = this.timestamps.filter(t => now - t < this.windowMs);
    if (this.timestamps.length >= this.maxPerWindow) return false;
    this.timestamps.push(now);
    return true;
  }
}

// --- Approval Prompt ---

interface ApprovalPromptInput {
  tool: string;
  severity: Severity;
  firewallResult: string;
  threats: string[];
  content: string;
}

export function formatApprovalPrompt(input: ApprovalPromptInput): string {
  const preview = input.content.length > 200
    ? input.content.slice(0, 200) + '...'
    : input.content;
  const threatList = input.threats.length > 0
    ? input.threats.join(', ')
    : 'none identified';

  return [
    '🛡️ ShieldCortex — Tool Call Intercepted',
    '',
    `Tool:       ${input.tool}`,
    `Risk:       ${input.severity} (${input.firewallResult})`,
    `Threats:    ${threatList}`,
    `Content:    "${preview}"`,
    '',
    '[Approve]  [Deny]',
  ].join('\n');
}

// --- WS2 fail-closed fallback (guard load/eval failure) ---
// Deliberately DUPLICATED from tool-action-guard.ts's CATASTROPHIC list, not
// imported — this file already avoids a compile-time dependency on the main
// package across the plugin build boundary (see ToolGuardVerdictLike above),
// and the fallback specifically must keep working when THAT dependency is
// what's broken. Narrow by design: only the unambiguous, essentially-never-
// benign catastrophic shapes, so a broken/unwired guard still fails closed on
// "rm -rf /"-class commands without turning every tool call into a denial
// whenever the guard is merely unavailable (e.g. mid-upgrade) — that would
// itself break unattended agents/cron, the outcome ShieldCortex exists to
// prevent. Mirrored in scripts/pre-tool-hook.mjs for the Claude Code surface.
const FALLBACK_CATASTROPHIC_PATTERNS: RegExp[] = [
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

// WS2 dangerous-tier fallback (issue #59). Ports EVERY signal in
// tool-action-guard.ts's DANGEROUS array — a drift test
// (ws2-gate-degraded-integration-59) fails if the guard gains a DANGEROUS
// signal this list doesn't cover, so "kept in sync" is enforced, not just
// claimed. Used ONLY when the real guard can't scan: a recognised-dangerous
// shape routes through `failurePolicy` exactly as an unattended real verdict
// would, instead of the pre-#59 fail-OPEN. Copies the real (already anti-ReDoS,
// FP-narrowed) patterns verbatim, so read-only forms — `crontab -l`, `npm ls
// -g`, `--global-style`, shred use/mention — still pass. The one guard shape
// NOT here is bare `npx`/`bunx`: those are gated CONDITIONALLY by
// `isGatedNpxBunx` (shape-based, #96), not by a DANGEROUS pattern, and a blunt
// fallback matching them would over-gate `npx tsc`; `uvx`/`dlx` (unconditional)
// ARE covered. Mirrored in scripts/pre-tool-hook.mjs + hermes/sc_client.py.
const FALLBACK_DANGEROUS_PATTERNS: Array<{ re: RegExp; signal: string }> = [
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

const FALLBACK_SURFACE_KEYS = [
  'command', 'cmd', 'script', 'code', 'input', 'shell', 'run',
  'path', 'file_path', 'filePath', 'file', 'target', 'destination', 'dir', 'directory',
  'url', 'uri', 'endpoint', 'href', 'host', 'to',
];

// The fallback is an outage-only blunt scanner; an UNBOUNDED scan over crafted
// input is a ReDoS vector (some ported guard patterns are O(n²) on pathological
// token runs like `git push push push …`). Dangerous/catastrophic shapes appear
// early in any real command, so cap the scanned surface — 4 KB is far beyond a
// real shell command. The real guard (no cap) still scans in full when it works.
const FALLBACK_SCAN_CAP = 4096;

/** Same command/path/url field set tool-action-guard.ts extracts — narrow, not the whole args object. */
function fallbackExecSurface(args: Record<string, unknown> | undefined): string {
  const parts: string[] = [];
  for (const k of FALLBACK_SURFACE_KEYS) {
    const v = args?.[k];
    if (typeof v === 'string' && v.length > 0) parts.push(v);
  }
  return parts.join('   ').slice(0, FALLBACK_SCAN_CAP);
}

function fallbackCatastrophicMatch(args: Record<string, unknown> | undefined): boolean {
  const text = fallbackExecSurface(args);
  if (!text) return false;
  return FALLBACK_CATASTROPHIC_PATTERNS.some(re => re.test(text));
}

/** First matching dangerous signal for the WS2 fallback, or null (issue #59). */
function fallbackDangerousMatch(args: Record<string, unknown> | undefined): string | null {
  const text = fallbackExecSurface(args);
  if (!text) return null;
  for (const { re, signal } of FALLBACK_DANGEROUS_PATTERNS) {
    if (re.test(text)) return signal;
  }
  return null;
}

/** One-line summary of tool args for audit previews (bounded, no secrets dumped). */
export function summariseToolArgs(args: Record<string, unknown> | undefined): string {
  if (!args) return '';
  const parts: string[] = [];
  for (const [k, val] of Object.entries(args)) {
    if (typeof val === 'string') parts.push(`${k}=${val.slice(0, 80)}`);
    else if (typeof val === 'number' || typeof val === 'boolean') parts.push(`${k}=${val}`);
  }
  return parts.join(' ').slice(0, 160);
}

/** Operator-facing approval prompt for a gated action (not a memory write). */
export function formatActionGuardPrompt(toolName: string, v: ToolGuardVerdictLike): string {
  return [
    '🛡️ ShieldCortex — Action Intercepted',
    '',
    `Tool:       ${toolName}`,
    `Action:     ${v.action}`,
    `Risk:       ${v.severity}`,
    `Signals:    ${v.signals.join(', ') || 'none'}`,
    `Reason:     ${v.reason}`,
    '',
    '[Approve]  [Deny]',
  ].join('\n');
}

// --- Audit Logging (local JSONL) ---

const AUDIT_DIR = join(homedir(), '.shieldcortex', 'audit');

// Issue #95: an unwritable audit sink used to be swallowed by this bare catch —
// entries silently dropped forever. Still best-effort (an audit failure must
// never block the agent), but the FIRST failure now warns loudly with the sink
// path and the error, and later failures keep a drop count for the breadcrumb.
let auditSinkFailures = 0;
export function noteAuditSinkFailure(err: unknown): void {
  auditSinkFailures++;
  if (auditSinkFailures === 1) {
    const detail = err instanceof Error ? err.message : String(err);
    console.warn(
      `[shieldcortex] ⚠️ audit sink UNWRITABLE (${AUDIT_DIR}): ${detail} — audit entries are being DROPPED. ` +
      `Fix the directory permissions/disk; enforcement continues but leaves no trail until this is resolved.`,
    );
  }
}
export function __resetAuditSinkFailuresForTest(): void { auditSinkFailures = 0; }

function writeAuditEntry(entry: InterceptAuditEntry): void {
  try {
    mkdirSync(AUDIT_DIR, { recursive: true });
    const date = new Date().toISOString().slice(0, 10);
    const file = join(AUDIT_DIR, `realtime-${date}.jsonl`);
    appendFileSync(file, JSON.stringify(entry) + '\n');
  } catch (err) {
    // Best-effort — never block on audit failure, but never silent either (#95).
    noteAuditSinkFailure(err);
  }
}

// --- X-Ray Inline Guard ---
// Lightweight inline version of xrayMemoryContent for the plugin build boundary.
// Detects AI directive injection patterns in memory content.

const XRAY_AI_DIRECTIVE_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
  /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)/i,
  /override\s+(previous|prior|all)\s+(instructions?|rules?|constraints?)/i,
  /you\s+are\s+now\s+(?:in\s+)?(?:developer|god|admin|root|unrestricted)\s+mode/i,
  /enter\s+(?:developer|god|admin|DAN|jailbreak)\s+mode/i,
  /(?:system|hidden|secret)\s*(?:prompt|instruction|directive)\s*:/i,
  /\[SYSTEM\]\s*:/i,
  /\[INST\]/i,
  /<\|(?:system|user|assistant|im_start|im_end)\|>/i,
  /(?:decode|execute|follow)\s+(?:the\s+)?hidden\s+(?:instructions?|payload|message)/i,
  /(?:hidden|embedded|encoded)\s+(?:instructions?|directive|command)\s+(?:in|within|inside)/i,
];

const XRAY_FILENAME_PATTERNS: RegExp[] = [
  /ignore_previous/i, /decode_hidden/i, /execute_instructions/i,
  /override_previous/i, /developer_mode/i, /system_prompt/i,
  /jailbreak/i, /\[SYSTEM\]/i, /\[INST\]/i,
];

interface XRayGuardResult {
  allowed: boolean;
  findings: Array<{ category: string; title: string; severity: string }>;
  riskLevel: string;
}

function xrayMemoryGuard(content: string, title?: string): XRayGuardResult {
  const findings: Array<{ category: string; title: string; severity: string }> = [];
  const text = content.length > 50000 ? content.slice(0, 50000) : content;

  for (const pattern of XRAY_AI_DIRECTIVE_PATTERNS) {
    if (pattern.test(text)) {
      findings.push({ category: 'ai-directive', title: 'AI directive injection detected', severity: 'critical' });
      break;
    }
  }

  if (title) {
    for (const pattern of XRAY_FILENAME_PATTERNS) {
      if (pattern.test(title)) {
        findings.push({ category: 'ai-directive', title: 'AI directive in title', severity: 'critical' });
        break;
      }
    }
  }

  // Score: 100 - 60 per critical finding (single critical = blocked)
  const score = Math.max(0, 100 - findings.length * 60);
  const riskLevel = score >= 80 ? 'SAFE' : score >= 60 ? 'LOW' : score >= 40 ? 'MEDIUM' : score >= 20 ? 'HIGH' : 'CRITICAL';
  return { allowed: score >= 60, findings, riskLevel };
}

// --- Interceptor Factory ---

// Subset of shieldcortex/defence DefencePipelineResult (src/defence/pipeline.ts).
// Field paths verified against src/defence/types.ts: trust.score (TrustScore.score),
// sensitivity.level (SensitivityClassification.level), fragmentation.score
// (FragmentationAnalysis.score; fragmentation itself is nullable).
type PipelineRunner = (content: string, title: string, source: { type: string; identifier: string }) => {
  allowed: boolean;
  firewall: {
    result: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
    reason: string;
    threatIndicators: string[];
    anomalyScore: number;
    blockedPatterns: string[];
  };
  trust: { score: number };
  sensitivity: { level: string };
  fragmentation: { score: number } | null;
  auditId: number;
};

// ── Script source resolution (issue #4) ─────────────────────────────────────
// `bash deploy.sh` used to bypass EVERY Action Guard rule, because the guard
// only ever scanned the command string and never opened the file it pointed at.
// The guard core stays pure (doctor/self-check drive it with synthetic commands
// whose paths do not exist); this is the fs-backed half, wired in here.
//
// Zeroth law — this must never hang, block or crash the host gateway:
//   * `statSync` first: only a REGULAR file is read, so a FIFO/socket/device
//     (a `read` on which could block forever) is skipped, not opened;
//   * `/proc`, `/sys`, `/dev` are never touched;
//   * anything over the size cap is refused (the guard then records it as
//     `opaque-script-invocation` rather than pretending it was scanned);
//   * every error returns `null`. Nothing escapes.
// The resolver is DUPLICATED here, deliberately (#160).
//
// This plugin publishes as its own npm package and builds standalone
// (tsconfig.openclaw-plugin.json pins rootDir to plugins/openclaw), so it
// genuinely cannot import from src/ — converging by import broke the plugin
// build outright. A real constraint, then, not a tidiness failure.
//
// But two copies of a safety-railed file reader reached from untrusted tool
// input is two chances to drift, and drift is what #160 was about. So the
// copies are held together by a BEHAVIOURAL drift test that runs both
// implementations over one fixture table and requires identical answers
// (src/__tests__/enforcement-surface-parity.test.ts). Guard the duplication
// rather than pretend it away.
export const MAX_SCRIPT_SOURCE_BYTES = 262_144;   // 256KB — matches the guard core's cap
export const UNREADABLE_PATH_PREFIX = /^\/(?:proc|sys|dev)\//;

export function createScriptSourceResolver(cwd?: string): (scriptPath: string) => string | null {
  const base = cwd && typeof cwd === 'string' ? cwd : process.cwd();
  return (scriptPath: string): string | null => {
    try {
      if (!scriptPath || typeof scriptPath !== 'string') return null;
      const expanded = scriptPath.startsWith('~/') ? join(homedir(), scriptPath.slice(2)) : scriptPath;
      const full = isAbsolute(expanded) ? expanded : resolvePath(base, expanded);
      if (UNREADABLE_PATH_PREFIX.test(full)) return null;
      const st = statSync(full);
      if (!st.isFile() || st.size > MAX_SCRIPT_SOURCE_BYTES) return null;
      return readFileSync(full, 'utf8');
    } catch {
      return null;                          // missing, unreadable, anything — stay silent, stay alive
    }
  };
}

// #189 reviewed-script allowlist — DUPLICATED from
// src/defence/iron-dome/reviewed-scripts.ts for the same build-boundary reason
// as the resolver above (TS6059), and held to it by the same parity test
// (src/__tests__/enforcement-surface-parity.test.ts). Same rails, same
// answers, or the drift test goes red.
const REVIEWED_MAX_ENTRIES = 200;
const REVIEWED_MAX_PATH_LENGTH = 1_024;
const REVIEWED_SHA256_RE = /^[0-9a-f]{64}$/;

export function createReviewedScriptCheck(
  rawEntries: unknown,
  cwd?: string,
): (scriptPath: string, source: string) => boolean {
  if (!Array.isArray(rawEntries) || rawEntries.length === 0) return () => false;
  const byCanonical = new Map<string, string>();          // canonical path → sha256
  for (const item of rawEntries.slice(0, REVIEWED_MAX_ENTRIES)) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) continue;
    const rec = item as Record<string, unknown>;
    if (typeof rec.path !== 'string' || typeof rec.sha256 !== 'string') continue;
    const path = rec.path.trim();
    const sha256 = rec.sha256.trim().toLowerCase();
    if (!path || path.length > REVIEWED_MAX_PATH_LENGTH || !isAbsolute(path)) continue;
    if (!REVIEWED_SHA256_RE.test(sha256)) continue;
    try {
      byCanonical.set(realpathSync(path), sha256);
    } catch {
      /* pinned file missing — entry cannot match anything */
    }
  }
  if (byCanonical.size === 0) return () => false;

  const base = cwd && typeof cwd === 'string' ? cwd : process.cwd();
  return (scriptPath: string, source: string): boolean => {
    try {
      if (!scriptPath || typeof scriptPath !== 'string' || typeof source !== 'string') return false;
      const expanded = scriptPath.startsWith('~/') ? join(homedir(), scriptPath.slice(2)) : scriptPath;
      const full = isAbsolute(expanded) ? expanded : resolvePath(base, expanded);
      const expected = byCanonical.get(realpathSync(full));
      if (!expected) return false;
      return createHash('sha256').update(source, 'utf8').digest('hex') === expected;
    } catch {
      return false;
    }
  };
}

/** Raised when the operator never answered the approval card (#143). Distinct
 *  from a transport error, because the two have opposite handling: an error
 *  routes to failurePolicy, a timeout routes to the broker's asymmetric rule. */
export class ApprovalTimeout extends Error {
  constructor(public readonly timeoutMs: number) {
    super(`no approval answer within ${timeoutMs}ms`);
    this.name = 'ApprovalTimeout';
  }
}

/**
 * Race an approval against a deadline.
 *
 * `timeoutMs <= 0` means no deadline at all — the pre-#143 behaviour, where the
 * gateway's own card owns the waiting. A deadline is only ever applied when the
 * broker is in play, and it can only turn an unanswered card into the broker's
 * timeout rule, which for everything but a pre-cleared call is a denial.
 */
export function withApprovalDeadline(approval: Promise<boolean>, timeoutMs: number): Promise<boolean> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return approval;
  let timer: ReturnType<typeof setTimeout> | undefined;
  // A card answered after we stopped listening must not surface as an unhandled
  // rejection in the gateway process.
  const guarded = approval.catch(err => { throw err; });
  guarded.catch(() => { /* handled by the race below or deliberately dropped */ });
  return Promise.race([
    guarded,
    new Promise<boolean>((_resolve, reject) => {
      timer = setTimeout(() => reject(new ApprovalTimeout(timeoutMs)), timeoutMs);
    }),
  ]).finally(() => { if (timer) clearTimeout(timer); });
}

/** The cwd a tool call runs in, if the gateway or the call itself names one. */
function toolCallCwd(context: ToolCallContext): string | undefined {
  if (typeof context.cwd === 'string' && context.cwd) return context.cwd;
  for (const k of ['cwd', 'workdir', 'working_directory', 'workingDirectory', 'directory']) {
    const v = context.arguments?.[k];
    if (typeof v === 'string' && v) return v;
  }
  return undefined;
}

interface InterceptorOptions {
  maxPromptsPerMinute?: number;
  onAuditEntry?: (entry: InterceptAuditEntry) => void;
  /** Tool Action Guard evaluator, injected from `shieldcortex/defence` at runtime. */
  evaluateToolCall?: ToolGuardEvaluator;
  /** Approval broker (#143), injected from `shieldcortex/defence` at runtime.
   *  Absent, or present with `config.enabled: false`, means no model is ever
   *  consulted and the guard behaves exactly as it did before #143. */
  broker?: BrokerRuntime;
  /** Judge calls allowed per minute. The judge spends the OPERATOR's own rate
   *  limit, so a looping or compromised agent must not be able to spend it
   *  without bound. Exhausting it yields no judge, which yields a hold. */
  maxJudgeCallsPerMinute?: number;
}

/** How many recent tool NAMES the judge is told about. Names only, never
 *  arguments — see buildSessionSummary. */
const SESSION_TOOL_MEMORY = 12;
/** Tool names are registry-supplied, not free text, but an MCP server can name
 *  a tool anything at all — so they are reduced to an identifier shape before
 *  being placed anywhere near a prompt. */
const TOOL_NAME_SAFE = /[^A-Za-z0-9_.:-]/g;

export function createInterceptor(
  config: InterceptorConfig,
  pipeline: PipelineRunner,
  options?: InterceptorOptions,
): {
  handleToolCall: (context: ToolCallContext) => Promise<void>;
  resetSession: () => void;
} {
  const denyCache = new DenyCache();
  const rateLimiter = new RateLimiter(options?.maxPromptsPerMinute ?? 5);
  const log = config.logger ?? { info: console.log, warn: console.warn };
  const onAuditEntry = options?.onAuditEntry;
  const actionGuardCfg: ActionGuardConfig = config.actionGuard ?? { enabled: true, enforce: true, autoApprove: [] };
  const evaluateToolCall = options?.evaluateToolCall;
  const broker = options?.broker;
  // The judge rides the operator's own model pool, so its calls are their cost
  // and their rate limit. Bounded per minute, and running out means "no judge",
  // which the decision core reads as "hold for the human" — never as an allow.
  const judgeLimiter = new RateLimiter(options?.maxJudgeCallsPerMinute ?? 20);
  /** Bare tool names seen this session, newest last. See buildSessionSummary. */
  const recentTools: string[] = [];

  function emitAudit(entry: InterceptAuditEntry): void {
    writeAuditEntry(entry);
    onAuditEntry?.(entry);
  }

  function guardAuditBase(toolName: string, v: ToolGuardVerdictLike, preview: string): Omit<InterceptAuditEntry, 'action' | 'outcome'> {
    return {
      type: 'intercept', tool: toolName,
      severity: v.severity === 'catastrophic' ? 'critical' : v.decision === 'allow' ? 'low' : 'high',
      firewallResult: 'ACTION_GUARD', threats: v.signals,
      anomalyScore: v.decision === 'block' ? 1 : v.decision === 'allow' ? 0.1 : 0.6,
      trustScore: 0, sensitivityLevel: 'INTERNAL', fragmentationScore: null, pipelineDurationMs: 0,
      preview: preview.slice(0, 200), ts: new Date().toISOString(),
      // #192: the durable record keeps the evidence, not just the rule names.
      ...(v.matches && v.matches.length > 0 ? { matches: v.matches } : {}),
      // #189: an allow that leaned on the reviewed-script allowlist says so.
      ...(v.reviewedScripts && v.reviewedScripts.length > 0 ? { reviewedScripts: v.reviewedScripts } : {}),
    };
  }

  // ── Approval broker (#143) ────────────────────────────────────────────────

  /**
   * The ONLY thing the judge is told about the session.
   *
   * The design's third open question was "what does the broker see of the
   * session, and how do we stop *that* being the injection vector?" — a
   * poisoned transcript arguing its own approval is the obvious attack. The
   * answer here is the narrowest thing that still means anything: a list of
   * bare tool NAMES, sanitised to an identifier shape. No arguments, no
   * content, no memory text, no user or assistant turns.
   *
   * That is enough for "does this action fit what the session was doing?" —
   * an `npm install` in a session of Read/Edit/Bash is in pattern; the same
   * command as the first act of a session is not — and it carries no attacker
   * prose, because there is nowhere in it for prose to live.
   */
  function buildSessionSummary(): string | undefined {
    if (recentTools.length === 0) return undefined;
    const names = [...new Set(recentTools)].join(', ');
    return `tools used in this session so far (names only, no arguments): ${names}`;
  }

  function noteToolForSession(toolName: string): void {
    const safe = String(toolName ?? '').replace(TOOL_NAME_SAFE, '').slice(0, 60);
    if (!safe) return;
    recentTools.push(safe);
    if (recentTools.length > SESSION_TOOL_MEMORY) recentTools.shift();
  }

  /**
   * One broker pass over a dangerous-tier verdict.
   *
   * Returns null when the broker is not in play at all — no runtime injected,
   * or disabled by config — and the caller then behaves exactly as it did
   * before #143. Every *failure* inside a pass (no model seam, pool down, junk
   * reply, budget spent, core throwing) resolves to a decision of `hold` or to
   * null, both of which route to the operator. There is no path here that
   * produces an allow the guard would not otherwise have produced.
   */
  async function runBroker(context: ToolCallContext, v: ToolGuardVerdictLike): Promise<BrokerDecisionLike | null> {
    if (!broker || broker.config?.enabled !== true) return null;

    try {
      // No seam on this gateway build → no invoker → no judge. Not an error:
      // it is the honest state of every gateway shipping today.
      const invoke = createGatewayInvoker(context as BrokerInvokerContext, {
        model: broker.config.model,
        timeoutMs: broker.config.judgeTimeoutMs,
      });

      let judge: JudgeResultLike | null = null;
      if (invoke && judgeLimiter.shouldAllow()) {
        judge = await broker.runJudge(
          {
            tool: context.toolName,
            toolInput: context.arguments,
            verdict: { severity: v.severity, action: v.action, reason: v.reason, signals: v.signals },
            sessionSummary: buildSessionSummary(),
          },
          invoke,
          { timeoutMs: broker.config.judgeTimeoutMs },
        );
      } else if (invoke) {
        log.warn(`[shieldcortex] approval broker: judge budget spent this minute — holding ${context.toolName} for the operator`);
      }

      const decision = broker.brokerDecision({
        tool: context.toolName,
        toolInput: context.arguments,
        verdict: v,
        judge,
        policy: {
          allowPreClear: broker.config.allowPreClear,
          preClearConfidence: broker.config.preClearConfidence,
        },
      });
      // A decision we cannot read is not a decision. Falling back to null puts
      // the call on the pre-#143 path, which asks the human.
      if (!decision || typeof decision.outcome !== 'string') return null;
      return decision;
    } catch (err) {
      log.warn(`[shieldcortex] ⚠️ approval broker error: ${err instanceof Error ? err.message : err} — holding for the operator`);
      return null;
    }
  }

  /** How long to wait for a human once the broker is in play. */
  function brokerApprovalTimeoutMs(severity: string): number {
    if (!broker) return 0;
    if (typeof broker.approvalTimeoutMs === 'function') return broker.approvalTimeoutMs(broker.config, severity);
    return Math.min(broker.config.approvalTimeoutMs.sensitive, broker.config.approvalTimeoutMs.dangerous);
  }

  // WS2 fail-closed path (issue #59): when the real guard was never wired in or
  // throws, run the dependency-free fallback scan. Three tiers, so no dangerous
  // op is ever silently allowed on a scan failure — and every could-not-scan
  // decision leaves a `gate_degraded` audit row (ACTION_GUARD_FALLBACK marker),
  // so forensics can distinguish "scanned & allowed" from "could not scan":
  //   1. catastrophic → hard deny, always (ignores enforce:false).
  //   2. dangerous    → route through `failurePolicy` exactly as an unattended
  //                     real verdict would (deny by default); enforce:false
  //                     opts down to advisory.
  //   3. no match     → benign/unknown: fail OPEN (a degraded guard must not
  //                     wedge normal work) but leave a visible breadcrumb.
  function handleGuardUnavailable(context: ToolCallContext, reason: string): void {
    const preview = `${context.toolName} :: ${summariseToolArgs(context.arguments)}`.slice(0, 200);
    const degradedBase = {
      type: 'intercept' as const, tool: context.toolName,
      firewallResult: 'ACTION_GUARD_FALLBACK', trustScore: 0, sensitivityLevel: 'INTERNAL',
      fragmentationScore: null, pipelineDurationMs: 0, preview, ts: new Date().toISOString(),
    };

    // 1. Catastrophic — hard deny, always.
    if (fallbackCatastrophicMatch(context.arguments)) {
      emitAudit({
        ...degradedBase, severity: 'critical', threats: ['fallback-scan'], anomalyScore: 1,
        action: 'auto_deny', outcome: 'auto_denied',
      });
      log.warn(`[shieldcortex] action-guard UNAVAILABLE (${reason}) and fallback scan matched a catastrophic pattern — DENYING ${context.toolName} (fail-closed, WS2)`);
      throw new Error(`ShieldCortex: tool call blocked — action guard unavailable (${reason}), fallback catastrophic scan matched`);
    }

    // 2. Dangerous — route through failurePolicy (the "can't obtain a verdict"
    //    policy; a degraded guard is precisely that). enforce:false → advisory.
    const dangerousSignal = fallbackDangerousMatch(context.arguments);
    if (dangerousSignal) {
      const dBase = { ...degradedBase, severity: 'high' as Severity, threats: ['fallback-scan', dangerousSignal], anomalyScore: 0.6 };
      if (!actionGuardCfg.enforce) {
        emitAudit({ ...dBase, action: 'gate_degraded', outcome: 'failure_allowed' });
        log.warn(`[shieldcortex] ⚠️ action-guard unavailable (${reason}) — advisory (enforce:false), allowing dangerous ${context.toolName} [${dangerousSignal}]`);
        return;
      }
      const failAction = config.failurePolicy.high;
      emitAudit({ ...dBase, action: 'gate_degraded', outcome: failAction === 'deny' ? 'failure_denied' : 'failure_allowed' });
      if (failAction === 'deny') {
        log.warn(`[shieldcortex] action-guard UNAVAILABLE (${reason}) and fallback matched a DANGEROUS op [${dangerousSignal}] — DENYING ${context.toolName} (fail-closed, failure policy: deny)`);
        throw new Error(`ShieldCortex: tool call blocked — action guard unavailable (${reason}), dangerous fallback match [${dangerousSignal}], failure policy: deny`);
      }
      return;
    }

    // 3. No match — benign/unknown. Fail open, but never silently: the
    //    gate_degraded breadcrumb makes the outage window auditable.
    emitAudit({ ...degradedBase, severity: 'low', threats: ['fallback-scan'], anomalyScore: 0.1, action: 'gate_degraded', outcome: 'failure_allowed' });
    log.warn(`[shieldcortex] ⚠️ action-guard unavailable (${reason}) — allowing ${context.toolName} (fallback matched nothing; fail-open)`);
  }

  // Action Guard: gates non-memory tool calls (shell / file / network / git).
  // This is what makes "Iron Dome protects what the agent DOES" true at runtime.
  async function runActionGuard(context: ToolCallContext): Promise<void> {
    if (!actionGuardCfg.enabled) return;

    if (typeof evaluateToolCall !== 'function') {
      handleGuardUnavailable(context, 'evaluateToolCall not wired');
      return;
    }

    let v: ToolGuardVerdictLike;
    try {
      // 4th arg (issue #4): lets the pure guard core scan the CONTENTS of a
      // script the command invokes (`bash deploy.sh`) through this fs-backed
      // resolver. An evaluator that predates the seam simply ignores it.
      v = evaluateToolCall(context.toolName, context.arguments || {}, undefined, {
        resolveScriptSource: createScriptSourceResolver(toolCallCwd(context)),
        // #189: same allowlist, same predicate semantics as the hook surface —
        // config is RAW here, validated inside createReviewedScriptCheck.
        ...(actionGuardCfg.reviewedScripts && actionGuardCfg.reviewedScripts.length > 0
          ? { isReviewedScript: createReviewedScriptCheck(actionGuardCfg.reviewedScripts, toolCallCwd(context)) }
          : {}),
      });
    } catch (err) {
      handleGuardUnavailable(context, `action-guard error: ${err instanceof Error ? err.message : err}`);
      return;
    }
    if (v.decision === 'allow') {
      // Issue #95: a RECOGNISED allow (the guard evaluated a known operation
      // family and let it through — severity above benign) leaves an audit
      // entry, so forensics can distinguish "scanned & allowed" from "never
      // scanned". Benign allows stay unaudited by design (volume discipline);
      // `actionGuard.auditAllows: false` opts the recognised entries off too.
      if (v.severity !== 'benign' && actionGuardCfg.auditAllows !== false) {
        const allowPreview = `${context.toolName} :: ${summariseToolArgs(context.arguments)}`;
        emitAudit({ ...guardAuditBase(context.toolName, v, allowPreview), action: 'allow', outcome: 'allowed' });
      }
      return;
    }

    const preview = `${context.toolName} :: ${summariseToolArgs(context.arguments)}`;
    const base = guardAuditBase(context.toolName, v, preview);
    const severity: Severity = v.severity === 'catastrophic' ? 'critical' : 'high';

    // Catastrophic / exfil — hard block, always enforced when the guard is enabled.
    if (v.decision === 'block') {
      emitAudit({ ...base, action: 'auto_deny', outcome: 'auto_denied' });
      // Surface the block to the gateway log (journald). Blocks are recorded in
      // the ShieldCortex audit jsonl, but were otherwise invisible to an operator
      // tailing the gateway; a denial — especially a false positive — must be seen.
      log.warn(`[shieldcortex] action-guard BLOCKED ${context.toolName}: ${v.reason} [${v.signals.join(", ")}]`);
      throw new Error(`ShieldCortex: tool call blocked — ${v.reason}`);
    }

    // Per-agent autoApprove allowlist: a recognised-dangerous op whose family,
    // action, or signal is pre-approved passes without gating. This is the escape
    // hatch that lets enforce-by-default coexist with unattended agents doing
    // legitimate dangerous work. It NEVER applies to catastrophic ops — those
    // hard-block above, before this branch is reached.
    const autoApprove = actionGuardCfg.autoApprove ?? [];
    if (autoApprove.length > 0) {
      const hay = [v.family, v.action, ...v.signals].map(s => String(s).toLowerCase());
      const matched = autoApprove.some(a => {
        const n = a.toLowerCase();
        return hay.some(h => h === n || h.includes(n));
      });
      if (matched) {
        emitAudit({ ...base, action: 'require_approval', outcome: 'approved' });
        return;
      }
    }

    // require_approval — ENFORCED by default (P1/WS1). `enforce:false` opts back
    // down to warn-and-allow (advisory) for operators who want the old behaviour.
    if (!actionGuardCfg.enforce) {
      log.warn(`[shieldcortex] ⚠️ Action Guard: ${context.toolName} — ${v.reason}`);
      emitAudit({ ...base, action: 'warn', outcome: 'warned' });
      return;
    }

    // ── AI-assisted approval broker (#143) ──────────────────────────────────
    // Sits between the guard's verdict and the human, and can only move the
    // answer toward caution. Off by default; when off, `brokered` is null and
    // everything below is the pre-#143 code path unchanged.
    const brokered = await runBroker(context, v);
    // Every downstream audit row for a brokered call carries the broker's own
    // record alongside the guard's, so one row answers "was a model consulted,
    // what did it say, and what did that change?".
    const auditBase = brokered ? { ...base, broker: brokered.audit } : base;

    if (brokered?.outcome === 'harden') {
      // The judge found something the rules did not. Deny outright rather than
      // offer the operator a button to be socially-engineered into tapping.
      emitAudit({ ...auditBase, action: 'require_approval', outcome: 'auto_denied' });
      log.warn(`[shieldcortex] approval broker HARDENED ${context.toolName} to a denial: ${brokered.reason}`);
      throw new Error(`ShieldCortex: tool call blocked — ${brokered.reason}`);
    }

    if (brokered?.outcome === 'pre_clear') {
      // Reversible, on-host, in-context, judge-confident: proceed without
      // waiting. Loud on purpose — a release nobody approved must never be a
      // silent one, because the audit row is the only thing that will ever tell
      // the operator it happened.
      emitAudit({ ...auditBase, action: 'require_approval', outcome: 'approved' });
      log.warn(`[shieldcortex] approval broker PRE-CLEARED ${context.toolName} without waiting for the operator: ${brokered.reason} [${v.signals.join(', ')}]`);
      return;
    }

    if (typeof context.requireApproval !== 'function') {
      // Unattended (no approver, e.g. cron/heartbeat): fail closed on the failure
      // policy. High-severity dangerous defaults to deny — surfaced loudly to the
      // gateway log so an operator sees it, because a silent no-op is exactly the
      // failure mode we are eliminating.
      //
      // With the broker in play this can only get STRICTER: no approver is the
      // timeout case by definition, and `timeoutOutcome` answers 'approve' only
      // for a pre-cleared call, which already returned above. So a brokered call
      // that reaches here denies even where failurePolicy would have allowed.
      const failAction = config.failurePolicy[severity];
      const brokerDenies = brokered ? broker!.timeoutOutcome(brokered) === 'deny' : false;
      const deny = failAction === 'deny' || brokerDenies;
      emitAudit({ ...auditBase, action: 'require_approval', outcome: deny ? 'failure_denied' : 'failure_allowed' });
      if (deny) {
        log.warn(`[shieldcortex] action-guard DENIED (unattended, no approver) ${context.toolName}: ${v.reason} [${v.signals.join(", ")}]`);
        throw new Error(`ShieldCortex: tool call blocked — ${v.reason} (no approver, failure policy: deny)`);
      }
      return;
    }

    if (!rateLimiter.shouldAllow()) {
      emitAudit({ ...auditBase, action: 'rate_limit', outcome: 'auto_denied' });
      throw new Error('ShieldCortex: tool call auto-denied (approval rate limit exceeded)');
    }

    let approved: boolean;
    try {
      approved = await withApprovalDeadline(
        context.requireApproval(formatActionGuardPrompt(context.toolName, v)),
        brokered ? brokerApprovalTimeoutMs(v.severity) : 0,
      );
    } catch (err) {
      if (brokered && err instanceof ApprovalTimeout) {
        // The asymmetric path. Silence is only ever a yes for something the
        // broker already pre-cleared — and that returned long before here — so
        // in practice this is always a deny. It reads the broker's own derived
        // flag rather than re-deriving its own idea of what is safe.
        const outcome = broker!.timeoutOutcome(brokered);
        emitAudit({ ...auditBase, action: 'require_approval', outcome: outcome === 'approve' ? 'approved' : 'auto_denied' });
        if (outcome === 'approve') {
          log.warn(`[shieldcortex] approval broker: no answer in ${err.timeoutMs}ms — auto-approving pre-cleared ${context.toolName}`);
          return;
        }
        log.warn(`[shieldcortex] approval broker: no answer in ${err.timeoutMs}ms — DENYING ${context.toolName} (fail-closed)`);
        throw new Error(`ShieldCortex: tool call blocked — no answer from the operator within ${err.timeoutMs}ms (fail-closed)`);
      }
      const failAction = config.failurePolicy[severity];
      log.warn(`[shieldcortex] ⚠️ requireApproval error: ${err instanceof Error ? err.message : err} — failure policy: ${failAction}`);
      emitAudit({ ...auditBase, action: 'require_approval', outcome: failAction === 'deny' ? 'failure_denied' : 'failure_allowed' });
      if (failAction === 'deny') {
        throw new Error('ShieldCortex: tool call blocked — approval error, failure policy: deny');
      }
      return;
    }

    if (approved) {
      emitAudit({ ...auditBase, action: 'require_approval', outcome: 'approved' });
      return;
    }
    emitAudit({ ...auditBase, action: 'require_approval', outcome: 'denied' });
    throw new Error('ShieldCortex: tool call denied by user');
  }

  async function handleToolCall(context: ToolCallContext): Promise<void> {
    // Remember the NAME only. This is the entirety of what the approval broker's
    // judge will ever learn about the session — see buildSessionSummary.
    noteToolForSession(context.toolName);

    // Non-memory tools go through the Action Guard (what the agent DOES); the
    // memory-write tools continue through the content defence pipeline below.
    if (!(WATCHED_TOOLS as readonly string[]).includes(context.toolName)) {
      await runActionGuard(context);
      return;
    }

    const { title, content } = extractContent(context.toolName, context.arguments);
    const fullContent = [title, content].filter(Boolean).join(' ');
    if (!fullContent.trim()) return;

    // X-Ray content scan — fast, synchronous, no I/O
    const xrayResult = xrayMemoryGuard(content, title || undefined);
    if (!xrayResult.allowed) {
      const xrayEntry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity: 'critical',
        firewallResult: 'BLOCK', threats: xrayResult.findings.map(f => f.category),
        anomalyScore: 1,
        // X-Ray short-circuits before the pipeline runs — no pipeline result.
        trustScore: 0, sensitivityLevel: 'INTERNAL', fragmentationScore: null, pipelineDurationMs: 0,
        action: 'auto_deny', outcome: 'auto_denied',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(xrayEntry);
      throw new Error(`ShieldCortex: tool call blocked by X-Ray memory guard (risk: ${xrayResult.riskLevel}, findings: ${xrayResult.findings.length})`);
    }

    let severity: Severity;
    let firewallResult: string;
    let threats: string[];
    let anomalyScore: number;
    let trustScore: number;
    let sensitivityLevel: string;
    let fragmentationScore: number | null;
    let pipelineDurationMs: number;

    try {
      const pipelineStart = Date.now();
      const result = pipeline(content, title, { type: 'agent', identifier: 'openclaw' });
      pipelineDurationMs = Date.now() - pipelineStart;
      severity = mapSeverity(result.firewall);
      firewallResult = result.firewall.result;
      threats = result.firewall.threatIndicators;
      anomalyScore = result.firewall.anomalyScore;
      trustScore = result.trust.score;
      sensitivityLevel = result.sensitivity.level;
      fragmentationScore = result.fragmentation?.score ?? null;
    } catch (err) {
      log.warn(`[shieldcortex] ⚠️ Defence pipeline error: ${err instanceof Error ? err.message : err}`);
      const failAction = config.failurePolicy.high;
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity: 'high',
        firewallResult: 'ERROR', threats: ['pipeline_error'], anomalyScore: 0,
        // Pipeline threw — no result in scope, use documented defaults.
        trustScore: 0, sensitivityLevel: 'INTERNAL', fragmentationScore: null, pipelineDurationMs: 0,
        action: 'require_approval', outcome: failAction === 'deny' ? 'failure_denied' : 'failure_allowed',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      if (failAction === 'deny') {
        throw new Error('ShieldCortex: tool call blocked — pipeline error, failure policy: deny');
      }
      return;
    }

    if (denyCache.isDenied(context.toolName, fullContent)) {
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, trustScore, sensitivityLevel, fragmentationScore, pipelineDurationMs,
        action: 'auto_deny', outcome: 'auto_denied',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      throw new Error('ShieldCortex: tool call auto-denied (previously denied content)');
    }

    const action = config.severityActions[severity];

    if (action === 'log') {
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, trustScore, sensitivityLevel, fragmentationScore, pipelineDurationMs,
        action: 'log', outcome: 'logged',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      return;
    }

    if (action === 'warn') {
      log.warn(`[shieldcortex] ⚠️ ${severity} risk in ${context.toolName}: ${threats.join(', ') || 'anomaly detected'}`);
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, trustScore, sensitivityLevel, fragmentationScore, pipelineDurationMs,
        action: 'warn', outcome: 'warned',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      return;
    }

    // action === 'require_approval'
    if (typeof context.requireApproval !== 'function') {
      // requireApproval unavailable (pre-v2026.3.28) — apply failurePolicy, not blanket allow
      const failAction = config.failurePolicy[severity];
      log.warn(`[shieldcortex] ⚠️ requireApproval not available for ${severity} risk in ${context.toolName} — failure policy: ${failAction}`);
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, trustScore, sensitivityLevel, fragmentationScore, pipelineDurationMs,
        action: 'require_approval',
        outcome: failAction === 'deny' ? 'failure_denied' : 'failure_allowed',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      if (failAction === 'deny') {
        throw new Error(`ShieldCortex: tool call blocked — requireApproval unavailable, failure policy: deny`);
      }
      return;
    }

    if (!rateLimiter.shouldAllow()) {
      log.warn('[shieldcortex] ⚠️ Too many approval prompts — auto-denying');
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, trustScore, sensitivityLevel, fragmentationScore, pipelineDurationMs,
        action: 'rate_limit', outcome: 'auto_denied',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      denyCache.addDenial(context.toolName, fullContent);
      throw new Error('ShieldCortex: tool call auto-denied (rate limit exceeded)');
    }

    const message = formatApprovalPrompt({ tool: context.toolName, severity, firewallResult, threats, content: fullContent });

    let approved: boolean;
    try {
      approved = await context.requireApproval(message);
    } catch (err) {
      const failAction = config.failurePolicy[severity];
      log.warn(`[shieldcortex] ⚠️ requireApproval error: ${err instanceof Error ? err.message : err} — failure policy: ${failAction}`);
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, trustScore, sensitivityLevel, fragmentationScore, pipelineDurationMs,
        action: 'require_approval',
        outcome: failAction === 'deny' ? 'failure_denied' : 'failure_allowed',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      if (failAction === 'deny') {
        throw new Error(`ShieldCortex: tool call blocked — requireApproval error, failure policy: deny`);
      }
      return;
    }

    if (approved) {
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, trustScore, sensitivityLevel, fragmentationScore, pipelineDurationMs,
        action: 'require_approval', outcome: 'approved',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      return;
    }

    // Denied
    denyCache.addDenial(context.toolName, fullContent);
    const entry: InterceptAuditEntry = {
      type: 'intercept', tool: context.toolName, severity, firewallResult,
      threats, anomalyScore, trustScore, sensitivityLevel, fragmentationScore, pipelineDurationMs,
      action: 'require_approval', outcome: 'denied',
      preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
    };
    emitAudit(entry);
    throw new Error('ShieldCortex: tool call denied by user');
  }

  function resetSession(): void {
    denyCache.reset();
  }

  return { handleToolCall, resetSession };
}
