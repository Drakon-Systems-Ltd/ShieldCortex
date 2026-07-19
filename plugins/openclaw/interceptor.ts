import { createHash } from 'node:crypto';
import { mkdirSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

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
}
export type ToolGuardEvaluator = (toolName: string, args: Record<string, unknown>) => ToolGuardVerdictLike;

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

interface InterceptorOptions {
  maxPromptsPerMinute?: number;
  onAuditEntry?: (entry: InterceptAuditEntry) => void;
  /** Tool Action Guard evaluator, injected from `shieldcortex/defence` at runtime. */
  evaluateToolCall?: ToolGuardEvaluator;
}

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
    };
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
      v = evaluateToolCall(context.toolName, context.arguments || {});
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

    if (typeof context.requireApproval !== 'function') {
      // Unattended (no approver, e.g. cron/heartbeat): fail closed on the failure
      // policy. High-severity dangerous defaults to deny — surfaced loudly to the
      // gateway log so an operator sees it, because a silent no-op is exactly the
      // failure mode we are eliminating.
      const failAction = config.failurePolicy[severity];
      emitAudit({ ...base, action: 'require_approval', outcome: failAction === 'deny' ? 'failure_denied' : 'failure_allowed' });
      if (failAction === 'deny') {
        log.warn(`[shieldcortex] action-guard DENIED (unattended, no approver) ${context.toolName}: ${v.reason} [${v.signals.join(", ")}]`);
        throw new Error(`ShieldCortex: tool call blocked — ${v.reason} (no approver, failure policy: deny)`);
      }
      return;
    }

    if (!rateLimiter.shouldAllow()) {
      emitAudit({ ...base, action: 'rate_limit', outcome: 'auto_denied' });
      throw new Error('ShieldCortex: tool call auto-denied (approval rate limit exceeded)');
    }

    let approved: boolean;
    try {
      approved = await context.requireApproval(formatActionGuardPrompt(context.toolName, v));
    } catch (err) {
      const failAction = config.failurePolicy[severity];
      log.warn(`[shieldcortex] ⚠️ requireApproval error: ${err instanceof Error ? err.message : err} — failure policy: ${failAction}`);
      emitAudit({ ...base, action: 'require_approval', outcome: failAction === 'deny' ? 'failure_denied' : 'failure_allowed' });
      if (failAction === 'deny') {
        throw new Error('ShieldCortex: tool call blocked — approval error, failure policy: deny');
      }
      return;
    }

    if (approved) {
      emitAudit({ ...base, action: 'require_approval', outcome: 'approved' });
      return;
    }
    emitAudit({ ...base, action: 'require_approval', outcome: 'denied' });
    throw new Error('ShieldCortex: tool call denied by user');
  }

  async function handleToolCall(context: ToolCallContext): Promise<void> {
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
