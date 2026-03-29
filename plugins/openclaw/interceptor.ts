import { createHash } from 'node:crypto';
import { mkdirSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type InterceptAction = 'log' | 'warn' | 'require_approval';
export type FailureAction = 'allow' | 'deny';

export interface InterceptorConfig {
  enabled: boolean;
  severityActions: Record<Severity, InterceptAction>;
  failurePolicy: Record<Severity, FailureAction>;
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
  action: InterceptAction | 'auto_deny' | 'rate_limit';
  outcome: 'approved' | 'denied' | 'auto_denied' | 'logged' | 'warned' | 'failure_allowed' | 'failure_denied';
  preview: string;
  ts: string;
}

const WATCHED_TOOLS = ['remember', 'mcp__memory__remember'] as const;

const CONTENT_FIELDS: Record<string, string[]> = {
  remember: ['content', 'title'],
  mcp__memory__remember: ['content', 'title'],
};

const DEFAULT_CONFIG: InterceptorConfig = {
  enabled: true,
  severityActions: {
    low: 'log',
    medium: 'warn',
    high: 'require_approval',
    critical: 'require_approval',
  },
  failurePolicy: {
    low: 'allow',
    medium: 'allow',
    high: 'deny',
    critical: 'deny',
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

// --- Audit Logging (local JSONL) ---

const AUDIT_DIR = join(homedir(), '.shieldcortex', 'audit');

function writeAuditEntry(entry: InterceptAuditEntry): void {
  try {
    mkdirSync(AUDIT_DIR, { recursive: true });
    const date = new Date().toISOString().slice(0, 10);
    const file = join(AUDIT_DIR, `realtime-${date}.jsonl`);
    appendFileSync(file, JSON.stringify(entry) + '\n');
  } catch {
    // Best-effort — never block on audit failure
  }
}

// --- Interceptor Factory ---

type PipelineRunner = (content: string, title: string, source: { type: string; identifier: string }) => {
  allowed: boolean;
  firewall: {
    result: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
    reason: string;
    threatIndicators: string[];
    anomalyScore: number;
    blockedPatterns: string[];
  };
  auditId: number;
};

interface InterceptorOptions {
  maxPromptsPerMinute?: number;
  onAuditEntry?: (entry: InterceptAuditEntry) => void;
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

  function emitAudit(entry: InterceptAuditEntry): void {
    writeAuditEntry(entry);
    onAuditEntry?.(entry);
  }

  async function handleToolCall(context: ToolCallContext): Promise<void> {
    if (!(WATCHED_TOOLS as readonly string[]).includes(context.toolName)) return;

    const { title, content } = extractContent(context.toolName, context.arguments);
    const fullContent = [title, content].filter(Boolean).join(' ');
    if (!fullContent.trim()) return;

    let severity: Severity;
    let firewallResult: string;
    let threats: string[];
    let anomalyScore: number;

    try {
      const result = pipeline(content, title, { type: 'agent', identifier: 'openclaw' });
      severity = mapSeverity(result.firewall);
      firewallResult = result.firewall.result;
      threats = result.firewall.threatIndicators;
      anomalyScore = result.firewall.anomalyScore;
    } catch (err) {
      log.warn(`[shieldcortex] ⚠️ Defence pipeline error: ${err instanceof Error ? err.message : err}`);
      const failAction = config.failurePolicy.high;
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity: 'high',
        firewallResult: 'ERROR', threats: ['pipeline_error'], anomalyScore: 0,
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
        threats, anomalyScore, action: 'auto_deny', outcome: 'auto_denied',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      throw new Error('ShieldCortex: tool call auto-denied (previously denied content)');
    }

    const action = config.severityActions[severity];

    if (action === 'log') {
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, action: 'log', outcome: 'logged',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      return;
    }

    if (action === 'warn') {
      log.warn(`[shieldcortex] ⚠️ ${severity} risk in ${context.toolName}: ${threats.join(', ') || 'anomaly detected'}`);
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, action: 'warn', outcome: 'warned',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      return;
    }

    // action === 'require_approval'
    if (typeof context.requireApproval !== 'function') {
      log.warn(`[shieldcortex] ⚠️ requireApproval not available — falling back to warn for ${severity} risk in ${context.toolName}`);
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, action: 'warn', outcome: 'warned',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      return;
    }

    if (!rateLimiter.shouldAllow()) {
      log.warn('[shieldcortex] ⚠️ Too many approval prompts — auto-denying');
      const entry: InterceptAuditEntry = {
        type: 'intercept', tool: context.toolName, severity, firewallResult,
        threats, anomalyScore, action: 'rate_limit', outcome: 'auto_denied',
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
        threats, anomalyScore, action: 'require_approval',
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
        threats, anomalyScore, action: 'require_approval', outcome: 'approved',
        preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
      };
      emitAudit(entry);
      return;
    }

    // Denied
    denyCache.addDenial(context.toolName, fullContent);
    const entry: InterceptAuditEntry = {
      type: 'intercept', tool: context.toolName, severity, firewallResult,
      threats, anomalyScore, action: 'require_approval', outcome: 'denied',
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
