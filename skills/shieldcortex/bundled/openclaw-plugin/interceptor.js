import { createHash } from 'node:crypto';
import { mkdirSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
const WATCHED_TOOLS = ['remember', 'mcp__memory__remember'];
const CONTENT_FIELDS = {
    remember: ['content', 'title'],
    mcp__memory__remember: ['content', 'title'],
};
// Defaults relaxed in v4.11.0: critical/high no longer block the tool call with
// a synchronous approval prompt. The defence pipeline still runs and
// `failurePolicy` still denies on critical/high, so the block is preserved —
// what changes is the user-facing approval gate. Opt back in with
// `severityActions: { high: 'require_approval', critical: 'require_approval' }`.
const DEFAULT_CONFIG = {
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
};
export { WATCHED_TOOLS, CONTENT_FIELDS, DEFAULT_CONFIG };
export function extractContent(toolName, args) {
    const fields = CONTENT_FIELDS[toolName];
    if (!fields)
        return { title: '', content: '' };
    const title = typeof args.title === 'string' ? args.title : '';
    const content = typeof args.content === 'string' ? args.content : '';
    return { title, content };
}
export function mapSeverity(firewall) {
    if (firewall.result === 'BLOCK')
        return 'critical';
    if (firewall.result === 'QUARANTINE')
        return 'high';
    if (firewall.result === 'ALLOW' && firewall.anomalyScore >= 0.3)
        return 'medium';
    return 'low';
}
// --- Deny Cache ---
// Exact replica of normalizeMemoryText() from index.ts (lines 426-434).
// Must produce identical output for SHA-256 hash consistency.
function normaliseContent(text) {
    return String(text || '')
        .toLowerCase()
        .replace(/[`"'\\]/g, ' ')
        .replace(/https?:\/\/\S+/g, ' ')
        .replace(/[^a-z0-9\s]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}
function hashContent(text) {
    return createHash('sha256').update(normaliseContent(text)).digest('hex');
}
const TWO_HOURS_MS = 2 * 60 * 60 * 1000;
export class DenyCache {
    cache = new Map();
    maxPerTool;
    ttlMs;
    constructor(maxPerTool = 200, ttlMs = TWO_HOURS_MS) {
        this.maxPerTool = maxPerTool;
        this.ttlMs = ttlMs;
    }
    isDenied(tool, content) {
        const entries = this.cache.get(tool);
        if (!entries)
            return false;
        const hash = hashContent(content);
        const now = Date.now();
        return entries.some(e => e.hash === hash && (now - e.ts) < this.ttlMs);
    }
    addDenial(tool, content) {
        const hash = hashContent(content);
        const now = Date.now();
        if (!this.cache.has(tool)) {
            this.cache.set(tool, []);
        }
        const entries = this.cache.get(tool);
        const live = entries.filter(e => (now - e.ts) < this.ttlMs);
        if (live.some(e => e.hash === hash))
            return;
        live.push({ hash, ts: now });
        while (live.length > this.maxPerTool) {
            live.shift();
        }
        this.cache.set(tool, live);
    }
    reset() {
        this.cache.clear();
    }
}
// --- Rate Limiter ---
export class RateLimiter {
    timestamps = [];
    maxPerWindow;
    windowMs;
    constructor(maxPerWindow = 5, windowMs = 60_000) {
        this.maxPerWindow = maxPerWindow;
        this.windowMs = windowMs;
    }
    shouldAllow() {
        const now = Date.now();
        this.timestamps = this.timestamps.filter(t => now - t < this.windowMs);
        if (this.timestamps.length >= this.maxPerWindow)
            return false;
        this.timestamps.push(now);
        return true;
    }
}
export function formatApprovalPrompt(input) {
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
function writeAuditEntry(entry) {
    try {
        mkdirSync(AUDIT_DIR, { recursive: true });
        const date = new Date().toISOString().slice(0, 10);
        const file = join(AUDIT_DIR, `realtime-${date}.jsonl`);
        appendFileSync(file, JSON.stringify(entry) + '\n');
    }
    catch {
        // Best-effort — never block on audit failure
    }
}
// --- X-Ray Inline Guard ---
// Lightweight inline version of xrayMemoryContent for the plugin build boundary.
// Detects AI directive injection patterns in memory content.
const XRAY_AI_DIRECTIVE_PATTERNS = [
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
const XRAY_FILENAME_PATTERNS = [
    /ignore_previous/i, /decode_hidden/i, /execute_instructions/i,
    /override_previous/i, /developer_mode/i, /system_prompt/i,
    /jailbreak/i, /\[SYSTEM\]/i, /\[INST\]/i,
];
function xrayMemoryGuard(content, title) {
    const findings = [];
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
export function createInterceptor(config, pipeline, options) {
    const denyCache = new DenyCache();
    const rateLimiter = new RateLimiter(options?.maxPromptsPerMinute ?? 5);
    const log = config.logger ?? { info: console.log, warn: console.warn };
    const onAuditEntry = options?.onAuditEntry;
    function emitAudit(entry) {
        writeAuditEntry(entry);
        onAuditEntry?.(entry);
    }
    async function handleToolCall(context) {
        if (!WATCHED_TOOLS.includes(context.toolName))
            return;
        const { title, content } = extractContent(context.toolName, context.arguments);
        const fullContent = [title, content].filter(Boolean).join(' ');
        if (!fullContent.trim())
            return;
        // X-Ray content scan — fast, synchronous, no I/O
        const xrayResult = xrayMemoryGuard(content, title || undefined);
        if (!xrayResult.allowed) {
            const xrayEntry = {
                type: 'intercept', tool: context.toolName, severity: 'critical',
                firewallResult: 'BLOCK', threats: xrayResult.findings.map(f => f.category),
                anomalyScore: 1, action: 'auto_deny', outcome: 'auto_denied',
                preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
            };
            emitAudit(xrayEntry);
            throw new Error(`ShieldCortex: tool call blocked by X-Ray memory guard (risk: ${xrayResult.riskLevel}, findings: ${xrayResult.findings.length})`);
        }
        let severity;
        let firewallResult;
        let threats;
        let anomalyScore;
        try {
            const result = pipeline(content, title, { type: 'agent', identifier: 'openclaw' });
            severity = mapSeverity(result.firewall);
            firewallResult = result.firewall.result;
            threats = result.firewall.threatIndicators;
            anomalyScore = result.firewall.anomalyScore;
        }
        catch (err) {
            log.warn(`[shieldcortex] ⚠️ Defence pipeline error: ${err instanceof Error ? err.message : err}`);
            const failAction = config.failurePolicy.high;
            const entry = {
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
            const entry = {
                type: 'intercept', tool: context.toolName, severity, firewallResult,
                threats, anomalyScore, action: 'auto_deny', outcome: 'auto_denied',
                preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
            };
            emitAudit(entry);
            throw new Error('ShieldCortex: tool call auto-denied (previously denied content)');
        }
        const action = config.severityActions[severity];
        if (action === 'log') {
            const entry = {
                type: 'intercept', tool: context.toolName, severity, firewallResult,
                threats, anomalyScore, action: 'log', outcome: 'logged',
                preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
            };
            emitAudit(entry);
            return;
        }
        if (action === 'warn') {
            log.warn(`[shieldcortex] ⚠️ ${severity} risk in ${context.toolName}: ${threats.join(', ') || 'anomaly detected'}`);
            const entry = {
                type: 'intercept', tool: context.toolName, severity, firewallResult,
                threats, anomalyScore, action: 'warn', outcome: 'warned',
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
            const entry = {
                type: 'intercept', tool: context.toolName, severity, firewallResult,
                threats, anomalyScore, action: 'require_approval',
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
            const entry = {
                type: 'intercept', tool: context.toolName, severity, firewallResult,
                threats, anomalyScore, action: 'rate_limit', outcome: 'auto_denied',
                preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
            };
            emitAudit(entry);
            denyCache.addDenial(context.toolName, fullContent);
            throw new Error('ShieldCortex: tool call auto-denied (rate limit exceeded)');
        }
        const message = formatApprovalPrompt({ tool: context.toolName, severity, firewallResult, threats, content: fullContent });
        let approved;
        try {
            approved = await context.requireApproval(message);
        }
        catch (err) {
            const failAction = config.failurePolicy[severity];
            log.warn(`[shieldcortex] ⚠️ requireApproval error: ${err instanceof Error ? err.message : err} — failure policy: ${failAction}`);
            const entry = {
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
            const entry = {
                type: 'intercept', tool: context.toolName, severity, firewallResult,
                threats, anomalyScore, action: 'require_approval', outcome: 'approved',
                preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
            };
            emitAudit(entry);
            return;
        }
        // Denied
        denyCache.addDenial(context.toolName, fullContent);
        const entry = {
            type: 'intercept', tool: context.toolName, severity, firewallResult,
            threats, anomalyScore, action: 'require_approval', outcome: 'denied',
            preview: fullContent.slice(0, 200), ts: new Date().toISOString(),
        };
        emitAudit(entry);
        throw new Error('ShieldCortex: tool call denied by user');
    }
    function resetSession() {
        denyCache.reset();
    }
    return { handleToolCall, resetSession };
}
