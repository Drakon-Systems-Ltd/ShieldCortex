/**
 * Session-guard index + degraded-run summary (#242 / #260).
 *
 * Claude Code already writes `session-guard/<sc-…>.jsonl` from the PreToolUse
 * hook and summarises at stop-hook. The OpenClaw interceptor — where the #242
 * cron incidents happened — wrote nothing. This module is the one formula
 * both planes use so a row keyed on a raw sessionId is never silently dropped
 * by the `/^sc-[a-f0-9]{16}$/` filename check.
 *
 * `actionKey` / binding fields are optional passengers. This module only
 * requires origin, sessionKey and a degraded outcome.
 */
import { createHmac, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const GUARD_DEGRADED_OUTCOMES = new Set([
  'auto_denied',
  'denied_no_prompt_surface',
  'failure_denied',
  'failure_allowed',
  'warned',
  'denied',
]);

export const GUARD_INDEX_ORIGINS = new Set(['claude-code-hook', 'openclaw-interceptor']);
export const SUMMARY_ORIGINS = new Set(['claude-code-stop-hook', 'openclaw-session-end']);

export function isGuardIndexOrigin(origin: unknown): boolean {
  return GUARD_INDEX_ORIGINS.has(String(origin ?? ''));
}

export function isSummaryOrigin(origin: unknown): boolean {
  return SUMMARY_ORIGINS.has(String(origin ?? ''));
}

export interface SessionGuardOptions {
  home?: string;
  salt?: string;
  origin?: string;
}

function stateHome(home?: string): string {
  return home ?? homedir();
}

function auditDirFor(home?: string): string {
  // Honour the same test/runtime override the interceptor uses. Only when the
  // caller did not pin a home — a pinned home is the isolation boundary.
  if (home === undefined) {
    const override = process.env.SHIELDCORTEX_AUDIT_DIR;
    if (typeof override === 'string' && override.trim()) return override.trim();
  }
  return join(stateHome(home), '.shieldcortex', 'audit');
}

/** Same formula as scripts/pre-tool-hook.mjs and scripts/stop-hook.mjs. */
export function sessionKeyFor(value: string | undefined, opts: SessionGuardOptions = {}): string | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  const salt = opts.salt ?? sessionKeySalt(opts.home);
  if (!salt) return null;
  return `sc-${createHmac('sha256', salt).update(`action-guard-session:${value}`).digest('hex').slice(0, 16)}`;
}

export function sessionKeySalt(home?: string): string | null {
  const fromEnv = process.env.SHIELDCORTEX_SESSION_SALT;
  if (typeof fromEnv === 'string' && /^[a-f0-9]{64}$/i.test(fromEnv)) return fromEnv.toLowerCase();
  try {
    const dir = join(stateHome(home), '.shieldcortex');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const primary = join(dir, 'action-guard-session-salt');
    if (existsSync(primary)) {
      const existing = readFileSync(primary, 'utf8').trim().toLowerCase();
      if (/^[a-f0-9]{64}$/.test(existing)) return existing;
    }
    const salt = randomBytes(32).toString('hex');
    try {
      writeFileSync(primary, `${salt}\n`, { flag: 'wx', mode: 0o600 });
      return salt;
    } catch {
      if (existsSync(primary)) {
        const raced = readFileSync(primary, 'utf8').trim().toLowerCase();
        if (/^[a-f0-9]{64}$/.test(raced)) return raced;
      }
      return salt;
    }
  } catch {
    return null;
  }
}

export function appendSessionGuardIndex(opts: {
  home?: string;
  entry: Record<string, unknown>;
}): boolean {
  const sessionKey = String(opts.entry.sessionKey ?? '');
  if (!/^sc-[a-f0-9]{16}$/.test(sessionKey)) return false;
  if (!isGuardIndexOrigin(opts.entry.origin)) return false;
  if (!GUARD_DEGRADED_OUTCOMES.has(String(opts.entry.outcome ?? ''))) return false;
  try {
    const dir = join(auditDirFor(opts.home), 'session-guard');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    appendFileSync(join(dir, `${sessionKey}.jsonl`), `${JSON.stringify({ recordKind: 'guard', ...opts.entry })}\n`);
    return true;
  } catch {
    return false;
  }
}

export function recordActionGuardDegraded(
  rawSessionId: string | undefined,
  opts: SessionGuardOptions = {},
): { recorded: boolean; count: number; sessionKey?: string; existing?: boolean } {
  const sessionKey = sessionKeyFor(rawSessionId, opts);
  if (!sessionKey) return { recorded: false, count: 0 };
  const indexFile = join(auditDirFor(opts.home), 'session-guard', `${sessionKey}.jsonl`);
  const rows = readJsonl(indexFile);
  if (rows.some((r) => isDegradedSummary(r, sessionKey))) {
    return { recorded: true, count: 0, existing: true, sessionKey };
  }
  const guards = rows.filter((r) => isDegradedGuard(r));
  if (guards.length === 0) return { recorded: false, count: 0, sessionKey };

  const threats = [...new Set(guards.flatMap((r) =>
    Array.isArray(r.threats) ? r.threats.map(String) : [],
  ))].slice(0, 25);
  const times = guards.map((r) => String(r.ts ?? '')).filter(Boolean).sort();
  const counts = guards.reduce<Record<string, number>>((acc, r) => {
    const outcome = String(r.outcome ?? 'unknown');
    acc[outcome] = (acc[outcome] ?? 0) + 1;
    return acc;
  }, {});
  const entry = {
    type: 'session_summary',
    recordKind: 'summary',
    origin: opts.origin ?? 'openclaw-session-end',
    sessionKey,
    action: 'session_health',
    outcome: 'action_guard_degraded',
    guardOutcomeCount: guards.length,
    outcomes: counts,
    threats,
    firstGuardTs: times[0],
    lastGuardTs: times[times.length - 1],
    ts: new Date().toISOString(),
  };
  try {
    const auditDir = auditDirFor(opts.home);
    mkdirSync(auditDir, { recursive: true, mode: 0o700 });
    const date = new Date().toISOString().slice(0, 10);
    appendFileSync(join(auditDir, `realtime-${date}.jsonl`), `${JSON.stringify(entry)}\n`);
    mkdirSync(join(auditDir, 'session-guard'), { recursive: true, mode: 0o700 });
    appendFileSync(indexFile, `${JSON.stringify(entry)}\n`);
    console.error(`[shieldcortex] action_guard_degraded sessionKey=${sessionKey} guardOutcomes=${guards.length} origin=${entry.origin}`);
    return { recorded: true, count: guards.length, sessionKey };
  } catch {
    return { recorded: false, count: guards.length, sessionKey };
  }
}

function isDegradedSummary(row: Record<string, unknown>, sessionKey: string): boolean {
  return (row.recordKind === 'summary' || row.type === 'session_summary')
    && isSummaryOrigin(row.origin)
    && row.sessionKey === sessionKey
    && row.outcome === 'action_guard_degraded';
}

function isDegradedGuard(row: Record<string, unknown>): boolean {
  return (row.recordKind === 'guard' || row.type === 'intercept')
    && isGuardIndexOrigin(row.origin)
    && GUARD_DEGRADED_OUTCOMES.has(String(row.outcome ?? ''));
}

function readJsonl(file: string): Array<Record<string, unknown>> {
  try {
    if (!existsSync(file)) return [];
    return readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).flatMap((line) => {
      try { return [JSON.parse(line) as Record<string, unknown>]; } catch { return []; }
    });
  } catch {
    return [];
  }
}
