/**
 * shieldcortex/enforce — the portable Action Guard.
 *
 * One function a host adapter calls before executing a tool:
 *   evaluateAction(toolName, args) → allow | require_approval | block
 *
 * This is NOT a hook protocol. The host must honour `block` / `require_approval`.
 * MCP, LangChain, and a custom loop that ignore the verdict are unbound.
 *
 * Deliberately does NOT import iron-dome/index.ts (that pulls sqlite).
 * Freeze / lease is a separate call so a scanner-only consumer never
 * touches ~/.shieldcortex/DECISIONS.md.
 */

export {
  evaluateToolCall,
  type ToolGuardDecision,
  type ToolGuardSeverity,
  type ToolGuardVerdict,
  type ToolGuardOptions,
  type ToolFamily,
} from './defence/iron-dome/tool-action-guard.js';

export {
  evaluateToolCallLease,
  type LeaseGateResult,
  type LeaseGateOptions,
} from './defence/iron-dome/session-lease-store.js';

import { evaluateToolCall, type ToolGuardVerdict } from './defence/iron-dome/tool-action-guard.js';
import {
  evaluateToolCallLease,
  type LeaseGateOptions,
  type LeaseGateResult,
} from './defence/iron-dome/session-lease-store.js';

export interface EvaluateActionOptions {
  /** Session identity for the lease mutex. Required when skipLease is false. */
  self?: string;
  dir?: string;
  nowMs?: number;
  ttlMs?: number;
  /** Skip freeze/lease. Use only when the host already consulted the ledger. */
  skipLease?: boolean;
}

export interface EvaluateActionResult {
  verdict: ToolGuardVerdict;
  lease: LeaseGateResult | null;
}

/**
 * Guard + freeze in one call. Freeze is consulted first in the lease helper
 * (it never throws). A freeze `block` is the host's problem to honour —
 * this function still returns the guard verdict so the audit row can record both.
 */
export function evaluateAction(
  toolName: string,
  args: Record<string, unknown> | null | undefined,
  opts: EvaluateActionOptions = {},
): EvaluateActionResult {
  const toolArgs = args ?? {};
  const lease = opts.skipLease
    ? null
    : evaluateToolCallLease(toolName, toolArgs, {
        self: opts.self ?? `anon-pid-${process.pid}`,
        dir: opts.dir,
        nowMs: opts.nowMs,
        ttlMs: opts.ttlMs,
      });
  const verdict = evaluateToolCall(toolName, toolArgs);
  return { verdict, lease };
}
