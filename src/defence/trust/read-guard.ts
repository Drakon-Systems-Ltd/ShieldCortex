/**
 * MCP read-path access guard.
 *
 * The `.mjs` prompt/session hooks already filter recalled rows before injecting
 * them into the prompt. The MCP read TOOLS (`get_memory`, `get_related`,
 * `get_context`, and `recall`) returned rows without applying the access-control
 * engine consistently — so a low-trust / compromised caller could pull RESTRICTED
 * or other-source memories verbatim. This guard closes that path by applying the
 * SAME `checkAccess('read')` tiers the search path uses:
 *
 *   - quarantined rows (trustScore === 0) are ALWAYS dropped (pending review);
 *   - when a caller source is present, rows the caller cannot read are dropped
 *     (RESTRICTED isolation below trust 0.7, own-only below 0.5);
 *   - owner / high-trust callers pass through in full (chosen policy — no content
 *     redaction on the MCP path; that is the prompt-hook surface's job).
 *
 * No source → only quarantined rows are dropped (callers that don't resolve an
 * identity get no source-relative ACL). In practice the MCP server always
 * resolves a source via resolveToolSource before calling the read tools.
 */

import { checkAccess } from './access-control.js';
import type { DefenceSource } from '../types.js';
import type { Memory, ContextSummary } from '../../memory/types.js';

/**
 * Core read decision, shared by the camelCase (Memory) and snake_case (raw row)
 * guards so the policy lives in exactly one place.
 */
function callerCanRead(
  id: number,
  storedSource: string | null,
  sensitivityLevel: string | null,
  trustScore: number,
  source: DefenceSource | undefined,
): boolean {
  // Quarantined memories are never surfaced through a normal read.
  if (trustScore === 0) return false;
  // Without a caller identity we cannot make a source-relative decision;
  // surface everything else (the server resolves a source in practice).
  if (!source) return true;
  return checkAccess({ id, source: storedSource, sensitivity_level: sensitivityLevel }, source, 'read').canRead;
}

/** Filter recalled memories (camelCase Memory) to those the caller may read. */
export function guardReadMemories(
  memories: Memory[],
  source: DefenceSource | undefined,
): Memory[] {
  return memories.filter((m) => callerCanRead(m.id, m.source, m.sensitivityLevel, m.trustScore, source));
}

/**
 * Filter raw snake_case DB rows (e.g. the export path's `SELECT *`) to those the
 * caller may read. Same policy as guardReadMemories, different field casing.
 */
export function guardReadRows<T extends Record<string, unknown>>(
  rows: T[],
  source: DefenceSource | undefined,
): T[] {
  return rows.filter((r) =>
    callerCanRead(
      Number(r.id),
      (r.source as string | null) ?? null,
      (r.sensitivity_level as string | null) ?? null,
      Number(r.trust_score ?? 1),
      source,
    ),
  );
}

/**
 * Sensitivity-only guard for SHARED-CONTEXT bootstrap surfaces (get_context,
 * start_session, the memory:// resources, restore_context, detect_contradictions).
 *
 * These surfaces feed the prompt / a broadly-shared project summary, so they must
 * NEVER surface RESTRICTED or quarantined rows to ANYONE (matching the .mjs
 * prompt hooks) — but, unlike the per-caller fetch tools, they do NOT apply the
 * source-relative own-only tier, so a low-trust subagent still receives the
 * INTERNAL project context it legitimately needs. Credential isolation without
 * the availability blackout.
 */
export function guardReadBySensitivity(memories: Memory[]): Memory[] {
  return memories.filter((m) => m.trustScore !== 0 && m.sensitivityLevel !== 'RESTRICTED');
}

/** Apply the sensitivity guard to every memory list in a context summary. */
export function guardContextSummary(summary: ContextSummary): ContextSummary {
  return {
    ...summary,
    recentMemories: guardReadBySensitivity(summary.recentMemories),
    keyDecisions: guardReadBySensitivity(summary.keyDecisions),
    activePatterns: guardReadBySensitivity(summary.activePatterns),
    pendingItems: guardReadBySensitivity(summary.pendingItems),
  };
}

/** Guard a single memory; returns null if the caller may not read it. */
export function guardReadMemory(
  memory: Memory | null | undefined,
  source: DefenceSource | undefined,
): Memory | null {
  if (!memory) return null;
  return guardReadMemories([memory], source)[0] ?? null;
}
