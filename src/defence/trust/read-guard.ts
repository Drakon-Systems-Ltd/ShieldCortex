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
import { redactContent } from '../sensitivity/redaction.js';
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
 * NEVER surface RESTRICTED, quarantined, or untrusted-inbound (`web:` / `email:`)
 * rows to ANYONE — matching the .mjs prompt hooks and SCOPE P4 (a web capture
 * written by agent A must not bootstrap agent B). Unlike the per-caller fetch
 * tools they do NOT apply the source-relative own-only tier, so a low-trust
 * subagent still receives INTERNAL project context. Credential isolation
 * without the availability blackout.
 */
function isUntrustedInboundSource(source: string | null | undefined): boolean {
  if (!source) return false;
  return source.startsWith('web:') || source.startsWith('email:');
}

export function guardReadBySensitivity(memories: Memory[]): Memory[] {
  return memories.filter((m) =>
    m.trustScore !== 0
    && m.sensitivityLevel !== 'RESTRICTED'
    && !isUntrustedInboundSource(m.source),
  );
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

/**
 * Dashboard / HTTP visualization-API read guard.
 *
 * The dashboard is the OWNER's surface, but it renders in a BROWSER — so raw
 * RESTRICTED (credential-class) content there is a leak vector (screenshots,
 * screen-shares, the browser's disk cache). Policy (REDACT, don't drop):
 *
 *   - RESTRICTED rows are KEPT (so the owner sees the memory exists and can
 *     review/delete it) but their `content` is replaced with a placeholder;
 *   - because sensitivity is classified on TITLE + CONTENT together, a secret can
 *     also live in the title or metadata — so credential SPANS in those fields are
 *     masked too (a benign label like "AWS deploy key" is left intact);
 *   - low-trust / trust-0 rows are NOT dropped: the dashboard is a management
 *     surface (its Review queue exists to triage exactly these), so the owner must
 *     see them. Only RESTRICTED *content* is withheld, never whole rows.
 *
 * RESTRICTED full content remains available via the CLI (`recall`/`get_memory`),
 * which is not a browser-render surface. Dropping quarantined rows is the MCP
 * read-boundary's job (a subagent caller), not the owner's dashboard.
 */
export const RESTRICTED_CONTENT_PLACEHOLDER = '🔒 [RESTRICTED content withheld — view via CLI]';

/** Mask credential spans in a string (no-op if it carries no secret); pass-through for non-strings. */
function scrubSecretSpans<T>(value: T): T {
  return typeof value === 'string' ? (redactContent(value) as unknown as T) : value;
}

/**
 * Redact a single RESTRICTED memory for display: withhold `content`, mask
 * credential spans in `title` and string `metadata` values. Returns a fresh copy
 * (never mutates the input — rows may be live cache objects). Non-RESTRICTED rows
 * pass through unchanged.
 */
function redactRestrictedMemory(m: Memory): Memory {
  // Always mask credential spans in the title (benign titles are untouched —
  // redactContent only rewrites known credential patterns). A secret can be
  // classified RESTRICTED via the title alone, and titles are shown for
  // manageability, so this closes the secret-in-title leak without hiding labels.
  const title = redactContent(m.title);
  if (m.sensitivityLevel !== 'RESTRICTED') {
    return title === m.title ? m : { ...m, title };
  }
  const metadata =
    m.metadata && typeof m.metadata === 'object' && !Array.isArray(m.metadata)
      ? Object.fromEntries(Object.entries(m.metadata).map(([k, v]) => [k, scrubSecretSpans(v)]))
      : m.metadata;
  return {
    ...m,
    content: RESTRICTED_CONTENT_PLACEHOLDER,
    title,
    metadata: metadata as Record<string, unknown>,
  };
}

/** Redact RESTRICTED memories for display (content withheld; title/metadata secret-scrubbed). */
export function redactRestrictedForDisplay(memories: Memory[]): Memory[] {
  return memories.map(redactRestrictedMemory);
}

/** Apply the dashboard redaction to every memory list in a context summary (used before formatting). */
export function guardDashboardContextSummary(summary: ContextSummary): ContextSummary {
  return {
    ...summary,
    recentMemories: redactRestrictedForDisplay(summary.recentMemories),
    keyDecisions: redactRestrictedForDisplay(summary.keyDecisions),
    activePatterns: redactRestrictedForDisplay(summary.activePatterns),
    pendingItems: redactRestrictedForDisplay(summary.pendingItems),
  };
}

/**
 * Returns true for a serialized-memory object — one carrying a sensitivity label
 * and a content field, in either camelCase (Memory) or snake_case (raw DB row).
 */
function isRedactableMemoryObject(o: Record<string, unknown>): boolean {
  const level = (o.sensitivityLevel ?? o.sensitivity_level) as unknown;
  return level === 'RESTRICTED' && typeof o.content === 'string';
}

/**
 * Deep-walk an arbitrary HTTP-response payload and redact every RESTRICTED memory
 * object it contains (withhold `content`; mask credential spans in `title` and
 * string `metadata`), returning a redacted COPY (the input is never mutated —
 * payloads often reference the live row cache).
 *
 * This is the comprehensive backstop for the visualization API: memories surface
 * at many different nesting depths (`{ memories: [...] }`, recall
 * `results[].memory`, openclaw `sessions[].memories[]`, review-queue
 * `sections.stale[]`, `contradictions[].memoryA`), so guarding each route by hand
 * would inevitably miss one. A single response interceptor that walks the whole
 * tree cannot. It does NOT reach content already baked into a pre-rendered string
 * (e.g. `/api/context`'s `formatted`) or bare title fields stripped of their
 * sensitivity label (the contradictions endpoints, the `memory_deleted` event) —
 * those are scrubbed at their own surface.
 */
export function deepRedactRestrictedContent<T>(value: T, seen: WeakSet<object> = new WeakSet()): T {
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value as object)) return value; // cycle guard
  seen.add(value as object);

  if (Array.isArray(value)) {
    return value.map((item) => deepRedactRestrictedContent(item, seen)) as unknown as T;
  }

  const obj = value as Record<string, unknown>;
  const copy: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    copy[key] = deepRedactRestrictedContent(obj[key], seen);
    // Mask credential spans in any title-bearing string field, wherever it sits —
    // titles are emitted bare (no sensitivity label) on recall/graph/contradictions
    // /memory_deleted surfaces, so this closes those leaks centrally. redactContent
    // only rewrites known credential patterns, so benign titles pass through.
    if (/title/i.test(key) && typeof copy[key] === 'string') {
      copy[key] = redactContent(copy[key] as string);
    }
  }
  if (isRedactableMemoryObject(copy)) {
    copy.content = RESTRICTED_CONTENT_PLACEHOLDER;
    if (copy.metadata && typeof copy.metadata === 'object' && !Array.isArray(copy.metadata)) {
      const md = copy.metadata as Record<string, unknown>;
      for (const k of Object.keys(md)) md[k] = scrubSecretSpans(md[k]);
    }
  }
  return copy as unknown as T;
}
