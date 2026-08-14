/**
 * Threat Graph query tool (Phase A.3, docs/design/2026-08-11-threat-graph.md).
 *
 * Read surface over threat_nodes / threat_edges. Bounded from day one: hard
 * row cap + byte cap with an explicit truncation marker — the unbounded-output
 * bug fixed in graph_query (Phase 0) does not get reintroduced here.
 */

import { getDatabase } from '../database/init.js';
import { listAllowances } from '../threat-graph/allowance.js';

export interface ThreatGraphQueryArgs {
  view: 'sources' | 'source' | 'events' | 'campaigns' | 'allowances' | 'conflicts';
  /** Node key for view 'source' (e.g. 'agent:build-bot'). */
  key?: string;
  /** Filter events by originating project. */
  project?: string;
  /** ISO timestamp — only rows seen at/after this. */
  since?: string;
  limit?: number;
}

export interface ThreatGraphQueryOptions {
  /** Response size ceiling in bytes (default 256 KB). */
  byteCap?: number;
}

const HARD_ROW_CAP = 200;
const DEFAULT_LIMIT = 50;
const DEFAULT_BYTE_CAP = 256 * 1024;

function mcpText(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

function parseAttrs(raw: string): Record<string, unknown> {
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function nodeView(row: any) {
  return {
    key: row.key,
    kind: row.kind,
    attrs: parseAttrs(row.attrs),
    first_seen: row.first_seen,
    last_seen: row.last_seen,
  };
}

/**
 * Serialise under the byte cap: halve the row list until it fits, marking
 * truncation explicitly so a consumer never mistakes a cut for completeness.
 */
function boundedPayload(
  base: Record<string, unknown>,
  listField: string,
  rows: unknown[],
  byteCap: number,
) {
  let kept = rows;
  let truncated = false;
  for (;;) {
    const body = { ...base, [listField]: kept, truncated };
    const text = JSON.stringify(body, null, 2);
    if (Buffer.byteLength(text, 'utf8') <= byteCap || kept.length === 0) return mcpText(body);
    truncated = true;
    kept = kept.slice(0, Math.max(0, Math.floor(kept.length / 2)));
  }
}

export function handleThreatGraphQuery(
  args: ThreatGraphQueryArgs,
  options?: ThreatGraphQueryOptions,
) {
  const db = getDatabase();
  const byteCap = options?.byteCap ?? DEFAULT_BYTE_CAP;
  const limit = Math.min(Math.max(1, args.limit ?? DEFAULT_LIMIT), HARD_ROW_CAP);
  const since = args.since ?? null;

  switch (args.view) {
    case 'sources': {
      const rows = db.prepare(`
        SELECT * FROM threat_nodes WHERE kind = 'source'
        ${since ? 'AND last_seen >= @since' : ''}
        ORDER BY last_seen DESC, key ASC LIMIT @limit
      `).all({ since, limit }) as any[];
      return boundedPayload({ view: 'sources', limit }, 'sources', rows.map(nodeView), byteCap);
    }

    case 'source': {
      const source = db.prepare("SELECT * FROM threat_nodes WHERE kind = 'source' AND key = ?")
        .get(args.key ?? '') as any;
      if (!source) {
        return mcpText({ error: `Source "${args.key ?? ''}" not found in the threat graph.` });
      }

      // Aggregate triggered edges → pattern nodes with counts.
      const patterns = db.prepare(`
        SELECT p.key, e.count, e.first_seen, e.last_seen
        FROM threat_edges e JOIN threat_nodes p ON p.id = e.dst
        WHERE e.src = ? AND e.predicate = 'triggered'
        ORDER BY e.count DESC, p.key ASC LIMIT ?
      `).all(source.id, limit) as any[];

      // Recent notable events pointing at this source.
      const events = db.prepare(`
        SELECT ev.* FROM threat_edges e JOIN threat_nodes ev ON ev.id = e.src
        WHERE e.dst = ? AND e.predicate = 'from_source' AND ev.kind = 'event'
        ORDER BY ev.last_seen DESC, ev.key ASC LIMIT ?
      `).all(source.id, limit) as any[];

      return boundedPayload(
        { view: 'source', source: nodeView(source), patterns, limit },
        'events',
        events.map(nodeView),
        byteCap,
      );
    }

    case 'events': {
      // Conflict review nodes reuse kind='event' but have their own 'conflicts'
      // view — keep them out of the generic events list.
      const rows = db.prepare(`
        SELECT * FROM threat_nodes WHERE kind = 'event' AND key NOT LIKE 'conflict:%'
        ${args.project ? "AND json_extract(attrs, '$.project') = @project" : ''}
        ${since ? 'AND last_seen >= @since' : ''}
        ORDER BY last_seen DESC, key ASC LIMIT @limit
      `).all({ project: args.project ?? null, since, limit }) as any[];
      return boundedPayload({ view: 'events', limit }, 'events', rows.map(nodeView), byteCap);
    }

    case 'allowances': {
      // Operator allowances (Loop 3): (source, pattern) pairs an operator has
      // approved enough to auto-release near-dup repeats. `now` is not
      // available deterministically here, so the active flag is evaluated at
      // read time — acceptable for a display surface.
      const rows = listAllowances(Date.now(), limit);
      return boundedPayload({ view: 'allowances', limit }, 'allowances', rows, byteCap);
    }

    case 'campaigns': {
      // Campaign detection is Phase D; the view exists so consumers need no
      // schema change when it lands.
      const rows = db.prepare(`
        SELECT * FROM threat_nodes WHERE kind = 'campaign'
        ORDER BY last_seen DESC LIMIT @limit
      `).all({ limit }) as any[];
      return boundedPayload({ view: 'campaigns', limit }, 'campaigns', rows.map(nodeView), byteCap);
    }

    case 'conflicts': {
      // Relation-channel conflict review items (Phase E — ShadowMerge defence).
      // Each node's attrs carry both contenders with full provenance. Resolution
      // is an operator mutation via the CLI (`threat-graph resolve-conflict`),
      // kept off this read surface deliberately.
      const rows = db.prepare(`
        SELECT * FROM threat_nodes
        WHERE kind = 'event' AND key LIKE 'conflict:%'
        ${since ? 'AND last_seen >= @since' : ''}
        ORDER BY last_seen DESC, key ASC LIMIT @limit
      `).all({ since, limit }) as any[];
      return boundedPayload({ view: 'conflicts', limit }, 'conflicts', rows.map(nodeView), byteCap);
    }

    default:
      return mcpText({ error: `Unknown view "${String((args as { view?: unknown }).view)}".` });
  }
}
