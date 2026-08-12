/**
 * Campaign detection (design doc Loop 4) — clusters CAUGHT events into
 * attributed campaigns via JS union-find over shared pivots. It answers
 * "these blocks across three sessions are one actor", NOT "is there a quiet
 * successful campaign" (a sub-threshold ALLOW mints no event, so it never
 * clusters — same honesty as the risk model).
 *
 * The pure `clusterEvents` below is the algorithm; the DB job that reads a
 * windowed event set and mints campaign nodes lives further down.
 *
 * SCOPE (Phase D): detection-only. The design's alert BUDGET — coalescing
 * campaigns into one digest per run with a per-week cap, and the
 * `threatGraph.campaignAlerts` config key — is deliberately NOT wired yet:
 * nothing emits alerts, so there is no flooding surface. Before any
 * dashboard/webhook consumer is wired to campaign nodes, that per-week cap +
 * digest MUST land first (bounded-everything includes alert volume). Campaigns
 * are queryable via the `threat_graph` tool and the CLI in the meantime.
 */

export interface CampaignEvent {
  id: number;
  source: string | null;
  session: string | null;
  patterns: string[];
  entities: string[];
}

export interface CampaignGroup {
  members: number[];
  sources: string[];
  sessions: string[];
  patterns: string[];
  entityOverlap: boolean;
}

export interface ClusterOptions {
  /** A pattern tripped by more than this many distinct sources is a HUB and
   * is excluded as a connector (co-tripping a popular detector is not a
   * campaign). */
  hubThreshold: number;
}

class UnionFind {
  private parent = new Map<number, number>();
  find(x: number): number {
    if (!this.parent.has(x)) { this.parent.set(x, x); return x; }
    let root = x;
    while (this.parent.get(root)! !== root) root = this.parent.get(root)!;
    // Path compression.
    let cur = x;
    while (this.parent.get(cur)! !== root) { const next = this.parent.get(cur)!; this.parent.set(cur, root); cur = next; }
    return root;
  }
  union(a: number, b: number): void {
    const ra = this.find(a), rb = this.find(b);
    if (ra !== rb) this.parent.set(ra, rb);
  }
}

/**
 * Cluster events into qualifying campaigns.
 *
 * Membership forms ONLY through strong pivots — source, session, and non-hub
 * pattern. entity_ref links never form membership (invariant 5: attacker text
 * can both manufacture and suppress entity sharing); they only raise a
 * component's confidence when a real link already connects it.
 *
 * A component qualifies when it has ≥2 events spanning ≥2 distinct sources OR
 * ≥2 distinct sessions.
 */
/** A pooled/non-attributable source key is a CATEGORY, not an actor —
 * `overflow` (the source-cap bucket) and `conversation:<hook>` (every
 * conversation detection on a hook). It must never act as a connector, or all
 * of its events collapse into one giant false campaign. */
function isPooledSource(key: string): boolean {
  return key === 'overflow' || key.startsWith('conversation:');
}

export function clusterEvents(events: CampaignEvent[], opts: ClusterOptions): CampaignGroup[] {
  const byId = new Map(events.map((e) => [e.id, e]));
  const hub = opts.hubThreshold;

  // Pivot → event ids.
  const sourcePivot = new Map<string, number[]>();
  const sessionPivot = new Map<string, number[]>();
  const patternPivot = new Map<string, number[]>();
  const push = (m: Map<string, number[]>, k: string, id: number) => {
    const arr = m.get(k); if (arr) arr.push(id); else m.set(k, [id]);
  };
  for (const e of events) {
    if (e.source) push(sourcePivot, e.source, e.id);
    if (e.session) push(sessionPivot, e.session, e.id);
    for (const p of e.patterns) push(patternPivot, p, e.id);
  }

  // Hub exclusion on ALL three axes (>= is inclusive: exactly hubThreshold is a
  // hub). A source spanning ≥hub distinct sessions is a category not an actor;
  // a session spanning ≥hub distinct sources is a shared bus; a pattern tripped
  // by ≥hub distinct sources is a popular detector. None may bridge a campaign.
  const distinct = (ids: number[], pick: (e: CampaignEvent) => string | null) =>
    new Set(ids.map((id) => pick(byId.get(id)!)).filter((x): x is string => !!x)).size;
  const hubSources = new Set<string>();
  for (const [src, ids] of sourcePivot) {
    if (isPooledSource(src) || distinct(ids, (e) => e.session) >= hub) hubSources.add(src);
  }
  const hubSessions = new Set<string>();
  for (const [sess, ids] of sessionPivot) if (distinct(ids, (e) => e.source) >= hub) hubSessions.add(sess);
  const hubPatterns = new Set<string>();
  for (const [pat, ids] of patternPivot) if (distinct(ids, (e) => e.source) >= hub) hubPatterns.add(pat);

  // Union through non-hub pivots only.
  const uf = new UnionFind();
  const unionAll = (ids: number[]) => { for (let i = 1; i < ids.length; i++) uf.union(ids[0], ids[i]); };
  for (const [src, ids] of sourcePivot) if (!hubSources.has(src)) unionAll(ids);
  for (const [sess, ids] of sessionPivot) if (!hubSessions.has(sess)) unionAll(ids);
  for (const [pat, ids] of patternPivot) if (!hubPatterns.has(pat)) unionAll(ids);

  // Group events by root.
  const comps = new Map<number, number[]>();
  for (const e of events) {
    const root = uf.find(e.id);
    const arr = comps.get(root); if (arr) arr.push(e.id); else comps.set(root, [e.id]);
  }

  const groups: CampaignGroup[] = [];
  for (const members of comps.values()) {
    if (members.length < 2) continue;
    const evs = members.map((id) => byId.get(id)!);
    const sources = [...new Set(evs.map((e) => e.source).filter((s): s is string => !!s))].sort();
    const sessions = [...new Set(evs.map((e) => e.session).filter((s): s is string => !!s))].sort();
    if (sources.length < 2 && sessions.length < 2) continue;

    const patterns = [...new Set(evs.flatMap((e) => e.patterns).filter((p) => !hubPatterns.has(p)))].sort();
    // Entity overlap: any entity mentioned by ≥2 members (forward-ready — the
    // projector mints no `mentions`/entity_ref yet, so this is currently
    // always false; it corroborates confidence once Phase E bridges entities).
    const entityCounts = new Map<string, number>();
    for (const e of evs) for (const ent of new Set(e.entities)) entityCounts.set(ent, (entityCounts.get(ent) ?? 0) + 1);
    const entityOverlap = [...entityCounts.values()].some((c) => c >= 2);

    groups.push({ members: members.sort((a, b) => a - b), sources, sessions, patterns, entityOverlap });
  }

  // Rank by severity (breadth then size then recency) so a maxCampaigns slice
  // keeps the MOST significant campaigns, not the oldest-anchored ones.
  return groups.sort((a, b) => {
    const breadth = (b.sources.length + b.sessions.length) - (a.sources.length + a.sessions.length);
    if (breadth !== 0) return breadth;
    if (b.members.length !== a.members.length) return b.members.length - a.members.length;
    return Math.max(...b.members) - Math.max(...a.members); // newer (higher id) first
  });
}

// ── DB job ───────────────────────────────────────────────────────────────────

import { getDatabase } from '../database/init.js';
import { createContentHash } from '../defence/audit/logger.js';

const DEFAULT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_HUB_THRESHOLD = 10;
const DEFAULT_MAX_CAMPAIGNS = 100;

export interface CampaignRunOptions {
  nowMs: number;
  windowMs?: number;
  hubThreshold?: number;
  maxCampaigns?: number;
}

export interface CampaignRunResult {
  campaigns: number;
  events: number;
  /** Set when more qualifying campaigns existed than maxCampaigns — surfaced
   * so a silent truncation is never mistaken for "nothing more" (invariant 6). */
  truncated?: string;
}

/**
 * Detect campaigns over the recent-event window and (re)materialise them as
 * `campaign` nodes + `part_of` edges. Idempotent: campaigns are a derived,
 * wall-clock-relative analysis (like source_risk), so each run clears the
 * prior campaign layer and recomputes — and campaign nodes/part_of edges are
 * excluded from the canonicalDump determinism contract.
 *
 * Campaign identity is a hash of its member event keys (ledger-stable), so a
 * recompute over the same window reproduces the same campaign key.
 */
export function runCampaignDetection(options: CampaignRunOptions): CampaignRunResult {
  const db = getDatabase();
  const windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;
  const hubThreshold = options.hubThreshold ?? DEFAULT_HUB_THRESHOLD;
  const maxCampaigns = options.maxCampaigns ?? DEFAULT_MAX_CAMPAIGNS;
  const windowStartIso = new Date(options.nowMs - windowMs).toISOString();

  const eventRows = db.prepare(
    "SELECT id, key, last_seen FROM threat_nodes WHERE kind = 'event' AND last_seen >= ?"
  ).all(windowStartIso) as Array<{ id: number; key: string; last_seen: string }>;

  const result: CampaignRunResult = { campaigns: 0, events: eventRows.length };
  const keyById = new Map<number, string>(eventRows.map((r) => [r.id, r.key]));
  const lastSeenById = new Map<number, string>(eventRows.map((r) => [r.id, r.last_seen]));

  if (eventRows.length === 0) return result;

  // ONE grouped query for all in-window events' pivots, bucketed in JS — not
  // an N+1 query per event (the design's single-windowed-query form).
  const eventIds = eventRows.map((r) => r.id);
  const placeholders = eventIds.map(() => '?').join(',');
  const pivotRows = db.prepare(`
    SELECT e.src AS event_id, e.predicate, n.key AS node_key
    FROM threat_edges e JOIN threat_nodes n ON n.id = e.dst
    WHERE e.predicate IN ('from_source','in_session','matched','mentions')
      AND e.src IN (${placeholders})
  `).all(...eventIds) as Array<{ event_id: number; predicate: string; node_key: string }>;

  const eventMap = new Map<number, CampaignEvent>(
    eventIds.map((id) => [id, { id, source: null, session: null, patterns: [], entities: [] }]),
  );
  for (const p of pivotRows) {
    const ev = eventMap.get(p.event_id);
    if (!ev) continue;
    if (p.predicate === 'from_source') ev.source = p.node_key;
    else if (p.predicate === 'in_session') ev.session = p.node_key;
    else if (p.predicate === 'matched') ev.patterns.push(p.node_key);
    else if (p.predicate === 'mentions') ev.entities.push(p.node_key);
  }

  const allGroups = clusterEvents([...eventMap.values()], { hubThreshold });
  if (allGroups.length > maxCampaigns) {
    result.truncated = `campaign cap: ${allGroups.length} qualifying, kept top ${maxCampaigns}`;
  }
  const groups = allGroups.slice(0, maxCampaigns);

  const clear = db.transaction(() => {
    // FK cascade removes part_of edges with the campaign nodes.
    db.prepare("DELETE FROM threat_nodes WHERE kind = 'campaign'").run();

    for (const g of groups) {
      const memberKeys = g.members.map((id) => keyById.get(id)!).sort();
      const campaignKey = createContentHash(memberKeys.join('|')).slice(0, 16);
      const seens = g.members.map((id) => lastSeenById.get(id)!).sort();
      const firstSeen = seens[0];
      const lastSeen = seens[seens.length - 1];

      db.prepare(`
        INSERT INTO threat_nodes (kind, key, label, attrs, first_seen, last_seen)
        VALUES ('campaign', ?, ?, ?, ?, ?)
        ON CONFLICT(kind, key) DO UPDATE SET attrs = excluded.attrs, last_seen = excluded.last_seen
      `).run(
        campaignKey,
        `${g.sources.length} sources · ${g.sessions.length} sessions · ${g.members.length} events`,
        JSON.stringify({
          sources: g.sources,
          sessions: g.sessions,
          patterns: g.patterns,
          size: g.members.length,
          entity_overlap: g.entityOverlap,
          window_days: Math.round(windowMs / 86_400_000),
          detected_at: new Date(options.nowMs).toISOString(),
        }),
        firstSeen,
        lastSeen,
      );
      const campId = (db.prepare("SELECT id FROM threat_nodes WHERE kind = 'campaign' AND key = ?").get(campaignKey) as { id: number }).id;
      for (const memberId of g.members) {
        db.prepare(`
          INSERT INTO threat_edges (src, predicate, dst, count, first_seen, last_seen, writer, evidence, attrs)
          VALUES (?, 'part_of', ?, 1, ?, ?, 'projector', '[]', '{}')
          ON CONFLICT(src, predicate, dst) DO NOTHING
        `).run(memberId, campId, lastSeen, lastSeen);
      }
      result.campaigns++;
    }
  });
  clear.immediate();

  return result;
}

