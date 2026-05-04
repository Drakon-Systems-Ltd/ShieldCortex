/**
 * Digest route — the "Cloudflare email" moment.
 *
 * Surfaces what ShieldCortex actually did for the user in the last N hours,
 * with a top moments feed and a delta vs the previous equivalent window.
 *
 * Without this, the product is invisible. With it, the user has a one-glance
 * answer to "is ShieldCortex earning its keep?" every time they open the
 * dashboard.
 */
import type { Express, Request, Response } from 'express';
import { getDatabase, isDatabaseInitialized } from '../../database/init.js';

export type DigestWindow = '24h' | '7d' | '30d';

const WINDOW_HOURS: Record<DigestWindow, number> = {
  '24h': 24,
  '7d': 168,
  '30d': 720,
};

interface DigestCounts {
  scanned: number;
  allowed: number;
  blocked: number;
  quarantined: number;
  memoriesCaptured: number;
  memoriesRecalled: number;
  highSalienceCaptures: number;
}

interface DigestMoment {
  kind: 'block' | 'quarantine' | 'capture' | 'recall' | 'pattern';
  title: string;
  detail: string;
  timestamp: string;
  memoryId?: number;
  auditId?: number;
}

export interface DigestResponse {
  window: DigestWindow;
  windowLabel: string;
  since: string;
  current: DigestCounts;
  previous: DigestCounts;
  delta: Partial<Record<keyof DigestCounts, number>>;
  topMoments: DigestMoment[];
  topThreatPatterns: Array<{ pattern: string; count: number }>;
  generatedAt: string;
}

const HIGH_SALIENCE_THRESHOLD = 0.6;

function isoSinceHoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

function safeCount<T extends Record<string, unknown>>(rows: T[], key: keyof T): number {
  if (!rows.length) return 0;
  const v = rows[0][key];
  return typeof v === 'number' ? v : Number(v ?? 0);
}

function getCountsBetween(sinceIso: string, untilIso: string | null, project?: string): DigestCounts {
  const db = getDatabase();
  const projectAudit = project ? 'AND da.project = @project' : '';
  const projectMem = project ? 'AND m.project = @project' : '';
  const upperBound = untilIso ? 'AND da.timestamp < @until' : '';
  const upperBoundMem = untilIso ? 'AND m.created_at < @until' : '';
  const upperBoundRecall = untilIso ? 'AND m.last_accessed < @until' : '';
  const params: Record<string, string> = { since: sinceIso };
  if (project) params.project = project;
  if (untilIso) params.until = untilIso;

  // Defence audit counts (single grouped query)
  const auditRows = db.prepare(`
    SELECT da.firewall_result AS result, COUNT(*) AS cnt
    FROM defence_audit da
    WHERE da.timestamp >= @since ${upperBound} ${projectAudit}
    GROUP BY da.firewall_result
  `).all(params) as Array<{ result: string; cnt: number }>;

  let allowed = 0, blocked = 0, quarantined = 0;
  for (const row of auditRows) {
    if (row.result === 'ALLOW') allowed = row.cnt;
    else if (row.result === 'BLOCK') blocked = row.cnt;
    else if (row.result === 'QUARANTINE') quarantined = row.cnt;
  }
  const scanned = allowed + blocked + quarantined;

  // Memories captured in window
  const memCapturedRows = db.prepare(`
    SELECT COUNT(*) AS cnt FROM memories m
    WHERE m.created_at >= @since ${upperBoundMem} ${projectMem}
  `).all(params) as Array<{ cnt: number }>;
  const memoriesCaptured = safeCount(memCapturedRows, 'cnt');

  // High-salience captures (salience >= threshold)
  const highSalRows = db.prepare(`
    SELECT COUNT(*) AS cnt FROM memories m
    WHERE m.created_at >= @since ${upperBoundMem} AND m.salience >= ${HIGH_SALIENCE_THRESHOLD} ${projectMem}
  `).all(params) as Array<{ cnt: number }>;
  const highSalienceCaptures = safeCount(highSalRows, 'cnt');

  // Memories recalled (last_accessed advanced past created_at within window)
  const recalledRows = db.prepare(`
    SELECT COUNT(*) AS cnt FROM memories m
    WHERE m.last_accessed >= @since ${upperBoundRecall}
      AND m.last_accessed > m.created_at
      ${projectMem}
  `).all(params) as Array<{ cnt: number }>;
  const memoriesRecalled = safeCount(recalledRows, 'cnt');

  return {
    scanned,
    allowed,
    blocked,
    quarantined,
    memoriesCaptured,
    memoriesRecalled,
    highSalienceCaptures,
  };
}

function getTopMoments(sinceIso: string, project: string | undefined, limit = 5): DigestMoment[] {
  const db = getDatabase();
  const projectAudit = project ? 'AND da.project = ?' : '';
  const projectMem = project ? 'AND m.project = ?' : '';
  const moments: DigestMoment[] = [];

  // Top blocks/quarantines (most severe firewall actions)
  const auditParams: unknown[] = project ? [sinceIso, project] : [sinceIso];
  const blocks = db.prepare(`
    SELECT da.id, da.timestamp, da.firewall_result, da.reason, da.source_type, da.source_identifier,
           da.threat_indicators, da.anomaly_score
    FROM defence_audit da
    WHERE da.timestamp >= ? ${projectAudit}
      AND da.firewall_result IN ('BLOCK', 'QUARANTINE')
    ORDER BY da.anomaly_score DESC, da.timestamp DESC
    LIMIT 3
  `).all(...auditParams) as Array<{
    id: number; timestamp: string; firewall_result: string; reason: string | null;
    source_type: string; source_identifier: string;
    threat_indicators: string | null; anomaly_score: number | null;
  }>;

  for (const b of blocks) {
    let indicators: string[] = [];
    try { indicators = b.threat_indicators ? JSON.parse(b.threat_indicators) : []; } catch { /* ignore */ }
    const top = indicators.slice(0, 2).join(', ');
    moments.push({
      kind: b.firewall_result === 'BLOCK' ? 'block' : 'quarantine',
      title: b.firewall_result === 'BLOCK'
        ? `Blocked ${top || b.reason || 'a suspicious payload'}`
        : `Quarantined ${top || b.reason || 'a suspicious memory'}`,
      detail: `${b.source_type}: ${b.source_identifier}`,
      timestamp: b.timestamp,
      auditId: b.id,
    });
  }

  // Top high-salience captures
  const memParams: unknown[] = project ? [sinceIso, project] : [sinceIso];
  const captures = db.prepare(`
    SELECT m.id, m.title, m.salience, m.category, m.created_at, m.project
    FROM memories m
    WHERE m.created_at >= ? ${projectMem}
      AND m.salience >= ${HIGH_SALIENCE_THRESHOLD}
    ORDER BY m.salience DESC, m.created_at DESC
    LIMIT 3
  `).all(...memParams) as Array<{
    id: number; title: string; salience: number; category: string;
    created_at: string; project: string | null;
  }>;

  for (const m of captures) {
    moments.push({
      kind: 'capture',
      title: `Captured: ${m.title}`,
      detail: `${m.category} · salience ${m.salience.toFixed(2)}${m.project ? ` · ${m.project}` : ''}`,
      timestamp: m.created_at,
      memoryId: m.id,
    });
  }

  // Top recalls in window (high access count + recently accessed)
  const recalls = db.prepare(`
    SELECT m.id, m.title, m.access_count, m.last_accessed, m.salience
    FROM memories m
    WHERE m.last_accessed >= ? ${projectMem}
      AND m.last_accessed > m.created_at
    ORDER BY m.access_count DESC, m.last_accessed DESC
    LIMIT 2
  `).all(...memParams) as Array<{
    id: number; title: string; access_count: number; last_accessed: string; salience: number;
  }>;

  for (const r of recalls) {
    moments.push({
      kind: 'recall',
      title: `Recalled: ${r.title}`,
      detail: `accessed ${r.access_count}× · salience ${r.salience.toFixed(2)}`,
      timestamp: r.last_accessed,
      memoryId: r.id,
    });
  }

  return moments
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    .slice(0, limit);
}

function getTopThreatPatterns(sinceIso: string, project: string | undefined): Array<{ pattern: string; count: number }> {
  const db = getDatabase();
  const projectCond = project ? 'AND da.project = ?' : '';
  const params: unknown[] = project ? [sinceIso, project] : [sinceIso];

  const rows = db.prepare(`
    SELECT da.threat_indicators
    FROM defence_audit da
    WHERE da.timestamp >= ? ${projectCond}
      AND da.threat_indicators IS NOT NULL
      AND da.threat_indicators != '[]'
    LIMIT 500
  `).all(...params) as Array<{ threat_indicators: string }>;

  const counts: Record<string, number> = {};
  for (const r of rows) {
    try {
      const list: string[] = JSON.parse(r.threat_indicators);
      for (const p of list) counts[p] = (counts[p] ?? 0) + 1;
    } catch { /* ignore */ }
  }

  return Object.entries(counts)
    .map(([pattern, count]) => ({ pattern, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
}

function buildDeltas(current: DigestCounts, previous: DigestCounts): DigestResponse['delta'] {
  const delta: DigestResponse['delta'] = {};
  for (const key of Object.keys(current) as Array<keyof DigestCounts>) {
    delta[key] = current[key] - previous[key];
  }
  return delta;
}

function windowLabelFor(window: DigestWindow): string {
  switch (window) {
    case '24h': return 'Last 24 hours';
    case '7d': return 'Last 7 days';
    case '30d': return 'Last 30 days';
  }
}

export function buildDigest(window: DigestWindow, project?: string): DigestResponse {
  const hours = WINDOW_HOURS[window];
  const since = isoSinceHoursAgo(hours);
  const previousSince = isoSinceHoursAgo(hours * 2);

  const current = getCountsBetween(since, null, project);
  const previous = getCountsBetween(previousSince, since, project);

  return {
    window,
    windowLabel: windowLabelFor(window),
    since,
    current,
    previous,
    delta: buildDeltas(current, previous),
    topMoments: getTopMoments(since, project, 5),
    topThreatPatterns: getTopThreatPatterns(since, project),
    generatedAt: new Date().toISOString(),
  };
}

export interface TimelineDay {
  date: string; // YYYY-MM-DD (UTC)
  scanned: number;
  blocked: number;
  quarantined: number;
  captured: number;
  recalled: number;
}

/**
 * Returns one row per day for the last `days` days, oldest first.
 * Days with zero activity are still included (gives a clean sparkline shape).
 */
export function buildTimeline(days: number, project?: string): TimelineDay[] {
  const db = getDatabase();
  const projectAudit = project ? 'AND da.project = @project' : '';
  const projectMem = project ? 'AND m.project = @project' : '';
  const since = isoSinceHoursAgo(days * 24);

  const params: Record<string, string> = { since };
  if (project) params.project = project;

  // Audit counts grouped by day (UTC)
  const auditRows = db.prepare(`
    SELECT substr(da.timestamp, 1, 10) AS day, da.firewall_result AS result, COUNT(*) AS cnt
    FROM defence_audit da
    WHERE da.timestamp >= @since ${projectAudit}
    GROUP BY day, da.firewall_result
  `).all(params) as Array<{ day: string; result: string; cnt: number }>;

  const captureRows = db.prepare(`
    SELECT substr(m.created_at, 1, 10) AS day, COUNT(*) AS cnt
    FROM memories m
    WHERE m.created_at >= @since ${projectMem}
    GROUP BY day
  `).all(params) as Array<{ day: string; cnt: number }>;

  const recallRows = db.prepare(`
    SELECT substr(m.last_accessed, 1, 10) AS day, COUNT(*) AS cnt
    FROM memories m
    WHERE m.last_accessed >= @since
      AND m.last_accessed > m.created_at
      ${projectMem}
    GROUP BY day
  `).all(params) as Array<{ day: string; cnt: number }>;

  // Build a complete day map with zero defaults
  const byDay: Record<string, TimelineDay> = {};
  const today = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setUTCDate(d.getUTCDate() - i);
    const key = d.toISOString().slice(0, 10);
    byDay[key] = { date: key, scanned: 0, blocked: 0, quarantined: 0, captured: 0, recalled: 0 };
  }

  for (const row of auditRows) {
    const day = byDay[row.day];
    if (!day) continue;
    if (row.result === 'BLOCK') day.blocked = row.cnt;
    else if (row.result === 'QUARANTINE') day.quarantined = row.cnt;
    day.scanned += row.cnt;
  }
  for (const row of captureRows) {
    if (byDay[row.day]) byDay[row.day].captured = row.cnt;
  }
  for (const row of recallRows) {
    if (byDay[row.day]) byDay[row.day].recalled = row.cnt;
  }

  return Object.values(byDay).sort((a, b) => a.date.localeCompare(b.date));
}

export function registerDigestRoutes(app: Express): void {
  app.get('/api/digest', (req: Request, res: Response) => {
    try {
      if (!isDatabaseInitialized()) {
        return res.status(503).json({ error: 'Database not initialised' });
      }
      const rawWindow = String(req.query.window ?? '24h');
      const window: DigestWindow = (rawWindow === '7d' || rawWindow === '30d') ? rawWindow : '24h';
      const project = typeof req.query.project === 'string' && req.query.project.trim()
        ? req.query.project.trim()
        : undefined;
      const digest = buildDigest(window, project);
      res.json(digest);
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get('/api/digest/timeline', (req: Request, res: Response) => {
    try {
      if (!isDatabaseInitialized()) {
        return res.status(503).json({ error: 'Database not initialised' });
      }
      const daysRaw = parseInt(String(req.query.days ?? '7'), 10);
      const days = Number.isFinite(daysRaw) ? Math.max(1, Math.min(90, daysRaw)) : 7;
      const project = typeof req.query.project === 'string' && req.query.project.trim()
        ? req.query.project.trim()
        : undefined;
      const timeline = buildTimeline(days, project);
      res.json({ days, project: project ?? null, timeline });
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });
}
