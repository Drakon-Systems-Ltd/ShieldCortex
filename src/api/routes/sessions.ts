/**
 * Session capture HTTP API. Powers the v4.18 dashboard replay UI.
 *
 * Routes:
 *   GET  /api/sessions                — paginated list of sessions
 *   GET  /api/sessions/:id            — single session metadata + kind histogram
 *   GET  /api/sessions/:id/events     — paginated event stream
 *   POST /api/sessions/import-jsonl   — import a transcript file by path
 *
 * All routes go through `requireNotLocked` (same as memory routes), so a
 * locked DB returns 503 instead of attempting to query.
 *
 * Pagination cap chosen to match `routes/memories.ts`: 200 max for lists,
 * 500 max for the event stream (replay needs more events at once).
 */

import type { Express, Request, Response } from 'express';
import { homedir, tmpdir } from 'os';
import { isAbsolute, join, normalize, resolve, sep } from 'path';
import { getDatabase } from '../../database/init.js';
import { getTimeline } from '../../sessions/timeline.js';
import { importJsonlTranscript } from '../../sessions/import-jsonl.js';
import { expandGlob, isGlobPattern } from '../../sessions/glob.js';

type Middleware = (_req: Request, res: Response, next: (err?: unknown) => void) => void;

const SESSIONS_DEFAULT_LIMIT = 50;
const SESSIONS_MAX_LIMIT = 200;
const EVENTS_DEFAULT_LIMIT = 100;
const EVENTS_MAX_LIMIT = 500;

interface SessionSummaryRow {
  session_id: string;
  project: string | null;
  first_ts: string;
  last_ts: string;
  event_count: number;
}

interface KindBreakdownRow {
  kind: string;
  count: number;
}

function clampLimit(raw: unknown, def: number, max: number): number {
  const parsed = typeof raw === 'string' ? parseInt(raw, 10) : NaN;
  if (!Number.isFinite(parsed) || parsed <= 0) return def;
  return Math.min(parsed, max);
}

function clampOffset(raw: unknown): number {
  const parsed = typeof raw === 'string' ? parseInt(raw, 10) : NaN;
  if (!Number.isFinite(parsed) || parsed < 0) return 0;
  return parsed;
}

export function registerSessionRoutes(app: Express, requireNotLocked: Middleware): void {
  // ── GET /api/sessions — paginated list ─────────────────────────────────
  app.get('/api/sessions', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const project = typeof req.query.project === 'string' ? req.query.project : null;
      const limit = clampLimit(req.query.limit, SESSIONS_DEFAULT_LIMIT, SESSIONS_MAX_LIMIT);
      const offset = clampOffset(req.query.offset);

      const filter = project ? 'WHERE project = ?' : '';
      const params: unknown[] = project ? [project] : [];

      const total = (
        db
          .prepare(
            `SELECT COUNT(DISTINCT session_id) AS c FROM session_events ${filter}`,
          )
          .get(...params) as { c: number }
      ).c;

      const rows = db
        .prepare(
          `SELECT
             session_id,
             MAX(project) AS project,
             MIN(ts) AS first_ts,
             MAX(ts) AS last_ts,
             COUNT(*) AS event_count
           FROM session_events
           ${filter}
           GROUP BY session_id
           ORDER BY last_ts DESC
           LIMIT ? OFFSET ?`,
        )
        .all(...params, limit, offset) as SessionSummaryRow[];

      res.json({
        sessions: rows,
        total,
        offset,
        limit,
        hasMore: offset + rows.length < total,
      });
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── GET /api/sessions/:id — metadata + kind histogram ─────────────────
  app.get('/api/sessions/:id', requireNotLocked, (req: Request, res: Response) => {
    try {
      const sessionId = String(req.params.id);
      const db = getDatabase();

      const summary = db
        .prepare(
          `SELECT
             session_id,
             MAX(project) AS project,
             MIN(ts) AS first_ts,
             MAX(ts) AS last_ts,
             COUNT(*) AS event_count
           FROM session_events
           WHERE session_id = ?
           GROUP BY session_id`,
        )
        .get(sessionId) as SessionSummaryRow | undefined;

      if (!summary) {
        res.status(404).json({ error: 'session not found' });
        return;
      }

      const kindRows = db
        .prepare(
          `SELECT kind, COUNT(*) AS count
           FROM session_events
           WHERE session_id = ?
           GROUP BY kind`,
        )
        .all(sessionId) as KindBreakdownRow[];

      const kinds: Record<string, number> = {};
      for (const row of kindRows) kinds[row.kind] = row.count;

      res.json({ ...summary, kinds });
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── GET /api/sessions/:id/events — paginated event stream ────────────
  app.get('/api/sessions/:id/events', requireNotLocked, (req: Request, res: Response) => {
    try {
      const sessionId = String(req.params.id);
      const limit = clampLimit(req.query.limit, EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT);
      const offset = clampOffset(req.query.offset);
      const db = getDatabase();

      const total = (
        db
          .prepare(`SELECT COUNT(*) AS c FROM session_events WHERE session_id = ?`)
          .get(sessionId) as { c: number }
      ).c;

      // Use the timeline reader for parsed payloads + canonical ordering, then
      // slice in JS. For very large sessions this is fine — the timeline is
      // capped at EVENTS_MAX_LIMIT per request anyway, and the dashboard
      // pages through it incrementally.
      const full = getTimeline(sessionId);
      const events = full.slice(offset, offset + limit);

      res.json({
        events,
        total,
        offset,
        limit,
        hasMore: offset + events.length < total,
      });
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── POST /api/sessions/import-jsonl ────────────────────────────────
  //
  // Body forms:
  //   { path: "/abs/path/to/file.jsonl" }  — import one file
  //   { path: "/glob/pattern/*.jsonl" }    — import all matching files
  //   { } or { path: null }                — default: ~/.claude/projects/**/*.jsonl
  //
  // Default glob exists so the dashboard's "Import JSONL" button has a
  // useful zero-arg action. The CLI exposes the same behaviour.
  app.post('/api/sessions/import-jsonl', requireNotLocked, async (req: Request, res: Response) => {
    try {
      const body = (req.body ?? {}) as { path?: unknown };
      const explicit = typeof body.path === 'string' && body.path.length > 0 ? body.path : null;
      const target = explicit ?? join(homedir(), '.claude', 'projects', '**', '*.jsonl');

      let files: string[];
      try {
        files = await resolveImportFiles(target);
      } catch (err) {
        // Path-traversal rejection from resolveImportFiles → 400 (caller error),
        // not 500 (server bug). Any other error rethrows.
        if (err instanceof Error && /must be under/i.test(err.message)) {
          res.status(400).json({ error: err.message });
          return;
        }
        throw err;
      }
      if (files.length === 0) {
        res.status(404).json({ error: `no JSONL files matched: ${target}` });
        return;
      }

      let eventCount = 0;
      let skipped = 0;
      let malformed = 0;
      let imported = 0;
      let failed = 0;
      let lastSessionId: string | null = null;
      const errors: Array<{ path: string; error: string }> = [];

      for (const file of files) {
        try {
          const r = importJsonlTranscript(file);
          eventCount += r.eventCount;
          skipped += r.skipped;
          malformed += r.malformed;
          if (r.sessionId) lastSessionId = r.sessionId;
          imported++;
        } catch (err) {
          failed++;
          errors.push({ path: file, error: (err as Error).message });
        }
      }

      // Special case: a single literal path that doesn't exist → 404. The
      // glob path already 404'd above when nothing matched; this covers
      // the "user typed a wrong path" UX.
      if (
        files.length === 1 &&
        imported === 0 &&
        errors.length === 1 &&
        /not found|ENOENT/i.test(errors[0].error)
      ) {
        res.status(404).json({ error: errors[0].error });
        return;
      }

      res.json({
        filesMatched: files.length,
        filesImported: imported,
        filesFailed: failed,
        eventCount,
        skipped,
        malformed,
        sessionId: files.length === 1 ? lastSessionId : null,
        errors: errors.slice(0, 10), // cap at 10 to keep response small
      });
    } catch (err) {
      const message = (err as Error).message;
      const status = /not found|ENOENT/i.test(message) ? 404 : 500;
      res.status(status).json({ error: message });
    }
  });
}

/**
 * Resolve `target` into a list of absolute file paths, ensuring every
 * result is rooted under a user-trusted directory. The dashboard binds to
 * `localhost` by default, but constraining imports is a useful
 * defence-in-depth measure when the dashboard is exposed via a tunnel,
 * docker port-map, or a careless reverse proxy. A stray POST with
 * `{ path: "/etc/secret.jsonl" }` should never read that file.
 *
 * Allowed roots:
 *   - the user's home directory (where `~/.claude/projects/...` lives)
 *   - the OS temp directory (where ad-hoc downloads + the test suite write)
 *
 * Both are per-user trust domains. Symlinks that point outside slip past
 * this check because we don't `realpath()` for perf reasons — the user
 * owns these trees, so a hostile symlink is a separate threat model.
 */
async function resolveImportFiles(target: string): Promise<string[]> {
  const roots = trustedRoots();

  // Expand `~` then make absolute. `path.normalize` collapses `..` so a
  // pattern like `~/../etc/passwd` resolves to `/etc/passwd` *before* the
  // under-root check below catches it.
  const expanded = expandHome(target, homedir());
  const absolute = isAbsolute(expanded) ? expanded : resolve(process.cwd(), expanded);
  const normalized = normalize(absolute);

  if (!isUnderTrustedRoot(normalized, roots)) {
    throw new Error(`path must be under home or temp directory: ${target}`);
  }

  if (!isGlobPattern(normalized)) return [normalized];

  // Defence in depth: `**` walks symlinked subtrees, so re-filter the
  // expansion. A symlink that escapes the trusted roots gets dropped here.
  return expandGlob(normalized).filter((p) => isUnderTrustedRoot(normalize(p), roots));
}

interface TrustedRoots {
  readonly entries: ReadonlyArray<{ root: string; withSep: string }>;
}

function trustedRoots(): TrustedRoots {
  // Deduplicate — on some macOS configs `tmpdir()` is a subdir of `homedir()`.
  const seen = new Set<string>();
  const entries: Array<{ root: string; withSep: string }> = [];
  for (const root of [homedir(), tmpdir()]) {
    const n = normalize(root);
    if (seen.has(n)) continue;
    seen.add(n);
    entries.push({ root: n, withSep: n.endsWith(sep) ? n : n + sep });
  }
  return { entries };
}

function isUnderTrustedRoot(p: string, roots: TrustedRoots): boolean {
  return roots.entries.some((r) => p === r.root || p.startsWith(r.withSep));
}

function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/') || p.startsWith('~\\')) return join(home, p.slice(2));
  return p;
}
