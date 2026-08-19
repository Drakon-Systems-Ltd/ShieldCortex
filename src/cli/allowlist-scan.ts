/**
 * `shieldcortex allowlist scan` (#309) — the batch review flow for the
 * reviewed-script allowlist.
 *
 * Discovery walks the places configured agent crons actually name scripts —
 * Hermes cron jobs (`~/.hermes/cron/jobs.json`), OpenClaw cron jobs
 * (`~/.openclaw/cron/jobs.json`), and any explicit `--glob` patterns — and
 * diffs every resolvable script against `actionGuard.reviewedScripts` by
 * content hash. An **absent** cron store is empty-ok. A store that **exists
 * but is unreadable or invalid JSON is incomplete discovery** — `scan`
 * exits 1 so automation cannot treat "we could not look" as "all clear".
 * Relative script names are not extracted (absolute or `~/` + extension only).
 *
 * Trust surface discipline, same #118 threat model as `allowlist add`:
 *   - Non-interactive runs LIST ONLY. They exit 3 when there is something a
 *     human should look at, so automation can detect "review needed" without
 *     being able to perform the review.
 *   - Pinning happens only per-item, on a TTY, through `pinReviewedScript` —
 *     the exact write path `add` uses. No env-var escape hatch.
 *   - `--yes` is refused outright without a TTY, and even with one it demands
 *     the operator TYPE the word "approve" — a batch pin must cost more than
 *     a reflex keystroke.
 *
 * The network sniff is advisory colour for the reviewer ("this thing talks to
 * the outside world"), never a gate: a script that hides its networking from
 * a one-line regex must not thereby earn a quieter review.
 */

import { readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve as resolvePath } from 'node:path';
import { isInteractive } from './approve.js';
import { pinReviewedScript, MAX_REVIEWABLE_BYTES, type AllowlistDeps } from './allowlist.js';
import { hashScriptSource, normaliseReviewedScripts } from '../defence/iron-dome/reviewed-scripts.js';
import { getReviewedScriptsRaw } from '../cloud/config.js';
import {
  defaultOpenClawCronDbPath,
  discoverDbCronScripts,
  OPENCLAW_CRON_DB_SOURCE,
} from './openclaw-cron-store.js';
import {
  correlateCronDenials,
  deniedScriptPaths,
  type CronDenialReport,
} from './cron-denial-audit.js';
import { expandHome, extractScriptPaths, SCRIPT_EXT_RE } from './script-paths.js';

export { extractScriptPaths } from './script-paths.js';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const RESET = '\x1b[0m';

export interface ScanDeps extends AllowlistDeps {
  /** Injected home for tests — default `os.homedir()`. Real ~/.hermes and
   *  ~/.openclaw must never be read under test. */
  home?: string;
  cwd?: string;
  hermesCronPath?: string;
  openclawCronPath?: string;
  /** OpenClaw's migrated SQLite cron store (#375). Default
   *  `<home>/.openclaw/state/openclaw.sqlite`; read-only, always injectable. */
  openclawDbPath?: string;
  /** ShieldCortex denial log, for the denied-first ordering (#375 P2).
   *  Default `<home>/.shieldcortex/denials.jsonl`. */
  denialsPath?: string;
  globs?: string[];
  /** Injected stdin for tests; default asks on the real terminal. */
  prompt?: (question: string) => Promise<string>;
}

export interface DiscoveredScript {
  /** Absolute path after `~/` expansion — NOT canonicalised yet. */
  path: string;
  sources: string[];
}

/** Sources whose scripts have never been through the per-item review flow.
 *  The first SQLite backfill is the one wave `--yes` must not swallow (#375). */
const FIRST_BACKFILL_SOURCES = new Set([OPENCLAW_CRON_DB_SOURCE]);

export type ScanStatus = 'current' | 'changed' | 'new' | 'missing' | 'too_large';

export interface ScanItem {
  /** Canonical path when the file resolves; the discovered path otherwise. */
  path: string;
  status: ScanStatus;
  sha256?: string;
  pinnedSha256?: string;
  networkHint: boolean;
  sources: string[];
  preview?: string;
  /**
   * Set when this script belongs to a scheduled job the guard denied inside
   * the correlation window (#375 P2). Carries the job name only — never a
   * denial surface or a command body.
   */
  deniedNote?: string;
}

// ── Discovery ───────────────────────────────────────────────

/** Advisory only — a reviewer hint, never a gate (see module header). */
const NETWORK_SNIFF_RE = /\b(?:requests|urllib|imaplib|smtplib|httpx|aiohttp|googleapiclient)\b|fetch\s*\(|\bcurl\b/;

/** A cron store that is absent is empty-ok; unreadable/malformed is distinct.
 *  `schema_mismatch` arrives with the SQLite source (#375): a store we can
 *  open whose cron table is not the shape we know how to read. */
export type CronSourceStatus = 'absent' | 'ok' | 'unreadable' | 'invalid_json' | 'schema_mismatch';

export interface CronSourceReport {
  path: string;
  status: CronSourceStatus;
}

function inspectJsonFile(path: string): { status: CronSourceStatus; doc?: unknown } {
  try {
    const raw = readFileSync(path, 'utf8');
    try {
      return { status: 'ok', doc: JSON.parse(raw) };
    } catch {
      return { status: 'invalid_json' };
    }
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && err.code === 'ENOENT') return { status: 'absent' };
    return { status: 'unreadable' };
  }
}

function jobsOf(doc: unknown): unknown[] {
  if (Array.isArray(doc)) return doc;
  if (doc && typeof doc === 'object' && Array.isArray((doc as Record<string, unknown>).jobs)) {
    return (doc as Record<string, unknown>).jobs as unknown[];
  }
  return [];
}

/** Hermes shape: `{ jobs: [{ prompt, script, … }] }` or a bare array. */
function hermesCandidates(doc: unknown, home: string): string[] {
  const out: string[] = [];
  for (const job of jobsOf(doc)) {
    if (!job || typeof job !== 'object') continue;
    const rec = job as Record<string, unknown>;
    if (typeof rec.script === 'string') {
      const s = rec.script.trim();
      if ((isAbsolute(s) || s.startsWith('~/')) && SCRIPT_EXT_RE.test(s) && !/\s/.test(s)) {
        out.push(expandHome(s, home));
      } else {
        // A `script` field holding a command line still names its script.
        out.push(...extractScriptPaths(s, home));
      }
    }
    if (typeof rec.prompt === 'string') out.push(...extractScriptPaths(rec.prompt, home));
  }
  return out;
}

/** OpenClaw shape: `{ version, jobs: [{ payload: { kind, message } }] }`.
 *  The stringified-payload sweep catches paths in fields we did not predict. */
function openclawCandidates(doc: unknown, home: string): string[] {
  const out: string[] = [];
  for (const job of jobsOf(doc)) {
    if (!job || typeof job !== 'object') continue;
    const payload = (job as Record<string, unknown>).payload;
    if (!payload || typeof payload !== 'object') continue;
    const rec = payload as Record<string, unknown>;
    if (typeof rec.message === 'string') out.push(...extractScriptPaths(rec.message, home));
    if (typeof rec.prompt === 'string') out.push(...extractScriptPaths(rec.prompt, home));
    try {
      out.push(...extractScriptPaths(JSON.stringify(payload), home));
    } catch {
      /* circular payloads cannot come from JSON, but never throw regardless */
    }
  }
  return out;
}

// Minimal glob: `*` and `?` within a segment, `**` for any directory depth.
// The walk budget caps runaway patterns; dirent.isDirectory() is false for
// symlinks, so `**` cannot loop through a symlink cycle.
const GLOB_WALK_BUDGET = 20_000;

function segmentToRegExp(segment: string): RegExp {
  const escaped = segment.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]');
  return new RegExp(`^${escaped}$`);
}

function expandGlob(pattern: string, cwd: string): string[] {
  const abs = isAbsolute(pattern) ? pattern : resolvePath(cwd, pattern);
  const out: string[] = [];
  const budget = { left: GLOB_WALK_BUDGET };

  const walk = (base: string, segs: string[]): void => {
    if (budget.left-- <= 0) return;
    if (segs.length === 0) {
      try {
        if (statSync(base).isFile() && SCRIPT_EXT_RE.test(base)) out.push(base);
      } catch {
        /* pattern named something that is not there */
      }
      return;
    }
    const [head, ...rest] = segs;
    if (head === '**') {
      walk(base, rest);
      let dirs: string[] = [];
      try {
        dirs = readdirSync(base, { withFileTypes: true })
          .filter((d) => d.isDirectory())
          .map((d) => d.name);
      } catch {
        /* unreadable directory — nothing beneath it to match */
      }
      for (const d of dirs) walk(join(base, d), segs);
      return;
    }
    if (head.includes('*') || head.includes('?')) {
      const re = segmentToRegExp(head);
      let names: string[] = [];
      try {
        names = readdirSync(base);
      } catch {
        return;
      }
      for (const n of names) if (re.test(n)) walk(join(base, n), rest);
      return;
    }
    walk(join(base, head), rest);
  };

  walk('/', abs.split('/').filter(Boolean));
  return out;
}

/** Union of every discovery source, deduped by expanded path. Never throws.
 *  Cron source health is returned separately so "file missing" ≠ "we could not look". */
export function discoverScripts(deps: ScanDeps = {}): {
  scripts: DiscoveredScript[];
  sources: CronSources;
} {
  const home = deps.home ?? homedir();
  const cwd = deps.cwd ?? process.cwd();
  const bySource = new Map<string, Set<string>>();
  const add = (path: string, source: string): void => {
    const sources = bySource.get(path) ?? new Set<string>();
    sources.add(source);
    bySource.set(path, sources);
  };

  const hermesPath = deps.hermesCronPath ?? join(home, '.hermes', 'cron', 'jobs.json');
  const hermes = inspectJsonFile(hermesPath);
  if (hermes.status === 'ok') {
    for (const p of hermesCandidates(hermes.doc, home)) add(p, 'hermes-cron');
  }

  // Legacy JSON store. Still read when present (mid-migration hosts run both),
  // and unioned with the SQLite store below. `.bak`/`.migrated` siblings left
  // behind by OpenClaw's migration are never read as live, and their existence
  // is never taken as proof that the live store is absent.
  const openclawPath = deps.openclawCronPath ?? join(home, '.openclaw', 'cron', 'jobs.json');
  const openclaw = inspectJsonFile(openclawPath);
  if (openclaw.status === 'ok') {
    for (const p of openclawCandidates(openclaw.doc, home)) add(p, 'openclaw-cron');
  }

  // Migrated SQLite store (#375). Probed directly — never gated on
  // `~/.openclaw` existing, so an EACCES on the path reports `unreadable`
  // rather than disappearing into "no OpenClaw here".
  const openclawDbPath = deps.openclawDbPath ?? defaultOpenClawCronDbPath(home);
  const db = discoverDbCronScripts({ dbPath: openclawDbPath, home });
  for (const s of db.scripts) add(s.path, OPENCLAW_CRON_DB_SOURCE);

  for (const pattern of deps.globs ?? []) {
    try {
      for (const p of expandGlob(pattern, cwd)) add(p, 'glob');
    } catch {
      /* a glob that cannot expand discovers nothing */
    }
  }

  return {
    scripts: [...bySource.entries()]
      .map(([path, sources]) => ({ path, sources: [...sources] }))
      .sort((a, b) => a.path.localeCompare(b.path)),
    sources: {
      hermes: { path: hermesPath, status: hermes.status },
      openclaw: { path: openclawPath, status: openclaw.status },
      openclawDb: { path: openclawDbPath, status: db.status },
      openclawCronUnverifiable:
        openclaw.status === 'absent' && db.status === 'absent' && openclawHostPresent(home),
    },
  };
}

export interface CronSources {
  hermes: CronSourceReport;
  openclaw: CronSourceReport;
  openclawDb: CronSourceReport;
  /**
   * #375 visibility rule. OpenClaw is installed here and NEITHER cron source
   * is readable — the JSON is gone and the SQLite store is not there either.
   * That is "we could not look", not "no crons": on the host this issue was
   * proven against, exactly this state hid 63 live jobs. Reported visibly and
   * exits 1. A host with no `~/.openclaw` at all stays empty-ok.
   */
  openclawCronUnverifiable: boolean;
}

/** Installed-ness, not cron-ness: the directory or its config file. Probed
 *  only to decide whether two absent cron sources are suspicious. */
function openclawHostPresent(home: string): boolean {
  for (const p of [join(home, '.openclaw'), join(home, '.openclaw', 'openclaw.json')]) {
    try {
      statSync(p);
      return true;
    } catch (e) {
      const err = e as NodeJS.ErrnoException;
      // Something is there that we cannot stat — treat OpenClaw as present so
      // the pair is reported rather than silently dismissed.
      if (err && err.code !== 'ENOENT') return true;
    }
  }
  return false;
}

function sourcesBroken(sources: CronSources): CronSourceReport[] {
  return [sources.hermes, sources.openclaw, sources.openclawDb].filter(
    (s) => s.status === 'unreadable' || s.status === 'invalid_json' || s.status === 'schema_mismatch',
  );
}

/** Every reason this scan could not see the whole picture. */
function discoveryIncomplete(sources: CronSources): boolean {
  return sourcesBroken(sources).length > 0 || sources.openclawCronUnverifiable;
}

// ── Classification ──────────────────────────────────────────

const PREVIEW_MAX_LINES = 40;
const PREVIEW_MAX_BYTES = 2_048;

/** Strip CSI/OSC and most C0 controls so a hostile script cannot spoof the
 *  review banner/path/hash on a TTY. Keep tab; turn CR into a visible marker. */
function sanitisePreviewLine(line: string): string {
  return line
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)?/g, '')
    .replace(/\u001b./g, '')
    .replace(/\r/g, '⏎')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
}

function makePreview(content: string): string {
  const lines = content.split('\n').map(sanitisePreviewLine);
  let preview = lines.slice(0, PREVIEW_MAX_LINES).join('\n');
  if (preview.length > PREVIEW_MAX_BYTES) preview = preview.slice(0, PREVIEW_MAX_BYTES);
  if (preview.length < content.length) preview += '\n…';
  return preview;
}

const STATUS_ORDER: Record<ScanStatus, number> = { new: 0, changed: 1, current: 2, missing: 3, too_large: 4 };

/** Diff discovered paths against the allowlist. Same drop rules as `add`:
 *  a path that does not resolve to a regular file cannot be pinned (reported
 *  as `missing`), and a >256KB file is never folded so there is nothing to
 *  exempt (reported as `too_large`). */
export function classifyScripts(discovered: DiscoveredScript[], rawEntries: unknown[]): ScanItem[] {
  const entries = normaliseReviewedScripts(rawEntries);
  const byPinnedPath = new Map(entries.map((e) => [e.path, e]));
  const byCanonical = new Map<string, ScanItem>();
  const missingSeen = new Map<string, ScanItem>();
  const out: ScanItem[] = [];

  for (const d of discovered) {
    let canonical: string;
    let size: number;
    try {
      canonical = realpathSync(d.path);
      const st = statSync(canonical);
      if (!st.isFile()) throw new Error('not a regular file');
      size = st.size;
    } catch {
      const seen = missingSeen.get(d.path);
      if (seen) {
        for (const s of d.sources) if (!seen.sources.includes(s)) seen.sources.push(s);
        continue;
      }
      const item: ScanItem = { path: d.path, status: 'missing', networkHint: false, sources: [...d.sources] };
      missingSeen.set(d.path, item);
      out.push(item);
      continue;
    }

    const seen = byCanonical.get(canonical);
    if (seen) {
      for (const s of d.sources) if (!seen.sources.includes(s)) seen.sources.push(s);
      continue;
    }

    let item: ScanItem;
    if (size > MAX_REVIEWABLE_BYTES) {
      item = { path: canonical, status: 'too_large', networkHint: false, sources: [...d.sources] };
    } else {
      let content: string;
      try {
        content = readFileSync(canonical, 'utf8');
      } catch {
        item = { path: d.path, status: 'missing', networkHint: false, sources: [...d.sources] };
        out.push(item);
        continue;
      }
      const sha256 = hashScriptSource(content);
      const pinned = byPinnedPath.get(canonical);
      const status: ScanStatus = !pinned ? 'new' : pinned.sha256 === sha256 ? 'current' : 'changed';
      item = {
        path: canonical,
        status,
        sha256,
        ...(pinned ? { pinnedSha256: pinned.sha256 } : {}),
        networkHint: NETWORK_SNIFF_RE.test(content),
        sources: [...d.sources],
        preview: makePreview(content),
      };
    }
    byCanonical.set(canonical, item);
    out.push(item);
  }

  return out.sort(scanItemOrder);
}

/** Denied first, then by status, then by path. */
function scanItemOrder(a: ScanItem, b: ScanItem): number {
  const denied = Number(Boolean(b.deniedNote)) - Number(Boolean(a.deniedNote));
  return denied || STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || a.path.localeCompare(b.path);
}

/**
 * Flag and re-sort the scripts of scheduled jobs that were guard-denied in
 * the correlation window (#375 P2), so the reviewer meets the scripts that are
 * demonstrably breaking crons before anything else.
 *
 * Denied paths come from the JOB's own discovered scripts, so this is a set
 * membership test — nothing here is derived from denial text. Correlation
 * yields pre-canonical paths and classification yields canonical ones, so both
 * are compared; a path that cannot be canonicalised simply does not match.
 */
export function markCronDenials(items: ScanItem[], report: CronDenialReport | null): ScanItem[] {
  if (!report || report.jobs.length === 0) return items;
  const byPath = deniedScriptPaths(report);
  if (byPath.size === 0) return items;

  const canonical = new Map<string, string>();
  for (const [path, jobName] of byPath) {
    canonical.set(path, jobName);
    try {
      canonical.set(realpathSync(path), jobName);
    } catch {
      /* a denied job naming a path that no longer resolves still matches by
         its literal path above */
    }
  }

  const days = Math.round(report.windowMs / 86_400_000);
  for (const item of items) {
    const jobName = canonical.get(item.path);
    if (jobName) item.deniedNote = `guard-denied in the last ${days} days (job: ${jobName})`;
  }
  return items.sort(scanItemOrder);
}

// ── Rendering ───────────────────────────────────────────────

function statusPaint(status: ScanStatus): string {
  if (status === 'new') return `${YELLOW}new${RESET}`;
  if (status === 'changed') return `${YELLOW}changed${RESET}`;
  if (status === 'current') return `${GREEN}current${RESET}`;
  if (status === 'missing') return `${RED}missing${RESET}`;
  return `${RED}too_large${RESET}`;
}

function renderSummary(items: ScanItem[], sources?: CronSources): string {
  const lines: string[] = [];
  if (sources) {
    for (const s of [sources.hermes, sources.openclaw, sources.openclawDb]) {
      if (s.status === 'absent') continue;
      if (s.status === 'ok') {
        lines.push(`${DIM}source ok: ${s.path}${RESET}`);
      } else if (s.status === 'invalid_json') {
        lines.push(`${RED}source INVALID JSON (did not scan): ${s.path}${RESET}`);
      } else if (s.status === 'schema_mismatch') {
        lines.push(`${RED}source SCHEMA MISMATCH (did not scan): ${s.path}${RESET}`);
      } else {
        lines.push(`${RED}source UNREADABLE (did not scan): ${s.path}${RESET}`);
      }
    }
    if (sources.openclawCronUnverifiable) {
      // Both absent while OpenClaw is installed. Absent sources are normally
      // silent; this pair is the one case where silence would be the bug.
      lines.push(
        `${RED}OpenClaw is installed but NO cron source is readable — discovery incomplete, not empty:${RESET}`,
      );
      lines.push(`${RED}  absent: ${sources.openclaw.path}${RESET}`);
      lines.push(`${RED}  absent: ${sources.openclawDb.path}${RESET}`);
    }
  }
  if (items.length === 0) {
    lines.push(
      `${DIM}Reviewed-script scan — no scripts discovered from readable Hermes/OpenClaw cron jobs ` +
        `(absolute or ~/ paths with script extensions only; relative names are not extracted).${RESET}`,
    );
    return lines.join('\n');
  }
  const count = (s: ScanStatus): number => items.filter((i) => i.status === s).length;
  lines.push(
    `${BOLD}Reviewed-script scan${RESET} — ${items.length} script(s) discovered: ` +
      `${count('current')} current · ${count('new')} new · ${count('changed')} changed · ` +
      `${count('missing')} missing · ${count('too_large')} too large`,
  );
  lines.push('');
  for (const i of items) {
    const notes: string[] = [i.sources.join(', ')];
    if (i.sha256) notes.push(`sha256 ${i.sha256.slice(0, 12)}…`);
    if (i.status === 'changed' && i.pinnedSha256) notes.push(`pinned ${i.pinnedSha256.slice(0, 12)}…`);
    if (i.status === 'missing') notes.push('path does not resolve — cannot pin');
    if (i.status === 'too_large') notes.push('>256KB — never folded, nothing to exempt');
    if (i.networkHint) notes.push(`${YELLOW}network?${RESET}`);
    if (i.deniedNote) notes.push(`${YELLOW}${i.deniedNote}${RESET}`);
    lines.push(`  ${statusPaint(i.status)}  ${BOLD}${i.path}${RESET}`);
    lines.push(`     ${DIM}${notes.join(' · ')}${RESET}`);
  }
  return lines.join('\n');
}

function renderReviewItem(item: ScanItem, index: number, total: number): string {
  const lines: string[] = [
    '',
    `${BOLD}── ${index}/${total} · ${item.status === 'changed' ? 'CHANGED' : 'NEW'} · ${item.path}${RESET}`,
  ];
  const meta: string[] = [`sha256 ${(item.sha256 ?? '').slice(0, 16)}…`];
  if (item.status === 'changed' && item.pinnedSha256) meta.push(`was ${item.pinnedSha256.slice(0, 16)}…`);
  meta.push(`sources: ${item.sources.join(', ')}`);
  if (item.networkHint) meta.push(`${YELLOW}network calls likely (advisory sniff)${RESET}`);
  lines.push(`   ${DIM}${meta.join(' · ')}${RESET}`);
  if (item.deniedNote) lines.push(`   ${YELLOW}${item.deniedNote}${RESET}`);
  if (item.preview) {
    lines.push(`   ${DIM}┄┄ first ${PREVIEW_MAX_LINES} lines ┄┄${RESET}`);
    for (const l of item.preview.split('\n')) lines.push(`   ${DIM}│${RESET} ${l}`);
    lines.push(`   ${DIM}┄┄${RESET}`);
  }
  return lines.join('\n');
}

// ── Interactive review ──────────────────────────────────────

async function ttyPrompt(question: string): Promise<string> {
  const { createInterface } = await import('node:readline/promises');
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await rl.question(question);
  } finally {
    rl.close();
  }
}

export interface ReviewResult {
  pinned: number;
  skipped: number;
  failed: number;
  quit: boolean;
}

/**
 * Per-item human review of every `new`/`changed` item. TTY-gated HERE, not
 * only in the CLI wrapper, so no caller (update hook included) can reach a
 * write without a human at the keyboard.
 */
export async function reviewScanItems(items: ScanItem[], deps: ScanDeps = {}): Promise<ReviewResult> {
  const log = deps.log ?? ((m: string) => console.log(m));
  const err = deps.error ?? ((m: string) => console.error(m));
  const result: ReviewResult = { pinned: 0, skipped: 0, failed: 0, quit: false };

  const reviewable = items.filter((i) => i.status === 'new' || i.status === 'changed');
  if (reviewable.length === 0) return result;

  const interactive = deps.interactive ?? isInteractive();
  if (!interactive) {
    err('shieldcortex allowlist scan review must be run by a human in an interactive terminal.');
    err('Refusing: stdin/stdout are not TTYs, so this could be the agent pinning its own payload as "reviewed".');
    return result;
  }

  const ask = deps.prompt ?? ttyPrompt;
  for (let i = 0; i < reviewable.length; i++) {
    const item = reviewable[i];
    log(renderReviewItem(item, i + 1, reviewable.length));
    const answer = (await ask(`  [y] pin / [n] skip / [q] quit > `)).trim().toLowerCase();
    if (answer === 'q' || answer === 'quit') {
      result.quit = true;
      log(`${DIM}Stopped — ${result.pinned} pinned this run stay pinned; the rest fold as usual.${RESET}`);
      break;
    }
    if (answer !== 'y' && answer !== 'yes') {
      result.skipped += 1;
      continue;
    }
    const note = (await ask('  note (optional, why is this trusted): ')).trim() || undefined;
    const pin = pinReviewedScript(item.path, note, {
      ...deps,
      ...(item.sha256 ? { expectedSha256: item.sha256 } : {}),
    });
    if (pin.ok) {
      result.pinned += 1;
      log(`  ${GREEN}✓${RESET} Pinned ${BOLD}${pin.entry.path}${RESET} — any edit re-gates it.`);
    } else {
      result.failed += 1;
      err(`  ✗ ${pin.error}`);
    }
  }
  return result;
}

// ── CLI entry ───────────────────────────────────────────────

/**
 * Denial correlation for the review ordering (#375 P2). Advisory: a
 * correlation that cannot run must never stop a scan from reporting what it
 * DID discover, so failures degrade to "no denied-first ordering" rather than
 * to an error. The honest cannot-look surface for correlation is `doctor`,
 * which reports it as a WARN rather than swallowing it.
 */
function correlateForScan(deps: ScanDeps): CronDenialReport | null {
  try {
    const home = deps.home ?? homedir();
    return correlateCronDenials({
      home,
      ...(deps.openclawDbPath ? { openclawDbPath: deps.openclawDbPath } : {}),
      ...(deps.denialsPath ? { denialsPath: deps.denialsPath } : {}),
      ...(typeof deps.now === 'number' ? { now: deps.now } : {}),
    });
  } catch {
    return null;
  }
}

const SCAN_USAGE =
  'Usage: shieldcortex allowlist scan [--json] [--yes] [--glob pat ...] [--hermes-cron p] [--openclaw-cron p] [--openclaw-cron-db p]';

/**
 * Exit codes: 0 nothing needs review (or review completed), 3 new/changed
 * found but not reviewable here (non-interactive — automation's "a human
 * should look" signal), 1 hard error.
 */
export async function runAllowlistScan(argv: string[], deps: ScanDeps = {}): Promise<number> {
  const log = deps.log ?? ((m: string) => console.log(m));
  const err = deps.error ?? ((m: string) => console.error(m));

  const globs = [...(deps.globs ?? [])];
  let json = false;
  let yes = false;
  let hermesCronPath = deps.hermesCronPath;
  let openclawCronPath = deps.openclawCronPath;
  let openclawDbPath = deps.openclawDbPath;

  const args = argv.filter((a) => a !== '--');
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') json = true;
    else if (a === '--yes') yes = true;
    else if (a === '--glob' || a === '--hermes-cron' || a === '--openclaw-cron' || a === '--openclaw-cron-db') {
      const value = args[i + 1];
      if (!value || value.startsWith('-')) {
        err(`${a} expects a value. ${SCAN_USAGE}`);
        return 1;
      }
      if (a === '--glob') globs.push(value);
      else if (a === '--hermes-cron') hermesCronPath = value;
      else if (a === '--openclaw-cron-db') openclawDbPath = value;
      else openclawCronPath = value;
      i += 1;
    } else {
      err(`Unknown option "${a}". ${SCAN_USAGE}`);
      return 1;
    }
  }

  const interactive = deps.interactive ?? isInteractive();
  if (yes && !interactive) {
    err('shieldcortex allowlist scan --yes must be run by a human in an interactive terminal.');
    err('Refusing: stdin/stdout are not TTYs, so this could be the agent batch-pinning its own payloads as "reviewed".');
    return 1;
  }

  const scanDeps: ScanDeps = { ...deps, hermesCronPath, openclawCronPath, openclawDbPath, globs };
  let items: ScanItem[];
  let sourceReport: CronSources;
  try {
    const readEntries = deps.readEntries ?? getReviewedScriptsRaw;
    const discovered = discoverScripts(scanDeps);
    sourceReport = discovered.sources;
    items = classifyScripts(discovered.scripts, readEntries());
    items = markCronDenials(items, correlateForScan(scanDeps));
  } catch (e) {
    err(`Scan failed: ${e instanceof Error ? e.message : String(e)}`);
    return 1;
  }

  const broken = sourcesBroken(sourceReport);
  const incomplete = discoveryIncomplete(sourceReport);
  const needsReview = items.filter((i) => i.status === 'new' || i.status === 'changed');

  if (json) {
    log(
      JSON.stringify(
        {
          sources: sourceReport,
          discoveryIncomplete: incomplete,
          counts: {
            current: items.filter((i) => i.status === 'current').length,
            new: items.filter((i) => i.status === 'new').length,
            changed: items.filter((i) => i.status === 'changed').length,
            missing: items.filter((i) => i.status === 'missing').length,
            too_large: items.filter((i) => i.status === 'too_large').length,
          },
          items: items.map((i) => ({
            path: i.path,
            status: i.status,
            sha256: i.sha256 ?? null,
            pinnedSha256: i.pinnedSha256 ?? null,
            networkHint: i.networkHint,
            sources: i.sources,
            cronDenied: i.deniedNote ?? null,
          })),
        },
        null,
        2,
      ),
    );
    if (incomplete) return 1;
    return needsReview.length > 0 ? 3 : 0;
  }

  log(renderSummary(items, sourceReport));
  if (incomplete) {
    if (broken.length > 0) {
      err(
        `Cron source(s) present but not readable/parseable — scan is incomplete. Fix: ${broken
          .map((s) => s.path)
          .join(', ')}`,
      );
    }
    if (sourceReport.openclawCronUnverifiable) {
      err(
        `OpenClaw is installed but neither cron source exists (${sourceReport.openclaw.path}, ` +
          `${sourceReport.openclawDb.path}) — scan could not look, so this is not "no crons".`,
      );
    }
    // Incomplete discovery must not look like "all clear".
    return 1;
  }
  if (needsReview.length === 0) return 0;

  if (!interactive) {
    log('');
    log(
      `${needsReview.length} new/changed need human review — run: ${BOLD}shieldcortex allowlist scan${RESET} in an interactive terminal.`,
    );
    return 3;
  }

  if (yes) {
    // First-backfill guard (#375). The SQLite migration hands `scan` a whole
    // wave of scripts no human has ever reviewed — on the host this was proven
    // against, 63 jobs at once. A batch pin there is one keystroke away from
    // blessing every payload the store happens to name, so the initial wave is
    // per-item only. Once those are pinned, `--yes` works as before.
    const unreviewedBackfill = needsReview.filter(
      (i) => i.status === 'new' && i.sources.some((s) => FIRST_BACKFILL_SOURCES.has(s)),
    );
    if (unreviewedBackfill.length > 0) {
      err(
        `Refusing --yes: ${unreviewedBackfill.length} script(s) come from the OpenClaw SQLite cron store ` +
          `(${OPENCLAW_CRON_DB_SOURCE}) and have never been reviewed.`,
      );
      err('The first sqlite backfill is per-item only — re-run `shieldcortex allowlist scan` without --yes.');
      return 1;
    }

    // Show the same previews the per-item loop would before batch approve.
    for (let i = 0; i < needsReview.length; i++) {
      log(renderReviewItem(needsReview[i], i + 1, needsReview.length));
    }
    const ask = deps.prompt ?? ttyPrompt;
    const answer = (
      await ask(
        `\nType ${BOLD}approve${RESET} to pin ALL ${needsReview.length} new/changed script(s) listed above at the hashes shown, anything else to cancel: `,
      )
    )
      .trim()
      .toLowerCase();
    if (answer !== 'approve') {
      log(`${DIM}Cancelled — nothing pinned. Re-run without --yes for per-item review.${RESET}`);
      return 0;
    }
    let failed = 0;
    for (const item of needsReview) {
      const pin = pinReviewedScript(item.path, undefined, {
        ...deps,
        ...(item.sha256 ? { expectedSha256: item.sha256 } : {}),
      });
      if (pin.ok) {
        log(`${GREEN}✓${RESET} Pinned ${BOLD}${pin.entry.path}${RESET}`);
      } else {
        err(`✗ ${pin.error}`);
        failed += 1;
      }
    }
    return failed > 0 ? 1 : 0;
  }

  const result = await reviewScanItems(items, scanDeps);
  return result.failed > 0 ? 1 : 0;
}

// ── `shieldcortex update` hook ──────────────────────────────

/**
 * Called near the end of `runUpdate`. Interactive terminals get the same
 * per-item review the CLI offers; headless runs get ONE dim pointer line and
 * no writes. Never throws — an update must not fail because a cron file was
 * strange.
 */
export async function maybeReviewAllowlistAfterUpdate(deps: ScanDeps = {}): Promise<void> {
  const log = deps.log ?? ((m: string) => console.log(m));
  try {
    const readEntries = deps.readEntries ?? getReviewedScriptsRaw;
    const discovered = discoverScripts(deps);
    const broken = sourcesBroken(discovered.sources);
    const incomplete = discoveryIncomplete(discovered.sources);
    const items = markCronDenials(
      classifyScripts(discovered.scripts, readEntries()),
      correlateForScan(deps),
    );
    const needsReview = items.filter((i) => i.status === 'new' || i.status === 'changed');

    if (incomplete) {
      const reasons = broken.map((s) => `${s.path}:${s.status}`);
      if (discovered.sources.openclawCronUnverifiable) {
        reasons.push(`${discovered.sources.openclawDb.path}:no readable OpenClaw cron source`);
      }
      log(
        `${DIM}reviewed-script scan: cron source incomplete (${reasons.join(', ')}) — ` +
          `run: shieldcortex allowlist scan${RESET}`,
      );
      // Still offer review for whatever we *did* find when interactive.
    }

    if (needsReview.length === 0 && !incomplete) return;

    const interactive = deps.interactive ?? isInteractive();
    if (!interactive) {
      if (needsReview.length > 0) {
        log(
          `${DIM}reviewed-script scan: ${needsReview.length} new/changed — run: shieldcortex allowlist scan${RESET}`,
        );
      }
      return;
    }
    if (needsReview.length === 0) return;
    log(renderSummary(items, discovered.sources));
    await reviewScanItems(items, deps);
  } catch (e) {
    log(`${DIM}reviewed-script scan skipped — ${e instanceof Error ? e.message : String(e)}${RESET}`);
  }
}
