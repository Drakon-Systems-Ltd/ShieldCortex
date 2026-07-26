import fs from 'fs';
import path from 'path';

/**
 * Reading the LIVE gateway plugin roster.
 *
 * Field incident #103 (veronica, 2026-07-19 → 26): `shieldcortex repair`
 * reported `✓ realtime plugin healthy: enabled, loaded in roster, versions
 * agree` on a host whose gateway had booted WITHOUT the plugin six days
 * earlier. The plugin was installed and enabled, so it was present in the
 * SQLite `installed_plugin_index.plugins_json` — and that is what the
 * reconciler was reading and calling "the loaded roster".
 *
 * It is not. `plugins_json` records what OpenClaw has INSTALLED and enabled;
 * it says nothing about what the running gateway process actually loaded. The
 * only ground truth for that is the gateway's own boot line:
 *
 *   [gateway] http server listening (14 plugins: acpx, anthropic, …; 4.0s)
 *
 * A plugin can be installed, enabled, allow-listed and index-present, and
 * still be absent from that line — which is precisely the fail-open the roster
 * proof exists to catch, and precisely what it missed.
 *
 * This module reads that line. When it cannot (log rotated, wiped from /tmp,
 * gateway logging elsewhere) it returns null, and callers MUST degrade to
 * "could not prove" rather than inheriting the index's optimism.
 */

/** A parsed `http server listening` boot roster line. */
export interface BootRoster {
  /** Plugin ids named on the line, in order. */
  plugins: string[];
  /** The count the gateway itself declared, for cross-checking. */
  declaredCount: number;
  /** Epoch ms parsed from the line's ISO timestamp, when present. */
  atMs: number | null;
  /** File the line came from, for operator-facing evidence. */
  source?: string;
}

/**
 * The gateway prints one line per boot. Two shapes are in the wild:
 *   "http server listening (14 plugins: a, b, c; 4.0s)"
 *   "http server listening (0 plugins; 1.2s)"
 * The trailing duration is optional, and the id list is absent when the count
 * is zero.
 */
const ROSTER_RE = /http server listening \((\d+) plugins?(?::\s*([^;)]+))?[;)]/;

/** ISO-8601 timestamp at the head of a gateway log line or JSON `time` field. */
const ISO_RE = /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))/;

function parseTimestamp(line: string): number | null {
  const m = ISO_RE.exec(line);
  if (!m) return null;
  const ms = Date.parse(m[1]);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Parse a single log line into a boot roster. PURE. Returns null when the line
 * is not a roster line.
 *
 * Accepts both the plain console format and the JSON-per-line file format,
 * since the gateway writes the same message through both.
 */
export function parseBootRosterLine(line: string): BootRoster | null {
  const m = ROSTER_RE.exec(line);
  if (!m) return null;
  const declaredCount = Number.parseInt(m[1], 10);
  const list = (m[2] ?? '').trim();
  const plugins = list
    ? list
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : [];
  return { plugins, declaredCount, atMs: parseTimestamp(line) };
}

/**
 * Scan text for the LAST roster line it contains. PURE.
 *
 * Last, not first: a log file spans many boots and only the most recent one
 * describes the process that is running now.
 */
export function parseLatestBootRoster(text: string): BootRoster | null {
  let latest: BootRoster | null = null;
  for (const line of text.split('\n')) {
    const parsed = parseBootRosterLine(line);
    if (parsed) latest = parsed;
  }
  return latest;
}

/** Does the roster name this plugin? */
export function rosterContains(roster: BootRoster, pluginId: string): boolean {
  return roster.plugins.includes(pluginId);
}

export interface ReadBootRosterOptions {
  /**
   * Directory the gateway writes its log files to. OpenClaw uses
   * `/tmp/openclaw` by default and announces it at boot ("log file: …").
   */
  logDir?: string;
  /**
   * Epoch ms the current gateway process started. When supplied, a roster line
   * older than this is from a PREVIOUS process and is rejected — a stale line
   * must never be read as proof about the process running now.
   */
  processStartedAtMs?: number;
  /** Injected for tests. */
  readDir?: (dir: string) => string[];
  readFile?: (file: string) => string;
  statMtimeMs?: (file: string) => number;
}

const DEFAULT_LOG_DIR = '/tmp/openclaw';

/**
 * Read the newest boot roster the gateway has written.
 *
 * Returns null — meaning "cannot prove" — when the log dir is missing, holds
 * no roster line, or the only line found predates the running process. Callers
 * must treat null as absence of evidence, NEVER as evidence of health.
 */
export function readLatestBootRoster(options: ReadBootRosterOptions = {}): BootRoster | null {
  const logDir = options.logDir ?? DEFAULT_LOG_DIR;
  const readDir = options.readDir ?? ((d: string) => fs.readdirSync(d));
  const readFile = options.readFile ?? ((f: string) => fs.readFileSync(f, 'utf-8'));
  const statMtimeMs = options.statMtimeMs ?? ((f: string) => fs.statSync(f).mtimeMs);

  let names: string[];
  try {
    names = readDir(logDir);
  } catch {
    return null;
  }

  const logs = names
    .filter((n) => n.startsWith('openclaw-') && n.endsWith('.log'))
    .map((n) => path.join(logDir, n));
  if (logs.length === 0) return null;

  // Newest file first: the current boot is in the most recently written log.
  const ordered = logs
    .map((file) => {
      let mtimeMs = 0;
      try {
        mtimeMs = statMtimeMs(file);
      } catch {
        mtimeMs = 0;
      }
      return { file, mtimeMs };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);

  for (const { file } of ordered) {
    let text: string;
    try {
      text = readFile(file);
    } catch {
      continue;
    }
    const roster = parseLatestBootRoster(text);
    if (!roster) continue;
    // A line from a previous process proves nothing about this one.
    if (
      options.processStartedAtMs != null &&
      roster.atMs != null &&
      roster.atMs < options.processStartedAtMs
    ) {
      return null;
    }
    return { ...roster, source: file };
  }
  return null;
}
