/**
 * Stale-dashboard detection + auto-kick.
 *
 * The macOS LaunchAgent (`com.shieldcortex.dashboard`, KeepAlive) spawns the Next
 * dashboard child ONCE and keeps that same process alive for days. `npm i -g`
 * installs atomically into a temp dir then renames — the old install dir is
 * deleted, but launchd does NOT re-exec the running parent. So after an update
 * the live dashboard keeps serving the OLD build (old assets, old theme) from
 * memory until the service is restarted. This has masqueraded as "the release
 * didn't take" three times (see project_dashboard_zombie_after_update).
 *
 * The signal: the running dashboard process started BEFORE the freshly-installed
 * build was written to disk → it is running stale code → kick it so launchd
 * respawns from the live install. Everything here is fail-soft: a missing
 * launchctl, a headless box, a non-darwin platform, or any error must NEVER throw
 * (this runs inside `postinstall`, where a throw breaks `npm install`).
 *
 * NOTE: `MACOS_SERVICE_LABEL` is the canonical label in service/install.ts; it is
 * duplicated here (a single stable string) to keep this module dependency-free so
 * postinstall can dynamic-import it cheaply without pulling in the installer.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const MACOS_SERVICE_LABEL = 'com.shieldcortex.dashboard';
const DEFAULT_MARGIN_MS = 2000;

/** Injectable IO so the orchestration is unit-testable without touching the OS. */
export interface StaleProbeDeps {
  platform: NodeJS.Platform;
  /** `launchctl print <domain>/<label>` stdout, or null if not loaded / errored. */
  printService: () => string | null;
  /** Epoch ms the given pid started, or null if unknown. */
  processStartMs: (pid: number) => number | null;
  /** Epoch ms the current install's build was written, or null if unknown. */
  installMtimeMs: () => number | null;
  marginMs?: number;
}

export interface StaleResult {
  stale: boolean;
  pid: number | null;
  reason: string;
}

/** Parse `launchctl print` output → running state + pid. Pure. */
export function parseLaunchctlState(output: string): { running: boolean; pid: number | null } {
  const running = /state\s*=\s*running\b/.test(output);
  const pidMatch = output.match(/\bpid\s*=\s*(\d+)/);
  return { running, pid: pidMatch ? Number(pidMatch[1]) : null };
}

/**
 * Parse `ps -o etime=` elapsed-time output → seconds. Format is `[[dd-]hh:]mm:ss`.
 * macOS `ps` has NO `etimes` keyword (Linux does), so the portable path is to
 * parse the formatted `etime`. Pure; returns null on junk.
 */
export function parseEtimeToSeconds(raw: string): number | null {
  const s = raw.trim();
  if (!s) return null;
  let days = 0;
  let rest = s;
  const dash = s.indexOf('-');
  if (dash !== -1) {
    days = Number.parseInt(s.slice(0, dash), 10);
    rest = s.slice(dash + 1);
  }
  const parts = rest.split(':');
  if (parts.length < 2 || parts.length > 3) return null;
  const nums = parts.map((p) => Number.parseInt(p, 10));
  if (nums.some((n) => !Number.isFinite(n)) || !Number.isFinite(days)) return null;
  const [h, m, sec] = parts.length === 3 ? nums : [0, ...nums];
  return days * 86400 + h * 3600 + m * 60 + sec;
}

/** Pure rule: the process started before the build was written (beyond a skew margin). */
export function isProcessStale(processStartMs: number, installMtimeMs: number, marginMs = DEFAULT_MARGIN_MS): boolean {
  return processStartMs < installMtimeMs - marginMs;
}

/** Detect a stale dashboard service. Fail-soft: any gap → { stale: false }. */
export function detectStaleDashboard(deps: StaleProbeDeps): StaleResult {
  const skip = (reason: string, pid: number | null = null): StaleResult => ({ stale: false, pid, reason });

  // The zombie is a macOS launchd phenomenon; other platforms manage restarts
  // differently (systemd Restart=, Windows) and are out of scope here.
  if (deps.platform !== 'darwin') return skip('not-darwin');

  const out = deps.printService();
  if (!out) return skip('service-not-loaded');

  const { running, pid } = parseLaunchctlState(out);
  if (!running || pid == null) return skip('service-not-running');

  const startMs = deps.processStartMs(pid);
  if (startMs == null) return skip('process-start-unknown', pid);

  const installMs = deps.installMtimeMs();
  if (installMs == null) return skip('install-mtime-unknown', pid);

  if (isProcessStale(startMs, installMs, deps.marginMs ?? DEFAULT_MARGIN_MS)) {
    return { stale: true, pid, reason: 'process-predates-install' };
  }
  return skip('process-current', pid);
}

/** Detect-then-kick. Returns what happened; never throws. */
export function maybeKickStaleDashboard(
  deps: StaleProbeDeps & { kick: () => boolean },
): { kicked: boolean; pid: number | null; reason: string } {
  const result = detectStaleDashboard(deps);
  if (!result.stale) return { kicked: false, pid: result.pid, reason: result.reason };
  const ok = deps.kick();
  return { kicked: ok, pid: result.pid, reason: ok ? 'kicked' : 'kick-failed' };
}

/** Real OS-backed deps (macOS launchctl/ps + this install's dist mtime). */
export function realDeps(): StaleProbeDeps & { kick: () => boolean } {
  const uid = process.getuid?.();
  const domain = typeof uid === 'number' ? `gui/${uid}` : 'gui/501';
  const target = `${domain}/${MACOS_SERVICE_LABEL}`;

  return {
    platform: process.platform,
    printService: () => {
      try {
        // execFileSync (no shell) — args are passed directly, so even though
        // `target` is built from numeric uid it can never be shell-interpreted.
        return execFileSync('launchctl', ['print', target], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      } catch {
        return null;
      }
    },
    processStartMs: (pid) => {
      try {
        // `etime` (formatted [[dd-]hh:]mm:ss) — macOS `ps` has no `etimes` keyword,
        // and `etime` is locale-independent (no month names, unlike `lstart`).
        const raw = execFileSync('ps', ['-o', 'etime=', '-p', String(pid)], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
        });
        const secs = parseEtimeToSeconds(raw);
        return secs == null ? null : Date.now() - secs * 1000;
      } catch {
        return null;
      }
    },
    installMtimeMs: () => {
      try {
        // This file compiles to dist/service/dashboard-staleness.js; dist/index.js
        // is the install's entrypoint — its mtime is when this build was written.
        const indexJs = join(dirname(fileURLToPath(import.meta.url)), '..', 'index.js');
        return existsSync(indexJs) ? statSync(indexJs).mtimeMs : null;
      } catch {
        return null;
      }
    },
    kick: () => {
      try {
        execFileSync('launchctl', ['kickstart', '-k', target], { stdio: 'ignore' });
        return true;
      } catch {
        return false;
      }
    },
  };
}

/**
 * Convenience for `postinstall`: detect + kick using real deps, fully wrapped so
 * it can never throw into the install. Returns a safe summary.
 */
export function autoKickStaleDashboardFromInstall(): { kicked: boolean; pid: number | null; reason: string } {
  try {
    return maybeKickStaleDashboard(realDeps());
  } catch {
    return { kicked: false, pid: null, reason: 'error' };
  }
}
