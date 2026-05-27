/**
 * Dashboard discovery hint.
 *
 * The dashboard never auto-launches. On non-headless systems where it is not
 * already running, this helper returns a structured hint so callers can format
 * it consistently. Returns null when the hint is not applicable (headless
 * host, dashboard already up).
 *
 * Used by:
 *   - scripts/postinstall.mjs   — surface after the install banner
 *   - src/cli/update.ts         — surface after a successful update
 *   - src/cli/doctor.ts         — enrich the dashboard fix line
 */
import http from 'node:http';

export const DASHBOARD_URL = 'http://localhost:3030';
export const DASHBOARD_PORT = 3030;
export const DASHBOARD_COMMAND = 'shieldcortex dashboard';

/**
 * A "headless" system is one where launching a browser to view the dashboard
 * would not work without forwarding. macOS and Windows are treated as headed
 * by default; on Linux, the absence of DISPLAY/WAYLAND_DISPLAY is the signal
 * (matches the existing doctor.ts heuristic).
 */
export function isHeadlessSystem() {
  if (process.platform === 'darwin' || process.platform === 'win32') return false;
  return !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY;
}

/**
 * Probe the local dashboard port. Returns true for any non-5xx response —
 * the goal is detecting *something* listening, not validating the response.
 * Times out fast so it never delays a postinstall or update flow.
 */
export function isDashboardRunning(timeoutMs = 800) {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (v) => { if (!settled) { settled = true; resolve(v); } };

    const req = http.get(
      { host: '127.0.0.1', port: DASHBOARD_PORT, path: '/', timeout: timeoutMs },
      (res) => {
        const ok = typeof res.statusCode === 'number' && res.statusCode < 500;
        res.resume();
        settle(ok);
      },
    );
    req.on('error', () => settle(false));
    req.on('timeout', () => { try { req.destroy(); } catch { /* ignore */ } settle(false); });
  });
}

/**
 * Returns the hint payload, or null when the dashboard should not be advertised
 * in this environment. Never throws.
 */
export async function getDashboardHint() {
  try {
    if (isHeadlessSystem()) return null;
    if (await isDashboardRunning()) return null;
    return {
      title: 'Open the ShieldCortex dashboard',
      command: DASHBOARD_COMMAND,
      url: DASHBOARD_URL,
      detail: 'Inspect memories, review quarantine, and watch real-time scans.',
    };
  } catch {
    return null;
  }
}
