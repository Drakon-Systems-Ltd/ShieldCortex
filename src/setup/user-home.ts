/**
 * ShieldCortex — WHOSE home a host-integration command writes under.
 *
 * Lifted out of `setup/openclaw.ts` (#574/#576 r2 blocker 3), because it was
 * never OpenClaw-specific. `os.homedir()` answers "the home of the process",
 * which under `sudo` is `/root` — and every file-copied integration
 * (`~/.openclaw/hooks/cortex-memory`, `~/.hermes/plugins/shieldcortex`) belongs
 * to the operator who typed the command, not to the uid it is running as.
 * `update` was passing `os.homedir()` straight through, so a sudo upgrade
 * refreshed nothing and reported success.
 *
 * The OPENCLAW_HOME override stays in `openclaw.ts`: that variable is
 * OpenClaw's own, and applying it to Hermes would point a Hermes refresh at a
 * tree OpenClaw named.
 */

import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

/**
 * A conservative POSIX-portable username. SUDO_USER is environment-controlled
 * and, in some sudo setups, attacker-influenceable — anything outside this
 * shape is ignored entirely rather than looked up (#429). Also excludes
 * leading dashes (argv option injection) and slashes/dots that could turn the
 * direct home-directory probes below into path traversal.
 */
export const SAFE_USERNAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;

/**
 * The home of the operator who invoked this command.
 *
 * `SUDO_USER` first, resolved with an argv-array `getent passwd` and never a
 * shell string (#429), falling back to the standard home locations probed
 * directly. Then, for `sudo su -` sessions that keep no `SUDO_USER`, the one
 * `/home/*` that carries one of `markers` — the config directories that say
 * "this is the human who uses this box".
 *
 * `markers` is the caller's, because the evidence differs per integration:
 * an OpenClaw command looks for `.openclaw`/`.claude`, a Hermes one for
 * `.hermes`. Nothing here creates anything.
 */
export function invokingUserHome(markers: readonly string[]): string {
  const sudoUser = process.env.SUDO_USER;
  if (sudoUser && SAFE_USERNAME.test(sudoUser)) {
    // Try getent passwd (reliable on Linux) — argv-array, no shell.
    try {
      const entry = execFileSync('getent', ['passwd', sudoUser], {
        encoding: 'utf-8',
        timeout: 5000,
      }).trim();
      const homeDir = entry.split(':')[5];
      if (homeDir && fs.existsSync(homeDir)) {
        return homeDir;
      }
    } catch {
      // getent not available (macOS) — probe the standard locations
    }

    // Fallback: the standard home locations, probed directly. Replaces a
    // `eval echo ~${sudoUser}` shell eval (#429) — same answer on any box
    // where that expansion would have worked, with no shell involved.
    for (const homeDir of [`/Users/${sudoUser}`, `/home/${sudoUser}`]) {
      if (fs.existsSync(homeDir)) {
        return homeDir;
      }
    }
  }

  const home = os.homedir();

  // If we're root without SUDO_USER (e.g. after `sudo su -`),
  // search /home/* for a user who has one of the marker dirs configured.
  if (home === '/root' || (process.getuid && process.getuid() === 0)) {
    try {
      const users = fs.readdirSync('/home');
      for (const username of users) {
        const userHome = path.join('/home', username);
        try {
          if (!fs.statSync(userHome).isDirectory()) continue;
        } catch { continue; }
        if (markers.some((marker) => fs.existsSync(path.join(userHome, marker)))) {
          return userHome;
        }
      }
    } catch {
      // /home not readable
    }
  }

  return home;
}

/** The markers each integration recognises as "a human lives here". */
export const OPENCLAW_HOME_MARKERS = ['.openclaw', '.claude'] as const;
export const HERMES_HOME_MARKERS = ['.hermes'] as const;

/**
 * The home a HERMES command writes under (#576 r2 blocker 3).
 *
 * Hermes' own root resolution (`HERMES_HOME`, profiles, the platform default)
 * happens in the probe, which is given this value as `HOME`. So this answers
 * only the question the probe cannot: which operator's environment is being
 * refreshed. `HERMES_HOME` is deliberately NOT read here — it travels
 * unexpanded to Hermes, which is the whole point of `hermesEnvironment`.
 */
export function hermesUserHome(): string {
  return invokingUserHome(HERMES_HOME_MARKERS);
}
