/**
 * Version Management Module
 *
 * Handles version checking, updates, and server restart functionality.
 */

import { execSync, exec } from 'child_process';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

// Get package.json path relative to this module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const packageJsonPath = path.resolve(__dirname, '../../package.json');

/**
 * Version captured at module load time.
 * This never changes during the process lifetime, so it accurately
 * reflects the code that is actually running — even after an external
 * npm update replaces the files on disk.
 */
const STARTUP_VERSION: string = (() => {
  try {
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
    return packageJson.version;
  } catch {
    return 'unknown';
  }
})();

// Cache for npm registry check (5 minute TTL)
let versionCache: {
  latestVersion: string | null;
  checkedAt: number;
} | null = null;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

export interface VersionInfo {
  currentVersion: string;
  runningVersion: string;
  latestVersion: string | null;
  updateAvailable: boolean;
  stale: boolean;
  checkedAt: string;
  cacheHit: boolean;
}

export interface UpdateResult {
  success: boolean;
  previousVersion: string;
  newVersion: string | null;
  error?: string;
  requiresRestart: boolean;
  mcpRestarted?: number;
}

/**
 * Get current installed version from package.json
 */
export function getCurrentVersion(): string {
  try {
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
    return packageJson.version;
  } catch {
    return 'unknown';
  }
}

/**
 * Get the version that was running when this process started.
 * Unlike getCurrentVersion(), this does NOT re-read from disk,
 * so it remains accurate even after an external upgrade.
 */
export function getRunningVersion(): string {
  return STARTUP_VERSION;
}

/**
 * Compare semver versions
 * Returns true if latest is newer than current
 */
function isNewerVersion(latest: string, current: string): boolean {
  const latestParts = latest.split('.').map(Number);
  const currentParts = current.split('.').map(Number);

  for (let i = 0; i < 3; i++) {
    if ((latestParts[i] || 0) > (currentParts[i] || 0)) return true;
    if ((latestParts[i] || 0) < (currentParts[i] || 0)) return false;
  }
  return false;
}

/**
 * Check npm registry for latest version (with caching)
 */
export async function checkForUpdates(forceRefresh = false): Promise<VersionInfo> {
  const currentVersion = getCurrentVersion();
  const now = Date.now();

  // Return cached result if still valid
  if (!forceRefresh && versionCache && now - versionCache.checkedAt < CACHE_TTL) {
    return {
      currentVersion,
      runningVersion: STARTUP_VERSION,
      latestVersion: versionCache.latestVersion,
      updateAvailable: versionCache.latestVersion
        ? isNewerVersion(versionCache.latestVersion, currentVersion)
        : false,
      stale: STARTUP_VERSION !== currentVersion,
      checkedAt: new Date(versionCache.checkedAt).toISOString(),
      cacheHit: true,
    };
  }

  // Query npm registry
  try {
    const result = execSync('npm view shieldcortex version', {
      encoding: 'utf-8',
      timeout: 10000, // 10 second timeout
    }).trim();

    versionCache = {
      latestVersion: result,
      checkedAt: now,
    };

    return {
      currentVersion,
      runningVersion: STARTUP_VERSION,
      latestVersion: result,
      updateAvailable: isNewerVersion(result, currentVersion),
      stale: STARTUP_VERSION !== currentVersion,
      checkedAt: new Date(now).toISOString(),
      cacheHit: false,
    };
  } catch {
    // Network error or npm not available
    return {
      currentVersion,
      runningVersion: STARTUP_VERSION,
      latestVersion: null,
      updateAvailable: false,
      stale: STARTUP_VERSION !== currentVersion,
      checkedAt: new Date(now).toISOString(),
      cacheHit: false,
    };
  }
}

/**
 * Perform npm update (runs in background)
 */
export function performUpdate(): Promise<UpdateResult> {
  const previousVersion = STARTUP_VERSION;

  return new Promise(resolve => {
    exec(
      'npm update -g shieldcortex',
      {
        timeout: 120000, // 2 minute timeout
      },
      (error, _stdout, stderr) => {
        if (error) {
          // Check for common permission errors
          const errorMessage = stderr || error.message;
          let userFriendlyError = errorMessage;

          if (errorMessage.includes('EACCES') || errorMessage.includes('permission denied')) {
            userFriendlyError =
              'Permission denied. Try running with sudo: sudo npm update -g shieldcortex';
          } else if (errorMessage.includes('ENOENT')) {
            userFriendlyError = 'npm not found. Make sure Node.js is installed.';
          } else if (errorMessage.includes('ETIMEDOUT') || errorMessage.includes('network')) {
            userFriendlyError = 'Network error. Check your internet connection.';
          }

          resolve({
            success: false,
            previousVersion,
            newVersion: null,
            error: userFriendlyError,
            requiresRestart: false,
          });
          return;
        }

        // Clear version cache to force refresh
        versionCache = null;

        // Get new version
        const newVersion = getCurrentVersion();

        // Kill MCP servers so Claude Code restarts them with updated code
        let mcpRestarted = 0;
        if (newVersion !== previousVersion) {
          mcpRestarted = restartMcpServers();
        }

        resolve({
          success: true,
          previousVersion,
          newVersion,
          requiresRestart: newVersion !== STARTUP_VERSION,
          mcpRestarted,
        });
      }
    );
  });
}

/**
 * Kill running MCP server processes so Claude Code respawns them with updated code.
 * Finds shieldcortex node processes (excluding the current visualization server).
 * Returns the number of processes signalled.
 */
export function restartMcpServers(): number {
  let killed = 0;
  try {
    const output = execSync(
      'pgrep -f "shieldcortex" 2>/dev/null || true',
      { encoding: 'utf-8', timeout: 5000 },
    ).trim();

    if (!output) return 0;

    const currentPid = process.pid;
    for (const line of output.split('\n')) {
      const pid = parseInt(line.trim(), 10);
      if (!pid || pid === currentPid) continue;

      try {
        process.kill(pid, 'SIGTERM');
        killed++;
        console.log(`[shieldcortex] Sent SIGTERM to MCP server (pid ${pid})`);
      } catch {
        // Process may have already exited
      }
    }
  } catch {
    // pgrep not available or failed — non-critical
  }
  return killed;
}

/**
 * Schedule server restart (with delay for client notification)
 */
export function scheduleRestart(delayMs = 3000): void {
  console.log(`[shieldcortex] Server restart scheduled in ${delayMs}ms`);

  setTimeout(() => {
    console.log('[shieldcortex] Restarting server...');
    process.exit(0); // Clean exit - systemd/pm2/nodemon will restart
  }, delayMs);
}
