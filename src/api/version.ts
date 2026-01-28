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

// Cache for npm registry check (5 minute TTL)
let versionCache: {
  latestVersion: string | null;
  checkedAt: number;
} | null = null;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

export interface VersionInfo {
  currentVersion: string;
  latestVersion: string | null;
  updateAvailable: boolean;
  checkedAt: string;
  cacheHit: boolean;
}

export interface UpdateResult {
  success: boolean;
  previousVersion: string;
  newVersion: string | null;
  error?: string;
  requiresRestart: boolean;
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
      latestVersion: versionCache.latestVersion,
      updateAvailable: versionCache.latestVersion
        ? isNewerVersion(versionCache.latestVersion, currentVersion)
        : false,
      checkedAt: new Date(versionCache.checkedAt).toISOString(),
      cacheHit: true,
    };
  }

  // Query npm registry
  try {
    const result = execSync('npm view claude-cortex version', {
      encoding: 'utf-8',
      timeout: 10000, // 10 second timeout
    }).trim();

    versionCache = {
      latestVersion: result,
      checkedAt: now,
    };

    return {
      currentVersion,
      latestVersion: result,
      updateAvailable: isNewerVersion(result, currentVersion),
      checkedAt: new Date(now).toISOString(),
      cacheHit: false,
    };
  } catch {
    // Network error or npm not available
    return {
      currentVersion,
      latestVersion: null,
      updateAvailable: false,
      checkedAt: new Date(now).toISOString(),
      cacheHit: false,
    };
  }
}

/**
 * Perform npm update (runs in background)
 */
export function performUpdate(): Promise<UpdateResult> {
  const previousVersion = getCurrentVersion();

  return new Promise(resolve => {
    exec(
      'npm update -g claude-cortex',
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
              'Permission denied. Try running with sudo: sudo npm update -g claude-cortex';
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

        resolve({
          success: true,
          previousVersion,
          newVersion,
          requiresRestart: newVersion !== previousVersion,
        });
      }
    );
  });
}

/**
 * Schedule server restart (with delay for client notification)
 */
export function scheduleRestart(delayMs = 3000): void {
  console.log(`[claude-cortex] Server restart scheduled in ${delayMs}ms`);

  setTimeout(() => {
    console.log('[claude-cortex] Restarting server...');
    process.exit(0); // Clean exit - systemd/pm2/nodemon will restart
  }, delayMs);
}
