/**
 * Control State Module
 *
 * Manages global control state for the Claude Cortex system.
 * Currently handles pause/resume functionality for memory creation.
 */

// Server start time for uptime calculation
const startTime = Date.now();

// Global pause state
let paused = false;

/**
 * Check if memory creation is paused
 */
export function isPaused(): boolean {
  return paused;
}

/**
 * Pause memory creation
 */
export function pause(): void {
  paused = true;
  console.log('[claude-cortex] Memory creation PAUSED');
}

/**
 * Resume memory creation
 */
export function resume(): void {
  paused = false;
  console.log('[claude-cortex] Memory creation RESUMED');
}

/**
 * Get control status
 */
export function getControlStatus(): {
  paused: boolean;
  uptime: number;
  uptimeFormatted: string;
} {
  const uptime = Date.now() - startTime;

  // Format uptime as human-readable
  const seconds = Math.floor(uptime / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  let uptimeFormatted: string;
  if (days > 0) {
    uptimeFormatted = `${days}d ${hours % 24}h ${minutes % 60}m`;
  } else if (hours > 0) {
    uptimeFormatted = `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  } else if (minutes > 0) {
    uptimeFormatted = `${minutes}m ${seconds % 60}s`;
  } else {
    uptimeFormatted = `${seconds}s`;
  }

  return {
    paused,
    uptime,
    uptimeFormatted,
  };
}
