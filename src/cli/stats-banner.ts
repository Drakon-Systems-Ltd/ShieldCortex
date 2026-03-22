/**
 * Stats banner — compact one-liner showing what ShieldCortex has protected
 */

import type { LifetimeStats } from '../defence/audit/queries.js';

const fmt = new Intl.NumberFormat('en-US');

function n(num: number): string {
  return fmt.format(num);
}

const GREEN  = '\x1b[32m';
const DIM    = '\x1b[2m';
const BOLD   = '\x1b[1m';
const RESET  = '\x1b[0m';

export function formatStatsBanner(stats: LifetimeStats): string | null {
  // Nothing to show on a fresh install
  if (stats.totalScans === 0) return null;

  const parts: string[] = [];

  if (stats.threatsBlocked > 0 || stats.quarantined > 0) {
    const blocked = stats.threatsBlocked + stats.quarantined;
    parts.push(`${GREEN}${BOLD}${n(blocked)}${RESET}${DIM} threats blocked${RESET}`);
  }

  if (stats.credentialLeaks > 0) {
    parts.push(`${GREEN}${BOLD}${n(stats.credentialLeaks)}${RESET}${DIM} credential leak${stats.credentialLeaks !== 1 ? 's' : ''} caught${RESET}`);
  }

  if (stats.memoriesProtected > 0) {
    parts.push(`${GREEN}${BOLD}${n(stats.memoriesProtected)}${RESET}${DIM} memories scanned${RESET}`);
  }

  if (parts.length === 0) {
    // Scans happened but nothing notable — show scan count
    parts.push(`${GREEN}${BOLD}${n(stats.totalScans)}${RESET}${DIM} scans completed${RESET}`);
  }

  return `🛡️  ShieldCortex: ${parts.join(`${DIM} · ${RESET}`)}`;
}

export async function printStatsBanner(): Promise<void> {
  try {
    const { isDatabaseInitialized } = await import('../database/init.js');
    if (!isDatabaseInitialized()) return;

    const { getLifetimeStats } = await import('../defence/audit/queries.js');
    const stats = getLifetimeStats();

    const banner = formatStatsBanner(stats);
    if (banner) {
      console.error(banner); // stderr so MCP stdout stays clean
    }
  } catch {
    // Never crash startup
  }
}
