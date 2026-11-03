/**
 * Chained-ledger settings (#617) from `~/.shieldcortex/config.json`:
 *
 *   "ledger": {
 *     "heartbeatMinutes": 60,   // heartbeat interval; >= 1, default hourly
 *     "keepSkeleton": true      // keep (seq, content_digest) of pruned rows
 *   }
 *
 * Turning `keepSkeleton` off is an explicit setting, and every checkpoint
 * written while it is off records `skeleton_kept: false`, so the verifier
 * reports those ranges as not re-checkable.
 */

import { readRawConfig } from '../../cloud/config.js';

export const DEFAULT_HEARTBEAT_MINUTES = 60;

export interface LedgerConfig {
  heartbeatIntervalMs: number;
  keepSkeleton: boolean;
}

/**
 * `readOnly` (#878): read config.json without changing it — no signature
 * adoption, no integrity-key mint, no self-heal rewrite, no lock audit. Doctor
 * passes it; the ledger writer keeps the ordinary read.
 */
export function resolveLedgerConfig(options: { readOnly?: boolean } = {}): LedgerConfig {
  let block: Record<string, unknown> = {};
  try {
    const raw = readRawConfig({ readOnly: options.readOnly === true }).ledger;
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) block = raw as Record<string, unknown>;
  } catch {
    // Unreadable config must never stop the ledger: fall back to defaults.
  }
  const minutes = typeof block.heartbeatMinutes === 'number' && Number.isFinite(block.heartbeatMinutes) && block.heartbeatMinutes >= 1
    ? block.heartbeatMinutes
    : DEFAULT_HEARTBEAT_MINUTES;
  return {
    heartbeatIntervalMs: Math.round(minutes * 60_000),
    keepSkeleton: block.keepSkeleton !== false,
  };
}
