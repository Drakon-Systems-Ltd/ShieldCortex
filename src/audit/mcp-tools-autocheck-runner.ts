/**
 * Detached entry point for the automatic MCP tool-description check (#915).
 * Spawned (unref'd, stdio ignored) by scripts/session-start-hook.mjs so session
 * start never waits on it. Exits 0 on every path.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { discoverMcpServers } from './mcp-config-scanner.js';
import {
  runAutoToolCheck,
  type AutoCheckState,
  type AutoCheckLedgerRow,
} from './mcp-tools-autocheck.js';

export function autoCheckEnabled(config: Record<string, unknown>): boolean {
  const ss = config.sessionStart;
  if (ss && typeof ss === 'object' && (ss as Record<string, unknown>).mcpToolCheck === false) return false;
  return true;
}

/**
 * Build the runner's `notify`. `deliverOperatorNotification` does not throw when
 * every channel fails (it returns `deliveredVia: null`), and with no channels
 * configured there is nothing to deliver to. Both mean the alert was NOT
 * delivered, so throw: runAutoToolCheck then leaves hashes uncommitted, does not
 * count the alert as notified, and writes an error ledger row (re-sent next run).
 */
export function makeAutoCheckNotify<N>(
  channels: unknown[],
  deliver: (n: N, deps: { channels: any[] }) => Promise<{ deliveredVia: string | null }>,
): (n: N) => Promise<void> {
  return async (n) => {
    if (channels.length === 0) throw new Error('no operator notification channel configured');
    const res = await deliver(n, { channels });
    if (!res || res.deliveredVia == null) throw new Error('operator notification not delivered via any channel');
  };
}

/**
 * Global/user configs only: a project-local config is repo-controlled and must
 * never be spawned automatically on session start (#925).
 */
export function discoverAutoCheckServers() {
  return discoverMcpServers({ includeProject: false });
}

/**
 * Open the memories DB with the default/ambient resolution. Passing an explicit
 * path would count as "operator chose this DB" and skip the unsafe-runtime guard
 * in database/init.ts (npx cache / project checkout); with no argument the guard
 * applies and initDatabase throws, which main() swallows (fail open).
 */
export function openAutoCheckDb<T>(init: (dbPath?: string) => T): T {
  return init();
}

export async function main(): Promise<void> {
  const home = os.homedir();
  const dataDir = path.join(home, '.shieldcortex');
  let config: Record<string, unknown> = {};
  try { config = JSON.parse(fs.readFileSync(path.join(dataDir, 'config.json'), 'utf-8')); } catch { /* defaults */ }
  if (!autoCheckEnabled(config)) return;

  const servers = discoverAutoCheckServers();
  if (servers.length === 0) return;

  const { initDatabase } = await import('../database/init.js');
  const db = openAutoCheckDb(initDatabase);
  const { SqliteToolHashStore, migrateLegacyToolHashes } = await import('./mcp-tool-hash-store.js');
  // Seed pre-scoping baselines into every source (project included) that defines the name (#925).
  migrateLegacyToolHashes(db as never, discoverMcpServers({ includeShadowed: true }));
  const store = new SqliteToolHashStore(db);
  const { logAudit } = await import('../defence/audit/logger.js');
  const { deliverOperatorNotification } = await import('../defence/iron-dome/operator-notify.js');
  const { configuredChannels } = await import('../cli/maintain.js');
  const channels = await configuredChannels();

  const statePath = path.join(dataDir, 'state', 'mcp-tool-check.json');
  const ss = (config.sessionStart ?? {}) as Record<string, unknown>;
  const intervalHours = typeof ss.mcpToolCheckIntervalHours === 'number' && ss.mcpToolCheckIntervalHours > 0 ? ss.mcpToolCheckIntervalHours : undefined;

  await runAutoToolCheck({
    servers,
    store,
    intervalHours,
    notify: makeAutoCheckNotify(channels, deliverOperatorNotification),
    ledger: (row: AutoCheckLedgerRow) => {
      logAudit({
        memory_id: null,
        project: null,
        timestamp: new Date().toISOString(),
        source_type: 'mcp-tools',
        source_identifier: row.server,
        trust_score: row.kind === 'suspicious' ? 0.1 : row.kind === 'changed' ? 0.5 : 1,
        sensitivity_level: 'internal',
        firewall_result: row.kind === 'suspicious' ? 'QUARANTINE' : 'ALLOW',
        operation: 'review',
        anomaly_score: row.kind === 'suspicious' ? 0.9 : row.kind === 'changed' ? 0.5 : 0,
        threat_indicators: JSON.stringify(row.kind === 'error' ? [] : [`mcp_tool_${row.kind}`]),
        blocked_patterns: '[]',
        reason: `mcp tool check (${row.kind}): ${row.detail}`.slice(0, 500),
        fragmentation_score: null,
        pipeline_duration_ms: null,
      });
    },
    loadState: (): AutoCheckState => JSON.parse(fs.readFileSync(statePath, 'utf-8')),
    saveState: (s) => {
      fs.mkdirSync(path.dirname(statePath), { recursive: true, mode: 0o700 });
      fs.writeFileSync(statePath, JSON.stringify(s), { mode: 0o600 });
    },
  });
}

// Run when executed directly (not when imported by tests).
if (process.argv[1] && /mcp-tools-autocheck-runner\.js$/.test(process.argv[1])) {
  main().catch(() => undefined).finally(() => process.exit(0));
}
