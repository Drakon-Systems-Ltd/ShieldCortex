/**
 * shieldcortex stats — detailed security report
 */

import { isDatabaseInitialized } from '../database/init.js';
import { getLifetimeStats } from '../defence/audit/queries.js';
import { getAuditStats } from '../defence/audit/queries.js';
import { getLicense } from '../license/store.js';
import { getTrialStatus } from '../license/trial.js';
import { existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const fmt = new Intl.NumberFormat('en-US');

function n(num: number): string {
  return fmt.format(num);
}

const BOLD  = '\x1b[1m';
const DIM   = '\x1b[2m';
const GREEN = '\x1b[32m';
const CYAN  = '\x1b[36m';
const RESET = '\x1b[0m';

function row(label: string, value: string | number, width = 36): string {
  const l = label + ':';
  const v = typeof value === 'number' ? n(value) : value;
  return `  ${l.padEnd(width - v.toString().length - 2)}${GREEN}${v}${RESET}`;
}

function section(title: string): string {
  return `\n  ${BOLD}${title}${RESET}\n  ${'─'.repeat(34)}`;
}

export async function runStatsCommand(): Promise<void> {
  if (!isDatabaseInitialized()) {
    // Try to init the default db first
    try {
      const { initDatabase } = await import('../database/init.js');
      const dbPath = process.env.CLAUDE_MEMORY_DB || join(homedir(), '.shieldcortex', 'memories.db');
      initDatabase(dbPath);
    } catch {
      console.log(`\n  No database found. Run ShieldCortex first to start collecting stats.\n`);
      return;
    }
  }

  try {
    const lifetime  = getLifetimeStats();
    const last24h   = getAuditStats('24h');
    const last7d    = getAuditStats('7d');

    const licenseFile = join(homedir(), '.shieldcortex', 'license.json');
    const license = getLicense();
    const trial   = getTrialStatus(existsSync(licenseFile));
    const tier    = license.valid ? license.tier : (trial?.active ? 'pro (trial)' : 'free');

    console.log(`\n  ${BOLD}🛡️  ShieldCortex Security Report${RESET}  ${DIM}[${tier}]${RESET}`);

    console.log(section('All Time'));
    console.log(row('Total scans',         lifetime.totalScans));
    console.log(row('Threats blocked',     lifetime.threatsBlocked));
    console.log(row('Quarantined',         lifetime.quarantined));
    console.log(row('Credential leaks',    lifetime.credentialLeaks));
    console.log(row('Memories protected',  lifetime.memoriesProtected));

    console.log(section('Last 24 Hours'));
    console.log(row('Scans',       last24h.totalOperations));
    console.log(row('Blocked',     last24h.blockedCount));
    console.log(row('Quarantined', last24h.quarantinedCount));

    console.log(section('Last 7 Days'));
    console.log(row('Scans',       last7d.totalOperations));
    console.log(row('Blocked',     last7d.blockedCount));
    console.log(row('Quarantined', last7d.quarantinedCount));

    const threats = last7d.threatBreakdown;
    const threatEntries = Object.entries(threats).sort((a, b) => b[1] - a[1]).slice(0, 5);
    if (threatEntries.length > 0) {
      console.log(section('Top Threat Types (7d)'));
      for (const [type, count] of threatEntries) {
        console.log(row(type, count));
      }
    }

    const isPro = license.valid || trial?.active;
    if (!isPro) {
      console.log(`\n  ${DIM}Upgrade to Pro for custom detection patterns.${RESET}`);
      console.log(`  ${CYAN}https://shieldcortex.ai/pricing${RESET}`);
    }

    console.log();
  } catch (err) {
    console.error('  Failed to load stats:', (err as Error).message);
  }
}
