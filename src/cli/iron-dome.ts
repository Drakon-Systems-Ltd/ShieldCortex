/**
 * Iron Dome CLI Commands
 *
 * Usage:
 *   shieldcortex iron-dome activate [--profile school|enterprise|personal|paranoid]
 *   shieldcortex iron-dome status
 *   shieldcortex iron-dome deactivate
 *   shieldcortex iron-dome scan --text "..."
 *   shieldcortex iron-dome scan --file <path>
 *   shieldcortex iron-dome audit [--tail] [--search <term>] [--date <date>]
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { initDatabase } from '../database/init.js';
import {
  activateIronDome,
  deactivateIronDome,
  getIronDomeStatus,
  scanForInjection,
} from '../defence/iron-dome/index.js';
import type { IronDomeProfile } from '../defence/iron-dome/config.js';
import { queryAuditLogs } from '../defence/audit/index.js';

const bold = '\x1b[1m';
const reset = '\x1b[0m';
const green = '\x1b[32m';
const red = '\x1b[31m';
const yellow = '\x1b[33m';
const cyan = '\x1b[36m';
const dim = '\x1b[2m';

/**
 * Ensure database is initialised for CLI commands.
 */
function ensureDb(): void {
  const dbPath = process.env.CLAUDE_MEMORY_DB || path.join(os.homedir(), '.shieldcortex', 'memories.db');
  initDatabase(dbPath);
}

/**
 * Handle the `iron-dome` subcommand.
 */
export async function handleIronDomeCommand(args: string[]): Promise<void> {
  const subcommand = args[0];

  if (!subcommand || subcommand === '--help' || subcommand === '-h') {
    printUsage();
    return;
  }

  ensureDb();

  switch (subcommand) {
    case 'activate':
      handleActivate(args.slice(1));
      break;
    case 'status':
      handleStatus();
      break;
    case 'deactivate':
      handleDeactivate();
      break;
    case 'scan':
      handleScan(args.slice(1));
      break;
    case 'audit':
      handleAudit(args.slice(1));
      break;
    default:
      console.error(`Unknown iron-dome command: ${subcommand}`);
      printUsage();
      process.exit(1);
  }
}

function printUsage(): void {
  console.log(`
${bold}Iron Dome — Behaviour Protection Layer${reset}

${bold}Usage:${reset}
  shieldcortex iron-dome activate [--profile <profile>]
  shieldcortex iron-dome status
  shieldcortex iron-dome deactivate
  shieldcortex iron-dome scan --text "..." | --file <path>
  shieldcortex iron-dome audit [--tail] [--search <term>]

${bold}Profiles:${reset}
  school       GDPR strict, pupil data locked
  enterprise   Financial protection, compliance
  personal     Lighter touch for personal use
  paranoid     Everything requires approval
`);
}

function handleActivate(args: string[]): void {
  let profile: IronDomeProfile | undefined;

  const profileIdx = args.indexOf('--profile');
  if (profileIdx !== -1 && args[profileIdx + 1]) {
    const p = args[profileIdx + 1] as IronDomeProfile;
    if (!['school', 'enterprise', 'personal', 'paranoid'].includes(p)) {
      console.error(`${red}Unknown profile: ${p}${reset}`);
      console.error(`Available: school, enterprise, personal, paranoid`);
      process.exit(1);
    }
    profile = p;
  }

  const config = activateIronDome(profile);

  console.log(`
${bold}${green}Iron Dome Activated${reset}

  Profile:          ${config.profile ?? 'default'}
  Trusted channels: ${config.trustedChannels.join(', ')}
  Kill phrase:      "${config.killPhrase}"
  Require approval: ${config.requireApproval.length} action type(s)
  Auto-approve:     ${config.autoApprove.length} action type(s)
  PII never output: ${config.piiRules.neverOutput.length} categories
  PII aggregates:   ${config.piiRules.aggregatesOnly.length} categories
`);
}

function handleStatus(): void {
  const status = getIronDomeStatus();

  if (!status.enabled) {
    console.log(`
${bold}Iron Dome Status${reset}
${'─'.repeat(40)}
  Status: ${dim}INACTIVE${reset}

  Run ${cyan}shieldcortex iron-dome activate${reset} to enable.
`);
    return;
  }

  const c = status.config;
  console.log(`
${bold}Iron Dome Status${reset}
${'─'.repeat(40)}
  Status:           ${green}ACTIVE${reset}
  Profile:          ${c.profile ?? 'custom'}
  Trusted channels: ${c.trustedChannels.join(', ')}
  Kill phrase:      "${c.killPhrase}"
  Require approval: ${c.requireApproval.join(', ')}
  Auto-approve:     ${c.autoApprove.join(', ')}
  PII never output: ${c.piiRules.neverOutput.length > 0 ? c.piiRules.neverOutput.join(', ') : '(none)'}
  PII aggregates:   ${c.piiRules.aggregatesOnly.length > 0 ? c.piiRules.aggregatesOnly.join(', ') : '(none)'}
  Sub-agent blocks: ${c.subAgentRestrictions.blockedOperations.length > 0 ? c.subAgentRestrictions.blockedOperations.join(', ') : '(none)'}
  Sanitise context: ${c.subAgentRestrictions.sanitiseContext ? 'yes' : 'no'}
`);
}

function handleDeactivate(): void {
  deactivateIronDome();
  console.log(`${bold}Iron Dome deactivated.${reset}`);
}

function handleScan(args: string[]): void {
  let text: string | undefined;

  const textIdx = args.indexOf('--text');
  const fileIdx = args.indexOf('--file');

  if (textIdx !== -1 && args[textIdx + 1]) {
    text = args[textIdx + 1];
  } else if (fileIdx !== -1 && args[fileIdx + 1]) {
    const filePath = args[fileIdx + 1];
    try {
      text = fs.readFileSync(filePath, 'utf-8');
    } catch (err: any) {
      console.error(`${red}Error reading file: ${err.message}${reset}`);
      process.exit(2);
    }
  }

  if (!text) {
    console.error('Usage: shieldcortex iron-dome scan --text "..." | --file <path>');
    process.exit(1);
  }

  const result = scanForInjection(text);

  if (result.clean) {
    console.log(`${green}CLEAN${reset} — No injection patterns detected (${result.textLength} chars scanned)`);
    process.exit(0);
  }

  console.log(`\n${'!'.repeat(3)}  ${red}${bold}INJECTION DETECTED${reset}  ${'!'.repeat(3)}`);
  console.log(`Risk level: ${result.riskLevel}`);
  console.log(`Detections: ${result.detections.length}`);
  console.log(`Scanned:    ${result.textLength} chars`);
  console.log();

  // Group by category
  const byCat: Record<string, typeof result.detections> = {};
  for (const d of result.detections) {
    (byCat[d.category] ??= []).push(d);
  }

  for (const [cat, dets] of Object.entries(byCat).sort(([a], [b]) => a.localeCompare(b))) {
    console.log(`  ${bold}[${cat}]${reset}`);
    for (const d of dets) {
      const sColor = d.severity === 'critical' ? red : d.severity === 'high' ? red : d.severity === 'medium' ? yellow : cyan;
      console.log(`    ${sColor}[${d.severity.toUpperCase()}]${reset} ${d.pattern}: ${d.description}`);
      const preview = d.match.slice(0, 120);
      const suffix = d.match.length > 120 ? '...' : '';
      console.log(`           ${dim}matched: "${preview}${suffix}"${reset}`);
    }
    console.log();
  }

  process.exit(1);
}

function handleAudit(args: string[]): void {
  const searchIdx = args.indexOf('--search');
  const search = searchIdx !== -1 ? args[searchIdx + 1] : undefined;
  const tail = args.includes('--tail');

  const logs = queryAuditLogs({
    firewallResult: undefined,
    limit: tail ? 20 : 50,
  });

  // Filter to iron-dome entries
  const ironDomeLogs = logs.filter(
    (log: any) => log.reason?.startsWith('[iron-dome:')
  );

  if (search) {
    const filtered = ironDomeLogs.filter(
      (log: any) => log.reason?.toLowerCase().includes(search.toLowerCase())
    );
    printAuditLogs(filtered);
  } else {
    printAuditLogs(ironDomeLogs);
  }
}

function printAuditLogs(logs: any[]): void {
  if (logs.length === 0) {
    console.log(`${dim}No Iron Dome audit entries found.${reset}`);
    return;
  }

  console.log(`\n${bold}Iron Dome Audit Log${reset} (${logs.length} entries)`);
  console.log('─'.repeat(60));

  for (const log of logs) {
    const resultColor = log.firewall_result === 'ALLOW' ? green : red;
    console.log(`  ${dim}${log.timestamp}${reset} ${resultColor}${log.firewall_result}${reset} ${log.reason ?? ''}`);
  }

  console.log();
}
