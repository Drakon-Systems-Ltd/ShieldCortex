/**
 * `shieldcortex scan` CLI — runs the defence pipeline and returns the #449
 * process-exit code. Does not call process.exit; the dispatcher does.
 */
import path from 'node:path';
import os from 'node:os';

import {
  SCAN_EXIT,
  SCAN_USAGE_LINES,
  formatScanToolFailure,
  scanVerdictExit,
  type ScanExitCode,
} from './scan-exit.js';

export { SCAN_EXIT, SCAN_USAGE_LINES, formatScanToolFailure, scanVerdictExit };
export type { ScanExitCode };

export function printScanUsage(writeErr: (line: string) => void = (l) => console.error(l)): void {
  for (const line of SCAN_USAGE_LINES) writeErr(line);
}

function printScanVerdict(result: {
  allowed: boolean;
  firewall: {
    result: string;
    reason: string;
    anomalyScore: number;
    threatIndicators: string[];
    blockedPatterns: string[];
  };
  trust: { score: number };
  sensitivity: { level: string };
  credentialScan?: { findings: Array<{ severity: string; provider?: string; type: string; match: string; action: string }> } | null;
}): void {
  const bold = '\x1b[1m';
  const reset = '\x1b[0m';
  const green = '\x1b[32m';
  const red = '\x1b[31m';
  const yellow = '\x1b[33m';

  const resultColor = result.firewall.result === 'ALLOW' ? green :
                      result.firewall.result === 'QUARANTINE' ? yellow : red;

  console.log(`\n${bold}ShieldCortex Scan Result${reset}`);
  console.log(`${'─'.repeat(50)}`);
  console.log(`  Result:      ${resultColor}${result.firewall.result}${reset}`);
  console.log(`  Trust:       ${result.trust.score.toFixed(2)}`);
  console.log(`  Sensitivity: ${result.sensitivity.level}`);
  console.log(`  Anomaly:     ${result.firewall.anomalyScore.toFixed(2)}`);
  console.log(`  Reason:      ${result.firewall.reason}`);

  if (result.firewall.threatIndicators.length > 0) {
    console.log(`  Threats:     ${result.firewall.threatIndicators.join(', ')}`);
  }
  if (result.firewall.blockedPatterns.length > 0) {
    console.log(`  Patterns:    ${result.firewall.blockedPatterns.join(', ')}`);
  }

  if (result.credentialScan && result.credentialScan.findings.length > 0) {
    console.log(`\n${bold}Credential Findings (${result.credentialScan.findings.length}):${reset}`);
    for (const f of result.credentialScan.findings) {
      const sColor = f.severity === 'critical' ? red : f.severity === 'high' ? red : yellow;
      console.log(`  ${sColor}[${f.severity.toUpperCase()}]${reset} ${f.provider ? f.provider + ' ' : ''}${f.type}: ${f.match} (${f.action})`);
    }
  }

  console.log();
}

export async function runScanCommand(text: string | undefined): Promise<ScanExitCode> {
  if (!text) {
    printScanUsage();
    return SCAN_EXIT.USAGE;
  }

  let result: Parameters<typeof printScanVerdict>[0] & { allowed: boolean };
  try {
    const dbPath = process.env.CLAUDE_MEMORY_DB || path.join(os.homedir(), '.shieldcortex', 'memories.db');
    const { initDatabase } = await import('../database/init.js');
    initDatabase(dbPath);

    const { runDefencePipeline } = await import('../defence/pipeline.js');
    const source = { type: 'cli' as const, identifier: 'shieldcortex-scan' };
    // Hardcoded identity in this dispatch → attested by construction. Operator
    // decision (accept-with-soak): test BLOCKs accrue to cli:shieldcortex-scan;
    // the advisory soak absorbs it, and enforce stays off until FP-measured.
    result = runDefencePipeline(text, 'CLI Scan', source, undefined, undefined, { sourceAttested: true });
  } catch (err) {
    console.error(formatScanToolFailure(err));
    return SCAN_EXIT.TOOL_FAILURE;
  }

  printScanVerdict(result);

  // A flush failure is not a scan failure: the verdict already printed.
  try {
    const { flushPendingCloudSync } = await import('../cloud/sync.js');
    await flushPendingCloudSync(8000);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Scan verdict stands; cloud flush failed: ${msg}`);
  }

  return scanVerdictExit(result.allowed);
}
