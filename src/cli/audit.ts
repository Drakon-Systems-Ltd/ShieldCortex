/**
 * Audit CLI Command
 *
 * Orchestrates all security scanners and produces a comprehensive
 * audit report of the developer's AI agent environment.
 *
 * Usage:
 *   npx shieldcortex audit                  # Terminal report
 *   npx shieldcortex audit --json           # JSON output
 *   npx shieldcortex audit --markdown       # Markdown output
 *   npx shieldcortex audit --ci             # CI mode (exit code reflects grade)
 */

import {
  scanMemories,
  scanMcpConfigs,
  scanEnvFiles,
  scanRulesFiles,
  formatTerminalReport,
  formatMarkdownReport,
  formatJsonReport,
  calculateGrade,
} from '../audit/index.js';
import type { AuditReport, AuditSeverity, ScannerResult, AuditFinding } from '../audit/types.js';

interface AuditOptions {
  format: 'terminal' | 'json' | 'markdown';
  ci: boolean;
}

function parseAuditArgs(args: string[]): AuditOptions {
  const options: AuditOptions = { format: 'terminal', ci: false };

  for (const arg of args) {
    if (arg === '--json') options.format = 'json';
    else if (arg === '--markdown' || arg === '--md') options.format = 'markdown';
    else if (arg === '--ci') { options.ci = true; options.format = 'json'; }
  }

  return options;
}

/**
 * Run the full audit.
 */
export async function handleAuditCommand(args: string[]): Promise<void> {
  const options = parseAuditArgs(args);
  const start = Date.now();

  // Get version from package.json
  let version = 'unknown';
  try {
    const { createRequire } = await import('module');
    const require = createRequire(import.meta.url);
    version = require('../../package.json').version;
  } catch { /* ignore */ }

  // Init database (needed for memory scanner's defence pipeline)
  try {
    const os = await import('os');
    const path = await import('path');
    const dbPath = process.env.CLAUDE_MEMORY_DB || path.join(os.homedir(), '.shieldcortex', 'memories.db');
    const { initDatabase } = await import('../database/init.js');
    initDatabase(dbPath);
  } catch {
    // If DB init fails, memory scanner will still work (pipeline just won't audit-log)
  }

  // Show progress in terminal mode
  if (options.format === 'terminal') {
    process.stdout.write('\x1b[36m  Scanning agent environment...\x1b[0m\n\n');
  }

  // Run all scanners
  const scanners: ScannerResult[] = [];

  if (options.format === 'terminal') process.stdout.write('  \x1b[2m[1/4] Memory files...\x1b[0m');
  const memoryResult = scanMemories();
  scanners.push(memoryResult);
  if (options.format === 'terminal') process.stdout.write(`\r  \x1b[32m[1/4]\x1b[0m Memory files     \x1b[2m${memoryResult.durationMs}ms\x1b[0m\n`);

  if (options.format === 'terminal') process.stdout.write('  \x1b[2m[2/4] MCP configs...\x1b[0m');
  const mcpResult = scanMcpConfigs();
  scanners.push(mcpResult);
  if (options.format === 'terminal') process.stdout.write(`\r  \x1b[32m[2/4]\x1b[0m MCP configs      \x1b[2m${mcpResult.durationMs}ms\x1b[0m\n`);

  if (options.format === 'terminal') process.stdout.write('  \x1b[2m[3/4] Environment secrets...\x1b[0m');
  const envResult = scanEnvFiles();
  scanners.push(envResult);
  if (options.format === 'terminal') process.stdout.write(`\r  \x1b[32m[3/4]\x1b[0m Environment      \x1b[2m${envResult.durationMs}ms\x1b[0m\n`);

  if (options.format === 'terminal') process.stdout.write('  \x1b[2m[4/4] Rules files...\x1b[0m');
  const rulesResult = scanRulesFiles();
  scanners.push(rulesResult);
  if (options.format === 'terminal') process.stdout.write(`\r  \x1b[32m[4/4]\x1b[0m Rules files      \x1b[2m${rulesResult.durationMs}ms\x1b[0m\n\n`);

  // Aggregate findings
  const allFindings: AuditFinding[] = scanners.flatMap(s => s.findings);

  // Sort by severity (critical first)
  const severityOrder: Record<AuditSeverity, number> = {
    critical: 0, high: 1, medium: 2, low: 3, info: 4,
  };
  allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Count by severity
  const bySeverity: Record<AuditSeverity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const f of allFindings) {
    bySeverity[f.severity]++;
  }

  const grade = calculateGrade(bySeverity);

  const report: AuditReport = {
    grade,
    totalFindings: allFindings.length,
    bySeverity,
    scanners,
    findings: allFindings,
    durationMs: Date.now() - start,
    timestamp: new Date().toISOString(),
    version,
  };

  // Output report
  switch (options.format) {
    case 'json':
      console.log(formatJsonReport(report));
      break;
    case 'markdown':
      console.log(formatMarkdownReport(report));
      break;
    default:
      console.log(formatTerminalReport(report));
      break;
  }

  // Exit code
  if (options.ci) {
    // In CI mode: fail on critical or high findings
    const hasBlockingFindings = bySeverity.critical > 0 || bySeverity.high > 0;
    process.exit(hasBlockingFindings ? 1 : 0);
  } else {
    // In normal mode: exit 0 for A/B, exit 1 for C/D/F
    process.exit(grade === 'A' || grade === 'B' ? 0 : 1);
  }
}
