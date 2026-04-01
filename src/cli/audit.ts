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
 *   npx shieldcortex audit --deps           # Also scan ./node_modules for malicious packages
 *   npx shieldcortex audit --deps-global    # Also scan global npm node_modules
 *   npx shieldcortex audit --deps-path /p   # Also scan specific node_modules path
 *   npx shieldcortex audit --deps --quarantine         # Scan + quarantine CRITICAL/HIGH
 *   npx shieldcortex audit --deps --clean --force      # Scan + permanently delete CRITICAL
 *   npx shieldcortex audit --deps --auto-protect       # Scan + auto-quarantine CRITICAL
 */

import { requireFeature, FeatureGatedError } from '../license/gate.js';
import {
  scanMemories,
  scanMcpConfigs,
  scanEnvFiles,
  scanRulesFiles,
  scanDependencies,
  resolveNodeModulesPath,
  quarantinePackage,
  cleanPackage,
  formatTerminalReport,
  formatMarkdownReport,
  formatJsonReport,
  calculateGrade,
} from '../audit/index.js';
import type { AuditReport, AuditSeverity, ScannerResult, AuditFinding } from '../audit/types.js';

interface AuditOptions {
  format: 'terminal' | 'json' | 'markdown';
  ci: boolean;
  /** Scan node_modules when true */
  deps: boolean;
  /** 'local' | 'global' | 'path' */
  depsMode: 'local' | 'global' | 'path';
  /** Custom path for --deps-path */
  depsPath?: string;
  /** Move CRITICAL + HIGH packages to quarantine */
  quarantine: boolean;
  /** Permanently delete CRITICAL packages */
  clean: boolean;
  /** Scan + quarantine CRITICAL automatically, warn about HIGH */
  autoProtect: boolean;
  /** Skip confirmation prompt for --clean */
  force: boolean;
}

function parseAuditArgs(args: string[]): AuditOptions {
  const options: AuditOptions = {
    format: 'terminal',
    ci: false,
    deps: false,
    depsMode: 'local',
    quarantine: false,
    clean: false,
    autoProtect: false,
    force: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--json') {
      options.format = 'json';
    } else if (arg === '--markdown' || arg === '--md') {
      options.format = 'markdown';
    } else if (arg === '--ci') {
      options.ci = true;
      options.format = 'json';
    } else if (arg === '--deps') {
      options.deps = true;
      options.depsMode = 'local';
    } else if (arg === '--deps-global') {
      options.deps = true;
      options.depsMode = 'global';
    } else if (arg === '--deps-path') {
      options.deps = true;
      options.depsMode = 'path';
      const next = args[i + 1];
      if (next && !next.startsWith('--')) {
        options.depsPath = next;
        i++; // consume path argument
      }
    } else if (arg === '--quarantine') {
      options.quarantine = true;
      options.deps = true;
    } else if (arg === '--clean') {
      options.clean = true;
      options.deps = true;
    } else if (arg === '--auto-protect') {
      options.autoProtect = true;
      options.deps = true;
    } else if (arg === '--force') {
      options.force = true;
    }
  }

  return options;
}

/**
 * Run the full audit.
 */
export async function handleAuditCommand(args: string[]): Promise<void> {
  const options = parseAuditArgs(args);
  const start = Date.now();

  // --clean without --force: print warning and exit
  if (options.clean && !options.force && !options.ci) {
    console.error(
      '\x1b[33m⚠  Are you sure? Use --force to confirm.\x1b[0m\n' +
      '   --clean permanently deletes CRITICAL packages from node_modules.\n' +
      '   Run: shieldcortex audit --deps --clean --force',
    );
    process.exit(1);
  }

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
  const totalSteps = options.deps ? 5 : 4;

  if (options.format === 'terminal') process.stdout.write(`  \x1b[2m[1/${totalSteps}] Memory files...\x1b[0m`);
  const memoryResult = scanMemories();
  scanners.push(memoryResult);
  if (options.format === 'terminal') process.stdout.write(`\r  \x1b[32m[1/${totalSteps}]\x1b[0m Memory files     \x1b[2m${memoryResult.durationMs}ms\x1b[0m\n`);

  if (options.format === 'terminal') process.stdout.write(`  \x1b[2m[2/${totalSteps}] MCP configs...\x1b[0m`);
  const mcpResult = scanMcpConfigs();
  scanners.push(mcpResult);
  if (options.format === 'terminal') process.stdout.write(`\r  \x1b[32m[2/${totalSteps}]\x1b[0m MCP configs      \x1b[2m${mcpResult.durationMs}ms\x1b[0m\n`);

  if (options.format === 'terminal') process.stdout.write(`  \x1b[2m[3/${totalSteps}] Environment secrets...\x1b[0m`);
  const envResult = scanEnvFiles();
  scanners.push(envResult);
  if (options.format === 'terminal') process.stdout.write(`\r  \x1b[32m[3/${totalSteps}]\x1b[0m Environment      \x1b[2m${envResult.durationMs}ms\x1b[0m\n`);

  if (options.format === 'terminal') process.stdout.write(`  \x1b[2m[4/${totalSteps}] Rules files...\x1b[0m`);
  const rulesResult = scanRulesFiles();
  scanners.push(rulesResult);
  if (options.format === 'terminal') process.stdout.write(`\r  \x1b[32m[4/${totalSteps}]\x1b[0m Rules files      \x1b[2m${rulesResult.durationMs}ms\x1b[0m\n`);

  // Optional: dependency scan
  let nodeModulesPath = '';
  if (options.deps) {
    nodeModulesPath = resolveNodeModulesPath(options.depsMode, options.depsPath);
    if (options.format === 'terminal') {
      process.stdout.write(`  \x1b[2m[5/${totalSteps}] Dependencies (${nodeModulesPath})...\x1b[0m`);
    }
    const depsResult = scanDependencies({ nodeModulesPath });
    scanners.push(depsResult);
    if (options.format === 'terminal') {
      process.stdout.write(`\r  \x1b[32m[5/${totalSteps}]\x1b[0m Dependencies     \x1b[2m${depsResult.durationMs}ms\x1b[0m\n`);
    }
  }

  if (options.format === 'terminal') process.stdout.write('\n');

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

  // ── Post-scan actions ────────────────────────────────────────────────────

  const depFindings = allFindings.filter(f => f.scanner === 'dependency');

  if (options.quarantine && depFindings.length > 0) {
    try { requireFeature('deps_quarantine'); } catch (e) {
      if (e instanceof FeatureGatedError) { console.error('\n' + e.message); process.exit(1); }
      throw e;
    }
    const eligible = depFindings.filter(
      f => f.severity === 'critical' || f.severity === 'high',
    );
    if (eligible.length === 0) {
      if (options.format === 'terminal') {
        console.log('\n\x1b[32m✓  No CRITICAL or HIGH dependency findings to quarantine.\x1b[0m');
      }
    } else {
      if (options.format === 'terminal') {
        console.log(`\n\x1b[33m⚠  Quarantining ${eligible.length} package(s)...\x1b[0m`);
      }
      for (const finding of eligible) {
        const dest = quarantinePackage(finding, nodeModulesPath);
        if (dest && options.format === 'terminal') {
          console.log(`  \x1b[31m✗\x1b[0m  Quarantined: ${finding.title}`);
          console.log(`       → ${dest}`);
        }
      }
    }
  }

  if (options.clean && depFindings.length > 0) {
    try { requireFeature('deps_clean'); } catch (e) {
      if (e instanceof FeatureGatedError) { console.error('\n' + e.message); process.exit(1); }
      throw e;
    }
    const criticals = depFindings.filter(f => f.severity === 'critical');
    if (criticals.length === 0) {
      if (options.format === 'terminal') {
        console.log('\n\x1b[32m✓  No CRITICAL dependency findings to clean.\x1b[0m');
      }
    } else {
      if (options.format === 'terminal') {
        console.log(`\n\x1b[31m🗑  Cleaning ${criticals.length} CRITICAL package(s)...\x1b[0m`);
      }
      for (const finding of criticals) {
        const deleted = cleanPackage(finding, nodeModulesPath);
        if (deleted && options.format === 'terminal') {
          console.log(`  \x1b[31m✗\x1b[0m  Deleted: ${deleted}`);
        }
      }
    }
  }

  if (options.autoProtect && depFindings.length > 0) {
    try { requireFeature('deps_auto_protect'); } catch (e) {
      if (e instanceof FeatureGatedError) { console.error('\n' + e.message); process.exit(1); }
      throw e;
    }
    const criticals = depFindings.filter(f => f.severity === 'critical');
    const highs = depFindings.filter(f => f.severity === 'high');

    if (criticals.length > 0) {
      if (options.format === 'terminal') {
        console.log(`\n\x1b[33m⚠  Auto-protect: quarantining ${criticals.length} CRITICAL package(s)...\x1b[0m`);
      }
      for (const finding of criticals) {
        const dest = quarantinePackage(finding, nodeModulesPath);
        if (dest && options.format === 'terminal') {
          console.log(`  \x1b[31m✗\x1b[0m  Quarantined: ${finding.title}`);
          console.log(`       → ${dest}`);
        }
      }
    }

    if (highs.length > 0 && options.format === 'terminal') {
      console.log(`\n\x1b[33m⚠  Auto-protect: ${highs.length} HIGH finding(s) detected (manual review required):\x1b[0m`);
      for (const finding of highs) {
        console.log(`  \x1b[33m!\x1b[0m  ${finding.title}`);
      }
    }

    if (criticals.length === 0 && highs.length === 0 && options.format === 'terminal') {
      console.log('\n\x1b[32m✓  Auto-protect: no CRITICAL or HIGH dependency findings.\x1b[0m');
    }
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
