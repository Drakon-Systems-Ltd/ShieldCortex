/**
 * Report Formatter
 *
 * Formats the audit report for terminal output with:
 *   - ASCII art shield header
 *   - Security grade (A-F)
 *   - Colour-coded findings by severity
 *   - Summary statistics
 *   - Markdown export mode for CI/GitHub
 */

import type { AuditReport, AuditFinding, AuditGrade, AuditSeverity, ScannerResult } from './types.js';

// ── ANSI Colours ──

const c = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  red:     '\x1b[31m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  blue:    '\x1b[34m',
  magenta: '\x1b[35m',
  cyan:    '\x1b[36m',
  white:   '\x1b[37m',
  bgRed:   '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow:'\x1b[43m',
  brightRed: '\x1b[91m',
};

// ── Grade Colours ──

function gradeColour(grade: AuditGrade): string {
  switch (grade) {
    case 'A': return c.green;
    case 'B': return c.blue;
    case 'C': return c.yellow;
    case 'D': return c.brightRed;
    case 'F': return c.red;
  }
}

function severityColour(severity: AuditSeverity): string {
  switch (severity) {
    case 'critical': return c.red;
    case 'high': return c.brightRed;
    case 'medium': return c.yellow;
    case 'low': return c.cyan;
    case 'info': return c.dim;
  }
}

function severityIcon(severity: AuditSeverity): string {
  switch (severity) {
    case 'critical': return 'X';
    case 'high': return '!';
    case 'medium': return '~';
    case 'low': return '-';
    case 'info': return 'i';
  }
}

// ── ASCII Art ──

const SHIELD_ART = `
   _____ __    _      __    ______           __
  / ___// /_  (_)__  / /___/ / ____/___  _____/ /____  _  __
  \\__ \\/ __ \\/ / _ \\/ / __  / /   / __ \\/ ___/ __/ _ \\| |/_/
 ___/ / / / / /  __/ / /_/ / /___/ /_/ / /  / /_/  __/>  <
/____/_/ /_/_/\\___/_/\\__,_/\\____/\\____/_/   \\__/\\___/_/|_|
`;

const GRADE_ART: Record<AuditGrade, string> = {
  A: `
  ╔═══════════════════╗
  ║    Grade:  A       ║
  ║    ALL CLEAR       ║
  ╚═══════════════════╝`,
  B: `
  ╔═══════════════════╗
  ║    Grade:  B       ║
  ║    LOW RISK        ║
  ╚═══════════════════╝`,
  C: `
  ╔═══════════════════╗
  ║    Grade:  C       ║
  ║    MODERATE RISK   ║
  ╚═══════════════════╝`,
  D: `
  ╔═══════════════════╗
  ║    Grade:  D       ║
  ║    HIGH RISK       ║
  ╚═══════════════════╝`,
  F: `
  ╔═══════════════════════╗
  ║    Grade:  F           ║
  ║    CRITICAL RISK       ║
  ╚═══════════════════════╝`,
};

// ── Terminal Formatter ──

/**
 * Format an audit report for terminal display.
 */
export function formatTerminalReport(report: AuditReport): string {
  const lines: string[] = [];
  const gc = gradeColour(report.grade);

  // Header
  lines.push(`${c.cyan}${SHIELD_ART}${c.reset}`);
  lines.push(`${c.bold}  Security Audit${c.reset}  v${report.version}  ${c.dim}${report.timestamp}${c.reset}`);
  lines.push('');

  // Grade box
  lines.push(`${gc}${c.bold}${GRADE_ART[report.grade]}${c.reset}`);
  lines.push('');

  // Summary bar
  const summaryParts: string[] = [];
  if (report.bySeverity.critical > 0) summaryParts.push(`${c.red}${report.bySeverity.critical} critical${c.reset}`);
  if (report.bySeverity.high > 0) summaryParts.push(`${c.brightRed}${report.bySeverity.high} high${c.reset}`);
  if (report.bySeverity.medium > 0) summaryParts.push(`${c.yellow}${report.bySeverity.medium} medium${c.reset}`);
  if (report.bySeverity.low > 0) summaryParts.push(`${c.cyan}${report.bySeverity.low} low${c.reset}`);
  if (report.bySeverity.info > 0) summaryParts.push(`${c.dim}${report.bySeverity.info} info${c.reset}`);

  if (summaryParts.length > 0) {
    lines.push(`  ${c.bold}Findings:${c.reset} ${summaryParts.join('  ')}`);
  } else {
    lines.push(`  ${c.green}${c.bold}No security issues found.${c.reset}`);
  }
  lines.push('');

  // Scanner results
  lines.push(`  ${c.bold}Scanners${c.reset}`);
  lines.push(`  ${'─'.repeat(60)}`);

  for (const scanner of report.scanners) {
    const findingCount = scanner.findings.length;
    const icon = scanner.skipped ? `${c.dim}○${c.reset}` :
                 findingCount === 0 ? `${c.green}✓${c.reset}` :
                 `${c.red}✗${c.reset}`;
    const countStr = scanner.skipped ? `${c.dim}skipped${c.reset}` :
                     findingCount === 0 ? `${c.green}clean${c.reset}` :
                     `${c.red}${findingCount} finding(s)${c.reset}`;
    const scannedStr = scanner.skipped ? '' : ` (${scanner.itemsScanned} scanned)`;
    const timeStr = `${c.dim}${scanner.durationMs}ms${c.reset}`;

    lines.push(`  ${icon}  ${scanner.name.padEnd(25)} ${countStr}${scannedStr}  ${timeStr}`);
    if (scanner.skipped && scanner.skipReason) {
      lines.push(`     ${c.dim}${scanner.skipReason}${c.reset}`);
    }
  }
  lines.push('');

  // Detailed findings (grouped by severity)
  const severityOrder: AuditSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const hasPrintableFindings = report.findings.some(f => f.severity !== 'info');

  if (hasPrintableFindings) {
    lines.push(`  ${c.bold}Findings${c.reset}`);
    lines.push(`  ${'─'.repeat(60)}`);

    for (const severity of severityOrder) {
      const findings = report.findings.filter(f => f.severity === severity);
      if (findings.length === 0) continue;

      // Skip info findings in the detailed view (they're noise)
      if (severity === 'info') continue;

      for (const finding of findings) {
        const sc = severityColour(finding.severity);
        const icon = severityIcon(finding.severity);
        lines.push(`  ${sc}[${icon}] ${finding.severity.toUpperCase().padEnd(8)}${c.reset} ${finding.title}`);
        lines.push(`     ${c.dim}${finding.description}${c.reset}`);
        if (finding.filePath) {
          lines.push(`     ${c.dim}File: ${finding.filePath}${c.reset}`);
        }
        if (finding.matchedText) {
          lines.push(`     ${c.dim}Match: ${finding.matchedText}${c.reset}`);
        }
        lines.push('');
      }
    }
  }

  // Footer
  lines.push(`  ${'─'.repeat(60)}`);
  lines.push(`  ${c.dim}Scan completed in ${report.durationMs}ms${c.reset}`);
  lines.push(`  ${c.dim}Learn more: https://shieldcortex.ai/docs/audit${c.reset}`);
  lines.push('');

  return lines.join('\n');
}

// ── Markdown Formatter (for CI/GitHub) ──

/**
 * Format an audit report as markdown (for GitHub PR comments).
 */
export function formatMarkdownReport(report: AuditReport): string {
  const lines: string[] = [];
  const gradeEmoji = report.grade === 'A' ? '🟢' :
                     report.grade === 'B' ? '🔵' :
                     report.grade === 'C' ? '🟡' :
                     report.grade === 'D' ? '🟠' : '🔴';

  lines.push(`## ${gradeEmoji} ShieldCortex Security Audit — Grade ${report.grade}`);
  lines.push('');

  // Summary table
  if (report.totalFindings > 0) {
    lines.push('| Severity | Count |');
    lines.push('|----------|-------|');
    if (report.bySeverity.critical > 0) lines.push(`| 🔴 Critical | ${report.bySeverity.critical} |`);
    if (report.bySeverity.high > 0) lines.push(`| 🟠 High | ${report.bySeverity.high} |`);
    if (report.bySeverity.medium > 0) lines.push(`| 🟡 Medium | ${report.bySeverity.medium} |`);
    if (report.bySeverity.low > 0) lines.push(`| 🔵 Low | ${report.bySeverity.low} |`);
    if (report.bySeverity.info > 0) lines.push(`| ⚪ Info | ${report.bySeverity.info} |`);
    lines.push('');
  } else {
    lines.push('**No security issues found.** All checks passed.');
    lines.push('');
  }

  // Findings
  const printable = report.findings.filter(f => f.severity !== 'info');
  if (printable.length > 0) {
    lines.push('### Findings');
    lines.push('');

    for (const finding of printable) {
      const icon = finding.severity === 'critical' ? '🔴' :
                   finding.severity === 'high' ? '🟠' :
                   finding.severity === 'medium' ? '🟡' : '🔵';
      lines.push(`- ${icon} **${finding.title}**`);
      lines.push(`  ${finding.description}`);
      if (finding.filePath) lines.push(`  📄 \`${finding.filePath}\``);
      lines.push('');
    }
  }

  lines.push('---');
  lines.push(`*Scanned by [ShieldCortex](https://shieldcortex.ai) v${report.version} in ${report.durationMs}ms*`);

  return lines.join('\n');
}

// ── JSON Formatter ──

/**
 * Format an audit report as JSON (for programmatic consumption).
 */
export function formatJsonReport(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}
