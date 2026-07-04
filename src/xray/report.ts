/**
 * X-Ray Report Formatter
 *
 * Beautiful terminal output for X-Ray scan results.
 * Follows the same ANSI colour style as src/audit/report-formatter.ts
 * and src/cli/stats-banner.ts.
 */

import type { XRayResult, XRayFinding } from './types.js';

// ── ANSI Colours ────────────────────────────────────────────

const c = {
  reset:     '\x1b[0m',
  bold:      '\x1b[1m',
  dim:       '\x1b[2m',
  red:       '\x1b[31m',
  green:     '\x1b[32m',
  yellow:    '\x1b[33m',
  blue:      '\x1b[34m',
  magenta:   '\x1b[35m',
  cyan:      '\x1b[36m',
  white:     '\x1b[37m',
  bgRed:     '\x1b[41m',
  bgGreen:   '\x1b[42m',
  bgYellow:  '\x1b[43m',
  brightRed: '\x1b[91m',
};

// ── Helpers ─────────────────────────────────────────────────

function scoreColour(score: number): string {
  if (score >= 80) return c.green;
  if (score >= 60) return c.yellow;
  if (score >= 40) return c.brightRed;
  return c.red;
}

function riskColour(level: string): string {
  switch (level) {
    case 'SAFE': return c.green;
    case 'LOW': return c.yellow;
    case 'MEDIUM': return c.brightRed;
    case 'HIGH': return c.red;
    case 'CRITICAL': return c.red;
    default: return c.white;
  }
}

function severityColour(severity: string): string {
  switch (severity) {
    case 'critical': return c.red;
    case 'high': return c.brightRed;
    case 'medium': return c.yellow;
    case 'low': return c.cyan;
    case 'info': return c.dim;
    default: return c.white;
  }
}

function severityIcon(severity: string): string {
  switch (severity) {
    case 'critical': return 'X';
    case 'high': return '!';
    case 'medium': return '~';
    case 'low': return '-';
    case 'info': return 'i';
    default: return '?';
  }
}

// ── ASCII Art ───────────────────────────────────────────────

const XRAY_ART = `
  ╔═══════════════════════════════════════╗
  ║        ShieldCortex  X-Ray            ║
  ║     Package & File Risk Scanner       ║
  ╚═══════════════════════════════════════╝`;

// ── Terminal Formatter ──────────────────────────────────────

/**
 * Format an X-Ray result for terminal display.
 */
export function formatXRayReport(result: XRayResult): string {
  const lines: string[] = [];
  const sc = scoreColour(result.trustScore);
  const rc = riskColour(result.riskLevel);

  // Header
  lines.push(`${c.cyan}${XRAY_ART}${c.reset}`);
  lines.push('');
  lines.push(`  ${c.bold}Target:${c.reset}  ${result.target}`);
  lines.push(`  ${c.bold}Mode:${c.reset}    ${result.deepScan ? `${c.magenta}Deep Scan (Pro)${c.reset}` : 'Standard Scan'}`);
  lines.push('');

  // Trust Score
  lines.push(`  ╔══════════════════════════╗`);
  lines.push(`  ║  Trust Score: ${sc}${c.bold}${String(result.trustScore).padStart(3)}${c.reset}${' '.repeat(8)}║`);
  lines.push(`  ║  Risk Level: ${rc}${c.bold}${result.riskLevel.padEnd(9)}${c.reset}  ║`);
  lines.push(`  ╚══════════════════════════╝`);
  lines.push('');

  // Severity summary
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of result.findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }

  const summaryParts: string[] = [];
  if (bySeverity.critical > 0) summaryParts.push(`${c.red}${bySeverity.critical} critical${c.reset}`);
  if (bySeverity.high > 0) summaryParts.push(`${c.brightRed}${bySeverity.high} high${c.reset}`);
  if (bySeverity.medium > 0) summaryParts.push(`${c.yellow}${bySeverity.medium} medium${c.reset}`);
  if (bySeverity.low > 0) summaryParts.push(`${c.cyan}${bySeverity.low} low${c.reset}`);
  if (bySeverity.info > 0) summaryParts.push(`${c.dim}${bySeverity.info} info${c.reset}`);

  if (summaryParts.length > 0) {
    lines.push(`  ${c.bold}Findings:${c.reset} ${summaryParts.join('  ')}`);
  } else {
    lines.push(`  ${c.green}${c.bold}No risk indicators found.${c.reset}`);
  }
  lines.push('');

  // Detailed findings grouped by severity
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const printable = result.findings.filter(f => f.severity !== 'info');

  if (printable.length > 0) {
    lines.push(`  ${c.bold}Details${c.reset}`);
    lines.push(`  ${'─'.repeat(60)}`);

    for (const severity of severityOrder) {
      const findings = result.findings.filter(f => f.severity === severity);
      if (findings.length === 0 || severity === 'info') continue;

      for (const finding of findings) {
        const sc2 = severityColour(finding.severity);
        const icon = severityIcon(finding.severity);
        const categoryTag = `${c.dim}[${finding.category}]${c.reset}`;

        lines.push(`  ${sc2}[${icon}] ${finding.severity.toUpperCase().padEnd(8)}${c.reset} ${categoryTag} ${finding.title}`);
        lines.push(`     ${c.dim}${finding.description}${c.reset}`);

        if (finding.file) {
          const loc = finding.line ? `${finding.file}:${finding.line}` : finding.file;
          lines.push(`     ${c.dim}File: ${loc}${c.reset}`);
        }
        if (finding.evidence) {
          lines.push(`     ${c.dim}Evidence: ${finding.evidence}${c.reset}`);
        }
        lines.push('');
      }
    }
  }

  // Footer
  lines.push(`  ${'─'.repeat(60)}`);
  lines.push(`  ${c.dim}Files scanned: ${result.filesScanned}  |  ${result.scannedAt.toISOString()}${c.reset}`);

  if (!result.deepScan) {
    lines.push(`  ${c.dim}Run with --deep for deep scanning: npm registry analysis, binary inspection,${c.reset}`);
    lines.push(`  ${c.dim}dependency graph risk, and AI-directive detection in metadata.${c.reset}`);
  }

  lines.push('');

  return lines.join('\n');
}

// ── Markdown Formatter ──────────────────────────────────────

/**
 * Format an X-Ray result as markdown.
 */
export function formatXRayMarkdown(result: XRayResult): string {
  const lines: string[] = [];

  const riskEmoji = result.riskLevel === 'SAFE' ? '🟢' :
                    result.riskLevel === 'LOW' ? '🔵' :
                    result.riskLevel === 'MEDIUM' ? '🟡' :
                    result.riskLevel === 'HIGH' ? '🟠' : '🔴';

  lines.push(`## ${riskEmoji} ShieldCortex X-Ray — ${result.target}`);
  lines.push('');
  lines.push(`**Trust Score:** ${result.trustScore}/100  `);
  lines.push(`**Risk Level:** ${result.riskLevel}  `);
  lines.push(`**Mode:** ${result.deepScan ? 'Deep Scan (Pro)' : 'Standard'}  `);
  lines.push(`**Files Scanned:** ${result.filesScanned}`);
  lines.push('');

  const printable = result.findings.filter(f => f.severity !== 'info');
  if (printable.length > 0) {
    lines.push('### Findings');
    lines.push('');

    for (const finding of printable) {
      const icon = finding.severity === 'critical' ? '🔴' :
                   finding.severity === 'high' ? '🟠' :
                   finding.severity === 'medium' ? '🟡' : '🔵';
      lines.push(`- ${icon} **[${finding.category}]** ${finding.title}`);
      lines.push(`  ${finding.description}`);
      if (finding.file) {
        const loc = finding.line ? `${finding.file}:${finding.line}` : finding.file;
        lines.push(`  📄 \`${loc}\``);
      }
      lines.push('');
    }
  } else {
    lines.push('**No risk indicators found.** All checks passed.');
    lines.push('');
  }

  lines.push('---');
  lines.push(`*Scanned by [ShieldCortex X-Ray](https://shieldcortex.ai) at ${result.scannedAt.toISOString()}*`);

  return lines.join('\n');
}
