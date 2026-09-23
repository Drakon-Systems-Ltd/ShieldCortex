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
import { getFindingDetail } from './finding-detail.js';
import { sanitiseDisplayField } from '../cli/term-ui.js';

/**
 * Every string below that came from a scanned file, its name, or a config the
 * audit read is attacker-influenced. It is sanitised BEFORE the formatter adds
 * its own ANSI, so an escape sequence in a memory file cannot clear the screen
 * and a newline in a file name cannot forge a finding line (issue #514).
 */
const safe = sanitiseDisplayField;

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

    lines.push(`  ${icon}  ${safe(scanner.name).padEnd(25)} ${countStr}${scannedStr}  ${timeStr}`);
    if (scanner.skipped && scanner.skipReason) {
      lines.push(`     ${c.dim}${safe(scanner.skipReason)}${c.reset}`);
    }
  }
  lines.push('');

  // Detailed findings (grouped by severity)
  const severityOrder: AuditSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const hasPrintableFindings = report.findings.some(f => f.severity !== 'info');

  if (hasPrintableFindings) {
    lines.push(`  ${c.bold}Findings${c.reset}`);
    lines.push(`  ${'─'.repeat(60)}`);

    // Skip info findings in the detailed view (they're noise)
    const printable = report.findings.filter(f => f.severity !== 'info');
    const rank = (f: AuditFinding) => severityOrder.indexOf(f.severity);

    const pushFinding = (finding: AuditFinding, indent: string) => {
      const sc = severityColour(finding.severity);
      const icon = severityIcon(finding.severity);
      const detail = getFindingDetail(finding);
      lines.push(`${indent}${sc}[${icon}] ${finding.severity.toUpperCase().padEnd(8)}${c.reset} ${safe(finding.title)}`);
      lines.push(`${indent}   ${c.dim}${safe(finding.description)}${c.reset}`);
      if (detail) {
        lines.push(`${indent}   ${c.dim}Rule: ${safe(detail.ruleIds.join(', '))}${c.reset}`);
        if (detail.line !== undefined && detail.excerpt) {
          lines.push(`${indent}   ${c.dim}Line ${detail.line}: ${safe(detail.excerpt)}${c.reset}`);
        }
      }
      // `Match:` repeats the rule ids for most memory findings; print it only
      // when it says something the Rule line did not (a credential fragment).
      if (finding.matchedText && finding.matchedText !== detail?.ruleIds.join(', ').slice(0, 120)) {
        lines.push(`${indent}   ${c.dim}Match: ${safe(finding.matchedText)}${c.reset}`);
      }
    };

    // Findings that name a file are grouped under it, worst file first: a file
    // with five findings is one thing to go and look at, not five (issue #514).
    const byFile = new Map<string, AuditFinding[]>();
    for (const finding of printable) {
      if (!finding.filePath) continue;
      const group = byFile.get(finding.filePath);
      if (group) group.push(finding);
      else byFile.set(finding.filePath, [finding]);
    }
    const files = [...byFile.entries()]
      .map(([filePath, group]) => ({ filePath, group: group.sort((a, b) => rank(a) - rank(b)) }))
      .sort((a, b) => rank(a.group[0]) - rank(b.group[0]) || a.filePath.localeCompare(b.filePath));

    for (const { filePath, group } of files) {
      lines.push(`  ${c.bold}File: ${safe(filePath)}${c.reset}`);
      for (const finding of group) pushFinding(finding, '    ');
      const next = group.map(f => getFindingDetail(f)?.nextCommand).find(Boolean);
      // A command is only worth printing if pasting it does what it shows. If
      // sanitising would alter it, the name holds something that cannot be
      // displayed faithfully, so say that instead of offering a near-miss.
      if (next && safe(next) === next) {
        lines.push(`    ${c.cyan}Next: ${next}${c.reset}`);
      } else if (group.some(f => getFindingDetail(f))) {
        lines.push(`    ${c.cyan}Next: shieldcortex scan-skill <this file>${c.reset}${c.dim}  (the name has characters that cannot be shown safely, so no paste-ready command is offered)${c.reset}`);
      }
      lines.push('');
    }

    for (const finding of printable.filter(f => !f.filePath).sort((a, b) => rank(a) - rank(b))) {
      pushFinding(finding, '  ');
      lines.push('');
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
 * Wrap attacker-influenced text in a Markdown code span that cannot be broken
 * from inside (#547). A backtick in a file name closed the single-backtick
 * span the report used, and everything after it rendered as Markdown.
 *
 * CommonMark: a code span is delimited by a backtick run of any length, and
 * closes only at a run of exactly that length, so the delimiter here is one
 * longer than the longest run in the text. Content that begins or ends with a
 * backtick is padded with one space on each side; the renderer strips one
 * space from each end when both are present, so the padding is invisible and
 * the backtick stays inside the span.
 */
export function markdownCodeSpan(text: string): string {
  let longest = 0;
  for (const run of text.match(/`+/g) ?? []) longest = Math.max(longest, run.length);
  const fence = '`'.repeat(longest + 1);
  const body = text.startsWith('`') || text.endsWith('`') ? ` ${text} ` : text;
  return `${fence}${body}${fence}`;
}

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
      lines.push(`- ${icon} **${safe(finding.title)}**`);
      lines.push(`  ${safe(finding.description)}`);
      if (finding.filePath) lines.push(`  📄 ${markdownCodeSpan(safe(finding.filePath))}`);
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
