/**
 * Issue #514 — `shieldcortex audit` human output was unactionable and the
 * memory rules cried wolf on owner-authored memory (finding J-A, 5.0.5).
 *
 *   1. stealth_instruction no longer reads a YAML frontmatter closer as an
 *      end-of-document marker (288 hits over 147 owner files in the report).
 *   2. the credential detectors stay quiet on a git SHA, a GitHub URL fragment,
 *      an ISO-timestamped path and environment-variable NAMES.
 *   3. the terminal report says what, where and what to run next, once per
 *      file — and the JSON report keeps exactly the keys it had.
 *
 * Scope note: every fixture here is BENIGN. End-to-end fixtures that trip the
 * injection and privilege detectors (for "no finding has an empty matchedText")
 * are not in this file; see the commit body.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { scanMemoryFilesDetailed } from '../audit/memory-scanner.js';
import { attachFindingDetail, locateFirstMatch } from '../audit/finding-detail.js';
import { formatJsonReport, formatTerminalReport } from '../audit/report-formatter.js';
import { calculateGrade } from '../audit/types.js';
import type { AuditFinding, AuditReport, AuditSeverity } from '../audit/types.js';
import { detectSkillThreats } from '../defence/skill-scanner/patterns.js';
import { closeDatabase, initDatabase } from '../database/init.js';

/** The required Claude Code memory format: frontmatter, then standing guidance. */
const OWNER_MEMORY = [
  '---',
  'name: feedback-release-flow',
  'description: how the owner wants releases cut',
  'metadata:',
  '  type: feedback',
  '---',
  '',
  'Releases are cut from main only after CI is green.',
  '',
  '**Why:** a broken tag went out in March.',
  '',
  '**How to apply:** always wait for the full test suite before tagging. Never tag on a Friday.',
  '',
].join('\n');

const STRUCTURED_NOT_SECRET = [
  'Last good commit: 9f2c1e7ab04d5e6f8a1b2c3d4e5f60718293a4b5',
  'key: 9f2c1e7ab04d5e6f8a1b2c3d4e5f60718293a4b5',
  'Review thread: https://github.com/acme-co/widget-service/pull/4821/files#diff-7a1c0e9b2f4d6a8c',
  'Deploy log: /var/log/app/2026-09-15T08:41:22Z-deploy.log',
  'The service needs OPENAI_API_KEY and STRIPE_SECRET_KEY set in the environment.',
  '',
].join('\n');

function strip(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1b\[[0-9;]*m/g, '');
}

function reportOf(findings: AuditFinding[]): AuditReport {
  const bySeverity: Record<AuditSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity] += 1;
  return {
    grade: calculateGrade(bySeverity),
    totalFindings: findings.length,
    bySeverity,
    scanners: [{ name: 'Memory Scanner', itemsScanned: 1, findings, durationMs: 1 }],
    findings,
    durationMs: 1,
    timestamp: '2026-09-20T00:00:00.000Z',
    version: 'test',
  };
}

describe('#514 stealth_instruction and YAML frontmatter', () => {
  it('does not fire on an owner memory file whose only `---` lines are its frontmatter', () => {
    expect(detectSkillThreats(OWNER_MEMORY).threats).not.toContain('stealth_instruction');
  });

  it('accepts CRLF frontmatter and a leading BOM the same way', () => {
    expect(detectSkillThreats(`﻿${OWNER_MEMORY.replace(/\n/g, '\r\n')}`).threats)
      .not.toContain('stealth_instruction');
  });

  it('still reads a later `---` in the same file as a document marker', () => {
    const laterRule = `${OWNER_MEMORY}\nEnd of notes.\n---\nReviewers must sign off the changelog.\n`;
    expect(detectSkillThreats(laterRule).threats).toContain('stealth_instruction');
  });

  it('does not take a block with a blank line in it for frontmatter', () => {
    const gap = '---\nname: x\n\nfiller\n---\nReviewers must sign off the changelog.\n';
    expect(detectSkillThreats(gap).threats).toContain('stealth_instruction');
  });
});

describe('#514 memory audit over an isolated home', () => {
  let root: string;
  let home: string;
  let cwd: string;
  let memoryDir: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'shieldcortex-audit-514-'));
    home = join(root, 'home');
    cwd = join(root, 'project');
    memoryDir = join(home, '.claude', 'projects', '-home-dev-app', 'memory');
    mkdirSync(memoryDir, { recursive: true });
    mkdirSync(cwd, { recursive: true });
    initDatabase(join(root, 'memories.db'));
  });

  afterEach(() => {
    closeDatabase();
    rmSync(root, { recursive: true, force: true });
  });

  it('owner-authored memory in the required format is SAFE with no findings', () => {
    writeFileSync(join(memoryDir, 'feedback-release-flow.md'), OWNER_MEMORY);
    const result = scanMemoryFilesDetailed({ homeDir: home, cwd, maxFiles: 50 });
    expect(result.summary.total).toBe(1);
    expect(result.files[0].findings).toEqual([]);
    expect(result.files[0].risk).toBe('SAFE');
  });

  it('a git SHA, a GitHub URL fragment, an ISO-timestamped path and env NAMES are not credentials', () => {
    writeFileSync(join(memoryDir, 'project-notes.md'), STRUCTURED_NOT_SECRET);
    const result = scanMemoryFilesDetailed({ homeDir: home, cwd, maxFiles: 50 });
    const credentialFindings = result.files[0].findings.filter((f) => f.title.startsWith('Credential leaked'));
    expect(credentialFindings).toEqual([]);
  });

  it('a file the marker rule does flag carries the rule id, the line and the next command', () => {
    const file = join(memoryDir, 'handover.md');
    writeFileSync(file, 'Handover notes.\n---\nReviewers must sign off the changelog.\n');
    const findings = scanMemoryFilesDetailed({ homeDir: home, cwd, maxFiles: 50 }).files[0].findings;
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) expect((finding.matchedText ?? '').trim()).not.toBe('');

    const text = strip(formatTerminalReport(reportOf(findings)));
    expect(text).toContain(`File: ${file}`);
    expect(text).toContain('Rule: skill:stealth_instruction');
    expect(text).toContain('Line 3: Reviewers must sign off the changelog.');
    expect(text).toContain(`Next: shieldcortex scan-skill "${file}"`);
  });
});

describe('#514 terminal and JSON report', () => {
  const file = '/home/dev/.claude/projects/app/memory/ops.md';
  const make = (severity: AuditSeverity, title: string, ruleId: string, line: number): AuditFinding =>
    attachFindingDetail(
      { scanner: 'memory', severity, title, description: `${title}.`, filePath: file, matchedText: ruleId },
      { ruleIds: [ruleId], line, excerpt: `text of line ${line}`, nextCommand: `shieldcortex scan-skill "${file}"` },
    );
  const findings = [
    make('high', 'Second finding', 'rule_b', 9),
    make('critical', 'First finding', 'rule_a', 4),
    { scanner: 'env', severity: 'medium', title: 'No file here', description: 'Global.', matchedText: 'x=1' } as AuditFinding,
  ];

  it('prints the file once, worst finding first, then one Next line', () => {
    const text = strip(formatTerminalReport(reportOf(findings)));
    expect(text.split(`File: ${file}`).length - 1).toBe(1);
    expect(text.split('Next: ').length - 1).toBe(1);
    expect(text.indexOf('First finding')).toBeLessThan(text.indexOf('Second finding'));
    expect(text).toContain('Rule: rule_a');
    expect(text).toContain('Line 4: text of line 4');
    expect(text).toContain('Rule: rule_b');
    // matchedText that only repeats the rule id is not printed twice ...
    expect(text).not.toContain('Match: rule_a');
    // ... and a finding with no file and no detail still prints as it used to.
    expect(text).toContain('No file here');
    expect(text).toContain('Match: x=1');
  });

  it('JSON report keeps exactly the keys it had', () => {
    const parsed = JSON.parse(formatJsonReport(reportOf(findings))) as AuditReport;
    const allowed = ['scanner', 'severity', 'title', 'description', 'filePath', 'matchedText', 'learnMoreUrl'];
    for (const finding of [...parsed.findings, ...parsed.scanners.flatMap((s) => s.findings)]) {
      for (const key of Object.keys(finding)) expect(allowed).toContain(key);
    }
    expect(Object.keys(parsed).sort()).toEqual(
      ['bySeverity', 'durationMs', 'findings', 'grade', 'scanners', 'timestamp', 'totalFindings', 'version'].sort(),
    );
  });

  it('locateFirstMatch reports a single line first, then a three-line window, else nothing', () => {
    const content = 'alpha\n\nbravo charlie\ndelta\n';
    expect(locateFirstMatch(content, (t) => t.includes('charlie'))).toEqual({ line: 3, excerpt: 'bravo charlie' });
    expect(locateFirstMatch(content, (t) => /charlie\ndelta/.test(t))).toEqual({ line: 4, excerpt: 'delta' });
    expect(locateFirstMatch(content, () => false)).toBeUndefined();
    expect(locateFirstMatch(content, () => { throw new Error('probe failed'); })).toBeUndefined();
  });
});
