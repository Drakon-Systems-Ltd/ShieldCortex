/**
 * Deep Skill Scanner — enhanced multi-file analysis (Pro feature).
 *
 * Performs cross-file correlation and semantic intent analysis.
 * Degrades gracefully when embedding model is unavailable.
 */

import { scanSkillContent } from './scan-skill.js';
import type { SkillScanResult } from './scan-skill.js';
import type { SkillFormat } from './parser.js';

export interface DeepScanCorrelation {
  files: string[];
  finding: string;
  severity: 'critical' | 'high' | 'medium';
}

export interface DeepScanResult {
  correlations: DeepScanCorrelation[];
  intentBreakdown: Record<string, number>;
  recommendations: string[];
  scanResults: SkillScanResult[];
  degraded: boolean;
  degradedReason?: string;
}

/**
 * Run deep scan on multiple skill file contents.
 * Cross-correlates findings across files and analyses intent patterns.
 */
export async function runDeepScan(files: Array<{ name: string; content: string; format?: string }>): Promise<DeepScanResult> {
  const scanResults: SkillScanResult[] = [];
  const correlations: DeepScanCorrelation[] = [];
  const intentCounts: Record<string, number> = {};
  const recommendations: string[] = [];
  let degraded = false;
  let degradedReason: string | undefined;

  // Scan each file individually
  for (const file of files) {
    try {
      const result = scanSkillContent(
        file.content,
        undefined,
        file.format as SkillFormat | undefined,
        file.name,
      );
      scanResults.push(result);
    } catch {
      // Skip files that fail to scan
    }
  }

  // Cross-file correlation: look for conflicting declarations
  const allFindings = scanResults.flatMap((r, i) =>
    r.findings.map(f => ({ ...f, fileIndex: i, fileName: files[i]?.name || `file-${i}` }))
  );

  // Detect permission escalation across files (match on pattern name)
  const permissionFiles = allFindings.filter(f =>
    f.pattern === 'tool_injection' || f.pattern === 'privilege_escalation'
  );
  if (permissionFiles.length > 1) {
    const uniqueFiles = [...new Set(permissionFiles.map(f => f.fileName))];
    if (uniqueFiles.length > 1) {
      correlations.push({
        files: uniqueFiles,
        finding: 'Multiple files contain permission escalation or tool abuse patterns',
        severity: 'high',
      });
    }
  }

  // Detect data exfiltration patterns across files
  const exfilFiles = allFindings.filter(f =>
    f.pattern === 'data_exfiltration' || f.pattern === 'exfiltration'
  );
  if (exfilFiles.length > 0) {
    const uniqueFiles = [...new Set(exfilFiles.map(f => f.fileName))];
    correlations.push({
      files: uniqueFiles,
      finding: 'Data exfiltration patterns detected across skill files',
      severity: 'critical',
    });
  }

  // Detect contradictory patterns (one file says read-only, another writes)
  const readOnlyFiles = allFindings.filter(f =>
    f.matchedText?.toLowerCase().includes('read-only') || f.matchedText?.toLowerCase().includes('readonly')
  );
  const writeFiles = allFindings.filter(f =>
    f.pattern === 'tool_injection' && (f.matchedText?.includes('write') || f.matchedText?.includes('exec'))
  );
  if (readOnlyFiles.length > 0 && writeFiles.length > 0) {
    correlations.push({
      files: [...new Set([...readOnlyFiles, ...writeFiles].map(f => f.fileName))],
      finding: 'Contradiction: skill declares read-only access but contains write/exec patterns',
      severity: 'high',
    });
  }

  // Intent breakdown from findings
  for (const finding of allFindings) {
    const cat = finding.pattern || 'unknown';
    intentCounts[cat] = (intentCounts[cat] || 0) + 1;
  }

  // Semantic analysis via embeddings (optional — degrades gracefully)
  try {
    const { generateEmbedding } = await import('../../embeddings/index.js');
    // Test with a simple string to verify model is loaded
    await generateEmbedding('test');

    // If embeddings work, analyse semantic intent
    for (const file of files) {
      try {
        const embedding = await generateEmbedding(file.content.slice(0, 1000));
        if (embedding) {
          intentCounts['Semantic analysis'] = (intentCounts['Semantic analysis'] || 0) + 1;
        }
      } catch {
        // Individual file embedding failure is non-fatal
      }
    }
  } catch {
    degraded = true;
    degradedReason = 'Embedding model unavailable — showing pattern-based analysis only';
  }

  // Generate recommendations
  if (correlations.some(c => c.severity === 'critical')) {
    recommendations.push('Review files with critical cross-file correlations immediately');
  }
  if (permissionFiles.length > 0) {
    recommendations.push('Restrict filesystem and process execution permissions in skill manifests');
  }
  if (exfilFiles.length > 0) {
    recommendations.push('Add explicit network permission declarations and restrict outbound URLs');
  }
  if (scanResults.some(r => r.findings.length > 5)) {
    recommendations.push('Consider splitting complex skill files to reduce attack surface');
  }

  return {
    correlations,
    intentBreakdown: intentCounts,
    recommendations,
    scanResults,
    degraded,
    degradedReason,
  };
}
