import type { EnvironmentScanResult, TaintLabel } from './types.js';

const TAINT_COLOURS: Record<TaintLabel, string> = {
  trusted: '\x1b[32m',
  untrusted: '\x1b[33m',
  suspicious: '\x1b[91m',
  hostile: '\x1b[31m',
};
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

export function formatEnvScanReport(result: EnvironmentScanResult): string {
  const lines: string[] = [];
  const colour = TAINT_COLOURS[result.taint.label];

  lines.push('');
  lines.push(`${BOLD}Environment Firewall Report${RESET}`);
  lines.push('─'.repeat(60));
  lines.push(`  URL:          ${result.url}`);
  if (result.finalUrl !== result.url) lines.push(`  Final URL:    ${result.finalUrl}`);
  lines.push(`  Status:       ${result.statusCode ?? 'n/a'} (${result.bytesReceived} bytes, ${result.fetchDurationMs}ms)`);
  lines.push(`  Taint:        ${colour}${result.taint.label.toUpperCase()}${RESET} — ${result.taint.reason}`);
  lines.push(`  Provenance:   ${result.provenance.score.toFixed(2)} (${result.provenance.signals.finalDomain})`);

  if (result.provenance.reasons.length > 0) {
    lines.push(`\n${BOLD}Provenance signals:${RESET}`);
    for (const r of result.provenance.reasons) lines.push(`  - ${r}`);
  }

  if (result.hidden.hits.length > 0) {
    lines.push(`\n${BOLD}Hidden content (${result.hidden.hits.length}):${RESET}`);
    const grouped = new Map<string, number>();
    for (const h of result.hidden.hits) grouped.set(h.technique, (grouped.get(h.technique) ?? 0) + 1);
    for (const [technique, count] of grouped) lines.push(`  - ${technique}: ${count}`);
  }

  if (result.injection.visibleHits.length > 0 || result.injection.hiddenHits.length > 0) {
    lines.push(`\n${BOLD}Injection patterns:${RESET}`);
    for (const hit of [...result.injection.hiddenHits, ...result.injection.visibleHits]) {
      const surfaceTag = hit.surface === 'hidden' ? `${TAINT_COLOURS.hostile}[HIDDEN]${RESET}` : `${DIM}[visible]${RESET}`;
      lines.push(`  ${surfaceTag} ${hit.pattern}: "${hit.snippet.slice(0, 80)}"`);
    }
  }

  if (result.risks.length > 0) {
    lines.push(`\n${BOLD}Risks:${RESET}`);
    for (const r of result.risks) lines.push(`  - ${r}`);
  }

  lines.push('');
  lines.push(result.summary);
  lines.push('');
  return lines.join('\n');
}

export function formatEnvScanMarkdown(result: EnvironmentScanResult): string {
  const lines: string[] = [];
  lines.push(`# Environment Firewall Report`);
  lines.push('');
  lines.push(`- **URL**: ${result.url}`);
  if (result.finalUrl !== result.url) lines.push(`- **Final URL**: ${result.finalUrl}`);
  lines.push(`- **Status**: ${result.statusCode ?? 'n/a'} (${result.bytesReceived} bytes, ${result.fetchDurationMs}ms)`);
  lines.push(`- **Taint**: \`${result.taint.label.toUpperCase()}\` — ${result.taint.reason}`);
  lines.push(`- **Provenance score**: ${result.provenance.score.toFixed(2)} (${result.provenance.signals.finalDomain})`);

  if (result.provenance.reasons.length > 0) {
    lines.push('');
    lines.push('## Provenance signals');
    for (const r of result.provenance.reasons) lines.push(`- ${r}`);
  }

  if (result.hidden.hits.length > 0) {
    lines.push('');
    lines.push('## Hidden content');
    for (const h of result.hidden.hits) {
      lines.push(`- \`${h.technique}\` (${h.charCount} chars): ${h.sample}`);
    }
  }

  if (result.injection.visibleHits.length > 0 || result.injection.hiddenHits.length > 0) {
    lines.push('');
    lines.push('## Injection patterns');
    for (const hit of [...result.injection.hiddenHits, ...result.injection.visibleHits]) {
      lines.push(`- **[${hit.surface}]** \`${hit.pattern}\`: "${hit.snippet.slice(0, 120)}"`);
    }
  }

  if (result.risks.length > 0) {
    lines.push('');
    lines.push('## Risks');
    for (const r of result.risks) lines.push(`- ${r}`);
  }

  return lines.join('\n');
}
