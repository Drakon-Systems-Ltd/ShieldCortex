/**
 * Format-aware scan profile (issue #121).
 *
 * Skill and hook instruction docs (SKILL.md, HOOK.md) are, by their nature,
 * dense with imperative language — "run the following", "use the Bash tool",
 * "npm install", "skip verification", "never ask for permission". On their own
 * these are ordinary teaching instructions, not attacks, yet the raw pattern
 * scanner scored them high/critical and drowned legitimate skills in false
 * positives (superpowers executing-plans, using-git-worktrees, the
 * cortex-memory hook, …).
 *
 * The profile enforces a single rule for skill/hook-format files:
 *
 *   Imperative-instruction density ALONE can never carry a high or critical
 *   verdict. A high/critical verdict additionally requires at least one HARD
 *   corroborating signal — data exfiltration, credential access, or agent
 *   configuration mutation. When no hard signal is present, every finding is
 *   capped at 'medium'.
 *
 * The cap applies only to skill-md / hook-md formats. Code formats (hook-js,
 * continue-json) and rules/CLAUDE.md files are unaffected — their threats are
 * carried by concrete code/exfil signals, not instruction density.
 */

import type { SkillFormat } from './parser.js';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Pattern / firewall-indicator names that constitute HARD corroborating
 * evidence: exfiltration, credential access, or configuration mutation.
 * Presence of any of these lifts the density cap for skill/hook-format files.
 *
 * Names span both the skill/code pattern groups (patterns.ts) and the
 * firewall's ThreatIndicator vocabulary (defence/types.ts), since findings
 * from both sources share the SkillThreatFinding.pattern field.
 */
export const HARD_SIGNAL_PATTERNS: ReadonlySet<string> = new Set([
  // ── Exfiltration ──
  'data_exfiltration',
  'credential_exfil',
  'fragmented_payload',
  // ── Credential access ──
  'credential_leak',
  'restricted_content',
  'scope_escalation',
  // ── Configuration mutation / persistence ──
  'persistence',
  // ── Code-level hard evidence (only reachable via code formats; listed so a
  //    mis-detected code format is never silently capped) ──
  'filesystem_access',
]);

/** Formats whose findings are subject to the imperative-density cap. */
export function isInstructionDensityFormat(format: SkillFormat): boolean {
  return format === 'skill-md' || format === 'hook-md';
}

const CAP: Severity = 'medium';
const RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

/** True when at least one finding is a hard corroborating signal. */
export function hasHardSignal(findings: ReadonlyArray<{ pattern: string }>): boolean {
  return findings.some((f) => HARD_SIGNAL_PATTERNS.has(f.pattern));
}

/**
 * Apply the format-aware density cap.
 *
 * When `format` is a skill/hook doc and no hard corroborating signal is present
 * among the findings, clamp every finding's severity down to 'medium'. Returns
 * a NEW array (input is never mutated); `capped` reports whether any severity
 * was actually lowered.
 */
export function applyDensityCap<T extends { pattern: string; severity: Severity }>(
  findings: T[],
  format: SkillFormat,
): { findings: T[]; capped: boolean } {
  if (!isInstructionDensityFormat(format) || hasHardSignal(findings)) {
    return { findings, capped: false };
  }

  let capped = false;
  const out = findings.map((f) => {
    if (RANK[f.severity] > RANK[CAP]) {
      capped = true;
      return { ...f, severity: CAP };
    }
    return f;
  });

  return { findings: out, capped };
}
