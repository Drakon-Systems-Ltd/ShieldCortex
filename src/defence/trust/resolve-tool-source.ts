/**
 * Resolve and harden the source of an MCP tool call.
 *
 * MCP callers can self-declare any source they like. This module:
 * 1. Always computes the environment-inferred trust ceiling first.
 * 2. Clamps any over-claimed declared source down to that ceiling.
 * 3. Drops a same-score identity that the environment did not confirm
 *    (owner spoof / operator spoof). A genuine trust downgrade is kept
 *    only after the unattested rewrite (#283) so it cannot wear a host
 *    ACL key.
 * 4. Writes a `SOURCE_ELEVATION_BLOCKED` row to defence_audit when a clamp
 *    happens, so operators can spot prompt-injection trying to escalate
 *    its own trust or wear another agent's name.
 * 5. Writes a `SOURCE_MISSING` row when no source was declared, preserving
 *    the existing visibility into unconfigured callers.
 * 6. #283: rewrites any declaration the environment did not confirm onto a
 *    stamped identifier (`unattested>…`) so stored source + checkAccess
 *    ownership keys cannot equal a host-attested `${type}:${identifier}`
 *    row. Runs even under strictSourceMode (strict must not re-open spoof).
 *    Does not raise score (unattested pin is 0.3, never env-override 0.5).
 *    Writer-supplied claim stamps are stripped before rewrite so they cannot
 *    smuggle a 0.5 env-override pin.
 */

import type { DefenceSource } from '../types.js';
import { clampSourceToCeiling } from './env-detector.js';
import { logAudit } from '../audit/logger.js';
import { getStrictSourceMode } from '../../cloud/config.js';
import { scoreSource } from './source-scorer.js';

export interface ResolveToolSourceOptions {
  /** Tool name (e.g. 'remember', 'recall') — recorded in the audit reason. */
  toolName: string;
  /** Active project scope, recorded on the audit row. */
  project: string | null;
  /** Test seam / override; defaults to the config-file strictSourceMode. */
  strict?: boolean;
}

export interface ResolvedToolSource {
  source: DefenceSource;
  /**
   * True when the resolved identity is SYSTEM-derived (no declaration, a
   * clamped over-claim, or a declaration the environment independently
   * confirms) or the deployment runs strictSourceMode. Deliberately NOT a
   * field on DefenceSource — that type is caller-suppliable through the
   * scan-only/SDK surfaces, and attestation must never be self-served.
   *
   * #283: after an unattested rewrite the bit is forced false — strict mode
   * must not mark a rewritten claim as host-attested owner material.
   */
  attested: boolean;
  clamped: boolean;
}

/**
 * Pure attestation derivation (exported for exhaustive unit testing).
 *
 * strictSourceMode does not verify identities — it is the operator's opt-in
 * to hardened consequences (unknown sources score 0.3, sub-trust writes
 * auto-quarantine), so risk-based trust penalties keyed on claimed
 * identities are part of the posture they chose.
 */
export function deriveAttested(input: {
  declared: DefenceSource | undefined;
  resolved: DefenceSource;
  clamped: boolean;
  strict: boolean;
  envInferred?: DefenceSource;
}): boolean {
  if (input.strict) return true;
  if (!input.declared) return true;
  if (input.clamped) return true;
  if (
    input.envInferred &&
    input.declared.type === input.envInferred.type &&
    input.declared.identifier === input.envInferred.identifier
  ) {
    return true;
  }
  return false;
}

const CLAIM_STAMP_PREFIXES = ['env-override>', 'env-claim>', 'unattested>', 'unrecognised>'] as const;

/** Strip a leading claim stamp (case-insensitive) so writers cannot smuggle pins. */
export function stripClaimStamp(identifier: string): string {
  const lower = identifier.toLowerCase();
  for (const p of CLAIM_STAMP_PREFIXES) {
    if (lower.startsWith(p)) return identifier.slice(p.length);
  }
  return identifier;
}

function sameIdentity(a: DefenceSource, b: DefenceSource): boolean {
  return a.type === b.type && a.identifier === b.identifier;
}

/**
 * #283 — rewrite a declaration the environment did not confirm so the stored
 * source string (and checkAccess ownership key) cannot equal a host-attested
 * `${type}:${identifier}` row. Strips any writer-supplied claim stamp first
 * (a declared `env-override>…` must not retain the 0.5 pin). Score must not
 * rise: agent stamps pin at 0.3 via `unattested`.
 *
 * Exported for unit tests.
 */
export function rewriteUnattestedSource(source: DefenceSource): DefenceSource {
  const bareId = stripClaimStamp(source.identifier) || source.identifier;
  const candidate: DefenceSource = { type: source.type, identifier: `unattested>${bareId}` };
  const before = scoreSource({ type: source.type, identifier: bareId }).score;
  const after = scoreSource(candidate).score;
  // Never raise trust. file:import (0.4) → file:unattested would score as
  // generic file 0.6 — fall back to agent:unattested at 0.3.
  if (after > before + 1e-9) {
    return { type: 'agent', identifier: `unattested>${bareId}` };
  }
  return candidate;
}

/**
 * Resolve the effective source for an MCP tool call.
 *
 * Returns the source the rest of the pipeline should use. When a caller
 * over-claims trust the declared source is dropped, an audit row is written,
 * and the env-inferred source is returned instead.
 */
export function resolveToolSource(
  declaredSource: DefenceSource | undefined,
  options: ResolveToolSourceOptions,
): ResolvedToolSource {
  const clampResult = clampSourceToCeiling(declaredSource);
  const { declaredScore, ceilingScore, detection } = clampResult;
  let { source, clamped } = clampResult;
  const strict = options.strict ?? getStrictSourceMode();
  const env = detection.source;

  // Score clamp only rejects a declaration that OUTSCORES the ceiling.
  // A same-score different identity is not a downgrade — it is spoofing.
  const identitySpoof = !!(
    declaredSource
    && !clamped
    && declaredScore !== null
    && declaredScore === ceilingScore
    && !sameIdentity(declaredSource, env)
  );
  if (identitySpoof) {
    source = env;
    clamped = true;
  }

  // #283: environment confirmation is the only thing that keeps a bare
  // declared identity. strictSourceMode must NOT skip this rewrite — it only
  // affects consequence posture, not "did the host confirm this name".
  const envConfirmed = !declaredSource
    || clamped
    || sameIdentity(declaredSource, env);

  let rewritten = false;
  if (declaredSource && !envConfirmed) {
    const beforeKey = `${source.type}:${source.identifier}`;
    const beforeScore = scoreSource(source).score;
    source = rewriteUnattestedSource(source);
    // Extra belt if rewrite somehow elevated.
    if (scoreSource(source).score > beforeScore + 1e-9) {
      source = { type: 'agent', identifier: `unattested>${stripClaimStamp(declaredSource.identifier)}` };
    }
    rewritten = `${source.type}:${source.identifier}` !== beforeKey
      || source.identifier.startsWith('unattested>');
    if (rewritten) {
      try {
        logAudit({
          memory_id: null,
          project: options.project,
          timestamp: new Date().toISOString(),
          source_type: source.type,
          source_identifier: source.identifier,
          trust_score: scoreSource(source).score,
          sensitivity_level: 'PUBLIC',
          firewall_result: 'ALLOW',
          operation: null,
          anomaly_score: 0,
          threat_indicators: JSON.stringify(['identity_unattested']),
          blocked_patterns: '[]',
          reason:
            `SOURCE_UNATTESTED_REWRITTEN: tool=${options.toolName}, ` +
            `declared=${declaredSource.type}:${declaredSource.identifier} (score=${declaredScore}), ` +
            `rewritten=${source.type}:${source.identifier} — reason: environment did not confirm identity`,
          fragmentation_score: null,
          pipeline_duration_ms: null,
        });
      } catch {
        // Audit logging must never break tool execution.
      }
    }
  }

  // Attestation: rewritten claims are never host-attested, even under strict.
  let attested = deriveAttested({
    declared: declaredSource,
    resolved: source,
    clamped,
    strict,
    envInferred: env,
  });
  if (rewritten || (declaredSource && !envConfirmed)) {
    attested = false;
  }

  if (clamped && declaredSource) {
    try {
      logAudit({
        memory_id: null,
        project: options.project,
        timestamp: new Date().toISOString(),
        source_type: source.type,
        source_identifier: source.identifier,
        trust_score: ceilingScore,
        sensitivity_level: 'PUBLIC',
        firewall_result: 'BLOCK',
        operation: null,
        anomaly_score: 0,
        threat_indicators: JSON.stringify(['privilege_escalation']),
        blocked_patterns: '[]',
        reason:
          `SOURCE_ELEVATION_BLOCKED: tool=${options.toolName}, ` +
          `declared=${declaredSource.type}:${declaredSource.identifier} (score=${declaredScore}), ` +
          `clamped=${source.type}:${source.identifier} (score=${ceilingScore}) ` +
          `via ${detection.method} (confidence: ${detection.confidence})` +
          (identitySpoof
            ? ' — reason: same-score identity is not self-declarable'
            : ''),
        fragmentation_score: null,
        pipeline_duration_ms: null,
      });
    } catch {
      // Audit logging must never break tool execution.
    }
    return { source, attested, clamped };
  }

  if (!declaredSource) {
    try {
      logAudit({
        memory_id: null,
        project: options.project,
        timestamp: new Date().toISOString(),
        source_type: source.type,
        source_identifier: source.identifier,
        trust_score: ceilingScore,
        sensitivity_level: 'PUBLIC',
        firewall_result: 'ALLOW',
        operation: null,
        anomaly_score: 0,
        threat_indicators: '[]',
        blocked_patterns: '[]',
        reason:
          `SOURCE_MISSING: tool=${options.toolName}, ` +
          `inferred=${source.type}:${source.identifier} ` +
          `via ${detection.method} (confidence: ${detection.confidence})`,
        fragmentation_score: null,
        pipeline_duration_ms: null,
      });
    } catch {
      // Audit logging must never break tool execution.
    }
  }

  return { source, attested, clamped };
}
