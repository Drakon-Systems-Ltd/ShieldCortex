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
 * 6. #283: rewrites unattested below-ceiling declarations onto a stamped
 *    identifier (`unattested>…`) so stored source + checkAccess ownership
 *    keys cannot equal a host-attested `${type}:${identifier}` row. Does
 *    not raise score (unattested pin is 0.3, never env-override 0.5).
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

/** Already-stamped claim identifiers must not be double-wrapped. */
function isClaimStamp(identifier: string): boolean {
  return (
    identifier.startsWith('env-override>')
    || identifier.startsWith('env-claim>')
    || identifier.startsWith('unattested>')
    || identifier.startsWith('unrecognised>')
  );
}

/**
 * #283 — rewrite an unattested resolved identity so the stored source string
 * (and therefore the checkAccess ownership key) cannot equal a host-attested
 * `${type}:${identifier}` row. Score must not rise: agent stamps pin at 0.3
 * via `unattested`.
 *
 * Exported for unit tests.
 */
export function rewriteUnattestedSource(source: DefenceSource): DefenceSource {
  if (isClaimStamp(source.identifier)) return source;
  // Stamp identifier on every unattested type so ownership cannot collide
  // with a host-attested row of the same type:id. Agent is the dangerous
  // inbound-exemption case; other types still need ACL-key separation.
  return { type: source.type, identifier: `unattested>${source.identifier}` };
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

  // Score clamp only rejects a declaration that OUTSCORES the ceiling.
  // A same-score different identity is not a downgrade — it is spoofing
  // (`user:approved` or `cli:openclaw-jarvis` against env `cli:mcp`, all 0.9).
  // Genuine downgrades stay honoured only after the unattested rewrite below.
  const env = detection.source;
  const identitySpoof = !!(
    declaredSource
    && !clamped
    && declaredScore !== null
    && declaredScore === ceilingScore
    && (declaredSource.type !== env.type || declaredSource.identifier !== env.identifier)
  );
  if (identitySpoof) {
    source = env;
    clamped = true;
  }

  const attested = deriveAttested({
    declared: declaredSource,
    resolved: source,
    clamped,
    strict,
    envInferred: env,
  });

  // #283: unattested below-ceiling declarations (the default cli:* 0.9 path
  // honouring agent:browser 0.3) used to keep the bare identity. Rewrite the
  // stored source so ownership and inbound guards cannot treat it as host-
  // attested. Do this BEFORE returns so the resolved source is final.
  if (declaredSource && !attested && !clamped) {
    const beforeScore = scoreSource(source).score;
    const rewritten = rewriteUnattestedSource(source);
    const afterScore = scoreSource(rewritten).score;
    // Score must not rise (env-override pin would). Defensive floor.
    source = afterScore > beforeScore + 1e-9
      ? { type: 'agent', identifier: `unattested>${declaredSource.identifier}` }
      : rewritten;
    if (`${source.type}:${source.identifier}` !== `${declaredSource.type}:${declaredSource.identifier}`) {
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
        operation: null, // source-resolution meta-event, not a memory read/write/delete
        anomaly_score: 0,
        threat_indicators: JSON.stringify(['privilege_escalation']),
        blocked_patterns: '[]',
        reason:
          `SOURCE_ELEVATION_BLOCKED: tool=${options.toolName}, ` +
          `declared=${declaredSource.type}:${declaredSource.identifier} (score=${declaredScore}), ` +
          `clamped=${source.type}:${source.identifier} (score=${ceilingScore}) ` +
          `via ${detection.method} (confidence: ${detection.confidence})` +
          // Without this a same-score identity drop reads as a contradiction:
          // the scores are EQUAL, yet the claim was rejected.
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

  // No declared source — inferred from environment. Preserve the existing
  // SOURCE_MISSING visibility so operators see unconfigured callers.
  if (!declaredSource) {
    try {
      logAudit({
        memory_id: null,
        project: options.project,
        timestamp: new Date().toISOString(),
        source_type: source.type,
        source_identifier: source.identifier,
        // Record the inferred trust, not a dummy zero. This path can grant
        // cli:mcp at 0.9; logging 0 made the one high-trust grant look empty.
        trust_score: ceilingScore,
        sensitivity_level: 'PUBLIC',
        firewall_result: 'ALLOW',
        operation: null, // source-resolution meta-event, not a memory read/write/delete
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
