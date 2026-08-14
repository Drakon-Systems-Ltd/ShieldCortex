/**
 * Resolve and harden the source of an MCP tool call.
 *
 * MCP callers can self-declare any source they like. This module:
 * 1. Always computes the environment-inferred trust ceiling first.
 * 2. Clamps any over-claimed declared source down to that ceiling.
 * 3. Drops a same-score identity that the environment did not confirm
 *    (owner spoof / operator spoof). A genuine trust downgrade is kept.
 * 4. Writes a `SOURCE_ELEVATION_BLOCKED` row to defence_audit when a clamp
 *    happens, so operators can spot prompt-injection trying to escalate
 *    its own trust or wear another agent's name.
 * 5. Writes a `SOURCE_MISSING` row when no source was declared, preserving
 *    the existing visibility into unconfigured callers.
 * 6. Stamps any identity the environment did not confirm, so `checkAccess`
 *    cannot mistake a declaration for the host-attested identity of the same
 *    name, and writes a `SOURCE_UNATTESTED` row for it. The clamp only asks
 *    whether a claim OUTSCORES the environment; a below-ceiling claim
 *    (`hook:session-end` at 0.8 under a `cli:*` 0.9 ceiling) is not an
 *    over-claim, yet it wore the real hook's name for free. See
 *    ./attestation-stamp.ts.
 */

import type { DefenceSource } from '../types.js';
import { applyOwnershipStamp } from './attestation-stamp.js';
import { clampSourceToCeiling } from './env-detector.js';
import { logAudit } from '../audit/logger.js';
import { getStrictSourceMode } from '../../cloud/config.js';

export interface ResolveToolSourceOptions {
  /** Tool name (e.g. 'remember', 'recall') — recorded in the audit reason. */
  toolName: string;
  /** Active project scope, recorded on the audit row. */
  project: string | null;
  /** Test seam / override; defaults to the config-file strictSourceMode. */
  strict?: boolean;
}

export interface ResolvedToolSource {
  /**
   * The identity the rest of the pipeline uses. Carries the ownership stamp when
   * the environment did not confirm it, so the ACL cannot mistake a declaration
   * for the host-attested identity of the same name.
   */
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
  /**
   * Did the ENVIRONMENT confirm this identity — the question ownership needs.
   *
   * Deliberately not the same predicate as `attested`. `attested` folds in
   * strictSourceMode, which is an operator's opt-in to hardened CONSEQUENCES
   * (risk accrual keyed on claimed identities); treating a declaration as
   * confirmed is defensible there. It is not defensible for ownership: under
   * strict mode a declared `hook:session-end` would otherwise own the real
   * hook's RESTRICTED rows, i.e. the hardened posture would carry the hole the
   * default one does. Ownership therefore asks only about the environment.
   */
  envConfirmed: boolean;
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

/**
 * Pure environment-confirmation derivation (exported for exhaustive testing).
 *
 * True when the resolved identity came FROM the host environment rather than
 * from the caller: nothing declared, an over-claim we replaced with the
 * env-inferred source, or a declaration the environment independently produced.
 * Unlike `deriveAttested` this ignores strictSourceMode — see
 * `ResolvedToolSource.envConfirmed`.
 */
export function deriveEnvConfirmed(input: {
  declared: DefenceSource | undefined;
  clamped: boolean;
  envInferred: DefenceSource;
}): boolean {
  if (!input.declared) return true;
  if (input.clamped) return true;
  return (
    input.declared.type === input.envInferred.type
    && input.declared.identifier === input.envInferred.identifier
  );
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
  // Genuine downgrades (file:import 0.4 < cli:mcp 0.9) stay honoured.
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
  const envConfirmed = deriveEnvConfirmed({ declared: declaredSource, clamped, envInferred: env });

  // Fed ONCE, here. Everything downstream — the stored `source` string, the
  // `checkAccess` caller key, the threat-graph node key — derives from this
  // source, so read / delete / revoke cannot drift apart on ownership.
  source = applyOwnershipStamp(source, envConfirmed);

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
    return { source, attested, clamped, envConfirmed };
  }

  // Declared, within the ceiling, but the environment never produced this
  // identity. Previously the quietest path in the resolver: honoured verbatim,
  // no audit row, and — before the ownership stamp — owning the host-attested
  // rows of whatever name it declared. Record it so the ledger distinguishes a
  // self-declared identity from a confirmed one.
  if (declaredSource && !envConfirmed) {
    try {
      logAudit({
        memory_id: null,
        project: options.project,
        timestamp: new Date().toISOString(),
        source_type: source.type,
        source_identifier: source.identifier,
        // Non-null whenever a source was declared; the fallback only satisfies
        // the type, it is unreachable inside this branch.
        trust_score: declaredScore ?? ceilingScore,
        sensitivity_level: 'PUBLIC',
        // ALLOW, not BLOCK: the declaration is honoured (a downgrade is a
        // legitimate feature). Only its ownership is namespaced.
        firewall_result: 'ALLOW',
        operation: null, // source-resolution meta-event, not a memory read/write/delete
        anomaly_score: 0,
        threat_indicators: '[]',
        blocked_patterns: '[]',
        reason:
          `SOURCE_UNATTESTED: tool=${options.toolName}, ` +
          `declared=${declaredSource.type}:${declaredSource.identifier} (score=${declaredScore}), ` +
          `keyed=${source.type}:${source.identifier} — environment inferred ` +
          `${env.type}:${env.identifier} via ${detection.method} ` +
          `(confidence: ${detection.confidence}), so the declared identity owns only its own writes`,
        fragmentation_score: null,
        pipeline_duration_ms: null,
      });
    } catch {
      // Audit logging must never break tool execution.
    }
    return { source, attested, clamped, envConfirmed };
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

  return { source, attested, clamped, envConfirmed };
}
