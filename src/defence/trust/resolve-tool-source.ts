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
 * 6. Rewrites any identity the ENVIRONMENT did not confirm into the `claimed>`
 *    keyspace, so a below-ceiling self-declaration (`hook:session-end` 0.8 on a
 *    `cli:*` 0.9 host) can never own, delete or hierarchy-revoke the rows of the
 *    real holder of that name, and writes a `SOURCE_UNATTESTED_CLAIM` audit row
 *    (#283). The stamp does not change the trust score, and it does not depend
 *    on strictSourceMode — see `deriveEnvConfirmed` vs `deriveAttested`.
 */

import type { DefenceSource } from '../types.js';
import { clampSourceToCeiling } from './env-detector.js';
import { logAudit } from '../audit/logger.js';
import { getStrictSourceMode } from '../../cloud/config.js';
import { markUnattestedIdentifier } from './attestation.js';

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
 * Did the ENVIRONMENT confirm this identity? Pure, exported for exhaustive
 * unit testing.
 *
 * This is the physical question — "did anything other than the writer vouch
 * for this name?" — and it is the ONLY input to the `claimed>` ownership stamp.
 * Deliberately NOT a function of strictSourceMode: strict mode is an operator
 * posture toggle, not a source of evidence, and a mode that hardens
 * consequences must not be the thing that hands a writer-chosen name the
 * ownership key it could not earn otherwise (#283 strict path).
 */
export function deriveEnvConfirmed(input: {
  declared: DefenceSource | undefined;
  clamped: boolean;
  envInferred?: DefenceSource;
}): boolean {
  // Nothing declared — the identity IS the environment inference.
  if (!input.declared) return true;
  // Over-claim rejected: the identity we return is the env ceiling, not theirs.
  if (input.clamped) return true;
  // Declared exactly what the environment independently inferred.
  return !!(
    input.envInferred
    && input.declared.type === input.envInferred.type
    && input.declared.identifier === input.envInferred.identifier
  );
}

/**
 * Pure attestation derivation (exported for exhaustive unit testing).
 *
 * This is the LEDGER bit — it rides to `defence_audit.source_attested` and
 * gates threat-graph risk accrual and graph conflict trust. strictSourceMode
 * does not verify identities, but it is the operator's opt-in to hardened
 * consequences (unknown sources score 0.3, sub-trust writes auto-quarantine),
 * so risk-based trust penalties keyed on claimed identities are part of the
 * posture they chose — hence strict still attests here.
 *
 * That is precisely why this bit must NOT drive the ownership stamp: see
 * `deriveEnvConfirmed`. Under strict, ownership keys on env-confirmation while
 * the ledger keeps its wider meaning, and the two no longer have to agree.
 */
export function deriveAttested(input: {
  declared: DefenceSource | undefined;
  resolved: DefenceSource;
  clamped: boolean;
  strict: boolean;
  envInferred?: DefenceSource;
}): boolean {
  if (input.strict) return true;
  return deriveEnvConfirmed(input);
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

  const envConfirmed = deriveEnvConfirmed({
    declared: declaredSource,
    clamped,
    envInferred: env,
  });
  const attested = deriveAttested({
    declared: declaredSource,
    resolved: source,
    clamped,
    strict,
    envInferred: env,
  });

  // #283: an env-unconfirmed identity is writer-chosen. Move it into a disjoint
  // keyspace BEFORE it leaves this function, so every downstream consumer —
  // the stored `source` string, the `checkAccess` caller key shared by
  // read/delete/revoke, and the read guards — inherits the same stamp from one
  // place. `scoreSource` strips the marker, so trust is unchanged.
  //
  // Keyed on env-confirmation, NOT on `attested`: strict attests everything for
  // the ledger, and keying the stamp there let strictSourceMode — the hardened
  // posture — be the one place a writer-chosen `hook:session-end` kept the
  // ownership key on every default `cli:*` 0.9 host.
  if (!envConfirmed) {
    source = { type: source.type, identifier: markUnattestedIdentifier(source.identifier) };
    try {
      logAudit({
        memory_id: null,
        project: options.project,
        timestamp: new Date().toISOString(),
        source_type: source.type,
        source_identifier: source.identifier,
        trust_score: declaredScore ?? ceilingScore,
        sensitivity_level: 'PUBLIC',
        firewall_result: 'ALLOW',
        operation: null, // source-resolution meta-event, not a memory read/write/delete
        anomaly_score: 0,
        threat_indicators: JSON.stringify(['unattested_identity']),
        blocked_patterns: '[]',
        reason:
          `SOURCE_UNATTESTED_CLAIM: tool=${options.toolName}, ` +
          `declared=${declaredSource?.type}:${declaredSource?.identifier} (score=${declaredScore}), ` +
          `bound=${source.type}:${source.identifier} — below the ${detection.method} ` +
          `ceiling ${ceilingScore}, so the environment never confirmed it; ` +
          `ownership is keyed on the stamped identity, not the claimed name`,
        fragmentation_score: null,
        pipeline_duration_ms: null,
      });
    } catch {
      // Audit logging must never break tool execution.
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
