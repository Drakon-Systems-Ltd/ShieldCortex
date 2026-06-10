/**
 * shieldcortex/scan — edge-safe, scan-only entry point.
 *
 * This module runs the PURE defence detection layers (sanitise → trust →
 * firewall → sensitivity → fragmentation → credential-leak) with NO static
 * dependency on:
 *   - better-sqlite3 (the native binding)
 *   - @huggingface/transformers (the ~349MB ML stack)
 *   - the database layer, cloud sync, the events bus, or audit persistence
 *
 * It exists so CI runners, serverless/edge functions, and integrators who only
 * need synchronous regex/heuristic scanning can `import { scan } from
 * 'shieldcortex/scan'` without pulling a native build or the ML dependency.
 *
 * Differences vs the full `runDefencePipeline` (from 'shieldcortex/defence'):
 *   - No audit row is written (auditId is always 0 — a sentinel).
 *   - No cloud sync / defence events are emitted.
 *   - The DB-backed custom firewall rules and custom injection patterns layers
 *     are ABSENT. Scan-only callers have no local DB of rules to apply, so only
 *     the built-in detection layers run. To use custom rules/patterns, use the
 *     full pipeline (which requires the database) or the SaaS API.
 *   - Fragmentation is always null: that layer correlates entities ACROSS
 *     stored memories, which is impossible without a DB. A single, stateless
 *     scan can never assemble a multi-memory fragmentation signal, so the layer
 *     is a no-op here (matching `runDefencePipeline`'s own score-0 result when
 *     no prior entities exist in the DB).
 *
 * CommonJS note: this package is ESM-only. CJS consumers can reach this entry
 * with a dynamic import: `const { scan } = await import('shieldcortex/scan')`.
 * A dedicated CJS build is a deliberate non-goal for this phase.
 *
 * IMPORTANT — DO NOT add imports that transitively pull the DB/ML stack:
 *   - import `scoreSource` from './defence/trust/source-scorer.js' directly,
 *     NOT from './defence/trust/index.js' (that re-exports resolve-tool-source,
 *     which imports the audit logger → database/init → better-sqlite3).
 *   - do NOT import './defence/pipeline.js', './defence/audit/*',
 *     './defence/fragmentation/index.js', './api/events.js', './cloud/*',
 *     './database/*', './defence/custom-rules/*', or './defence/custom-patterns/*'.
 * The src/__tests__/scan-only-entry.test.ts import-graph assertion enforces this
 * against the compiled dist output.
 */

import type {
  DefenceConfig,
  DefencePipelineResult,
  DefenceSource,
  FirewallAnalysis,
  SensitivityClassification,
  TrustScore,
} from './defence/types.js';
import { DEFAULT_DEFENCE_CONFIG } from './defence/types.js';

import { sanitiseInput } from './defence/input-sanitisation/index.js';
import { scoreSource } from './defence/trust/source-scorer.js';
import { analyzeFirewall } from './defence/firewall/index.js';
import { classifySensitivity } from './defence/sensitivity/index.js';
import { scanForCredentials } from './defence/credential-leak/index.js';

export interface ScanOptions {
  /** Optional title/context scanned alongside the content. */
  title?: string;
  /** Source attribution for trust scoring. Defaults to a generic user source. */
  source?: DefenceSource;
  /** Override the default defence config (mode, thresholds, etc.). */
  config?: DefenceConfig;
}

const DEFAULT_SOURCE: DefenceSource = { type: 'user', identifier: 'scan-only' };

/**
 * Run the pure defence pipeline on a piece of content.
 *
 * Returns a `DefencePipelineResult`-shaped object with the verdict, indicators,
 * and per-layer results — minus persistence (auditId is always 0, fragmentation
 * is always null, no DB-backed custom rules are applied).
 *
 * Fail-closed: if any layer throws, the result defaults to BLOCK.
 */
export function scan(content: string, options: ScanOptions = {}): DefencePipelineResult {
  const cfg = options.config ?? { ...DEFAULT_DEFENCE_CONFIG };
  const title = options.title ?? '';
  const source = options.source ?? DEFAULT_SOURCE;

  try {
    // 1. Input sanitisation (Layer 1) — strip dangerous bytes before analysis.
    const sanitisation = sanitiseInput(content);
    const cleanContent = sanitisation.sanitised;

    // 2. Score trust.
    const trust: TrustScore = scoreSource(source);

    // 3. Run firewall on sanitised content, feeding back the strip categories so
    // the encoding detector accounts for zero-width/bidi bytes the sanitiser
    // already removed (same contract as runDefencePipeline).
    const firewall: FirewallAnalysis = analyzeFirewall(
      cleanContent,
      title,
      source,
      trust.score,
      cfg,
      sanitisation.strippedCategories,
    );

    // Carry forward sanitisation threat indicators (deduped).
    for (const indicator of sanitisation.threatIndicators) {
      if (!firewall.threatIndicators.includes(indicator)) {
        firewall.threatIndicators.push(indicator);
      }
    }

    // 4. Classify sensitivity.
    const sensitivity: SensitivityClassification = classifySensitivity(cleanContent, title);

    // 5. Fragmentation is omitted in scan-only: it correlates entities across
    // stored memories, which requires a DB this entry deliberately avoids. With
    // no prior memories there is nothing to correlate, so the layer is null —
    // exactly what the full pipeline produces with an empty entity store.

    // 6. Credential leak detection.
    const credentialScan = scanForCredentials(cleanContent);

    // 7. Determine final decision (mirrors runDefencePipeline's precedence,
    // minus the DB-backed custom-rules/custom-patterns and fragmentation steps).
    let allowed: boolean;
    let reason: string;

    const credentialBlocked = credentialScan.findings.some(f => f.action === 'blocked');

    if (firewall.result === 'BLOCK') {
      allowed = false;
      reason = firewall.reason;
    } else if (credentialBlocked) {
      allowed = false;
      const blockedTypes = credentialScan.findings
        .filter(f => f.action === 'blocked')
        .map(f => (f.provider ? `${f.provider} ${f.type}` : f.type));
      reason = `Blocked: credential leak detected (${blockedTypes.join(', ')})`;
      firewall.result = 'BLOCK';
      if (!firewall.threatIndicators.includes('credential_leak')) {
        firewall.threatIndicators.push('credential_leak');
      }
    } else if (firewall.result === 'QUARANTINE') {
      allowed = false;
      reason = `Quarantined: ${firewall.reason}`;
    } else if (sensitivity.level === 'RESTRICTED') {
      allowed = false;
      reason = `Blocked: content classified as RESTRICTED (${sensitivity.detectedPatterns.join(', ')})`;
      firewall.result = 'BLOCK';
      firewall.reason = reason;
      if (!firewall.threatIndicators.includes('restricted_content')) {
        firewall.threatIndicators.push('restricted_content');
      }
    } else if (firewall.result !== 'ALLOW') {
      allowed = false;
      reason = `Unexpected firewall result: ${firewall.result}`;
    } else {
      allowed = true;
      reason = firewall.reason;
    }

    // Keep top-level reason and firewall.reason consistent for downstream callers.
    firewall.reason = reason;

    // Surface credential findings even when non-blocking.
    if (credentialScan.leaked && !firewall.threatIndicators.includes('credential_leak')) {
      firewall.threatIndicators.push('credential_leak');
    }

    return {
      allowed,
      firewall,
      fragmentation: null,
      sensitivity,
      trust,
      credentialScan: credentialScan.leaked ? credentialScan : undefined,
      auditId: 0,
    };
  } catch (err) {
    // FAIL-CLOSED: on error, default to BLOCK for security.
    console.error('[scan-only] Pipeline error, failing closed:', err);
    return {
      allowed: false,
      firewall: {
        result: 'BLOCK',
        reason: 'Pipeline error — fail-closed for security',
        threatIndicators: ['pipeline_error'],
        anomalyScore: 1.0,
        blockedPatterns: [],
      },
      fragmentation: null,
      sensitivity: {
        level: 'RESTRICTED',
        confidence: 0,
        detectedPatterns: [],
        redactionRequired: true,
      },
      trust: {
        score: 0,
        source,
        hierarchy: [],
      },
      auditId: 0,
    };
  }
}

/** Alias for {@link scan}. */
export const scanText = scan;

export type { DefencePipelineResult, DefenceSource, DefenceConfig } from './defence/types.js';
export { DEFAULT_DEFENCE_CONFIG } from './defence/types.js';
