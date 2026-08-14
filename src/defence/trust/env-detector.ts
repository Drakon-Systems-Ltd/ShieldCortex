/**
 * Environment-Based Source Inference
 *
 * Detects caller identity from process environment variables instead of
 * relying on the MCP client to self-declare. The MCP server process inherits
 * the parent's environment, which isn't forgeable via MCP tool parameters.
 *
 * This addresses Phase 1 limitation: "security is opt-in" — with env detection,
 * Claude Code agents get correct trust automatically with zero configuration.
 */

import type { DefenceSource } from '../types.js';
import { scoreSource } from './source-scorer.js';

/** Highest trust an integrator env string may confer. Host-attested rungs sit above this. */
export const ENV_OVERRIDE_SCORE_CAP = 0.5;

const ENV_OVERRIDE_ORIGIN = 'env-override';

/** Rungs the host process attests, never a caller-controlled string. These remap to `agent`. */
type HostOnlySourceType = 'user' | 'cli';

const HOST_ONLY_TYPES: ReadonlySet<string> = new Set<HostOnlySourceType>(['user', 'cli']);

/** Every DefenceSource type an integrator env string is allowed to keep. */
type OverrideSourceType = Exclude<DefenceSource['type'], HostOnlySourceType>;

/**
 * Runtime allowlist, derived from `DefenceSource['type']` rather than hand-listed.
 *
 * The `Record<OverrideSourceType, true>` annotation is the completeness check:
 * it must name EVERY non-host type, so adding a member to `DefenceSource['type']`
 * fails to compile here until that member is classified. A hand-maintained list
 * silently omitted `tool_response`, which let `tool_response:browser` fall
 * through to `agent:browser` — 0.3 and inbound-EXEMPT, i.e. strictly weaker than
 * the 0.5 inbound-blocked row an honest stamp produces.
 */
const OVERRIDE_TYPE_TABLE: Record<OverrideSourceType, true> = {
  hook: true,
  email: true,
  web: true,
  agent: true,
  file: true,
  api: true,
  tool_response: true,
};

const OVERRIDE_TYPES: ReadonlySet<string> = new Set(Object.keys(OVERRIDE_TYPE_TABLE));

/** Stamp env provenance onto an identifier, idempotently. */
function withOverrideOrigin(identifier: string): string {
  return identifier.startsWith(`${ENV_OVERRIDE_ORIGIN}>`)
    ? identifier
    : `${ENV_OVERRIDE_ORIGIN}>${identifier}`;
}

/**
 * #283 — below-cap integrator claims must not collide with a host-attested
 * `${type}:${identifier}` ACL key, and must not raise trust. `env-override>`
 * pins at 0.5 (the cap); below-cap uses `env-claim>` pinned at 0.3.
 *
 * Stamps **agent** below-cap claims (the inbound-exempt type). Other below-cap
 * types (email/web) stay bare — they are already inbound-blocked by type and
 * do not inherit the agent ownership exemption. At-cap non-agent claims still
 * get env-override> so they cannot wear host tool_response:/agent:cron keys.
 */
const ENV_CLAIM_ORIGIN = 'env-claim';

function withEnvClaimOrigin(identifier: string): string {
  const lower = identifier.toLowerCase();
  if (
    lower.startsWith(`${ENV_CLAIM_ORIGIN}>`)
    || lower.startsWith(`${ENV_OVERRIDE_ORIGIN}>`)
    || lower.startsWith('unattested>')
  ) {
    return identifier;
  }
  return `${ENV_CLAIM_ORIGIN}>${identifier}`;
}

/**
 * Bind a SHIELDCORTEX_AGENT_SOURCE claim to an identity scoreSource will
 * actually honour at ≤ ENV_OVERRIDE_SCORE_CAP. Pipeline / store / ACL all
 * re-score from type+identifier, so a ceiling-number-only clamp would leave
 * `agent:user-spawned` at 0.9 on the write path.
 *
 * Three bands, by the score the claimed identity actually earns:
 *
 * - **Below the cap** — keep type and identifier verbatim. Stamping provenance
 *   here would RAISE trust (`agent:some-agent` 0.3 → `env-override>` 0.5).
 * - **Exactly at the cap** — keep the type (it is already capped, and the type
 *   carries the inbound-untrusted decision), but stamp the identifier. A bare
 *   `agent:cron` / `tool_response:browser` is indistinguishable from the
 *   host-attested `${type}:${identifier}` ACL key of a real scheduler or tool
 *   response; the prefix keeps the score at 0.5 while making the row's env
 *   provenance legible to the ACL and the audit ledger.
 * - **Above the cap** — rebind onto the agent hierarchy at `env-override>…`,
 *   which `scoreAgent` pins at 0.5.
 */
export function bindIntegratorOverrideSource(
  claimedType: string,
  identifier: string,
): DefenceSource {
  // Env input is an open string. Completeness over DefenceSource cannot see
  // TOOL_RESPONSE / mystery / typos. Lowercase first (same as
  // isUntrustedInboundType) and never fall through to `agent` — that is the
  // only inbound-exempt type.
  const normalised = claimedType.trim().toLowerCase();
  let sourceType: DefenceSource['type'];
  if (HOST_ONLY_TYPES.has(normalised)) {
    sourceType = 'agent';
  } else if (OVERRIDE_TYPES.has(normalised)) {
    sourceType = normalised as OverrideSourceType;
  } else {
    return {
      type: 'web',
      identifier: `unrecognised>${normalised || claimedType}:${identifier}`,
    };
  }
  const candidate: DefenceSource = { type: sourceType, identifier };
  const score = scoreSource(candidate).score;

  if (score < ENV_OVERRIDE_SCORE_CAP) {
    // #283: bare below-cap agent claims used to keep `agent:browser` verbatim,
    // so checkAccess treated them as OWNER of host-attested agent:browser rows
    // and guardReadBySensitivity treated type=agent as inbound-exempt. Stamp
    // without raising score (env-claim → 0.3, never env-override → 0.5).
    if (sourceType === 'agent') {
      return { type: 'agent', identifier: withEnvClaimOrigin(identifier) };
    }
    return candidate;
  }
  if (score === ENV_OVERRIDE_SCORE_CAP) {
    return { type: sourceType, identifier: withOverrideOrigin(identifier) };
  }
  return {
    type: 'agent',
    identifier: sourceType === 'agent'
      ? withOverrideOrigin(identifier)
      : withOverrideOrigin(`${sourceType}:${identifier}`),
  };
}

export interface EnvDetectionResult {
  source: DefenceSource;
  method:
    | 'env:CLAUDE_CODE_ENTRYPOINT'
    | 'env:CLAUDE_AGENT_CONTEXT'
    | 'env:CODEX_INTERNAL_ORIGINATOR_OVERRIDE'
    | 'env:CODEX_THREAD_ID'
    | 'env:SHIELDCORTEX_AGENT_SOURCE'
    | 'default';
  confidence: 'high' | 'medium' | 'low';
}

/**
 * Infer caller source from process environment variables.
 *
 * Priority order:
 * 1. SHIELDCORTEX_AGENT_SOURCE — explicit override label. May name the
 *    process (e.g. "agent:user-spawned>task-1") but cannot outrank 0.5.
 * 2. CLAUDE_CODE_ENTRYPOINT=subagent — Claude Code sub-agent
 * 3. CLAUDE_AGENT_CONTEXT — generic agent context marker
 * 4. Codex origin / thread vars — Codex CLI or VS Code extension
 * 5. CLAUDE_CODE_ENTRYPOINT present (any value) — direct Claude Code CLI
 * 6. No recognised env vars → agent:unknown (trust ~0.3, treated as untrusted agent)
 */
export function inferSourceFromEnvironment(): EnvDetectionResult {
  // 1. Explicit ShieldCortex source override (for integrators)
  const scSource = process.env.SHIELDCORTEX_AGENT_SOURCE;
  if (scSource) {
    const colon = scSource.indexOf(':');
    // Bare token (no `:`) is the documented "defaults to agent" form.
    // A typed claim (`type:identifier`) is classified by bind — unknown
    // types must not inherit that default, or `mystery:x` becomes agent:x.
    const bound = colon === -1
      ? bindIntegratorOverrideSource('agent', scSource)
      : bindIntegratorOverrideSource(
          scSource.slice(0, colon),
          scSource.slice(colon + 1) || scSource,
        );
    // Integrator override labels the process. It is not a host attestation.
    // `user` and `cli` remap to `agent` (operator/CLI rungs are host-only).
    // Any remaining claim that would score above 0.5 — including the
    // documented `agent:user-spawned` 0.9 origin, plus hook/api residuals —
    // is rebound to `agent:env-override>…` so scoreSource itself is ≤0.5.
    // Claims that land exactly on 0.5 keep their type (so `tool_response`
    // stays inbound-blocked) but carry an `env-override>` identifier so they
    // cannot impersonate a host-attested `agent:cron` / `tool_response:*` row.
    return {
      source: bound,
      method: 'env:SHIELDCORTEX_AGENT_SOURCE',
      confidence: 'high',
    };
  }

  // 2. Claude Code sub-agent
  if (process.env.CLAUDE_CODE_ENTRYPOINT === 'subagent') {
    return {
      source: { type: 'agent', identifier: 'agent-spawned' },
      method: 'env:CLAUDE_CODE_ENTRYPOINT',
      confidence: 'high',
    };
  }

  // 3. Generic agent context
  const agentCtx = process.env.CLAUDE_AGENT_CONTEXT;
  if (agentCtx) {
    const identifier = agentCtx === 'subagent' ? 'agent-spawned' :
                       agentCtx === 'hook' ? 'hook' :
                       `agent-context:${agentCtx}`;
    return {
      source: { type: 'agent', identifier },
      method: 'env:CLAUDE_AGENT_CONTEXT',
      confidence: 'medium',
    };
  }

  // 4. Codex CLI / IDE extension
  const codexOrigin = process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE;
  if (codexOrigin) {
    const identifier = codexOrigin === 'codex_vscode' ? 'codex-vscode' : `codex:${codexOrigin}`;
    return {
      source: { type: 'cli', identifier },
      method: 'env:CODEX_INTERNAL_ORIGINATOR_OVERRIDE',
      confidence: 'high',
    };
  }

  if (process.env.CODEX_THREAD_ID || process.env.CODEX_CI) {
    return {
      source: { type: 'cli', identifier: process.env.CODEX_THREAD_ID ? 'codex-cli' : 'codex-ci' },
      method: 'env:CODEX_THREAD_ID',
      confidence: 'medium',
    };
  }

  // 5. Direct Claude Code CLI (entrypoint present but not subagent)
  if (process.env.CLAUDE_CODE_ENTRYPOINT) {
    return {
      source: { type: 'cli', identifier: 'mcp' },
      method: 'env:CLAUDE_CODE_ENTRYPOINT',
      confidence: 'high',
    };
  }

  // 6. No recognised env vars — unknown caller (use 'agent' type for lower trust)
  return {
    source: { type: 'agent', identifier: 'unknown' },
    method: 'default',
    confidence: 'low',
  };
}

/**
 * Resolve the effective source for an MCP tool call.
 *
 * If the caller explicitly passes a source, use it.
 * Otherwise, infer from environment.
 *
 * @param declaredSource - Source passed by the MCP client (may be undefined)
 * @param strictMode - If true, unknown sources get lower trust
 * @returns The resolved source and whether it was inferred
 */
export function resolveSource(
  declaredSource?: DefenceSource,
  strictMode: boolean = false,
): { source: DefenceSource; inferred: boolean; detection?: EnvDetectionResult } {
  if (declaredSource) {
    return { source: declaredSource, inferred: false };
  }

  const detection = inferSourceFromEnvironment();

  // In strict mode, downgrade unknown sources
  if (strictMode && detection.method === 'default') {
    return {
      source: { type: 'agent', identifier: 'unknown:strict' },
      inferred: true,
      detection,
    };
  }

  return {
    source: detection.source,
    inferred: true,
    detection,
  };
}

export interface CeilingClampResult {
  /** The effective source after clamping (declared if safe, env-inferred otherwise). */
  source: DefenceSource;
  /** True when the declared source claimed higher trust than the runtime environment justifies. */
  clamped: boolean;
  /** Trust score of the declared source (only meaningful when a declared source was passed). */
  declaredScore: number | null;
  /** Trust score the runtime environment actually permits. */
  ceilingScore: number;
  /** The environment-inferred source used as the trust ceiling. */
  ceiling: DefenceSource;
  /** Detection metadata for the environment inference. */
  detection: EnvDetectionResult;
}

/**
 * Clamp a caller-declared source against the environment-inferred trust ceiling.
 *
 * MCP callers are arbitrary processes — a prompt-injected agent could claim
 * `{type:'user', identifier:'direct'}` to get trust=1.0 and bypass quarantine.
 * To prevent that, we compute the highest trust the actual runtime allows
 * (from env vars like CLAUDE_CODE_ENTRYPOINT) and refuse any declared source
 * that would score higher.
 *
 * Semantics:
 * - If no declared source: return env-inferred (no clamping).
 * - If declaredScore <= ceilingScore: trust the declared source (allows
 *   legitimate downgrades, e.g. an agent labelling input as `email`).
 * - If declaredScore > ceilingScore: drop the declared source and use the
 *   env-inferred one, with `clamped: true` so the caller can audit it.
 */
export function clampSourceToCeiling(
  declaredSource: DefenceSource | undefined,
): CeilingClampResult {
  const detection = inferSourceFromEnvironment();
  const rawCeiling = scoreSource(detection.source).score;
  const ceilingScore = detection.method === 'env:SHIELDCORTEX_AGENT_SOURCE'
    ? Math.min(rawCeiling, ENV_OVERRIDE_SCORE_CAP)
    : rawCeiling;

  if (!declaredSource) {
    return {
      source: detection.source,
      clamped: false,
      declaredScore: null,
      ceilingScore,
      ceiling: detection.source,
      detection,
    };
  }

  const declaredScore = scoreSource(declaredSource).score;
  if (declaredScore > ceilingScore) {
    return {
      source: detection.source,
      clamped: true,
      declaredScore,
      ceilingScore,
      ceiling: detection.source,
      detection,
    };
  }

  return {
    source: declaredSource,
    clamped: false,
    declaredScore,
    ceilingScore,
    ceiling: detection.source,
    detection,
  };
}
