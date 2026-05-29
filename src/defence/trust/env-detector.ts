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
 * 1. SHIELDCORTEX_AGENT_SOURCE — explicit override (e.g. "agent:user-spawned>task-1")
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
    const [type, ...rest] = scSource.split(':');
    const identifier = rest.join(':') || scSource;
    const validTypes = ['user', 'cli', 'hook', 'email', 'web', 'agent', 'file', 'api'] as const;
    const sourceType = validTypes.includes(type as any) ? (type as DefenceSource['type']) : 'agent';
    return {
      source: { type: sourceType, identifier },
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
  const ceilingScore = scoreSource(detection.source).score;

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
