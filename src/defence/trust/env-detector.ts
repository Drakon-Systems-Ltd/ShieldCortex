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
