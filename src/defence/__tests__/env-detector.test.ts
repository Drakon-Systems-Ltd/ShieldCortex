/**
 * Environment-Based Source Inference Tests
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { inferSourceFromEnvironment, resolveSource, clampSourceToCeiling } from '../trust/env-detector.js';
import { scoreSource } from '../trust/source-scorer.js';

// Mock the audit logger before importing resolve-tool-source so we can assert
// SOURCE_ELEVATION_BLOCKED rows get written without needing a real database.
// The repo is ESM-only; use unstable_mockModule + top-level await import.
jest.unstable_mockModule('../audit/logger.js', () => ({
  logAudit: jest.fn(() => 1),
  createContentHash: jest.fn(() => 'hash'),
}));

const { logAudit } = (await import('../audit/logger.js')) as { logAudit: jest.Mock };
const { resolveToolSource } = await import('../trust/resolve-tool-source.js');

describe('Environment-Based Source Inference', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Clear all relevant env vars
    delete process.env.CLAUDE_CODE_ENTRYPOINT;
    delete process.env.CLAUDE_AGENT_CONTEXT;
    delete process.env.CODEX_CI;
    delete process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE;
    delete process.env.CODEX_THREAD_ID;
    delete process.env.SHIELDCORTEX_AGENT_SOURCE;
  });

  afterEach(() => {
    // Restore original env
    process.env = { ...originalEnv };
  });

  describe('inferSourceFromEnvironment', () => {
    it('should detect direct Claude Code CLI', () => {
      process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
      const result = inferSourceFromEnvironment();
      expect(result.source).toEqual({ type: 'cli', identifier: 'mcp' });
      expect(result.method).toBe('env:CLAUDE_CODE_ENTRYPOINT');
      expect(result.confidence).toBe('high');
    });

    it('should detect Claude Code sub-agent', () => {
      process.env.CLAUDE_CODE_ENTRYPOINT = 'subagent';
      const result = inferSourceFromEnvironment();
      expect(result.source).toEqual({ type: 'agent', identifier: 'agent-spawned' });
      expect(result.confidence).toBe('high');
    });

    it('should detect CLAUDE_AGENT_CONTEXT=subagent', () => {
      process.env.CLAUDE_AGENT_CONTEXT = 'subagent';
      const result = inferSourceFromEnvironment();
      expect(result.source.type).toBe('agent');
      expect(result.source.identifier).toBe('agent-spawned');
      expect(result.method).toBe('env:CLAUDE_AGENT_CONTEXT');
    });

    it('should detect CLAUDE_AGENT_CONTEXT=hook', () => {
      process.env.CLAUDE_AGENT_CONTEXT = 'hook';
      const result = inferSourceFromEnvironment();
      expect(result.source.identifier).toBe('hook');
    });

    it('should parse SHIELDCORTEX_AGENT_SOURCE with type prefix', () => {
      process.env.SHIELDCORTEX_AGENT_SOURCE = 'agent:user-spawned>task-1';
      const result = inferSourceFromEnvironment();
      // Documented label is kept as a suffix; origin is rebound so the
      // identity itself cannot score parent-tier 0.63/0.9.
      expect(result.source).toEqual({ type: 'agent', identifier: 'env-override>user-spawned>task-1' });
      expect(result.method).toBe('env:SHIELDCORTEX_AGENT_SOURCE');
      expect(result.confidence).toBe('high');
      expect(scoreSource(result.source).score).toBe(0.5);
    });

    it('should handle SHIELDCORTEX_AGENT_SOURCE without type prefix', () => {
      process.env.SHIELDCORTEX_AGENT_SOURCE = 'some-agent';
      const result = inferSourceFromEnvironment();
      expect(result.source.type).toBe('agent'); // defaults to agent
      expect(result.source.identifier).toBe('some-agent');
    });

    it('should prioritise SHIELDCORTEX_AGENT_SOURCE over CLAUDE_CODE_ENTRYPOINT', () => {
      process.env.SHIELDCORTEX_AGENT_SOURCE = 'agent:custom-tool';
      process.env.CLAUDE_CODE_ENTRYPOINT = 'subagent';
      const result = inferSourceFromEnvironment();
      expect(result.source).toEqual({ type: 'agent', identifier: 'custom-tool' });
    });

    it('refuses operator and CLI types on the integrator override — they cannot become the ceiling', () => {
      for (const claimed of ['user:direct', 'user:approved', 'cli:mcp'] as const) {
        process.env.SHIELDCORTEX_AGENT_SOURCE = claimed;
        const inferred = inferSourceFromEnvironment();
        expect(inferred.source.type).toBe('agent');
        expect(inferred.method).toBe('env:SHIELDCORTEX_AGENT_SOURCE');
        const clamp = clampSourceToCeiling(undefined);
        expect(clamp.clamped).toBe(false);
        expect(clamp.source.type).toBe('agent');
        expect(scoreSource(clamp.source).score).toBeLessThanOrEqual(0.5);
        expect(clamp.ceilingScore).toBe(scoreSource(clamp.source).score);
      }
    });

    it('caps agent:user-spawned, hook, and api env claims at 0.5 — identity re-score included', () => {
      const cases: Array<{ env: string; note: string }> = [
        { env: 'agent:user-spawned', note: 'parent-tier agent origin' },
        { env: 'agent:user-spawned>task-1', note: 'documented integrator form' },
        { env: 'hook:x', note: 'hook residual' },
        { env: 'api:x', note: 'api residual' },
      ];
      for (const { env } of cases) {
        process.env.SHIELDCORTEX_AGENT_SOURCE = env;
        const clamp = clampSourceToCeiling(undefined);
        expect(clamp.clamped).toBe(false);
        expect(clamp.ceilingScore).toBeLessThanOrEqual(0.5);
        expect(scoreSource(clamp.source).score).toBe(clamp.ceilingScore);
        expect(scoreSource(clamp.source).score).toBeLessThanOrEqual(0.5);
        expect(clamp.source).not.toEqual({ type: 'agent', identifier: 'user-spawned' });
        expect(clamp.detection.method).toBe('env:SHIELDCORTEX_AGENT_SOURCE');
      }
    });

    it('keeps already-low override identities (no wrap, no raise)', () => {
      process.env.SHIELDCORTEX_AGENT_SOURCE = 'agent:some-agent';
      const inferred = inferSourceFromEnvironment();
      expect(inferred.source).toEqual({ type: 'agent', identifier: 'some-agent' });
      expect(scoreSource(inferred.source).score).toBe(0.3);
    });

    it('should return unknown:default with low confidence when no env vars set', () => {
      const result = inferSourceFromEnvironment();
      // Unknown sources default to 'agent' type for lower trust (security fix)
      expect(result.source).toEqual({ type: 'agent', identifier: 'unknown' });
      expect(result.method).toBe('default');
      expect(result.confidence).toBe('low');
    });
  });

  describe('resolveSource', () => {
    it('should use declared source when provided', () => {
      const declared = { type: 'agent' as const, identifier: 'user-spawned>task-1' };
      const result = resolveSource(declared);
      expect(result.source).toEqual(declared);
      expect(result.inferred).toBe(false);
      expect(result.detection).toBeUndefined();
    });

    it('should infer from environment when no source declared', () => {
      process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
      const result = resolveSource(undefined);
      expect(result.source).toEqual({ type: 'cli', identifier: 'mcp' });
      expect(result.inferred).toBe(true);
      expect(result.detection).toBeDefined();
    });

    it('should downgrade unknown sources in strict mode', () => {
      // No env vars → unknown
      const result = resolveSource(undefined, true);
      expect(result.source).toEqual({ type: 'agent', identifier: 'unknown:strict' });
      expect(result.inferred).toBe(true);
    });

    it('should not downgrade env-detected sources in strict mode', () => {
      process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
      const result = resolveSource(undefined, true);
      // Not default method, so no downgrade
      expect(result.source).toEqual({ type: 'cli', identifier: 'mcp' });
    });
  });

  describe('clampSourceToCeiling', () => {
    it('clamps a caller-declared user:direct source under a sub-agent env', () => {
      process.env.CLAUDE_CODE_ENTRYPOINT = 'subagent';
      const declared = { type: 'user' as const, identifier: 'direct' };

      const result = clampSourceToCeiling(declared);

      expect(result.clamped).toBe(true);
      expect(result.source).toEqual({ type: 'agent', identifier: 'agent-spawned' });
      expect(result.declaredScore).toBe(scoreSource(declared).score);
      expect(result.ceilingScore).toBe(
        scoreSource({ type: 'agent', identifier: 'agent-spawned' }).score,
      );
      expect(result.declaredScore).toBeGreaterThan(result.ceilingScore);
    });

    it('does not clamp when declared trust is at or below the ceiling', () => {
      process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
      const declared = { type: 'agent' as const, identifier: 'user-spawned>task-1' };

      const result = clampSourceToCeiling(declared);

      expect(result.clamped).toBe(false);
      expect(result.source).toEqual(declared);
    });

    it('returns env-inferred source when no declared source is passed', () => {
      process.env.CLAUDE_CODE_ENTRYPOINT = 'subagent';

      const result = clampSourceToCeiling(undefined);

      expect(result.clamped).toBe(false);
      expect(result.declaredScore).toBeNull();
      expect(result.source).toEqual({ type: 'agent', identifier: 'agent-spawned' });
    });
  });

  describe('resolveToolSource', () => {
    beforeEach(() => {
      logAudit.mockClear();
    });

    it('drops a caller-claimed user:direct under a sub-agent env and writes SOURCE_ELEVATION_BLOCKED', () => {
      process.env.CLAUDE_CODE_ENTRYPOINT = 'subagent';

      const resolved = resolveToolSource(
        { type: 'user', identifier: 'direct' },
        { toolName: 'remember', project: 'test-project' },
      );

      expect(resolved.source).toEqual({ type: 'agent', identifier: 'agent-spawned' });
      // A rejected over-claim resolves to the env identity — attested.
      expect(resolved.attested).toBe(true);
      expect(resolved.clamped).toBe(true);
      expect(logAudit).toHaveBeenCalledTimes(1);
      const entry = logAudit.mock.calls[0][0] as {
        firewall_result: string;
        reason: string;
        threat_indicators: string;
        project: string | null;
      };
      expect(entry.firewall_result).toBe('BLOCK');
      expect(entry.reason).toContain('SOURCE_ELEVATION_BLOCKED');
      expect(entry.reason).toContain('tool=remember');
      expect(entry.reason).toContain('declared=user:direct');
      expect(entry.threat_indicators).toContain('privilege_escalation');
      expect(entry.project).toBe('test-project');
    });

    it('honours declared sources that score at or below the env ceiling', () => {
      process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
      const declared = { type: 'agent' as const, identifier: 'user-spawned>task-1' };

      const resolved = resolveToolSource(declared, {
        toolName: 'recall',
        project: null,
        strict: false,
      });

      expect(resolved.source).toEqual(declared);
      // An accepted self-declaration is honoured but not attested.
      expect(resolved.attested).toBe(false);
      expect(logAudit).not.toHaveBeenCalled();
    });

    it('writes a SOURCE_MISSING audit row when no source is declared', () => {
      process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';

      const resolved = resolveToolSource(undefined, {
        toolName: 'recall',
        project: null,
      });

      expect(resolved.source).toEqual({ type: 'cli', identifier: 'mcp' });
      // Env-inferred identity — attested.
      expect(resolved.attested).toBe(true);
      expect(logAudit).toHaveBeenCalledTimes(1);
      const entry = logAudit.mock.calls[0][0] as { firewall_result: string; reason: string; trust_score: number };
      expect(entry.firewall_result).toBe('ALLOW');
      expect(entry.reason).toContain('SOURCE_MISSING');
      expect(entry.trust_score).toBe(scoreSource({ type: 'cli', identifier: 'mcp' }).score);
    });

    it('does not grant user:direct from SHIELDCORTEX_AGENT_SOURCE with no declared source', () => {
      process.env.SHIELDCORTEX_AGENT_SOURCE = 'user:direct';

      const resolved = resolveToolSource(undefined, {
        toolName: 'recall',
        project: null,
      });

      expect(resolved.source.type).toBe('agent');
      expect(resolved.source).not.toEqual({ type: 'user', identifier: 'direct' });
      expect(scoreSource(resolved.source).score).toBeLessThan(1);
      const entry = logAudit.mock.calls[0][0] as { trust_score: number };
      expect(entry.trust_score).toBe(scoreSource(resolved.source).score);
      expect(entry.trust_score).not.toBe(0);
    });

    it('does not grant agent:user-spawned 0.9 from the integrator override', () => {
      process.env.SHIELDCORTEX_AGENT_SOURCE = 'agent:user-spawned';

      const resolved = resolveToolSource(undefined, {
        toolName: 'remember',
        project: null,
      });

      expect(scoreSource(resolved.source).score).toBeLessThanOrEqual(0.5);
      const entry = logAudit.mock.calls[0][0] as { trust_score: number };
      expect(entry.trust_score).toBe(scoreSource(resolved.source).score);
      expect(entry.trust_score).toBeLessThanOrEqual(0.5);
    });
  });
});
