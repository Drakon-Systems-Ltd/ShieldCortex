/**
 * Environment-Based Source Inference Tests
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { inferSourceFromEnvironment, resolveSource } from '../trust/env-detector.js';

describe('Environment-Based Source Inference', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Clear all relevant env vars
    delete process.env.CLAUDE_CODE_ENTRYPOINT;
    delete process.env.CLAUDE_AGENT_CONTEXT;
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
      expect(result.source).toEqual({ type: 'agent', identifier: 'user-spawned>task-1' });
      expect(result.method).toBe('env:SHIELDCORTEX_AGENT_SOURCE');
      expect(result.confidence).toBe('high');
    });

    it('should handle SHIELDCORTEX_AGENT_SOURCE without type prefix', () => {
      process.env.SHIELDCORTEX_AGENT_SOURCE = 'some-agent';
      const result = inferSourceFromEnvironment();
      expect(result.source.type).toBe('agent'); // defaults to agent
      expect(result.source.identifier).toBe('some-agent');
    });

    it('should prioritise SHIELDCORTEX_AGENT_SOURCE over CLAUDE_CODE_ENTRYPOINT', () => {
      process.env.SHIELDCORTEX_AGENT_SOURCE = 'cli:custom-tool';
      process.env.CLAUDE_CODE_ENTRYPOINT = 'subagent';
      const result = inferSourceFromEnvironment();
      expect(result.source).toEqual({ type: 'cli', identifier: 'custom-tool' });
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
});
