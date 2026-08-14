/**
 * Agent Trust Scorer Tests
 */

import { describe, it, expect } from '@jest/globals';
import { scoreAgent, getAgentDepth, buildAgentHierarchy, DEFAULT_AGENT_CONFIG } from '../trust/agent-scorer.js';

describe('Agent Trust Scorer', () => {
  describe('scoreAgent', () => {
    it('should score user-spawned parent at 0.9', () => {
      expect(scoreAgent('user-spawned')).toBe(0.9);
    });

    it('should decay by 0.7 per generation', () => {
      expect(scoreAgent('user-spawned>task-1')).toBe(0.63);
      expect(scoreAgent('user-spawned>task-1>subtask')).toBe(0.441);
    });

    it('should score env-override origin at 0.5 even with a parent-tier suffix', () => {
      expect(scoreAgent('env-override')).toBe(0.5);
      expect(scoreAgent('env-override>user-spawned')).toBe(0.5);
      expect(scoreAgent('env-override>user-spawned>task-1')).toBe(0.5);
    });

    it('should score cron origin at 0.5', () => {
      expect(scoreAgent('cron')).toBe(0.5);
    });

    it('should score agent-spawned at 0.3', () => {
      expect(scoreAgent('agent-spawned')).toBe(0.3);
    });

    it('should decay cron sub-agents', () => {
      expect(scoreAgent('cron>job-1')).toBe(0.35);
    });

    it('should default unknown origins to 0.3', () => {
      expect(scoreAgent('unknown-origin')).toBe(0.3);
    });

    it('should block agents beyond max depth', () => {
      const deep = 'user-spawned>a>b>c>d>e>f'; // depth 6, max is 5
      expect(scoreAgent(deep)).toBe(0);
    });

    it('should allow agents at max depth', () => {
      const atMax = 'user-spawned>a>b>c>d>e'; // depth 5 = max
      expect(scoreAgent(atMax)).toBeGreaterThan(0);
    });

    it('should accept custom config', () => {
      const config = { ...DEFAULT_AGENT_CONFIG, decayFactor: 0.5 };
      expect(scoreAgent('user-spawned>task', config)).toBe(0.45);
    });
  });

  describe('getAgentDepth', () => {
    it('should return 0 for parent agents', () => {
      expect(getAgentDepth('user-spawned')).toBe(0);
    });

    it('should count hierarchy depth', () => {
      expect(getAgentDepth('user-spawned>a>b>c')).toBe(3);
    });
  });

  describe('buildAgentHierarchy', () => {
    it('should build readable hierarchy', () => {
      const hierarchy = buildAgentHierarchy('user-spawned>task-1');
      expect(hierarchy).toHaveLength(2);
      expect(hierarchy[0]).toContain('user-spawned');
      expect(hierarchy[0]).toContain('0.900');
      expect(hierarchy[1]).toContain('task-1');
      expect(hierarchy[1]).toContain('0.630');
    });
  });

  describe('integration with scoreSource', () => {
    it('should use hierarchy scoring for agent sources', async () => {
      const { scoreSource } = await import('../trust/source-scorer.js');

      const parent = scoreSource({ type: 'agent', identifier: 'user-spawned' });
      expect(parent.score).toBe(0.9);

      const child = scoreSource({ type: 'agent', identifier: 'user-spawned>task-1' });
      expect(child.score).toBe(0.63);

      // Hierarchy should show agent chain
      expect(child.hierarchy[0]).toContain('Agent Hierarchy');
    });

    it('should not affect non-agent sources', async () => {
      const { scoreSource } = await import('../trust/source-scorer.js');

      const cli = scoreSource({ type: 'cli', identifier: 'mcp' });
      expect(cli.score).toBe(0.9);
    });
  });
});
