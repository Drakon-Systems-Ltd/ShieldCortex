/**
 * Trust source scorer — assigns trust levels based on memory source.
 */

import type { DefenceSource, TrustScore } from '../types.js';
import { scoreAgent, buildAgentHierarchy } from './agent-scorer.js';

const BASE_SCORES: Record<string, number> = {
  'user:direct': 1.0,
  'user:approved': 0.9,
};

const TYPE_SCORES: Record<DefenceSource['type'], number> = {
  user: 1.0,
  cli: 0.9,
  hook: 0.8,
  api: 0.7,
  file: 0.6,
  email: 0.4,
  web: 0.3,
  agent: 0.5,
};

const HIERARCHY_DISPLAY = [
  'user:direct = 1.0',
  'user:approved = 0.9',
  'cli:* = 0.9',
  'hook:* = 0.8',
  'api:* = 0.7',
  'file:* = 0.6',
  'agent:* = hierarchy',
  'email:* = 0.4',
  'web:* = 0.3',
];

export function scoreSource(source: DefenceSource): TrustScore {
  const key = `${source.type}:${source.identifier}`;

  // Exact match overrides
  const baseScore = BASE_SCORES[key];
  if (baseScore !== undefined) {
    return { score: baseScore, source, hierarchy: [...HIERARCHY_DISPLAY, `>> ${key} = ${baseScore}`] };
  }

  // Agent hierarchy scoring
  if (source.type === 'agent') {
    const score = scoreAgent(source.identifier);
    return {
      score,
      source,
      hierarchy: [
        'Agent Hierarchy:',
        ...buildAgentHierarchy(source.identifier),
        `>> ${key} = ${score}`,
      ],
    };
  }

  // Type fallback
  const score = TYPE_SCORES[source.type] ?? 0;
  return { score, source, hierarchy: [...HIERARCHY_DISPLAY, `>> ${key} = ${score}`] };
}
