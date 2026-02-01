/**
 * Trust source scorer — assigns trust levels based on memory source.
 */

import type { DefenceSource, TrustScore } from '../types.js';

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

export function scoreSource(source: DefenceSource): TrustScore {
  const key = `${source.type}:${source.identifier}`;
  const score = BASE_SCORES[key] ?? TYPE_SCORES[source.type] ?? 0;

  return {
    score,
    source,
    hierarchy: [
      'user:direct = 1.0',
      'user:approved = 0.9',
      'api:* = 0.7',
      'file:* = 0.6',
      'email:* = 0.4',
      'web:* = 0.3',
      'agent:* = 0.1',
      `>> ${key} = ${score}`,
    ],
  };
}
