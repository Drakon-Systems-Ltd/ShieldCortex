/**
 * Assembly detection — scoring heuristics for fragmented payload risk
 *
 * Evaluates whether overlapping entities across memories could combine
 * into a coherent attack payload (e.g., URL + credential = exfiltration).
 */

import type { ExtractedEntity } from './entity-extractor.js';
import type { OverlappingEntity } from './temporal-analyzer.js';

export interface AssemblyAnalysis {
  score: number;
  risk: string;
  suspiciousPatterns: string[];
}

/**
 * Detect whether overlapping entities suggest payload assembly
 */
export function detectAssembly(
  overlapping: OverlappingEntity[],
  newEntities: ExtractedEntity[]
): AssemblyAnalysis {
  if (overlapping.length === 0) {
    return { score: 0, risk: 'none', suspiciousPatterns: [] };
  }

  let score = 0;
  const suspiciousPatterns: string[] = [];

  const overlapTypes = new Set(overlapping.map(o => o.type));
  const newTypes = new Set(newEntities.map(e => e.type));
  const allTypes = new Set([...overlapTypes, ...newTypes]);

  const allMemoryIds = new Set<number>();
  for (const o of overlapping) {
    for (const id of o.memoryIds) {
      allMemoryIds.add(id);
    }
  }
  const memoryCount = allMemoryIds.size;

  // URL + credential → high risk
  if (allTypes.has('url') && (allTypes.has('credential') || allTypes.has('api_key'))) {
    score += 0.4;
    suspiciousPatterns.push(
      `URL and credential entities found across ${memoryCount} memories — possible exfiltration pattern`
    );
  }

  // URL + command → medium risk
  if (allTypes.has('url') && allTypes.has('command')) {
    score += 0.3;
    suspiciousPatterns.push(
      `URL and command entities found across ${memoryCount} memories — possible remote execution pattern`
    );
  }

  // Command + file path → medium risk
  if (allTypes.has('command') && allTypes.has('file_path')) {
    score += 0.25;
    suspiciousPatterns.push(
      `Command and file path entities found across ${memoryCount} memories — possible local exploitation pattern`
    );
  }

  // IP address + credential → high risk
  if (allTypes.has('ip_address') && (allTypes.has('credential') || allTypes.has('api_key'))) {
    score += 0.4;
    suspiciousPatterns.push(
      `IP address and credential entities found across ${memoryCount} memories — possible lateral movement pattern`
    );
  }

  // Multiple overlapping entities from different sources
  if (memoryCount >= 3) {
    score += 0.1 * Math.min(memoryCount - 2, 3);
    suspiciousPatterns.push(
      `Entities overlap across ${memoryCount} distinct memory sources`
    );
  }

  // More than 3 overlapping entities bonus
  if (overlapping.length > 3) {
    score += 0.2;
    suspiciousPatterns.push(
      `${overlapping.length} overlapping entities detected — high fragment density`
    );
  }

  score = Math.min(score, 1.0);

  let risk: string;
  if (score >= 0.7) {
    risk = 'critical';
  } else if (score >= 0.4) {
    risk = 'high';
  } else if (score >= 0.2) {
    risk = 'medium';
  } else {
    risk = 'low';
  }

  return { score, risk, suspiciousPatterns };
}
