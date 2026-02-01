/**
 * Fragmentation Detector
 *
 * Detects fragmented payload assembly — the attack vector where individually
 * benign memories combine into an attack when assembled. Inspired by the
 * Palo Alto research on memory poisoning through fragment accumulation.
 */

import type { DefenceConfig, FragmentationAnalysis } from '../types.js';
import { extractEntities, storeExtractedEntities } from './entity-extractor.js';
import { findOverlappingEntities } from './temporal-analyzer.js';
import { detectAssembly } from './assembly-detector.js';

export { extractEntities, storeExtractedEntities } from './entity-extractor.js';
export type { ExtractedEntity } from './entity-extractor.js';
export { getRecentEntities, findOverlappingEntities } from './temporal-analyzer.js';
export type { OverlappingEntity } from './temporal-analyzer.js';
export { detectAssembly } from './assembly-detector.js';
export type { AssemblyAnalysis } from './assembly-detector.js';

/**
 * Full fragmentation analysis pipeline for incoming content
 */
export function analyzeFragmentation(
  content: string,
  title: string,
  config: DefenceConfig
): FragmentationAnalysis {
  const fullText = `${title}\n${content}`;
  const newEntities = extractEntities(fullText);

  if (newEntities.length === 0) {
    return {
      score: 0,
      relatedMemoryIds: [],
      suspiciousEntities: [],
      assemblyRisk: 'none',
    };
  }

  const windowHours = config.fragmentationWindowHours;
  const overlapping = findOverlappingEntities(newEntities, windowHours);
  const assembly = detectAssembly(overlapping, newEntities);

  const relatedMemoryIds = [
    ...new Set(overlapping.flatMap(o => o.memoryIds)),
  ];

  const suspiciousEntities = overlapping.map(
    o => `${o.type}:${o.value} (${o.occurrences} occurrences)`
  );

  return {
    score: assembly.score,
    relatedMemoryIds,
    suspiciousEntities,
    assemblyRisk: assembly.risk,
  };
}

/**
 * Store fragmentation data for a newly created memory
 */
export function storeFragmentationData(memoryId: number, content: string): void {
  const entities = extractEntities(content);
  storeExtractedEntities(memoryId, entities);
}
