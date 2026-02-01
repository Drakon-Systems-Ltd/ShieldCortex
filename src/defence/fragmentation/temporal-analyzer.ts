/**
 * Temporal analysis of entity fragments
 *
 * Looks for entity overlap across memories within a time window,
 * detecting potential fragment assembly over time.
 */

import { getDatabase } from '../../database/init.js';
import type { ExtractedEntity } from './entity-extractor.js';

export interface OverlappingEntity {
  type: string;
  value: string;
  occurrences: number;
  memoryIds: number[];
}

export interface RecentEntity {
  entity_type: string;
  entity_value: string;
  memory_id: number;
  detected_at: string;
}

/**
 * Query fragmentation_entities for entries within the time window
 */
export function getRecentEntities(windowHours: number): RecentEntity[] {
  const db = getDatabase();
  const rows = db.prepare(
    `SELECT entity_type, entity_value, memory_id, detected_at
     FROM fragmentation_entities
     WHERE detected_at >= datetime('now', ? || ' hours')
     ORDER BY detected_at DESC`
  ).all(-windowHours) as RecentEntity[];

  return rows;
}

/**
 * Find entities from the new memory that also appear in recent memories
 */
export function findOverlappingEntities(
  entities: ExtractedEntity[],
  windowHours: number
): OverlappingEntity[] {
  if (entities.length === 0) return [];

  const recent = getRecentEntities(windowHours);
  const overlapping: OverlappingEntity[] = [];

  for (const entity of entities) {
    const matches = recent.filter(
      r => r.entity_type === entity.type && r.entity_value === entity.value
    );

    if (matches.length > 0) {
      const memoryIds = [...new Set(matches.map(m => m.memory_id))];
      overlapping.push({
        type: entity.type,
        value: entity.value,
        occurrences: matches.length,
        memoryIds,
      });
    }
  }

  return overlapping;
}
