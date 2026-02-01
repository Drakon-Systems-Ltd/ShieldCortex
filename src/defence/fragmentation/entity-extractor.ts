/**
 * Entity extraction from memory content
 *
 * Identifies security-relevant entities (URLs, credentials, commands, etc.)
 * that could be fragments of a larger attack payload.
 */

import { getDatabase } from '../../database/init.js';

export interface ExtractedEntity {
  type: 'url' | 'credential' | 'command' | 'file_path' | 'api_key' | 'ip_address';
  value: string;
}

// ── Regex patterns ──

const URL_PATTERN = /https?:\/\/[^\s"'<>)\]]+/gi;

const API_KEY_PATTERNS = [
  /sk-[A-Za-z0-9]{20,}/g,       // OpenAI-style
  /AKIA[A-Z0-9]{16}/g,          // AWS access key
  /ghp_[A-Za-z0-9]{36,}/g,      // GitHub PAT
  /gho_[A-Za-z0-9]{36,}/g,      // GitHub OAuth
  /glpat-[A-Za-z0-9\-_]{20,}/g, // GitLab PAT
  /xox[bposa]-[A-Za-z0-9\-]+/g, // Slack tokens
];

const CREDENTIAL_PATTERN = /(?:token|password|secret|key|auth)[=:\s]+["']?([A-Za-z0-9_\-]{20,})["']?/gi;

const COMMAND_PATTERNS = /(?:^|\s)((?:curl|wget|ssh|scp|rsync|chmod|chown|rm|sudo|apt|yum|pip|npm|docker|kubectl|nc|ncat|bash|sh|python|perl|ruby|eval|exec)\s+[^\n]{3,})/gim;

const UNIX_PATH_PATTERN = /(?:^|\s)(\/(?:etc|var|tmp|usr|home|opt|root|dev|proc|sys|bin|sbin)\/[^\s"'<>]+)/gm;
const WINDOWS_PATH_PATTERN = /(?:^|\s)([A-Z]:\\[^\s"'<>]+)/gm;

const IPV4_PATTERN = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

/**
 * Extract security-relevant entities from content
 */
export function extractEntities(content: string): ExtractedEntity[] {
  const entities: ExtractedEntity[] = [];
  const seen = new Set<string>();

  const add = (type: ExtractedEntity['type'], value: string) => {
    const key = `${type}:${value}`;
    if (!seen.has(key)) {
      seen.add(key);
      entities.push({ type, value });
    }
  };

  // URLs
  for (const match of content.matchAll(URL_PATTERN)) {
    add('url', match[0]);
  }

  // API keys (check before generic credentials)
  for (const pattern of API_KEY_PATTERNS) {
    for (const match of content.matchAll(pattern)) {
      add('api_key', match[0]);
    }
  }

  // Credentials
  for (const match of content.matchAll(CREDENTIAL_PATTERN)) {
    add('credential', match[1]);
  }

  // Commands
  for (const match of content.matchAll(COMMAND_PATTERNS)) {
    add('command', match[1].trim());
  }

  // File paths
  for (const match of content.matchAll(UNIX_PATH_PATTERN)) {
    add('file_path', match[1]);
  }
  for (const match of content.matchAll(WINDOWS_PATH_PATTERN)) {
    add('file_path', match[1]);
  }

  // IP addresses
  for (const match of content.matchAll(IPV4_PATTERN)) {
    const ip = match[1];
    const parts = ip.split('.').map(Number);
    if (parts.every(p => p >= 0 && p <= 255)) {
      add('ip_address', ip);
    }
  }

  return entities;
}

/**
 * Store extracted entities in the fragmentation_entities table
 */
export function storeExtractedEntities(memoryId: number, entities: ExtractedEntity[]): void {
  if (entities.length === 0) return;

  const db = getDatabase();
  const stmt = db.prepare(
    'INSERT INTO fragmentation_entities (memory_id, entity_type, entity_value) VALUES (?, ?, ?)'
  );

  const insertMany = db.transaction((items: ExtractedEntity[]) => {
    for (const entity of items) {
      stmt.run(memoryId, entity.type, entity.value);
    }
  });

  insertMany(entities);
}
