/**
 * Entity extraction from memory content
 *
 * Identifies security-relevant entities (URLs, credentials, commands, etc.)
 * that could be fragments of a larger attack payload.
 *
 * CHARTER: this is the SYNC-PATH working set for fragment-assembly scoring
 * (24h window). It is NOT superseded by the threat graph: the graph's event
 * tier records only caught/notable rows, while fragment assembly is about
 * individually-innocuous ALLOW writes that only add up to an attack in
 * aggregate — exactly the rows the graph never sees. The threat graph's
 * campaign detection (Phase D) complements this with cross-source
 * attribution over CAUGHT events; neither replaces the other.
 */

import { getDatabase } from '../../database/init.js';
import { getCredentialRegexesByName } from '../credential-leak/patterns.js';

export interface ExtractedEntity {
  type: 'url' | 'credential' | 'command' | 'file_path' | 'api_key' | 'ip_address';
  value: string;
}

// ── Regex patterns ──

const URL_PATTERN = /https?:\/\/[^\s"'<>)\]]+/gi;

// Token-shaped provider regexes are sourced from the single source of truth
// (credential-leak/patterns.ts) rather than re-declared here, so there is ONE
// definition of "what an OpenAI / AWS / GitHub key looks like" across the
// codebase (Phase 17 C3). We pull only the specific prefixed-token providers
// this extractor already matched — NOT the broad/low-confidence heuristics
// (bare 32-hex, UUID) — so the set of tokens classified as `api_key` is
// unchanged. GitLab + the broad Slack-variant matcher have no canonical
// equivalent, so they stay defined locally (different scope).
const API_KEY_PATTERNS = [
  ...getCredentialRegexesByName([
    'OpenAI API Key',                 // sk-...
    'AWS Access Key ID',              // AKIA...
    'GitHub Personal Access Token',   // ghp_...
    'GitHub OAuth Token',             // gho_...
  ]),
  /glpat-[A-Za-z0-9\-_]{20,}/g, // GitLab PAT (no canonical equivalent)
  /xox[bposa]-[A-Za-z0-9\-]+/g, // Slack tokens (broader than canonical xoxb rule)
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

  try {
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
  } catch {
    // DB not initialized (e.g. SaaS context) — skip entity storage
  }
}
